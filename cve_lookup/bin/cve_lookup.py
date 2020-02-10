# $SPLUNK_HOME/etc/apps/cryptonite/bin/cve_lookup.py

import sys
import xml.dom.minidom, xml.sax.saxutils
import os
import json
import logging
import time
import requests
import StringIO
import gzip
import datetime
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib.modularinput import *

class MyScript(Script):

    def get_scheme(self):
        scheme = Scheme("cve_lookup")
        scheme.description = "Fetch CVE information from NVD json feed."
        scheme.use_external_validation = True
        scheme.use_single_instance = False

        apikey_argument = Argument("format")
        apikey_argument.data_type = Argument.data_type_string
        apikey_argument.description = "zip or gz"
        apikey_argument.required_on_create = True
        scheme.add_argument(apikey_argument)

        apikey_argument = Argument("years")
        apikey_argument.data_type = Argument.data_type_string
        apikey_argument.description = "Comma seperated years."
        apikey_argument.required_on_create = True
        scheme.add_argument(apikey_argument)

        return scheme

    def validate_input(self, validation_definition):
        format = str(validation_definition.parameters["format"]).lower()
        years = str(validation_definition.parameters["years"]).lower().split(',')
        if format.lower() == "zip" or format.lower() == "gz":
            pass
        else:
            raise ValueError("format attribute should be 'zip' or 'gz'.")
        for year in years:
            accepted_years = {'2019', '2018', '2017'}
            y = year.strip()
            if y not in accepted_years:
                raise ValueError("Allowed years: 2017, 2018 or 2019")
            

    def stream_events(self, inputs, ew):
        for input_name, input_item in inputs.inputs.iteritems():
            load_data(input_name, input_item, ew)


def load_data(input_name,input_item, ew):
    try:
        format = str(input_item["format"]).lower()
        years = str(input_item["years"]).split(",")
        for year in years:
            yr = year.strip()
            logging.info("Fetching cve information for year %s" % yr)
            url = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%s.json.%s' % (yr,format) 
            logging.info("url=%s" % url) 
            response = requests.get(url)
            data = {}
            
            if format == "gz":
                compressedFile = StringIO.StringIO(response.content)
                decompressedFile = gzip.GzipFile(fileobj=compressedFile)
                data = json.load(decompressedFile)
            else:
                f = StringIO.StringIO() 
                f.write(response.content)
                input_zip = zipfile.ZipFile(f)
                for i in input_zip.namelist():
                    if i == "nvdcve-1.0-%s.json" % yr:
                        data = json.loads(input_zip.read(i))
                        break

            logging.info("No of cve records fetched for %s: %s" %(yr, str(len(data["CVE_Items"]))))
            for d in data["CVE_Items"]:
                info_event_json = {}
                info_event_json["cve"] = d["cve"]["CVE_data_meta"]["ID"]
                info_event_json["impact"] = d["impact"]
                info_event_json["publishedDate"] = d["publishedDate"]
                info_event_json["lastModifiedDate"] = d["lastModifiedDate"]
                info_event_json["description"] = d["cve"]["description"]
                event = Event()
                event.data = json.dumps(info_event_json)
                event.sourceType = "cveinfo"
                ew.write_event(event)

                product_event_json = {}
                product_event_json["cve"] = d["cve"]["CVE_data_meta"]["ID"]
                product_event_json["affects"] = d["cve"]["affects"]
                event = Event()
                event.data = json.dumps(product_event_json)
                event.sourceType = "cveproducts"
                ew.write_event(event)

                references_event_json = {}
                references_event_json["cve"] = d["cve"]["CVE_data_meta"]["ID"]
                references_event_json["references"] = d["cve"]["references"]
                event = Event()
                event.data = json.dumps(references_event_json)
                event.sourceType = "cvereferences"
                ew.write_event(event)
    except Exception as e:
        logging.error(e)

if __name__ == "__main__":
    sys.exit(MyScript().run(sys.argv))
