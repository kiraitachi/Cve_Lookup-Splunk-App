# Cve_Lookup-Splunk-App 2020 Fixed

It is a Splunk App that pulls down CVE information from the National Vulnerability Database using its new JSON 1.0 feed. The app extracts CVE information, its impact, affected products, vendors and associated advisory and references. It could be a great addition to enrich data that your security team already looks into for creating very informative correlation.

-----------------------------------------------------------------------------------------------------------------------------------------

# Indexes and Sourcetypes
index=cve with a default retention of 3 days.
Sourcetypes are cveinfo, cvereferences and cveproducts

# Data feed
Data is pulled through a modular input [cve://<name] where you can specify the cron/interval and specify what format to download (gz or zip).

# Dashboards
It has two sample dashboards for you to play with and get a feel of what you can do with this data. The dashboards allow you to lookup CVE by Year (supported years are 2017-2019) and lookup CVE by Vendor. Screenshots below.

-----------------------------------------------------------------------------------------------------------------------------------------
# Downloads

Go to Relase section or just click here:
https://github.com/kiraitachi/Cve_Lookup-Splunk-App/releases/download/1.0/Cve_Lookup-Splunk-App-1.0.tar.gz


# Credits
This repo is fixed upload fork of the original code done by ManishMenon86. Since I tried reaching him for a fix of the new 2020 CVE bug with no avail, I decided to download the Splunk App and fiddle in the code to correct the issue.

Other than that all credits are due to him.

Author: https://splunkbase.splunk.com/apps/#/author/manishmenon86
https://splunkbase.splunk.com/app/4540/

You can also find more information on his Blog:
https://fuzzmymind.com/2019/06/13/cve-lookup-splunk-app/
