#!/usr/bin/python
#Author : Srinivas Gadi

import urllib2
import platform
import os
def get_host_region():
        import pdb;pdb.set_trace()
	host_API = 'https://devops.oraclecorp.com/ws/public/v1/hosts/assets/%s/properties/' %(platform.uname()[1])
	response = urllib2.urlopen(host_API).read()
        for region in response.split(","):
            if region.split(":")[0] == ' "eng-region"' :
               return (region.split(":")[1].replace('"','')).strip()
#	host_site = str(json.loads(response.read())[u'eng-region'])

if get_host_region():
   print get_host_region()
else:
   try:
     print os.popen('grep -i eng-region /etc/asset/asset.properties').read().strip().split('=')[1]
   except:
     print "None"
