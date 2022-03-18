#!/usr/bin/python
# Author : Srinivas Gadi
# Purpose : OIT Patching pre installation

import os
import sys
import urllib2
import getpass
import platform
import socket
from commands import getstatusoutput
import logging
import re
import time
# import argparse
import socket


def sanpshot():

    try:
       get_json='https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/monthly_patch.json'
       response = urllib2.urlopen(get_json).read()
       dict_data=eval(response)
       return dict_data['patch_snapshot_date']

    except:
       sys.exit('Failed to read json')

def get_log_file():
    host = socket.gethostname()
    hostname=host.split('.')[0]
    
    csv_log="/root/%s.csv" %hostname

    local_file_exits = os.path.isfile(csv_log)
 
    if local_file_exits:
       return csv_log
    else:
       return False

def get_data_cves():
    patch_url='https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/ol_cpu_patching.py'

    patching_script='rm -rf /tmp/ol_cpu_patching.py;cd /tmp;wget %s' %patch_url
    (state,output) = getstatusoutput(patching_script)
    if state == 0:
       cmd='python /tmp/ol_cpu_patching.py -q -cv'
       (state,output) = getstatusoutput(cmd)
       if state == 0:
          #print('cves data = %s' %output)
          ''' if SECURITY ADVISORY LIST empty, it means its already patched.'''
          SAL=output.split('\n')[-1].split('\t')[1]
          if SAL:
             return 'Not patched'
          else:
             return 'Patched'
       else:
          return output
    else:
       return 'Failed to download patching script'

def get_data():
       snaphost_date=sanpshot()
#       print("snaphost_date = %s" %snaphost_date)
       log_file=get_log_file()
       if log_file:
          (state,output) = getstatusoutput("grep -w %s %s" %(snaphost_date, log_file))
          if state == 0:     
              '''remove escape charcters from output'''
              reaesc = re.compile(r'\x1b[^m]*m')
              output = reaesc.sub('', output)
              #return output
          else:
              output =  'NotPatched with %s snapshot' %snaphost_date 
       else:
         output = get_data_cves()

       output = '%s:%s' %(socket.gethostname(),output)
       return output



print(get_data())
