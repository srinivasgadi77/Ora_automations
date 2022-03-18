#!/usr/bin/python
# Author : Srinivas Gadi
# Purpose : OIT Patching pre installation

import os
import sys
import urllib2
import platform
import re
import time
# import argparse
import socket

try:
   import commands
except:
   import subprocess as commands


def get_os_type():
    status, result = commands.getstatusoutput('cat /etc/*release')
    if 'Oracle VM server release' in result or 'Oracle VM Server release' in result:
           return 'DOM0'
    elif 'Oracle Linux Server release'  in result or 'Oracle Linux Server'  in result:
           return 'DOMU'
    elif 'Solaris' in result:
          return 'Solaris'

    linux_dist = platform.linux_distribution()[0] 
    if linux_dist == "Oracle Linux Server":
       return 'DOMU'
    elif linux_dist == 'Oracle VM server':
       return 'DOM0'
    else:
       sys.exit('EXIT: its a %s host' %result)

def get_os_version():
    os_version = platform.dist()[1].split('.')[0]
    if os_version:
      return eval(os_version)

def sanpshot():
    os_type=get_os_type()
    if os_type == 'DOMU':
       if get_os_version()==5:
          return 'OL5'
       else:
          get_json='https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/quarterly_patch.json'
    elif os_type == 'DOM0':
       get_json='https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/monthly_patch.json'
    else:
       sys.exit(os_type)

    try:
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
    (state,output) = commands.getstatusoutput(patching_script)
    if state == 0:
       cmd='python /tmp/ol_cpu_patching.py -q -cv'
       (state,output) = commands.getstatusoutput(cmd)
       if state == 0:
          #print('cves data = %s' %output)
          ''' if SECURITY ADVISORY LIST empty, it means its already patched.'''
          SAL=output.split('\n')[-1].split('\t')[1]
          if SAL:
             return 'Not patched|reboot_not_required '
          else:
             return 'Patched|reboot_not_required'
       else:
          return output
    else:
       return 'Failed to download patching script'

def is_reboot_required(log_file):
    '''Get uptime'''
   
    #get_uptime=commands.getoutput('cat /proc/uptime').split()[0]
    cmd="who -b | awk '{print $3,$4}'"
    status, result = commands.getstatusoutput(cmd)
    get_uptime=time.mktime(time.strptime(result,'%Y-%m-%d %H:%M'))

    #print("get_uptime  = %s" %get_uptime)
    
    '''Get when was the log file last updated'''
    #log_file="/tmp/test"
    file_last_update=os.path.getmtime(log_file)
    #time_now=time.time()
    #delta=time_now-file_last_update
    
    #print('delta=%s' %delta)
    if file_last_update > get_uptime:
       reboot_status='reboot_required'
    else:
       reboot_status='reboot_not_required'

    return reboot_status

def check_if_patch_running():
    #Check patching process still exists
     check_patching_process="ps -ef | grep cpu_patching.py| grep -v grep"
     status, result = commands.getstatusoutput(check_patching_process)
     if status == 0:
        return True
     else:
        return False

def filter_csv_log(output):
    for data in output.split(','):
        if 'FAIL' in data:
            return data
    return 'Patching Success'

def get_data():
       snaphost_date=sanpshot()
#       print("snaphost_date = %s" %snaphost_date)
       log_file=get_log_file()
       if log_file:
          
          if snaphost_date == 'OL5':
              return  "%s|%s" %('OL5_patch_success',is_reboot_required(log_file))

          #import pdb;pdb.set_trace()
          (state,output) = commands.getstatusoutput("grep -w %s %s | tail -1" %(snaphost_date, log_file))
          if state == 0 and output:    
              '''remove escape charcters from output'''
              reaesc = re.compile(r'\x1b[^m]*m')
              output = reaesc.sub('', output)
              #patch_status = filter_csv_log(output)
              #reboot_status=is_reboot_required(log_file)
              #output = "%s|%s" %(patch_status, reboot_status)

              return output
          else:
              output =  'NotPatched' 
       else:
         #output = "%s" %get_data_cves()
         output = "NotPatched"

       output = '%s|%s' %(socket.gethostname(),output)
       return output


if not check_if_patch_running():
   print(get_data())
else:
   print('Still patch process is running')

