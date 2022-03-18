#!/usr/bin/python
# Author : Srinivas Gadi
# Purpose : OIT Patching pre installation

import os
import sys
import urllib2
import platform
import re
import time
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

def read_json(key):
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
        #return dict_data['patch_snapshot_date']
        return dict_data[key]
    
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

def get_uek():
    #http://pd-yum-slc-01.us.oracle.com/data_files/oit/scripts/get_host_uek.py
    state,host_kernel=commands.getstatusoutput('curl --silent http://pd-yum-slc-01.us.oracle.com/data_files/oit/scripts/get_host_uek.py | python')
    if host_kernel == 'OL5':
       return host_kernel
    host_kernel=eval(host_kernel)
    
    return host_kernel

def verify_default_grub():
    #check if grub file exists
    os_version=get_os_version()
    get_uek_ver=get_uek()
    get_uek_ver='uek%s_kernel' %(get_uek_ver)

    get_latest_kernel=read_json(get_uek_ver)
    #print('os_version = %s' %os_version)
    #print('get_latest_kernel = %s' %get_latest_kernel)

    if os_version in [5, 6 ]:
       grub_file='/boot/grub/grub.conf'
    elif os_version in [7, 8 ]:
       grub_file='/boot/grub2/grub.cfg'
              
    if os.path.exists(grub_file)  and os.path.getsize(grub_file) > 0:
       cmd="grubby --default-kernel | grep vmlinuz-%s | grep -i el%s" %(get_latest_kernel,os_version) 
       (post_cve_status,post_cve_output) = commands.getstatusoutput(cmd)
       if post_cve_output:
          return "GrubSetWithLatestKernel",get_latest_kernel
       else:
          return "GrubNOTSetWithLatestKernel","NO"

def get_initrm():
    #rpm -ql kernel-uek-4.1.12-124.52.5.el7uek.x86_64 | grep init | grep boot
    os_version=get_os_version()
    host_uek="el%suek" %os_version

    get_uek_ver=get_uek()
    get_uek_ver="uek%s_kernel" %get_uek_ver

    get_latest_kernel=read_json(get_uek_ver)
    host_arch_status, host_arch = commands.getstatusoutput('uname -p')

    cmd = "rpm -ql kernel-uek-%s.%s.%s | grep init | grep boot | xargs -n1"  %(get_latest_kernel,host_uek,host_arch)
    initrm_status, initrm_res = commands.getstatusoutput(cmd)
    if initrm_status == 0 and initrm_res:
       return 'InitramFileCreated'
    else:
       return 'InitramFileNOTCreated'

def get_reboot_status(latest_kernel):
    cmd = "uname -r | grep %s" %latest_kernel
    kernel_status, kernel_res = commands.getstatusoutput(cmd)
    if kernel_status == 0 and kernel_res:
       return "Rebooted"
    else:
       return "RebootRequired"
    
def get_data():
       #snaphost_date=sanpshot()
       snaphost_date=read_json('patch_snapshot_date')
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
              output =  'NotPatched with latest snapshot(%s)' %snaphost_date 
       else:
         #output = "%s" %get_data_cves()
         output = "NotPatched"

       output = '%s|%s' %(socket.gethostname(),output)
       return output

#print(verify_default_grub())
#print(get_initrm())

if not check_if_patch_running():
   patch_status=get_data()
   if 'NotPatched' in patch_status or 'OL5' in patch_status:
      print(patch_status)
   else:
      get_defaukt_grub_status,latest_kernel = verify_default_grub()
      if get_defaukt_grub_status == "GrubSetWithLatestKernel":
         reboot_status = get_reboot_status(latest_kernel)
      else:
         reboot_status = "VerifyGrubAndReboot"

      print('%s,%s,%s,%s' %(patch_status,get_defaukt_grub_status,get_initrm(),reboot_status))
else:
   print('Still patch process is running')

