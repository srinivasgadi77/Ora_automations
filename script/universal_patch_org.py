#!/usr/bin/python
#Author: Srinivas Gadi
##Its laywer to patching script which will do some preliminary checks and exectute the patching script accrding to the DOM0/DOMU/OL5

import commands
import platform
import os, sys


def get_os_version():
    os_version = platform.dist()[1].split('.')[0]
    if os_version:
      return eval(os_version)

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

def execute_patch_scrit(patch_cmd):
    print("Executing : %s" %patch_cmd) 
    status, output = commands.getstatusoutput(patch_cmd)
	
    if not status:
       print('Executing %s\n' %patch_cmd)
       print("----------------------------\n")
       print(output)
    else:
       print('Failed to execute')
       print(output)

def patch_ol5():
    try:
       run_cmd="rm -rf /tmp/ol5_cpu_patching.py;wget -O /tmp/ol5_cpu_patching.py http://pd-yum-slc-01.us.oracle.com/data_files/oit/scripts/ol5_cpu_patching.py; chmod +x /tmp/ol5_cpu_patching.py; python /tmp/ol5_cpu_patching.py"
    except:
       run_cmd="rm -rf /tmp/ol5_cpu_patching.py;wget -O /tmp/ol5_cpu_patching.py --no-proxy --no-check-certificate http://pd-yum-slc-01.us.oracle.com/data_files/oit/scripts/ol5_cpu_patching.py; chmod +x /tmp/ol5_cpu_patching.py; python /tmp/ol5_cpu_patching.py"

    return run_cmd

def get_patch_script(os_type,os_version):

    if os_type == "DOMU":
    
       if os_version > 5:
    	   try:
              run_cmd="rm -rf /tmp/ol_cpu_patching.py;cd /tmp;wget https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/ol_cpu_patching.py;chmod +x /tmp/ol_cpu_patching.py; python /tmp/ol_cpu_patching.py  --quarterly  --security-patch"
           except:
    	      run_cmd = "rm -rf /tmp/ol_cpu_patching_no-proxy.py;cd /tmp;wget --no-proxy --no-check-certificate http://pd-yum-slc-01.us.oracle.com/data_files/oit/scripts/ol_cpu_patching_no-proxy.py;chmod +x /tmp/ol_cpu_patching_no-proxy.py;python /tmp/ol_cpu_patching_no-proxy.py --quarterly  --security-patch"
        
       return run_cmd
		
    if os_type == "DOM0":
       try:
    	    run_cmd="rm -rf /tmp/ovm_security_patch.py /tmp/ovm_security_patch.json;cd /tmp;wget https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/ovm_security_patch.py;wget https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/ovm_security_patch.json;chmod +x /tmp/ovm_security_patch.py;/tmp/ovm_security_patch.py -j ovm_security_patch.json -u"
       except:
    	    run_cmd="rm -rf /tmp/ovm_security_patch.py /tmp/ovm_security_patch.json;cd /tmp;wget --no-proxy --no-check-certificate https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/ovm_security_patch.py;wget --no-proxy --no-check-certificate https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/ovm_security_patch.json;chmod +x /tmp/ovm_security_patch.py;python /tmp/ovm_security_patch.py -j ovm_security_patch.json -u"
    
       return run_cmd
    else:
      print('Failed to identify the host type')
		
def check_fs_readOnly():
    cmd='cd /tmp;touch tmp_file.txt'
    result = os.popen(cmd).read().strip()

    if 'Read-only' in result or 'cannot' in result:
        return result
    else:
        return

def pre_stuff():
    FsReadOnly=check_fs_readOnly()
    if FsReadOnly:
       sys.exit('Read-only file system')

    os.popen('rm -rf /var/cache').read()
    os.popen('yum clean all').read()

def main():

   os_version=get_os_version()
   if os_version == 5:
      patch_cmd = patch_ol5()
      os_type='DOMU'
   else:
     os_type=get_os_type()
     if os_type == 'Solaris':
         print('EXIT: Its a Solaris host')
     else:    
         patch_cmd = get_patch_script(os_type,os_version)
	
         print('OS_TYPE : %s\nOS_VERSION : %s' %(os_type,os_version))
	
         execute_patch_scrit(patch_cmd)

main()
