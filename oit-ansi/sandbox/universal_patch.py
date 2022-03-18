#!/usr/bin/python
#Author: Srinivas Gadi
##Its laywer to patching script which will do some preliminary checks and exectute the patching script accrding to the DOM0/DOMU/OL5

import platform
import os, sys
import shutil

try:
   import commands
except: 
   import subprocess as commands

access_cmd="https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security"

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


def get_hostname():
    return os.popen('hostname -f').read().strip()


def execute_patch_scrit(patch_cmd):
    print("Executing : %s" %patch_cmd) 
    status, output = commands.getstatusoutput(patch_cmd)
    output='%s : %s' %(get_hostname(),output.strip())

    if not status:
       print(output)
       return True, True
    else:
       print(' ==> Runing with no proxy tag')
       return False, output

def patch_ol5():

       patch_cmd="wget -O /tmp/ol5_cpu_patching.py https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/ol5_cpu_patching.py"
       py_version='python'
       exe_cmd="/tmp/ol5_cpu_patching.py"

       run_exec_cmd = "%s;%s %s" %(patch_cmd,py_version,exe_cmd)
       status,_ = execute_patch_scrit(run_exec_cmd)
       if not status:
          run_exec_cmd = "%s;cd /tmp;wget -q %s %s;%s %s" %(del_old_cmd,no_proxy, patch_cmd,py_version,exe_cmd)

          #Execut patching
          status,res = execute_patch_scrit(run_exec_cmd)

          if not status:
             #sys.exit('Failed patch script due to %s:' %res)
             print('Failed patch script due to %s:' %res)
             return


def get_patch_script(os_type,os_version):
    no_proxy="--no-proxy --no-check-certificate"

    if os_type == "DOMU":

       if os_version > 5:
           patch_cmd="%s/ol_cpu_patching.py" %access_cmd
           download_loc="/tmp/ol_cpu_patching.py"
           
           #default python version considered as python 2
           py_version='python'
           exe_cmd="%s  --quarterly --security-patch --force-fix" %download_loc

           run_exec_cmd = "wget -O %s %s;%s %s" %(download_loc,patch_cmd,py_version,exe_cmd)

           status,result = execute_patch_scrit(run_exec_cmd)
           if not status:
              run_exec_cmd = "wget -O %s %s %s;%s %s" %(download_loc,no_proxy,patch_cmd,py_version,exe_cmd)

              status,res = execute_patch_scrit(run_exec_cmd)
              if not status:
                 #revert /bin/yum to orignal
                 print('Failed patch script due to %s:' %res)
                 #sys.exit('Failed patch script due to %s:' %res)
                 return
              
    elif os_type == "DOM0":
 
            del_cmd="rm -rf /tmp/ovm_security_patch.py /tmp/ovm_security_patch.json"
            run_patch_cmd="%s/ovm_security_patch.py" %access_cmd
            json_cmd="%s/ovm_security_patch.json" %access_cmd
    

            py_version='python'
            exe_cmd="/tmp/ovm_security_patch.py -j ovm_security_patch.json -u"

            run_exec_cmd = "%s;cd /tmp;wget -q %s; wget -q %s;%s %s" %(del_cmd, run_patch_cmd, json_cmd,py_version, exe_cmd)

            status,_ = execute_patch_scrit(run_exec_cmd)
            if not status:
               run_exec_cmd = "%s;cd /tmp;wget -q %s %s; wget -q %s %s;%s %s" %(del_cmd, no_proxy, run_patch_cmd, no_proxy, json_cmd,py_version, exe_cmd)
             
               status,failed_reason = execute_patch_scrit(run_exec_cmd)
               if not status:
                  sys.exit(' EXIT Patching failed due to %s' %failed_reason)
 
    else:
       print('Failed to identify the host type (DOM0/DOMU?)')
		
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

    os.popen('rm -rf /var/cache/yum').read()
    os.popen('yum clean all').read()

def detect_python_version():
    return sys.version_info[0]

def main():
   
   pre_stuff()

   os_version=get_os_version()
   if os_version == 5:
      patch_ol5()
      os_type='DOMU'
   else:
     os_type=get_os_type()

     if os_type == 'Solaris':
         print('EXIT: Its a Solaris host')
     else:    
         print('OS_TYPE : %s\nOS_VERSION : %s' %(os_type,os_version))
         get_patch_script(os_type,os_version)
	
	
         #execute_patch_scrit(patch_cmd)
main()

