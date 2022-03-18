#!/usr/bin/python
# Author: Srinivas Gadi
#This script is to identify the OL version, type and UEK
#Its simply exit ifs its OL5, and does not check any stuff

import os
import commands
import platform
import sys


def get_vm_uek_version():

    (uek_status,uek_cmd_output) = commands.getstatusoutput("uname -r| grep uek")
    if uek_status == 0:
       uek_major = uek_cmd_output.split(".")[0]
       uek_version='.'.join(uek_cmd_output.split(".")[0:2])
       if uek_version == "4.1":
          uek = 4
       elif uek_version == "5.4":
          uek = 6
       elif uek_version == "4.14":
          uek = 5
       elif uek_major == "3":
          uek = 3
       else:
          uek = 2
    else:
      uek = 0
    return uek

def get_ovm_uek_version():

	(uek_status,uek_cmd_output) = commands.getstatusoutput("uname -r| grep uek")
	if uek_status == 0:
	    uek_major = uek_cmd_output.split(".")[0]
	    uek_version='.'.join(uek_cmd_output.split(".")[0:2])
	    if uek_version == "5.4":
	      uek = 6
	    if uek_version == "4.14":
	      uek = 5
	    if uek_version == "4.1":
	      uek = 4
	    elif uek_major == "3":
	      uek = 3
	    elif uek_major == "2":
	      uek = 2
	    else:
	      uek = 2
	else:
	    uek = 0

        return uek
def get_os_version():
    return eval(platform.dist()[1].split('.')[0])


def get_os_type():

    if os.path.exists('/etc/oracle-release'):
       status, result = commands.getstatusoutput('cat /etc/oracle-release')
       if 'Oracle VM server release' in result or 'Oracle VM Server release' in result:
           return 'DOM0'
       elif 'Oracle Linux Server release'  in result:
           return 'DOMU'
       else:
          sys.exit('EXIT: its a %s host' %result)
    else:
          linux_dist = platform.linux_distribution()[0] 
	  if linux_dist == "Oracle Linux Server":
		return 'DOMU'
	  elif linux_dist == 'Oracle VM server':
 		return 'DOM0'
 	  else:
 		sys.exit('EXIT: its a %s host' %linux_dist )


def main():
    os_version = get_os_version()
    if os_version == 5:
        print("OL5")
        return

    os_type = get_os_type()
    if os_type == "DOM0":
    	uek_ver=get_ovm_uek_version()

    if os_type == "DOMU":
    	uek_ver=get_vm_uek_version()

    print(uek_ver)

main()
