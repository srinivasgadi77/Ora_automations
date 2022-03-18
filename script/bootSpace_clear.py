#!/usr/bin/python
#Default it leaves the lastest 3 kernels and removed the olders
#Incase if need, by explict tag --kc <NUMBER> : NUMBER -> how many kernels you want to retain

import os,sys,re,argparse,json
import platform,shutil,datetime
import subprocess,glob,time,commands

parser = argparse.ArgumentParser(description='Removing older kernels')
parser.add_argument('-kc', '--stay_kernel',help='TOTAL KERNEL COUNT SHOULD BE PRESENT IN SERVER',type=int,default=3)
values = parser.parse_args()

######FUNCTION TO WRITE TO SPECIFIC FILE WITH SPECIFIC DATA########

def log_general(mode,*message):
    obj = open('/tmp/kernel.log',mode)
    for i in range(len(message)):
      obj.write(message[i])

####LOG MULTIPLE LINE######

def log_write(message,output):
    obj = open('/tmp/kernel_cleanup.log',"a")
    obj.write("\n#####"+message+"#####\n")
    obj.write(output)
    obj.write("\n")
    obj.write("#"*30)
    obj.write("\n")

#####UNINSTALL PACKAGES#####

def uninstall(pkg):
  if isinstance(pkg,list):
    pkg = ' '.join(x.strip() for x in pkg)
  (rpm_unin_status,rpm_unin_cmd) = commands.getstatusoutput("rpm -e "+pkg)
  if rpm_unin_status == 0:
      log_write("BELOW PACKAGES ARE UNINSTALLED",pkg)
      log_write("ERRORS/OUTPUT DURING UNINSTALLATION",rpm_unin_cmd)
  else:
      log_write("UNINSTALL FAILED FOR BELOW PACKAGES",pkg)
      log_write("ERRORS OBSERVED DURING UNINSTALLATION",rpm_unin_cmd)

##MAIN FUNCTION

def main():
  # log = raw_input("ENTER THE LOG FILE NAME TO BE CREATED:")
  log=''
  all_kernel_versions=[]
  version=[]
  kernel_version_count = values.stay_kernel-1
  cur_kernel = os.uname()[2]
  (ker_list_status,ker_list_output)=commands.getstatusoutput("rpm -qa --last  kernel-uek kernel") #added kernel
  if ker_list_status == 0:
    list_kernel=ker_list_output.split("\n")
    for i in list_kernel:
      all_kernel_versions.append(i.split(" ")[0].strip())
    if "uek" in cur_kernel:
      all_kernel_versions.remove("kernel-uek-"+cur_kernel)
    # else:
    #   all_kernel_versions.remove("kernel-"+cur_kernel)
    if len(all_kernel_versions) != 0: 
      if len(all_kernel_versions) > kernel_version_count:
        for i in all_kernel_versions[kernel_version_count:]:  
          v1=i.rsplit('.',1)
          if "uek" in v1[0]:
            version.append(v1[0].lstrip("kernel-uek-").strip())
          # else:
          #   version.append(v1[0].lstrip("kernel-").strip())
        for i in version:
          (ker_grep_status,ker_grep_output) = commands.getstatusoutput("rpm -qa | grep -i kernel* | grep "+i)
          if ker_grep_status == 0:
            rm_pkg = ker_grep_output.split("\n")
            uninstall(rm_pkg)
      else:
        log_general("a","\nONLY %s KERNELS WERE PRESENT.CLEARANCE IS NOT POSSIBLE\n"%(values.stay_kernel))
    else:
      log_general("a","\nKERNEL UNINSTALLATION IS NOT POSSIBLE AS ONLY CURRENT KERNEL IS PRESENT\n")
  else:
    log_general("a","ISSUE WITH RPM COMMAND")
if __name__ == '__main__':
  main()	  
