#!/usr/bin/python

import platform,os,sys
from commands import *
grub_dir_exist = "NA"
userfile_exist = "NA"
ovm_passwd_enabled = "NA"
user_entries_grub = "NA"

######FUNCTION TO WRITE TO SPECIFIC FILE WITH SPECIFIC DATA########

def log_general(filename,mode,*message):
  with open(filename,mode) as obj:
    for i in range(len(message)):
      obj.write(message[i])


#####VALIDATE GRUB PASSWORD#####
def validate_grub():
  global grub_dir_exist,userfile_exist,ovm_passwd_enabled,user_entries_grub
  (status_dir,output_dir) =   getstatusoutput("ls -ld /etc/grub.d")
  if status_dir == 0:
    log_general(log,"a","\n/etc/grub.d DIRECTORY EXIST\n")
    grub_dir_exist="YES"
    (status_userfile, output_userfile) = getstatusoutput("ls -l /etc/grub.d/01_users")
    if status_userfile == 0:
      log_general(log,"a","\n/etc/grub.d/01_users FILE EXIST\n")
      userfile_exist = "YES"
      (status_checkpass,output_checkpass) = getstatusoutput("grep -v \"#\" /etc/grub.d/01_users | grep -v \"^$\" | grep -i pass")
      if status_checkpass == 0:
        log_general(log,"a","\nPASSWORD FIELD EXIST IN /etc/grub.d/01_users AND BELOW IS THE OUTPUT \n%s\n"%(output_checkpass))
        ovm_passwd_enabled = "YES"
      else:
        log_general(log,"a","\nPASSWORD FIELD DOESNOT EXIST IN /etc/grub.d/01_users\n")
        ovm_passwd_enabled = "NO"
    else:
      log_general(log,"a","\n/etc/grub.d/01_users FILE DOESNOT EXIST\n")
      userfile_exist = "NO"
    (status_pass_grub,output_pas_grub) = getstatusoutput("sed -n '/### BEGIN \/etc\/grub.d\/01_users ###/, /### END \/etc\/grub.d\/01_users ###/p' /boot/grub2/grub.cfg | wc -l")
    if status_pass_grub == 0:
      if int(output_pas_grub) > 2:
        log_general(log,"a","\n/boot/grub2/grub.cfg CONF FILE EXIST\n")
        user_entries_grub = "YES"
      else:
        user_entries_grub = "NO"
    else:
      log_general(log,"a","\n/boot/grub2/grub.cfg CONF FILE DOESNOT EXIST\n")
      user_entries_grub = "UNKNOWN"
  else:
    log_general(log,"a","\n/etc/grub.d DIRECTORY DOESNOT EXIST.\n")
    grub_dir_exist="NO"
  log_general(log,"a","\nSCRIPT EXECUTION COMPLETE AND BELOW IS THE STATUS.\n")
  log_general(log,"a","{HOSTNAME: %s}...{GRUB.D_DIR_EXIST: %s}...{01_USERS_FILEEXIST: %s}...{OVM_PASSWD_ENABLED: %s}...{ANY_USER_ENTRIES_IN_GRUB_FILE:%s}\n"%(hostname,grub_dir_exist,userfile_exist,ovm_passwd_enabled,user_entries_grub))
  print("{HOSTNAME: %s}...{GRUB.D_DIR_EXIST: %s}...{01_USERS_FILEEXIST: %s}...{OVM_PASSWD_ENABLED: %s}...{ANY_USER_ENTRIES_IN_GRUB_FILE:%s}"%(hostname,grub_dir_exist,userfile_exist,ovm_passwd_enabled,user_entries_grub))

####CREATING LOG FILE#####

def createlogfile():
  global log
  log = "/root/"+hostname+"_validate_password.log"
  file_exist = os.path.isfile(log)
  if file_exist == True:
    os.system("> "+log)
  else:
    os.system("touch "+log)

###MAIN FUNCTION#####
def main():
  createlogfile()
  validate_grub()


###MAIN EXECUTION###
if __name__ == '__main__':
  global hostname,ostype,linux_dist,majversion
  hostname = platform.node().split('.')[0].strip()
  ostype = platform.system()
  linux_dist = platform.linux_distribution()[0]
  majversion = platform.linux_distribution()[1].split('.')[0].strip()
  if ostype == "Linux":
    if linux_dist == "Oracle VM server":
      if int(majversion) == 3:
        main()
      else:
        print ("SELECTED SCRIPT IS NOT APPLICABLE FOR OVM %s. EXITING THE SCRIPT" %(majversion))
        sys.exit(1)
    else:
      print ("SELECTED SCRIPT IS NOT APPLICABLE FOR %s. EXITING THE SCRIPT" %(linux_dist))
      sys.exit(1)
  else:
    print ("SELECTED SCRIPT IS NOT APPLICABLE FOR %s. EXITING THE SCRIPT" %(ostype))
    sys.exit(1)

