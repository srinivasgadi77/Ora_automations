#!/usr/bin/python
##### LAST UPDATED: 09 MAR 2021
###V2: fix_repos(),fix_update_qemu_libvirt DEFINITIONS INCLUDED AS A PART OF VULNERABLITIY FIX FOR OL7 
###V3: BUGFIX INCLUDED FOR ISSUE REPORTED DURING SET DEFAULT GRUB
###V4: BUGFIX INCLUDED FOR ORACLE RELEASE FILE ISSUE
###V5: KSPLICE WILL BE UPDATED AS PER THE SNAPSHOT, DOCKER IS EXCLUDED
###V6: DISABLE OPTIONAL RPMS FROM PDITREPO AND ENABLE IN SNAPSHOT
###V7: SKIPPING THE TEMPORARY REMOVAL OF GLIBC AND PKGKIT IF PACKAGES ARE NOT LISTED IN JSON , ADDED VALIDATION CHECK FOR EXA HOSTS
###V8: DISABLE PROXY AS OPTIONAL ARGUMENT ADDED
###V9: RESTORES ALL THE REPOS FROM BACKUP AS PER REQUIREMENT PROVIDED BY JIRA OITBD-5369 
###V10: EXCLUDED COPY AND RESTORE OF YUM.CONF AND INCLUDED PROXY IN PEO_UPDATE.REPO
###V11: CHANGED THE LOCATION OF JSON AND CHECKSUM FILES FROM /tmp TO /var/tmp

import os,sys,re,argparse,json
import platform,shutil,datetime
import subprocess,glob,time,commands

parser = argparse.ArgumentParser(description='CVES PATCHING')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-q', '--quarterly', help='QUARTERLY CPU PATCH',action='store_true')
group.add_argument('-m', '--monthly', help='MONTHLY CPU PATCH',action='store_true')
group.add_argument('-j', '--jsonfile', help='JSON FILENAME')
group.add_argument('-c', '--canary', help='LATEST EXISTING REPO CPU PATCH',action='store_true')
group1 = parser.add_mutually_exclusive_group(required=True)
group1.add_argument('-s', '--security-patch', help='ONLY SECURITY PATCH EXECUTION',action='store_true',dest="security")
group1.add_argument('-u', '--full-upgrade', help='UPGRADE OF SERVER EXECUTION',action='store_true',dest="upgrade")
parser.add_argument('-f', '--force-fix', help='APPLY THE FIX FORCEFULLY',action='store_true',dest="fix")
parser.add_argument('-kc', '--stay_kernel',help='TOTAL KERNEL COUNT SHOULD BE PRESENT IN SERVER',type=int,default=3)
parser.add_argument('-e', '--exclude', help='EXCLUDE PACKAGES')
parser.add_argument('-d', '--disable_proxy', help='DISABLE PROXY DURING PATCH/UPGRADE',action='store_true')
values = parser.parse_args()

#####COLORS####

class bcolors:
    HEADER    = '\033[95m'
    OKBLUE    = '\033[94m'
    OKGREEN   = '\033[92m'
    WARNING   = '\033[93m'
    FAIL      = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'

######FUNCTION TO WRITE TO SPECIFIC FILE WITH SPECIFIC DATA########

def log_general(filename,mode,*message):
  with open(filename,mode) as obj:
    for i in range(len(message)):
      if "INITIATING" in message[i]:
        color = bcolors.OKBLUE
      elif "ERROR" in message[i] or "SKIP" in message[i]:
        color = bcolors.FAIL
      else:
        color = bcolors.ENDC
      obj.write(color+message[i]+bcolors.ENDC)

####LOG MULTIPLE LINE######

def log_write(message,output):
  with open(log,"a") as obj:
    obj.write("\n#####"+message+"#####\n")
    obj.write(bcolors.FAIL+output+bcolors.ENDC)
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

#######INSTALLING THE PACKAGE########

def ker_install(pkg):
  clean_cmd = commands.getoutput("yum clean all")
  if isinstance(pkg,list):
    pkg = ' '.join(x.strip() for x in pkg)
  if  int(majversion) == 7:
    (install_pkg_stat,ins_pkg) = commands.getstatusoutput("/usr/bin/yum install -y --disablerepo=* --enablerepo=ol7_uekr* -c /etc/yum.repos.d/old_repo/pditrepo.repo  "+pkg+ " 2>&1>>"+log)
  elif int(majversion) == 8:
    (install_pkg_stat,ins_pkg) = commands.getstatusoutput("/usr/bin/yum install -y --disablerepo=* --enablerepo=ol8_uekr* -c /etc/yum.repos.d/old_repo/pditrepo.repo  "+pkg+ " 2>&1>>"+log)
  else:
    (install_pkg_stat,ins_pkg) = commands.getstatusoutput("/usr/bin/yum install -y --disablerepo=* --enablerepo=ol6_uek*,ol6_uekr*,apol6_uekr4 -c /etc/yum.repos.d/old_repo/pditrepo.repo  "+pkg+ " 2>&1>>"+log)
  log_write("YUM ERROR RECORDED DURING OPTIONAL KERNEL INSTALL",ins_pkg)
  return install_pkg_stat

def install(pkg):
  clean_cmd = commands.getoutput("yum clean all")
  if isinstance(pkg,list):
    pkg = ' '.join(x.strip() for x in pkg)

 ##DISABLED INSTALLATION FROM PDITREPO
 # if int(majversion) == 7:
 #   (install_pkg_stat,ins_pkg) = commands.getstatusoutput("/usr/bin/yum install -y --disablerepo=* --enablerepo=ol7_latest,ol7_optional_latest,ol7_uekr3,ol7_uekr4 "+pkg+ " 2>&1>>"+log)
 # elif int(majversion) == 8:
 #   (install_pkg_stat,ins_pkg) = commands.getstatusoutput("/usr/bin/yum install -y --disablerepo=* --enablerepo=ol8_baseos_latest  "+pkg+ " 2>&1>>"+log)
 # else:
 #   (install_pkg_stat,ins_pkg) = commands.getstatusoutput("/usr/bin/yum install -y --disablerepo=* --enablerepo=ol6_uekr3_latest,ol6_uekr4,ol6_uek_latest,ol6_latest "+pkg+ " 2>&1>>"+log)

  #ENABLED INSTALLATION FROM SNAPSHOT
  (install_pkg_stat,ins_pkg) = commands.getstatusoutput("/usr/bin/yum install -y --disablerepo=* --enablerepo="+majversion+"_peo*  "+pkg+ " 2>&1>>"+log)
  log_write("YUM ERROR RECORDED DURING OPTIONAL PACKAGE INSTALL",ins_pkg)
  return install_pkg_stat

######WRTING TO DATABASE######

def dump_to_db():
  log_general(log,"a","\n###INITIATING STEP UPDATE TO DB\n")
  dict_output = {}
  db_keys=['host_name', 'date_patched', 'pre_os_version', 'updated_os_version', 'pre_kernel', 'upgraded_kernel', 'cves_status', 'reboot_status', 'kernel_status', 'cves_pending', 'pre_cves_critical', 'pre_cves_important', 'pre_cves_moderate', 'pre_cves_low', 'post_cves_critical', 'post_cves_important', 'post_cves_moderate', 'post_cves_low', 'owner_email', 'non_uek_status','uptrack_status','snapshot_date']

  db_values=[hostname,startdate,os_version,os_after_update,cur_kernel,new_kernel,CVES_stat,re_boot_status,kernel_status,cves_present,pre_cve_critical,pre_cve_important,pre_cve_moderate,pre_cve_low,cve_critical,cve_important,cve_moderate,cve_low,owner_email,non_uek,uptrack_status,patch_date]
  for i in range(len(db_keys)):
    dict_output[db_keys[i]] = str(db_values[i])
  db_cmd = "curl --request POST --url http://dent60vm0002-eoib1.us.oracle.com:8000/updatepatchstatus --header \'Content-Type: application/json\' --data \'"+json.dumps(dict_output)+"\'"
  (status,out) = commands.getstatusoutput(db_cmd)
  if status == 0:
    log_general(log,"a","\nDB HAS UPDATED WITH DETAILS\n")
  else:
    log_general(log,"a","\nDB UPDATE FAILED DUE TO ERRORS\n")

  data_summary = "\nCVE Status : %s, Kernel Status: %s - %s, Reboot Status: %s, Previous-Present-CVES:Critical_CVES %s:%s, Important_CVES: %s:%s,Moderate_CVES: %s:%s,Low_CVES: %s:%s  Grub_file %s,Uptrack status: %s\n"%(CVES_stat,kernel_status,new_kernel,re_boot_status,pre_cve_critical,cve_critical,pre_cve_important,cve_important,pre_cve_moderate,cve_moderate,pre_cve_low,cve_low,grub_file,uptrack_status)
  print (data_summary)


######WRITING TO CENTRAL CSV FILE (OPTIONAL: MANUALLY UPDATE DB WITH LOG IF REQUIRED) #########

def central_csv():
  tab_names = "HOST_NAME,DATE_PATCHED,SNAPSHOT_DATE,OWNER_EMAIL,PRE_OS_VERSION,UPDATED_OS_VERSION,PRE_KERNEL,UPGRADED_KERNEL,PRE_CVES_CRITICAL,PRE_CVES_IMPORTANT,PRE_CVES_MODERATE,PRE_CVES_LOW,CVES_STATUS,REBOOT_STATUS,CVES_PENDING,KERNEL_STATUS,POST_CVES_CRITICAL,POST_CVES_IMPORTANT,POST_CVES_MODERATE,POST_CVES_LOW,UPTRACK_STATUS"
  tab_data = "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n"%(hostname,startdate,patch_date,owner_email,os_version,os_after_update,cur_kernel,new_kernel,pre_cve_critical,pre_cve_important,pre_cve_moderate,pre_cve_low,CVES_stat,re_boot_status,cves_present,kernel_status,cve_critical,cve_important,cve_moderate,cve_low,uptrack_status)

  mount_exists=os.path.isdir("/log")
  if mount_exists == False:
    create_dir = commands.getoutput("mkdir /log")
  line="\n"
  (mount_status,mount_cmd) = commands.getstatusoutput("mount -o nolock adcnas402.us.oracle.com:/export/writeable/security/db_ol_patch /log")
  if mount_status == 0:
    file_exits = os.path.isfile("/log/"+hostname+".csv")
    if file_exits == False:
      log_general("/log/"+hostname+".csv","w",tab_names,line,tab_data)
    else:
      log_general("/log/"+hostname+".csv","a",tab_data)
    umount_cmd = commands.getoutput("umount /log")
  else:
    log_general(log,"a","\n OUTPUT IS NOT REDIRECTED TO CSV AS UNABLE TO MOUNT adcnas402.us.oracle.com:/export/writeable/security/db_ol_patch TO /log\n")


######WRITING THE OUTPUT TO CENTRALIZED FILE######

def output_to_central():
  tab_data = "\n%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s:%s,%s:%s,%s:%s,%s:%s,%s\n"%(hostname,startdate,patch_date,owner_email,os_version,os_after_update,cur_kernel,new_kernel,CVES_stat,re_boot_status,cves_present,kernel_status,pre_cve_critical,cve_critical,pre_cve_important,cve_important,pre_cve_moderate,cve_moderate,pre_cve_low,cve_low,uptrack_status)

  mount_exists=os.path.isdir("/log")
  if mount_exists == False:
    create_dir = commands.getoutput("mkdir /log")
  line="\n"
  (mount_status,mount_cmd) = commands.getstatusoutput("mount adcnas402:/export/writeable/security /log")
  if mount_status == 0:
    log_general("/log/ol_patch/"+hostname,"a",tab_data)
    umount_cmd = commands.getoutput("umount /log")
  else:
    log_general(log,"a","\n OUTPUT IS NOT REDIRECTED AS UNABLE TO MOUNT adcnas402:/export/writeable/security TO /log\n")

######WRITING THE OUTPUT TO CSV FILE######

def output_to_csv():
  global os_after_update
  os_after_update = platform.linux_distribution()[1]
  csv_data = "\n%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s:%s,%s:%s,%s:%s,%s:%s,%s\n"%(hostname,startdate,patch_date,owner_email,os_version,os_after_update,cur_kernel,new_kernel,CVES_stat,re_boot_status,cves_present,kernel_status,pre_cve_critical,cve_critical,pre_cve_important,cve_important,pre_cve_moderate,cve_moderate,pre_cve_low,cve_low,uptrack_status)
  tab_names = "Hostname,Patched_Date,Snapshot_date,owner_email_id,OS_Pre,OS_Post,Kernel_before,Kernel_after,CVE Critical_pre,CVE Important_pre,CVE Moderate_pre,CVE Low_pre,patch_status,Re_boot_Status,Current_CVES,Kernel_patch_status,CVES critical,CVE Important,CVE Moderate,CVE Low,Uptrack Status"
  tab_data = "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s"%(hostname,startdate,patch_date,owner_email,os_version,os_after_update,cur_kernel,new_kernel,pre_cve_critical,pre_cve_important,pre_cve_moderate,pre_cve_low,CVES_stat,re_boot_status,cves_present,kernel_status,cve_critical,cve_important,cve_moderate,cve_low,uptrack_status)

  mount_exists=os.path.isdir("/test1/writeable")
  if mount_exists == False:
    create_dir = commands.getoutput("mkdir -p /test1/writeable")
  line="\n"
  (mount_status,mount_cmd) = commands.getstatusoutput("mount -o nolock adcnas402.us.oracle.com:/export/writeable /test1/writeable")
  if mount_status == 0:
    log_general("/test1/writeable/ramsubba/apr_sam/"+hostname+".csv","a",csv_data)
    umount_cmd = commands.getoutput("umount /test1/writeable")
  else:
    log_general(log,"a","\n OUTPUT IS NOT REDIRECTED TO CSV AS UNABLE TO MOUNT adcnas402.us.oracle.com:/export/writeable TO /test1/writeable\n")
  local_file_exits = os.path.isfile("/root/"+hostname+".csv")
  if local_file_exits == False:
    log_general("/root/"+hostname+".csv","w",tab_names,line,tab_data)
  else:
    log_general("/root/"+hostname+".csv","a",line,tab_data)

######WRITE STATUS OF SCRIPT TO LOG FILE#####

def write_status_to_file():
  log_general(log,"a","\n###INITIATING STEP WRITE STATUS TO FILE\n")
  if rpm_stat != 0 or pre_status != 0:
    global startdate,os_after_update,new_kernel,re_boot_status,kernel_status
    global CVES_stat,non_uek,uptrack_status,grub_file
    global cves_present,pre_cve_critical,pre_cve_important,pre_cve_moderate,pre_cve_low
    global cve_critical,cve_important,cve_moderate,cve_low
    startdate = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    os_after_update,new_kernel,re_boot_status,kernel_status = "NA","NA","NA","OL_KERNEL_PATCH_FAILED"
    CVES_stat,non_uek,uptrack_status,grub_file = "OL_PATCH/UPGRADE_FAILED_DUE_TO_YUM_ERRORS","NA","NA","NA"
    cves_present,pre_cve_critical,pre_cve_important,pre_cve_moderate,pre_cve_low = 0,0,0,0,0
    cve_critical,cve_important,cve_moderate,cve_low = 0,0,0,0

  status_reboot_log = "\nCVE Status : %s, Kernel Status: %s - %s, Reboot Status: %s, Previous-Present-CVES:Critical_CVES %s:%s, Important_CVES: %s:%s,Moderate_CVES: %s:%s,Low_CVES: %s:%s  Grub_file %s,Uptrack status: %s\n"%(CVES_stat,kernel_status,new_kernel,re_boot_status,pre_cve_critical,cve_critical,pre_cve_important,cve_important,pre_cve_moderate,cve_moderate,pre_cve_low,cve_low,grub_file,uptrack_status)
  status_non_reboot_log = "\nCVE Status : %s, Kernel Status: %s - %s, Previous-Present-CVES:Critical_CVES %s:%s, Important_CVES: %s:%s,Moderate_CVES: %s:%s,Low_CVES: %s:%s  Grub_file %s,Uptrack status: %s\n"%(CVES_stat,kernel_status,new_kernel,pre_cve_critical,cve_critical,pre_cve_important,cve_important,pre_cve_moderate,cve_moderate,pre_cve_low,cve_low,grub_file,uptrack_status)
  if re_boot_status == "re_boot_required":
    log_general(log,"a",status_reboot_log)
  else:
    log_general(log,"a",status_non_reboot_log)


#########REMOVING THE /ETC/SYSTEM-FIPS FILE######

def remove_file(name):
  if values.fix and not values.canary:
    log_general(log,"a","\n###INITIATING STEP POST-FIX REMOVE SYSTEM FIPS FILE\n")
    if name == "/etc/system-fips":
      fips_exist = os.path.isfile("/etc/system-fips")
      if fips_status != 0 and  fips_exist == True:
        remove = commands.getoutput("rm -rf "+name)
  else:
    log_general(log,"a","\n###SKIPPING POST FIX REMOVE SYSTEM FIPS FILE AS FORCEFIX IS NOT APPLIED (or) SELECTION IS CANARY\n")

#####SET FILE PERMISSIONS IF NOT SET TO A FILE########

def set_file_permission(filename,permission):
  if values.fix and not values.canary:
    log_general(log,"a","\n###INITIATING STEP POST-FIX SET PERMISSIONS\n")
    deci_mode = os.stat(filename)
    oct_mode = oct(deci_mode.st_mode)
    file_permi = oct_mode[3:]
    if file_permi !=  permission:
      os.chmod(filename,int(permission,8))
  else:
    log_general(log,"a","\nSKIPPING STEP POST-FIX SET PERMISSIONS AS FORCEFIX IS NOT APPLIED (or) SELECTION IS CANARY\n")

#########OPTIONAL RPM INSTALL ####

def optional_pkg_install():
  if not values.canary:
    log_general(log,"a","\n###INITIATING STEP OPTIONAL PACKAGE INSTALL\n")
    if extra_rpms_optional:
      if rpm_optional:
        optional_pkg_status = install(rpm_optional)
        if optional_pkg_status == 0:
          log_general(log,"a","\nINSTALL OF OPTIONAL PACKAGES IS SUCCESSFUL\n")
        else:
          log_general(log,"a","\nFAILED TO INSTALL OPTIONAL PACKAGES\n")
  else:
    log_general(log,"a","\nSKIPPING STEP OPTIONAL PACKAGE INSTALL AS SELECTION IS CANARY\n")
####INSTALL GLIBC PKG KIT PACKAGES####

def restore_glibc_pkgkit():
  if not values.canary:
    if values.fix and int(majversion) >= 7:
      log_general(log,"a","\n###INITIATING STEP RESTORE TEMPORARY REMOVAL OF GLIBC AND PACKAGEKIT\n")
      if len(glibc_pkgs) > 0:
        if pkg_glibc:
          install_glibc_stat = install(pkg_glibc)
          if install_glibc_stat != 0:
            log_general(log,"a","\nGLIBC STATIC PACKAGES ARE NOT INSTALLED\n")
            print ("GLIBC STATIC PACKAGES ARE NOT INSTALLED")
      if len(pkgkit_pkg) > 0:
        if pkg_kit:
          install_pkg_stat = install(pkg_kit)
          if install_pkg_stat != 0:
            log_general(log,"a","\nPACKAGEKIT YUM PLUGIN PACKAGE IS NOT INSTALLED\n")
            print ("PACKAGEKIT YUM PLUGIN PACKAGE IS NOT INSTALLED")
    else:
      log_general(log,"a","\nSKIPPING RESTORE TEMPORARY REMOVAL OF GLIBC AND PACKAGEKIT\n")
  else:
    log_general(log,"a","\nSKIPPING RESTORE TEMPORARY REMOVAL OF GLIBC AND PACKAGEKIT AS SELECTED IS CANARY\n")


#######REPO RESTORATION BLOCK#########

def repo_restore():
  if not values.canary:
    log_general(log,"a","\n###INITIATING STEP REPO RESTORE\n")
    latest_repo = os.listdir(yum_repo_path)
    old_repo = os.listdir(repos_backup_path)
    for i in latest_repo:
      if i.endswith ('.repo'):
        shutil.move(os.path.join(yum_repo_path,i),os.path.join(tmp_path,i))
    for i in old_repo:
#      if i == "pditrepo.repo":
      if i.endswith ('.repo'):
        shutil.move(os.path.join(repos_backup_path,i),os.path.join(yum_repo_path,i))
#    if values.fix or values.disable_proxy:
#      log_general(log,"a","\n###INITIATING STEP FIX RESTORE OF PROXY IN /etc/yum.conf\n")
#      (proxy_status,proxy_check)=commands.getstatusoutput("grep -i proxy /etc/yum.conf")
#      if proxy_status == 0:
#        shutil.copy2("/etc/yum.conf.orig","/etc/yum.conf")
#        log_general(log,"a","\n/etc/yum.conf FILE IS RESTORED\n")
#      else:
#        log_general(log,"a","\nSKIPPED TO RESTORE /etc/yum.conf FILE AS PROXY IS NOT PRESENT\n")
  else:
    log_general(log,"a","\nSKIPPING STEP REPO RESTORE AS SELECTION IS CANARY\n")

####SET DEFAULT GRUB####

def set_default_grub():
  if values.fix and not values.canary:
    log_general(log,"a","\n###INITIATING STEP SET DEFAULT GRUB\n")  
    if grub_file == "UPDATED" and re_boot_status == "re_boot_required":
      (kernel_files_status,kernel_files_check) = commands.getstatusoutput("ls /boot |grep "+new_kernel+" |grep -v debug |grep -v ksplice | wc -l")
      (init_status,init_file_check) = commands.getstatusoutput("ls /boot |grep "+new_kernel+" |grep -v debug |grep -v ksplice|grep -i init")
      if init_status == 0:
        if int(kernel_files_check) >= 5:
          kernel_files_list = commands.getoutput("ls /boot |grep "+new_kernel+" |grep -v debug |grep -v ksplice")
          log_general(log,"a","\n"+kernel_files_list+"\n")
          if int(majversion) == 6:
            default_kernel_value = int(commands.getoutput("grep -i -w \"^default\" "+grub_conf_file).split("=")[1].strip())
            title_entries_list = list(commands.getoutput("grep -i title "+grub_conf_file).split("\n"))
            if new_kernel in title_entries_list[default_kernel_value] and not "debug" in title_entries_list[default_kernel_value]:
              log_general(log,"a","\nDefault kernel is set already\n","\nDefault Kernel is "+title_entries_list[default_kernel_value]+" \n")
            else:
              log_general(log,"a","\nSETTING THE LATEST KERNEL TO DEFAULT\n")
              kernel_file_exist = os.path.isfile("/boot/vmlinuz-"+new_kernel)
              if kernel_file_exist == True:
                cmd_set_kernel = commands.getoutput("grubby --set-default /boot/vmlinuz-"+new_kernel)
                new_default_value = int(commands.getoutput("grep -i -w \"^default\" "+grub_conf_file).split("=")[1].strip())
                log_general(log,"a","\nLATEST KERNEL IS SET TO DEFAULT\n","\nNEW DEFAULT VALUE IS "+str(new_default_value)+"\n","\nNEW KERNEL SET IS "+title_entries_list[new_default_value].strip()+"\n")
              else:
                log_general(log,"a","\nAS THE KERNEL FILE DOESNOT EXIST , DEFAULT KERNEL IS NOT SET\n")
          else:
            set_kernel = 0
            (saved_entry_status,saved_entry_check) = commands.getstatusoutput("grep -i saved_entry "+grubenv_file)
            vmlinuz_file = commands.getoutput("ls /boot |grep "+new_kernel+" |grep -v debug |grep -v ksplice|grep -i vmlinuz").strip()
            if saved_entry_status != 0:
              insert_saved_entry_cmd = commands.getoutput("echo \"saved_entry=0\" >> "+grubenv_file)
            default_kernel = commands.getoutput("grep -i saved_entry "+grubenv_file+"|tr -d \"#\"").split("=")[1].strip()
            (out_status,index_output_cmd) = commands.getstatusoutput("grubby --info /boot/"+vmlinuz_file+"|grep -i index")
            (nam_status,kernel_name_cmd) = commands.getstatusoutput("grubby --info /boot/"+vmlinuz_file+"|grep -i title")
            if out_status ==0 and nam_status == 0:  
              index_output = index_output_cmd.split("=")[1].strip() 
              kernel_name =  kernel_name_cmd.split("=")[1].strip()
              if default_kernel.isdigit() == True:
                if index_output == default_kernel:
                  log_general(log,"a","\nDefault kernel is set already\n","\nDefault kernel is "+kernel_name+"\n")
                else:
                  set_kernel = 1
              else:
                if not default_kernel:
                  set_kernel = 1
                if default_kernel:
                  if new_kernel in default_kernel and not "debug" in default_kernel:
                    log_general(log,"a","\nDefault kernel is set already\n","\nDefault kernel is "+default_kernel+"\n")
                  else:
                    set_kernel = 1
              if set_kernel == 1:
                log_general(log,"a","\nSETTING THE LATEST KERNEL TO DEFAULT\n")
                kernel_file_exist = os.path.isfile("/boot/vmlinuz-"+new_kernel)
                if kernel_file_exist == True:
                  cmd_set_kernel = commands.getoutput("/usr/sbin/grub2-set-default "+str(index_output))
                  new_default_value = commands.getoutput("grep -i saved_entry "+grubenv_file+"|tr -d \"#\"").split("=")[1].strip()
                  if new_default_value.isdigit() == True:
                    int_default_value = int(new_default_value)
                    log_general(log,"a","\nLATEST KERNEL IS SET TO DEFAULT\n","\nNEW DEFAULT VALUE IS "+str(new_default_value)+"\n","\nNEW KERNEL SET IS "+kernel_name+"\n")
                  else:
                    log_general(log,"a","\nLATEST KERNEL IS SET TO DEFAULT\n","\nNEW DEFAULT VALUE IS "+str(new_default_value)+"\n")
                else:
                  log_general(log,"a","\nAS THE KERNEL FILE DOESNOT EXIST , DEFAULT KERNEL IS NOT SET\n")
            else:
              if out_status != 0:
                log_write("SKIPPED SET DEFAULT GRUB DUE TO ERROR IN OUTPUT OF GETTING INDEX VALUE",index_output_cmd)
              else: 
                log_write("SKIPPED SET DEFAULT GRUB DUE TO ERROR IN OUTPUT OF GETTING NAME OF KERNEL",kernel_name_cmd)
        else:
          log_general(log,"a","\nONE OF THE KERNEL FILES ARE MISSING\n")
      else:
        log_general(log,"a","\nINITRAMFS FILE IS MISSING . NEED TO REINSTALL THE KERNEL\n")
  else:
    log_general(log,"a","\nSKIPPING STEP SET DEFAULT GRUB\n")

######INITRD VALIDATION BLOCK#######

def initrd_validation():
  log_general(log,"a","\n###INITIATING STEP INITRD VALIDATION\n")
  global grub_file
  if new_kernel != cur_kernel:
    if int(majversion) != 8:
      (ker_status,ker_cmd) = commands.getstatusoutput("grep -i vmlinuz-"+new_kernel+" "+grub_conf_file+"  2>&1>>"+log)
      if ker_status == 0:
        log_general(log,"a","\nGRUB FILE UPDATED\n")
        grub_file = "UPDATED"
      else:
        log_general(log,"a","\nGRUB FILE UNCHANGED\n")
        grub_file = "FAILED"
    else:
      (ker_status,ker_cmd) = commands.getstatusoutput("cat /boot/loader/entries/*"+new_kernel+".conf")
      if ker_status == 0:
        log_general(log,"a","\nGRUB FILE UPDATED\n")
        grub_file = "UPDATED"
      else:
        log_general(log,"a","\nGRUB FILE UNCHANGED\n")
        grub_file = "FAILED"
  else:
    grub_file = "UNCHANGED"


#######RETRY BLOCK#########

def retry_block():
  if not values.upgrade and not values.canary:
    if CVES_stat != "OL_PATCH_SUCCESSFUL":
      (retry_status,retry_output) = commands.getstatusoutput("grep -i \"RETRYING THE SECURITY AND KERNEL PATCH\" "+log)
      if retry_status != 0:
         log_general(log,"a","\nRETRYING THE SECURITY AND KERNEL PATCH\n")
         yum_process_status()
         kernel_pkg_install()
         validation()
      
#####FIX QUAGGA ISSUE####

def fix_quagga():
   log_general(log,"a","\nAPPLYING POST-FIX FOR QUAGGA\n")
   uninstall("quagga")
   (ins_quagga_status,ins_quagga_output) = commands.getstatusoutput("yum install quagga -y")
   if ins_quagga_status == 0:
     log_general(log,"a","\nQUAGGA INSTALLED SUCCESSFULLY. FIX IS APPLIED\n")
   else:
     log_general(log,"a","\nFAILED TO INSTALL QUAGGA\n")

#######BUG FIXES#####

def bug_fixes():
  if values.fix and not values.canary:
    log_general(log,"a","\n###INITIATING STEP POST BUGFIXES\n")
    if len(quagga_pkg) != 0:
      fix_quagga()
      validation()
  else:
    log_general(log,"a","\nSKIPPING STEP POST BUGFIXES AS FORCEFIX IS NOT APPLIED (or) SELECTION IS CANARY\n")

#######VALIDATION BLOCK#############

def validation():
  clean_cmd = commands.getoutput("yum clean all")
  log_general(log,"a","\n###INITIATING STEP VALIDATION\n")
  global new_kernel,cve_critical,cve_important,cve_moderate,cve_low,CVES_stat,re_boot_status
  global quagga_pkg
  cve_critical,cve_important,cve_moderate,cve_low = 0,0,0,0
  quagga_pkg = []
  if uek != 0:
    if values.canary:
      lastest_kernel = commands.getoutput("rpm -qa --last kernel-uek").split('\n')[0].split(' ')[0].lstrip('kernel-uek-')
      if lastest_kernel != cur_kernel:
        new_kernel = lastest_kernel
      else:
        new_kernel = cur_kernel

    elif uek_kernel:
      kernel_cmd = commands.getoutput("rpm -qa kernel-uek | grep "+uek_kernel+"| awk \'{print $1}\'|sed \'s/kernel-uek-//\'")
      if kernel_cmd:
        new_kernel = kernel_cmd
      else:
        new_kernel = cur_kernel
    elif extra_rpms_optional:
      if uek_optional:
        if uek_optional[uek_value]:
          kernel = uek_optional[uek_value].rstrip('*')
          kernel_cmd = commands.getoutput("rpm -qa kernel-uek | grep "+kernel+"| awk \'{print $1}\'|sed \'s/kernel-uek-//\'")
          if kernel_cmd:
            new_kernel = kernel_cmd
          else:
            new_kernel = cur_kernel
        else:
          new_kernel = cur_kernel
      else:
        new_kernel = cur_kernel
    else:
      new_kernel = cur_kernel
    
  else:
    lastest_kernel = commands.getoutput("rpm -qa --last kernel").split('\n')[0].split(' ')[0].lstrip('kernel-')
    if lastest_kernel != cur_kernel:
      new_kernel = lastest_kernel
    else:
      new_kernel = cur_kernel

  if new_kernel !=  cur_kernel:
     re_boot_status = "re_boot_required"
  else:
    re_boot_status = "re_boot_not_required"
  
  if values.canary:
    if values.security:
      post_check_cmd =  "yum --enablerepo=*latest,*uekr* --exclude=docker*,kernel* updateinfo list security "
  else:
    if values.security:
      post_check_cmd = "yum --exclude=docker*,kernel* updateinfo list security "
    else:
      post_check_cmd = "yum --disablerepo=* --enablerepo="+majversion+"_peo* --exclude=docker*,kernel* updateinfo list security"

  if values.upgrade:
    CVES_stat = patch_status
  else:
    log_general(log,"a","\nVERIFYING THE POST CVE USING BELOW COMMAND\n\n"+post_check_cmd+"\n\n")
    (post_cve_status,post_cve_output) = commands.getstatusoutput(post_check_cmd)
    post_list_cve = list(post_cve_output.split('\n'))
    log_general("/tmp/post_cve_result","w",post_cve_output)
    if post_cve_status == 0:
      for i in post_list_cve:
        if "quagga" in i:
          quagga_pkg.append(i)

        if "Critical" in i:
          cve_critical = cve_critical+1
        elif "Important" in i:
          cve_important = cve_important+1
        elif "Moderate" in i:
          cve_moderate = cve_moderate+1
        elif "Low" in i:
          cve_low = cve_low+1
        else:
          pass
      if cve_critical == 0 and cve_important == 0 and cve_moderate == 0 and cve_low == 0:
        CVES_stat = "OL_PATCH_SUCCESSFUL"
      elif cve_critical == 0:
        CVES_stat = "OL_CRITICAL_PATCH_SUCCESSFUL"
      else:
        CVES_stat = "OL_PATCH_FAILED"
    else:
      CVES_stat = "OL_PATCH_FAILED_DUE_TO_YUM_ISSUES"
    

######OPTIONAL KERNEL RPM INSTALLATION#####

def optional_kernel_pkg_install():
  clean_cmd = commands.getoutput("yum clean all")
  log_general(log,"a","\n###INITIATING STEP OPTIONAL KERNEL PACKAGE INSTALL\n")
  global kernel_status
  if extra_rpms_optional:
    if uek_optional:
      (uek_status,uek_cmd_output) = commands.getstatusoutput("uname -r| grep uek")
      if uek_status == 0:
        if uek_optional[str(uek)]:
          opt_uek_status  = ker_install(uek_optional[str(uek)])
          pkg=os.popen("rpm -qa | grep kernel-uek|awk -F\"[0-9]\" \'{print $1}\'").readlines()
          uek_ver = uek_optional[str(uek)].split("kernel-uek-")[1]
          list_pkg="yum install -y "+' '.join([x.strip() +uek_ver+"*" for x in pkg])
          cmd_grep_uek="grep kernel-uek-"+uek_ver+"*"
          uek_desp_cmd = ker_install(list_pkg)
          rpm_uek="rpm -qa | "+cmd_grep_uek+" &>>"+log
          (uek_exit_status,output)=commands.getstatusoutput(rpm_uek)
          if uek_exit_status != 0:
            kernel_status = "OL_KERNEL_PATCH_FAILED"
            log_general(log,"a","\nOPTIONAL UEK KERNEL PACKAGE INSTALLATION IS NOT SUCCESSFUL\n")
          else:
            kernel_name = uek_optional[str(uek)]
            uek_kernel = kernel_name.rstrip("*")
            kernel_check = commands.getoutput("rpm -qa kernel-uek | grep "+uek_kernel+"| awk \'{print $1}\'|sed \'s/kernel-uek-//\'")
            (init_status,init_file_check) = commands.getstatusoutput("ls /boot |grep "+kernel_check+" |grep -v debug |grep -v ksplice|grep -i init")
            (kernel_files_status,kernel_files_check) = commands.getstatusoutput("ls /boot |grep "+kernel_check+" |grep -v debug |grep -v ksplice | wc -l")
            if init_status == 0:
              if int(kernel_files_check) >= 5:
                kernel_status = "OL_KERNEL_PATCH_SUCCESSFUL"
                if int(majversion) >= 7:
                  (copy_status,copy_cmd) = commands.getstatusoutput("cp -pr "+grub_conf_file+" /tmp/grub.cfg.`date +\"%Y%m%d_%H%M%S\"`")
                  if copy_status == 0:
                    if values.fix:
                      (recreate_status,recreate_grub) = commands.getstatusoutput("/usr/sbin/grub2-mkconfig -o "+grub_conf_file)
                      if recreate_status == 0:
                        log_write("LOG FOR GRUB CONFIGURATION FILE GENERATION",recreate_grub)
                      else:
                        log_write("ERRORS DURING GRUB CONFIGURATION FILE GENERATION",recreate_grub)          
        else:
          kernel_status = "OL_KERNEL_NOT_SPECIFIED"
    else:
      kernel_status = "OL_KERNEL_NOT_SPECIFIED"
  else:
    kernel_status = "OL_KERNEL_NOT_SPECIFIED"

####APPLYING THE KERNEL PATCH####

def kernel_pkg_install():
  clean_cmd = commands.getoutput("yum clean all")
  log_general(log,"a","\n###INITIATING STEP KERNEL PACKAGE INSTALL\n")
  global kernel_status,non_uek
  if free >= min_boot_space:
    log_general(log,"a","\nBOOT SPACE IS AVAILABLE, PROCEEDING WITH KERNEL PATCH\n")
  
    ####NON-UEK INSTALL
    if values.canary:
      if values.upgrade:
        kernel_update_cmd = "/usr/bin/yum update --disablerepo=* --enablerepo=*latest --disablerepo=*playground_latest -y kernel-firmware.noarch kernel-debug-devel.x86_64 kernel-debug.x86_64 kernel-abi-whitelists.noarch kernel.x86_64 kernel-tools-libs kernel-tools kernel-headers kernel-devel 2>&1>>"+log
      else:
        kernel_update_cmd = "/usr/bin/yum update  --enablerepo=*latest --disablerepo=*playground_latest -y kernel-firmware.noarch kernel-debug-devel.x86_64 kernel-debug.x86_64 kernel-abi-whitelists.noarch kernel.x86_64 kernel-tools-libs kernel-tools kernel-headers kernel-devel 2>&1>>"+log
    else:
      if values.upgrade:
        kernel_update_cmd = "/usr/bin/yum --disablerepo=* --enablerepo="+majversion+"_peo* update -y kernel-firmware.noarch kernel-debug-devel.x86_64 kernel-debug.x86_64 kernel-abi-whitelists.noarch kernel.x86_64 kernel-tools-libs kernel-tools kernel-headers kernel-devel 2>&1>>"+log
      else:
        kernel_update_cmd = "/usr/bin/yum update -y kernel-firmware.noarch kernel-debug-devel.x86_64 kernel-debug.x86_64 kernel-abi-whitelists.noarch kernel.x86_64 kernel-tools-libs kernel-tools kernel-headers kernel-devel 2>&1>>"+log
    log_general(log,"a","\nEXECUTING THE UPDATE OF NON-UEK KERNEL USING BELOW COMMAND\n\n"+kernel_update_cmd+"\n\n")
    (kernel_update_status,kernel_update) = commands.getstatusoutput(kernel_update_cmd)
    log_write("YUM ERROR RECORDED DURING NON-UEK KERNEL PATCH",kernel_update)
    if kernel_update_status != 0:
      non_uek = "OL_NON-UEK_FAILED"
    else:
      non_uek = "OL_NON-UEK_SUCCESSFUL"
    log_general(log,"a","\n"+non_uek+"\n")
  
    ####UEK-INSTALL
    if uek != 0:
      clean_cmd = commands.getoutput("yum clean all")
      if not values.canary and not uek_kernel:
        optional_kernel_pkg_install()
      else:
        if values.canary:
          pkg=os.popen("rpm -qa | grep kernel-uek|awk -F\"[0-9]\" \'{print $1}\'| sed \'s/.$//\'").readlines()
          cmd_grep_uek = "rpm -qa --last kernel-uek | head -n 1"
          list_uek="yum --disablerepo=* --enablerepo=*latest,*uekr* install -y "+' '.join([x.strip() for x in pkg])
        else:
          pkg=os.popen("rpm -qa | grep kernel-uek|awk -F\"[0-9]\" \'{print $1}\'").readlines()
          cmd_grep_uek="grep kernel-uek-"+uek_kernel+"*"
          if values.upgrade:
            list_uek="yum --disablerepo=* --enablerepo="+majversion+"_peo* install -y "+' '.join([x.strip() + uek_kernel+"*" for x in pkg])
          else:
            list_uek="yum install -y "+' '.join([x.strip() + uek_kernel+"*" for x in pkg])

        log_general(log,"a","\nEXECUTING THE UPDATE OF UEK KERNEL USING BELOW COMMAND\n\n"+list_uek+"\n\n") 
        cmd_uek=commands.getoutput(list_uek+" &>>"+log )
        log_write("YUM ERROR RECORDED DURING UEK KERNEL INSTALL",cmd_uek)
        rpm_uek="rpm -qa | "+cmd_grep_uek+" &>>"+log
        (uek_exit_status,output)=commands.getstatusoutput(rpm_uek)
        if uek_exit_status != 0:
          kernel_status="OL_KERNEL_PATCH_FAILED"
        else:
          if values.canary:
            kernel_check_cmd = "rpm -qa kernel-uek --last | head -n 1| awk \'{print $1}\'|sed \'s/kernel-uek-//\'"
            log_general(log,"a","\nEXECUTING THE VERIFICATION OF UEK INSTALLED USING BELOW COMMAND\n\n"+kernel_check_cmd+"\n\n")
            kernel_check = commands.getoutput(kernel_check_cmd).split(" ")[0].strip()
          else:
            kernel_check_cmd = "rpm -qa kernel-uek | grep "+uek_kernel+"| awk \'{print $1}\'|sed \'s/kernel-uek-//\'"
            log_general(log,"a","\nEXECUTING THE VERIFICATION OF UEK INSTALLED USING BELOW COMMAND\n\n"+kernel_check_cmd+"\n\n")
            kernel_check = commands.getoutput(kernel_check_cmd)
          log_general(log,"a","\nVERIFIED UEK OUTPUT: "+kernel_check+"\n")
          (init_status,init_file_check) = commands.getstatusoutput("ls /boot |grep "+kernel_check+" |grep -v debug |grep -v ksplice|grep -i init")
          (kernel_files_status,kernel_files_check) = commands.getstatusoutput("ls /boot |grep "+kernel_check+" |grep -v debug |grep -v ksplice | wc -l")
          if init_status == 0:
            if int(kernel_files_check) >= 5:
              kernel_status = "OL_KERNEL_PATCH_SUCCESSFUL"
              if int(majversion) >= 7:
                (copy_status,copy_cmd) = commands.getstatusoutput("cp -pr "+grub_conf_file+" /tmp/grub.cfg.`date +\"%Y%m%d_%H%M%S\"`")
                if copy_status == 0:
                  if values.fix:
                    log_general(log,"a","\n###INITIATING FIX REGENERATING GRUB CONF FILE\n")
                    (recreate_status,recreate_grub) = commands.getstatusoutput("/usr/sbin/grub2-mkconfig -o "+grub_conf_file)
                    if recreate_status == 0:
                      log_write("LOG FOR GRUB CONFIGURATION FILE GENERATION",recreate_grub)
                    else:
                      log_write("ERRORS DURING GRUB CONFIGURATION FILE GENERATION",recreate_grub)
                  else:
                    log_general(log,"a","\nSKIPPING FIX REGENERATING GRUB CONF FILE\n")
            else:
              kernel_status = "OL_KERNEL_PATCH_PARTIAL_SUCCESSFUL"
          else:
            kernel_status = "OL_KERNEL_PATCH_FAILED_INITRAMFS/INITRD_MISSING"
    else:
      kernel_status = non_uek      
  else:
    non_uek = "OL_BOOT_SPACE_UNAVAILABLE"
    kernel_status="OL_BOOT_SPACE_UNAVAILABLE"
    log_general(log,"a","\nBOOT SPACE NOT AVAILABLE,SKIPPING THE KERNEL PATCH\n")

####UPDATING KSPLICE####

def update_ksplice():
  clean_cmd = commands.getoutput("yum clean all")
  global ksplice_status,uptrack_status
  if uek > 3 :
    log_general(log,"a","\n###INITIATING THE KSPLICE UPDATE\n")
    if not values.canary:
      with open("/etc/yum.repos.d/ksplice.repo","a") as OEL:
        print  >> OEL,"["+majversion+"_peo_ksplice]"
        print  >> OEL,"name="+majversion+"_peo_ksplice"
        print  >> OEL,"baseurl="+ksplice_url+"/"
        print  >> OEL,"gpgcheck=0"
        print  >> OEL,"enabled=1"
        print  >> OEL,"gpgkey="+gpg_url+""
        print  >> OEL,"timeout=300"
        print  >> OEL,"proxy=_none_"
        print  >> OEL
    clean_cmd = commands.getoutput("yum clean all")

    if values.canary:
      if values.upgrade:
        ksplice_cmd = "/usr/bin/yum --disablerepo=* --enablerepo=*ksplice -y install uptrack-offline uptrack-updates-`uname -r` 2>&1>>"+log
      else:
        ksplice_cmd = "/usr/bin/yum --enablerepo=*ksplice -y install uptrack-offline uptrack-updates-`uname -r` 2>&1>>"+log
    else:
      if values.upgrade:
        ksplice_cmd = "/usr/bin/yum --disablerepo=* --enablerepo="+majversion+"_peo* -y install uptrack-offline uptrack-updates-`uname -r` 2>&1>>"+log
      else:
        ksplice_cmd = "/usr/bin/yum  -y install uptrack-offline uptrack-updates-`uname -r` 2>&1>>"+log
    uptrack_cmd = "/usr/sbin/uptrack-upgrade -y 2>&1>>"+log

    log_general(log,"a","\nEXECUTING THE KSPLICE INSTALL WITH BELOW COMMAND\n\n"+ksplice_cmd+"\n\n")
    (ksplice_pkg_status,ksplice_pkg_output) = commands.getstatusoutput(ksplice_cmd)
    if ksplice_pkg_status == 0:
      ksplice_status = "KSPLICE_PKG_INSTALLED"
    else:
      ksplice_status = "KSPLICE_PKG_FAILED"
    log_general(log,"a","\n"+ksplice_status+"\n")
    log_write("YUM ERROR RECORDED DURING KSPLICE UPDATE",ksplice_pkg_output)

    log_general(log,"a","\nEXECUTING THE UPTRACK UPGRADE WITH BELOW COMMAND\n\n"+uptrack_cmd+"\n\n")
    (ksplice_upg_status, ksplice_upg_output) = commands.getstatusoutput(uptrack_cmd)
    if ksplice_upg_status == 0:
      uptrack_status = "UPTRACK_UPGRADE_COMPLETED"
    else:
      uptrack_status = "UPTRACK_UPGRADE_FAILED"
    log_general(log,"a","\n"+uptrack_status+"\n")
    log_write("ERRORS RECORDED DURING UPTRACK UPDATE COMMAND",ksplice_upg_output)
    
  else:
    log_general(log,"a","\nSKIPPING THE KSPLICE AS UEK < 4 \n")
    ksplice_status,uptrack_status = "NA","NA"

#####CLEAR BOOT SPACE####

def fix_boot_space_clearance():
  if values.fix and not values.canary:
    log_general(log,"a","\n###INITIATING STEP PRE-FIX BOOT SPACE CLEARANCE\n")
    all_kernel_versions=[]
    version=[]
    kernel_version_count = values.stay_kernel-1
    if free < min_boot_space:
      if uek != 0:
        if uek_kernel:
          kernel = uek_kernel
        elif extra_rpms_optional:
          if uek_optional:
            if uek_optional[uek_value]:
              kernel = uek_optional[uek_value].rstrip('*')
            else:
              kernel = ""
          else:
            kernel = ""
        else:
          kernel = ""
      else:
        lastest_kernel = commands.getoutput("rpm -qa --last kernel").split('\n')[0].split(' ')[0].lstrip('kernel-')
        if lastest_kernel != cur_kernel:
          kernel = ""
        else:
          kernel = cur_kernel
      if kernel:
        if uek != 0:
          (status,output)=commands.getstatusoutput("rpm -qa kernel-uek | grep "+kernel)
        else:
          status = 256
        if status != 0:
          (ker_list_status,ker_list_output)=commands.getstatusoutput("rpm -qa --last kernel kernel-uek")
          if ker_list_status == 0:
            list_kernel=ker_list_output.split("\n")
            for i in list_kernel:
              all_kernel_versions.append(i.split(" ")[0].strip())
            if "uek" in cur_kernel:
              all_kernel_versions.remove("kernel-uek-"+cur_kernel)
            else:
              all_kernel_versions.remove("kernel-"+cur_kernel)
            if len(all_kernel_versions) != 0:
              if len(all_kernel_versions) > kernel_version_count:
                for i in all_kernel_versions[kernel_version_count:]:
                  v1=i.rsplit('.',1)
                  if "uek" in v1[0]:
                    version.append(v1[0].lstrip("kernel-uek-").strip())
                  else:
                    version.append(v1[0].lstrip("kernel-").strip())
                for i in version:
                  (ker_grep_status,ker_grep_output) = commands.getstatusoutput("rpm -qa | grep -i kernel* | grep "+i)
                  if ker_grep_status == 0:
                    rm_pkg = ker_grep_output.split("\n")
                    uninstall(rm_pkg)
              else:
                log_general(log,"a","\nONLY %s KERNELS WERE PRESENT.CLEARANCE IS NOT POSSIBLE\n"%(values.stay_kernel))
            else:
              log_general(log,"a","\nKERNEL UNINSTALLATION IS NOT POSSIBLE AS ONLY CURRENT KERNEL IS PRESENT\n")
        else:
          log_general(log,"a","\nLATEST KERNEL IS ALREADY INSTALLED.CLERANCE IS NOT REQUIRED\n")
      else:
        log_general(log,"a","\nEITHER UEK-KENEL IS NOT SPECIFIED OR NON-UEK IS HAVING LATEST KERNEL.CLERANCE IS NOT REQUIRED\n")
    else:
      log_general(log,"a","\nBOOT SPACE IS AVAILABLE. CLEARANCE IS NOT REQUIRED\n")
  else:
    log_general(log,"a","\n#SKIPPING STEP BOOT SPACE CLEARANCE AS FORCEFIX IS NOTAPPLIED (or) SELECTION IS CANARY \n")
    

#####FILE SYSTEM CHECK######

def file_system_check(filesystem_name):
  log_general(log,"a","\n###INITIATING STEP FILE SYSTEM CHECK\n")
  global free,used,total
  fs_stat = os.statvfs(filesystem_name)
  total_fs = fs_stat.f_blocks*fs_stat.f_bsize
  free_fs = fs_stat.f_bfree*fs_stat.f_bsize
  used_fs = (fs_stat.f_blocks-fs_stat.f_bfree)*fs_stat.f_bsize
  #####CONVERSION TO MB'S####
  free = free_fs/1024/1024
  used = used_fs/1024/1024
  total = total_fs/1024/1024

####OS UPGRADE ######

def os_upgrade():
  clean_cmd = commands.getoutput("yum clean all")
  log_general(log,"a","\n###INITIATING STEP OS UPGRADE\n")
  global patch_status
  global endtime,runtime,enddate

  if values.canary:
    update_yum_cmd = "yum  --enablerepo=*latest,*addons update yum -y 2>&1>>"+log
    update_plugin_cmd = "yum --enablerepo=*latest,*addons install yum-plugin-security -y 2>&1>>"+log
    remove_yum_repo_cmd = "rm -f /etc/yum.repos.d/public-yum*"
    if int(majversion) == 8:
      upgrade_cmd = "yum --enablerepo=*latest,*addons update -y --exclude="+exclude_pkg+"  --skip-broken --setopt=protected_multilib=false --allowerasing --nobest 2>&1>>"+log
    else:
      upgrade_cmd = "yum --enablerepo=*latest,*addons update -y --exclude="+exclude_pkg+"  --skip-broken --setopt=protected_multilib=false 2>&1>>"+log
  else:
    update_yum_cmd = "yum  update yum -y 2>&1>>"+log
    update_plugin_cmd = "yum install yum-plugin-security -y 2>&1>>"+log
    remove_yum_repo_cmd = "rm -f /etc/yum.repos.d/public-yum*"
    if int(majversion) == 8:
      upgrade_cmd = "yum update -y --exclude="+exclude_pkg+"  --skip-broken --setopt=protected_multilib=false --allowerasing --nobest 2>&1>>"+log
    else:
      upgrade_cmd = "yum update -y --exclude="+exclude_pkg+"  --skip-broken --setopt=protected_multilib=false 2>&1>>"+log    
  
  update_yum = commands.getoutput(update_yum_cmd)
  update_plugin = commands.getoutput(update_plugin_cmd)
  remove_yum_repo = commands.getoutput(remove_yum_repo_cmd)
  log_general(log,"a","\nEXECUTING THE OS UPGRADE WITH BELOW COMMAND\n\n"+upgrade_cmd+"\n\n")
  (upgrade_status,upgrade_output) = commands.getstatusoutput(upgrade_cmd)
  log_write("YUM ERROR RECORDED DURING UPGRADE",upgrade_output)

  if upgrade_status == 0:
      patch_status = "OL_UPGRADE_SUCCESSFUL"
      log_general(log,"a","\n"+patch_status+"\n")
  else:
      patch_status = "OL_UPGRADE_FAILED"
      log_general(log,"a","\n"+patch_status+"\n")
  endtime = time.time()
  runtime = endtime - starttime
  enddate = datetime.datetime.now().strftime("%Y/%m/%d, %H:%M:%S")
  
  
####APPLYING THE SECURITY PATCHES#####

def security_patch():
  clean_cmd = commands.getoutput("yum clean all")
  log_general(log,"a","\n###INITIATING STEP SECURITY PATCH\n")
  global endtime,runtime,enddate
  
  if values.canary:
    update_yum_cmd = "yum  --enablerepo=*latest,*addons update yum -y 2>&1>>"+log
    update_plugin_cmd = "yum --enablerepo=*latest,*addons install yum-plugin-security -y 2>&1>>"+log
    remove_yum_repo_cmd = "rm -f /etc/yum.repos.d/public-yum*"

    update_security_1_cmd = "yum --enablerepo=*latest,*addons update --security -y --exclude="+exclude_pkg+"  --skip-broken --setopt=protected_multilib=false 2>&1>>"+log
    update_security_2_cmd = "yum --enablerepo=*latest,*addons updateinfo list security |grep -i elsa |awk \'{print $NF}\' |grep -vi ^kernel | xargs yum update -y --security --exclude="+exclude_pkg+"  --setopt=protected_multilib=false --skip-broken 2>&1>>"+log
    update_security_3_cmd = "yum --enablerepo=*latest,*addons updateinfo list security |egrep -i \'critical\' |awk \'{print $NF}\' |xargs yum update -y --security --exclude="+exclude_pkg+"  --setopt=protected_multilib=false 2>&1>>"+log
  else:
    update_yum_cmd = "yum  update yum -y 2>&1>>"+log
    update_plugin_cmd = "yum install yum-plugin-security -y 2>&1>>"+log
    remove_yum_repo_cmd = "rm -f /etc/yum.repos.d/public-yum*"

    update_security_1_cmd = "yum update --security -y --exclude="+exclude_pkg+"  --skip-broken --setopt=protected_multilib=false 2>&1>>"+log
    update_security_2_cmd = "yum updateinfo list security |grep -i elsa |awk \'{print $NF}\' |grep -vi ^kernel | xargs yum update -y --security --exclude="+exclude_pkg+"  --setopt=protected_multilib=false --skip-broken 2>&1>>"+log
    update_security_3_cmd = "yum updateinfo list security |egrep -i \'critical\' |awk \'{print $NF}\' |xargs yum update -y --security --exclude="+exclude_pkg+"  --setopt=protected_multilib=false 2>&1>>"+log

  update_yum = commands.getoutput(update_yum_cmd)
  update_plugin = commands.getoutput(update_plugin_cmd)
  remove_yum_repo = commands.getoutput(remove_yum_repo_cmd)
  log_general(log,"a","\nEXECUTING THE 1ST TRY OF SECURITY PATCH WITH BELOW COMMAND\n\n"+update_security_1_cmd+"\n\n")
  security_update = commands.getoutput(update_security_1_cmd)
  log_write("YUM ERROR RECORDED DURING 1ST TRY OF SECURITY PATCH",security_update)
  log_general(log,"a","\nEXECUTING THE 2ND TRY OF SECURITY PATCH WITH BELOW COMMAND\n\n"+update_security_2_cmd+"\n\n")
  security_update_2 = commands.getoutput(update_security_2_cmd)
  log_write("YUM ERROR RECORDED DURING 2ND TRY OF SECURITY PATCH",security_update_2)
  log_general(log,"a","\nEXECUTING THE 3RD TRY OF SECURITY PATCH WITH BELOW COMMAND\n\n"+update_security_3_cmd+"\n\n")
  security_update_3 = commands.getoutput(update_security_3_cmd)
  log_write("YUM ERROR RECORDED DURING 3RD TRY OF SECURITY PATCH",security_update_3)

  endtime = time.time()
  runtime = endtime - starttime
  enddate = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

###CHECK FOR YUM PROCESSES#####

def yum_process_status():
  clean_cmd = commands.getoutput("yum clean all")
  log_general(log,"a","\n###INITIATING STEP YUM PROCESS CHECK\n")
  global starttime,startdate
  startdate=datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
  starttime=time.time()
  y_count=commands.getoutput("ps -ef | grep -w \"/usr/bin/yum\"  | grep -v grep|wc -l")
  if y_count == "0":
    if values.upgrade:
      os_upgrade()
    else:
      security_patch()
  else:
    pid=commands.getoutput("ps -ef | grep -w \"/usr/bin/yum\"  | grep -v grep | awk \'{print $2}\'")
    print ("Already another yum process is runinng: process id = %s"%(pid))
    repo_restore()
    sys.exit()


####SEARCH THE STRING IN FILE AND APPEND IT#####

def search_entry(filename,string):
  if values.fix and not values.canary:
    log_general(log,"a","\n###INITIATING STEP SEARCH FOR ENTRIES IN LOGIN DEFS\n")
    with open(filename) as obj:
      for v in obj.readlines():
        v = v.strip()
        if (re.search(string,v,re.I)):
          log_general(log,"a","\n"+v+"\n","entries present\n")
    with open(log) as obj:
      v = obj.read()
      if (re.search("entries present",v,re.I)):
        pass
      else:
        log_general(filename,"a","\n SYS_GID_MIN               100\n","\n SYS_GID_MAX               499\n")
  else:
    log_general(log,"a","\n###SKIPPING FIX SEARCH FOR ENTRIES IN LOGIN DEFS AS FORCEFIX IS NOT APPLIED (or) SELECTION IS CANARY\n")

  
####TEMPORARY REMOVAL FIX FOR GLIBC AND PACKAGE KIT FOR OEL7#####

def fix_glibc_pkgkit():
  if not values.canary:
    if values.fix and int(majversion) >= 7:
      log_general(log,"a","\n###INITIATING STEP PRE-FIX TEMPORARY REMOVAL OF GLIBC AND PACKAGEKIT\n")
      if len(glibc_pkgs) > 0:
        log_general(log,"a","\nBELOW ARE THE LIST OF GLIBC PACKAGES WHICH ARE AVAILABLE FOR SECURITY \n","\n"+'\n'.join(glibc_pkgs)+"\n")
        if pkg_glibc:
          uninstall(pkg_glibc)
        else:
          log_general(log,"a","\nSKIPPING PRE-FIX TEMPORARY REMOVAL OF GLIBC AS PACKAGES NOT LISTED IN INPUT JSON\n")
      if len(pkgkit_pkg) > 0:
        log_general(log,"a","\nBELOW ARE THE LIST OF PACKAGEKIT PACKAGES WHICH ARE AVAILABLE FOR SECURITY \n","\n"+'\n'.join(pkgkit_pkg)+"\n")
        if pkg_kit:
          uninstall(pkg_kit)
        else:
          log_general(log,"a","\nSKIPPING PRE-FIX TEMPORARY REMOVAL OF PACKAGEKIT AS PACKAGES NOT LISTED IN INPUT JSON\n")
    else:
      log_general(log,"a","\nSKIPPING PRE-FIX TEMPORARY REMOVAL OF GLIBC AND PACKAGEKIT AS FORCEFIX IS NOT APPLIED (or) OS VERSION IS OTHER THAN 7\n")
  else:
    log_general(log,"a","\nSKIPPING PRE-FIX TEMPORARY REMOVAL OF GLIBC AND PACKAGEKIT AS SELECTION IS CANARY\n")

####FIX BY REMOVING PACKAGES####

def fix_removal_pkg():
  if values.fix and not values.canary:
    log_general(log,"a","\n###INITIATING STEP PRE-FIX BY REMOVING PACKAGES\n")
    if removal_pkg:
      uninstall(removal_pkg)
  else:
    log_general(log,"a","\nSKIPPING STEP PRE-FIX BY REMOVING PACKAGES AS FORCEFIX IS NOT APPLIED (or) SELECTION IS CANARY\n")

####FIX AND UPDATE QEMU AND LIBVIRT PACKAGES###

def fix_update_qemu_libvirt():
  clean_cmd = commands.getoutput("yum clean all")
  if values.fix and not values.canary:
    if int(majversion) == 7:
      log_general(log,"a","\n###INITIATING STEP PRE-FIX INSTALLING QEMU AND LIBVIRT PACKAGES\n")
      remove_libvirt = ["libvirt-libs.i686", "libvirt-devel.i686"] 

      ###UNINSTALL LIBVIRT PACKAGES
      uninstall(remove_libvirt)
      
      ##UPDATE QEMU AND LIBVIRT PACKAGE
      update_pkg_list = ["qemu-img", "qemu-kvm", "libvirt-libs", "libvirt-daemon*" ]
      update_pkg = ' '.join(update_pkg_list)
      update_qemu_libvirt_cmd = "yum update "+update_pkg+" -y --skip-broken --setopt=protected_multilib=false 2>&1>>"+log
      log_general(log,"a","\nEXECUTING THE PRE-FIX INSTALLATION OF QEMU AND LIBVIRT WITH BELOW COMMAND\n\n"+update_qemu_libvirt_cmd+"\n\n")      
      (qemu_status, qemu_output) = commands.getstatusoutput(update_qemu_libvirt_cmd)
      log_write("YUM ERROR RECORDED DURING QEMU AND LIBVIRT UPDATE",qemu_output)
      if qemu_status == 0:
        log_general(log,"a","\nQEMU AND LIBVIRT PACKAGES ARE UPDATED SUCCESSFULLY\n")
      else:
        log_general(log,"a","\nFALIED TO UPDATE QEMU AND LIBVIRT PACKAGES\n")
      
      ##MOVE CREATED REPO TO /TMP LOCATION
      move_repo_cmd = commands.getoutput("mv /etc/yum.repos.d/qemu_libvirt.repo /tmp")
      
    else:
      log_general(log,"a","\nSKIPPING STEP PRE-FIX INSTALL LIBVIRT,QEMU PKGS AS OS IS NOT 7\n")
  else:
    log_general(log,"a","\nSKIPPING STEP PRE-FIX INSTALL LIBVIRT,QEMU PKGS AS FORCEFIX IS NOT APPLIED (or) SELECTION IS CANARY\n")

######FIX AND UPDATE DOCKER#########

def fix_and_update_docker():
  log_general(log,"a","\n###INITIATING STEP PRE-FIX FOR DOCKER\n")
  clean_cmd = commands.getoutput("yum clean all")     
  if len(docker_pkg) != 0:
    log_general(log,"a","\nPROCEEDING WITH THE DOCKER UPDATE PATCH\n","\nBELOW ARE THE LIST OF DOCKER PACKAGES TO BE UPDATED\n","\n"+'\n'.join(docker_pkg)+"\n")
    docker_files = ["/etc/sysconfig/docker", "/etc/sysconfig/docker-network", "/etc/sysconfig/docker-storage", "/etc/systemd/system/docker.service.d/docker-sysconfig.conf"]
    for i in docker_files:
      file_exist = os.path.isfile(i)
      if file_exist:
        shutil.copy2(i,i+".orig")
      else:
        log_general(log,"a","\n"+i+" FILE DOESNOT EXIST.SO,COPY OF FILE IS NOT CREATED\n")
    if values.canary:
      docker_update_cmd = "yum --enablerepo=*latest,*addons update docker-cli docker-engine -y --skip-broken --setopt=protected_multilib=false 2>&1>>"+log
    else:
      docker_update_cmd = "yum update docker-cli docker-engine -y --skip-broken --setopt=protected_multilib=false 2>&1>>"+log
    (update_docker_status,update_docker_output) = commands.getstatusoutput(docker_update_cmd)
    log_write("YUM ERROR RECORDED DURING DOCKER UPDATE",update_docker_output)
    if update_docker_status == 0:
      log_general(log,"a","\nUPDATE OF DOCKER IS SUCCESSFUL\n")
      (stat,output) = commands.getstatusoutput("systemctl stop docker")
      (stat_stat,doc_out) = commands.getstatusoutput("systemctl status docker")
      log_general(log,"a","\nSTATUS OF DOCKER AFTER THE EXECUTING THE COMMAND DOCKER SERVICE TO STOP \n"+doc_out+"\n")
      for i in docker_files:
        file_exist_bkp = os.path.isfile(i+".orig")
        if file_exist_bkp:
          shutil.copy2(i+".orig",i)
      (start_status,start_output) = commands.getstatusoutput("systemctl start docker")
      if start_status == 0:
        log_general(log,"a","\nDOCKER STARTED SUCCESSFULLY\n")
      else:
        log_general(log,"a","\nFAILED TO START DOCKER AFTER UPDATE\n")
      (stat_stat,doc_out) = commands.getstatusoutput("systemctl status docker")
      log_general(log,"a","\nSTATUS OF DOCKER AFTER UPDATE\n"+doc_out+"\n")
    else:
      log_general(log,"a","\nFAILED TO UPDATE DOCKER\n")
  else:
    log_general(log,"a","\nSKIPPED THE UPDATE OF DOCKER AS THE SECURITY PATCH FOR DOCKER IS NOT LISTED\n")


######CHECKS FOR ISSUES IN RPM AND YUM COMMANDS#########

def rpm_yum_check():
  log_general(log,"a","\n###INITIATING STEP CHECK FOR YUM ERRORS AND CALCULATE PRE CVES COUNT\n")
  
  global rpm_stat,pre_status
  global pre_cve_critical,pre_cve_important,pre_cve_moderate,pre_cve_low
  global cves_present,docker_pkg,glibc_pkgs,pkgkit_pkg
  (rpm_stat,rpm_check) = commands.getstatusoutput("rpm -qa kernel kernel-uek")
  y_count=commands.getoutput("ps -ef | grep -w \"/usr/bin/yum\"  | grep -v grep|wc -l")
  if y_count == "0":
    clean_cmd = commands.getoutput("yum clean all")
    if values.canary:
      cmd_list_sec = "yum --exclude=docker*,kernel* --enablerepo=*latest,*addons updateinfo list security"
    else:
      cmd_list_sec = "yum --exclude=docker*,kernel* updateinfo list security"
    (pre_status,pre_cve_output) = commands.getstatusoutput(cmd_list_sec)
    if values.security:
      if pre_status == 0:
        if "ELSA" not in pre_cve_output:
          if not values.canary:
            if uek != 0:
              (k_status,k_check) =  commands.getstatusoutput("rpm -qa kernel-uek | grep -w "+uek_kernel)
              if k_status == 0:
                log_general(log,"a","\nSECURITY AND KERNEL PATCH IS ALREADY UPDATED\n")
                repo_restore()
                print ("SECURITY AND KERNEL PATCH IS ALREADY UPDATED")
                sys.exit()
  else:
    pid=commands.getoutput("ps -ef | grep -w \"/usr/bin/yum\"  | grep -v grep | awk \'{print $2}\'")
    print ("Already another yum process is runinng: process id = %s)"%(pid))
    sys.exit(1)
  if rpm_stat != 0 or pre_status != 0:
    if rpm_stat != 0:
      log_write("RPM ERRORS",rpm_check)
    else:
      log_write("YUM ERRORS",pre_cve_output)
    repo_restore()
    write_status_to_file()
    output_to_csv()
    output_to_central()
    central_csv()
    dump_to_db()
    sys.exit(1)
  pre_cve_critical,pre_cve_important,pre_cve_moderate,pre_cve_low = 0,0,0,0
  cves_present = 0
  docker_pkg, glibc_pkgs, pkgkit_pkg= [], [], []
  pre_list_cve = list(pre_cve_output.split('\n')) 
  log_general("/tmp/pre_cve_result","w",pre_cve_output)
  for i in pre_list_cve: 
    if "docker" in i:
      docker_pkg.append(i)
    if "glibc" in i:
      glibc_pkgs.append(i)
    if "PackageKit" in i:
      pkgkit_pkg.append(i)

    if "Critical" in i:
      cves_present = cves_present+1
      pre_cve_critical = pre_cve_critical+1
    elif "Important" in i:
      cves_present = cves_present+1
      pre_cve_important = pre_cve_important+1
    elif "Moderate" in i:
      cves_present = cves_present+1
      pre_cve_moderate = pre_cve_moderate+1
    elif "Low" in i:
      cves_present = cves_present+1
      pre_cve_low = pre_cve_low+1
    else:
      pass

#####BACKUP COPY OF A FILE #####

def conf_backup(src,dst):
    shutil.copy2(src,dst)

####FIX REPOS####

def fix_repos():

  if values.fix and not values.canary:
    if int(majversion) == 7: 
      i = "kvm/utils"
      ###CREATE QEMU REPO
      with open("/etc/yum.repos.d/qemu_libvirt.repo","w") as OEL:
        if "/" in i:
          print  >> OEL,"["+majversion+"_peo_"+i.split('/')[0]+"]"
          print  >> OEL,"name="+majversion+"_"+i.split('/')[0]+""
        else:
          print  >> OEL,"["+majversion+"_peo_"+i+"]"
          print  >> OEL,"name="+majversion+"_"+i+""
        print  >> OEL,"baseurl="+snapshot_url.replace("<repo_name>",i)
        print  >> OEL,"gpgcheck=0"
        print  >> OEL,"enabled=1"
        print  >> OEL,"gpgkey="+gpg_url+""
        print  >> OEL,"timeout=300"
        print  >> OEL,"proxy=_none_"
        print  >> OEL


#####CREATE PEO REPO#######

def create_peo_repo():
  clean_cmd = commands.getoutput("yum clean all")
  if not values.canary:
    log_general(log,"a","\n###INITIATING STEP CREATE REPO\n")
    global UEK2_pkg,UEK3_pkg,UEK4_pkg,UEK5_pkg,UEK6_pkg,COMMON_repo,uek_pkg
    UEK2_pkg,UEK3_pkg,UEK4_pkg,UEK5_pkg,UEK6_pkg,COMMON_repo = [],[],[],[],[],[]
    uek_pkg = []
    for i in selected_snap:
      if i.startswith ('UEKR6'):
        UEK6_pkg.append(i)
      elif i.startswith ('UEKR3'):
        UEK3_pkg.append(i)
      elif i.startswith ('UEKR4'):
        UEK4_pkg.append(i)
      elif i.startswith ('UEKR5'):
        UEK5_pkg.append(i)
      elif i.startswith ('UEK'):
        UEK2_pkg.append(i)
      else:
        COMMON_repo.append(i)
    
    with open("/root/peo_update.repo","w") as OEL:
      for i in COMMON_repo:
        if "/" in i:
          print  >> OEL,"["+majversion+"_peo_"+i.split('/')[0]+"]"
          print  >> OEL,"name="+majversion+"_"+i.split('/')[0]+""
        else:
          print  >> OEL,"["+majversion+"_peo_"+i+"]"
          print  >> OEL,"name="+majversion+"_"+i+""
        print  >> OEL,"baseurl="+snapshot_url.replace("<repo_name>",i)
        print  >> OEL,"gpgcheck=0"
        print  >> OEL,"enabled=1"
        print  >> OEL,"gpgkey="+gpg_url+""
        print  >> OEL,"timeout=300"
        print  >> OEL,"proxy=_none_"
        print  >> OEL
    if int(majversion) != 8:
      with open("/root/peo_update.repo","a") as OEL:
        print  >> OEL,"["+majversion+"_pdit_HMP]"
        print  >> OEL,"name="+majversion+"_pdit_HMP"
        print  >> OEL,"baseurl="+hmp_url+""
        print  >> OEL,"gpgcheck=0"
        print  >> OEL,"enabled=1"
        print  >> OEL,"gpgkey="+gpg_url+""
        print  >> OEL,"timeout=300"
        print  >> OEL,"proxy=_none_"
        print  >> OEL
    if uek != 0:
      if uek == 2:
        uek_pkg =  UEK2_pkg
      elif uek == 3:
        uek_pkg =  UEK3_pkg
      elif uek == 4:
        uek_pkg =  UEK4_pkg
      elif uek == 5:
        uek_pkg =  UEK5_pkg
      else:
        uek_pkg =  UEK6_pkg
    with open("/root/peo_update.repo","a") as OEL:
      for i in uek_pkg:
        if "/" in i:
          print  >> OEL,"["+majversion+"_peo_"+i.split('/')[0]+"]"
          print  >> OEL,"name="+majversion+"_"+i.split('/')[0]+""
        else:
          print  >> OEL,"["+majversion+"_peo_"+i+"]"
          print  >> OEL,"name="+majversion+"_"+i+""
        print  >> OEL,"baseurl="+snapshot_url.replace("<repo_name>",i)
        print  >> OEL,"gpgcheck=0"
        print  >> OEL,"enabled=1"
        print  >> OEL,"gpgkey="+gpg_url+""
        print  >> OEL,"timeout=300"
        print  >> OEL,"proxy=_none_"
        print  >> OEL        
    with open("/root/peo_update.repo","a") as OEL:
      print  >> OEL,"["+majversion+"_pdit_tools]"
      print  >> OEL,"name="+majversion+"_pdit_tools"
      print  >> OEL,"baseurl="+tools_url+""
      print  >> OEL,"gpgcheck=0"
      print  >> OEL,"enabled=1"
      print  >> OEL,"gpgkey="+gpg_url+""
      print  >> OEL,"timeout=300"
      print  >> OEL,"proxy=_none_"
      print  >> OEL
      print  >> OEL,"[main]"
      print  >> OEL,"plugins=1"
      print  >> OEL,"installonly_limit=2"
      print  >> OEL,"cacheddir=/tmp/peo_yum_cache"
      print  >> OEL,"protected_multilib=0"
      print  >> OEL
          
  else:
    log_general(log,"a","\nSKIPPING STEP CREATE REPO AS PATCH SELECTED IS CANARY\n")

######BACKUP OF PEO_UPDATE AND YUM REPOS######

def repo_backup():
  if not values.canary:
    log_general(log,"a","\n###INITIATING STEP REPO BACKUP\n")
    peo_backup_dir_exist = os.path.isdir(peo_backup_path)
    if peo_backup_dir_exist == False:
      os.mkdir(peo_backup_path,0755)
    repo_backup_dir_exist = os.path.isdir(repos_backup_path)
    if repo_backup_dir_exist == False:
      os.mkdir(repos_backup_path,0755)
    peo_repo_exist = os.path.isfile(os.path.join(src_root_path,peo_repo_name))
    if peo_repo_exist == True:
      shutil.move(os.path.join(src_root_path,peo_repo_name),os.path.join(peo_backup_path,peo_repo_name))
    repo_count = len(glob.glob(yum_repo_path+"/*.repo"))
    if repo_count != 0:
      repo_files=os.listdir(yum_repo_path)
      for i in repo_files:
        if i.endswith ('.repo'):
          check_mutable = commands.getoutput("lsattr "+os.path.join(yum_repo_path,i))
          if "i" in check_mutable[:16]:
            cmd_immutable = commands.getoutput("chattr -i "+os.path.join(yum_repo_path,i))
          shutil.move(os.path.join(yum_repo_path,i),os.path.join(repos_backup_path,i))
#    if values.fix or values.disable_proxy:
#      log_general(log,"a","\n###INITIATING FIX FOR PROXY IN YUM.CONF\n")
#      (proxy_status,proxy_check)=commands.getstatusoutput("grep -i proxy /etc/yum.conf")
#      if proxy_status == 0:
#        shutil.copy2("/etc/yum.conf","/etc/yum.conf.orig")
#        set_proxy = commands.getoutput("echo \"proxy=_none_\" >> /etc/yum.conf")
#    else:
#      log_general(log,"a","\nSKIPPING FIX FOR PROXY IN YUM.CONF AS FORCEFIX IS NOT APPLIED\n")
  else:
    log_general(log,"a","\nSKIPPING STEP REPO BACKUP AS PATCH SELECTED IS CANARY\n")
    
#####FIX FOR UEK4 KERNEL WITH MICROCODE_CTL PACKAGE##########

def fix_microcode():
  if values.fix and not values.canary:
    log_general(log,"a","\n###INITIATING STEP PRE-FIX MICROCODE\n")
    if uek == 4:
      (dmidecode_status, dmidecode_output) = commands.getstatusoutput("dmidecode -s system-product-name")
      if dmidecode_status == 0:
        vm_type_output= dmidecode_output.lower().strip()
        log_general(log,"a","\nSERVER TYPE: "+vm_type_output+"\n")
        if "standard" in vm_type_output:
          vm_type_output = vm_type_output.rsplit('(',1)[0].strip()
        if vm_type_output == "kvm" or vm_type_output == "hvm domu" or vm_type_output == "openstack compute" or vm_type_output == "standard pc":
          (microcode_status,microcode_output) = commands.getstatusoutput("rpm -qa | grep -i microcode_ctl")
          if microcode_status == 0:
            if  int(majversion) == 6:
              (list_conf_status,list_conf_output) = commands.getstatusoutput("ls /etc/dracut.conf.d/*microcode.conf")
            else:
              (list_conf_status,list_conf_output) = commands.getstatusoutput("ls /usr/lib/dracut/dracut.conf.d/*microcode.conf")
            if list_conf_status == 0:
              (cat_status,cat_output) = commands.getstatusoutput("cat "+list_conf_output.strip())
              if cat_output:
                if "yes" in cat_output:
                  (change_micro_status,change_micro_output) = commands.getstatusoutput("sed -i \"s/yes/no/g\" "+list_conf_output.strip())
                  log_general(log,"a","\nMICROCODE_CTL FIX IS APPLIED\n")
                  (cat_status,cat_ouptut) = commands.getstatusoutput("cat "+list_conf_output.strip())
                  log_general(log,"a","\n####BELOW IS THE OUTPUT OF MICROCODE_CTL CONF FILE####\n",cat_ouptut,"\n#####END OF MICROCODE_CTL CONF FILE#####\n")
                else:
                  log_general(log,"a","\nSKIPPING THE MICROCODE_CTL FIX AS THE MICROCODE CONF FILE IS ALREADY SET TO \"NO\"  ON THE MACHINE")
                  (cat_status,cat_ouptut) = commands.getstatusoutput("cat "+list_conf_output.strip())
                  log_general(log,"a","\n####BELOW IS THE OUTPUT OF MICROCODE_CTL CONF FILE####\n",cat_ouptut,"\n#####END OF MICROCODE_CTL CONF FILE#####\n")
              else:
                log_general(log,"a","\nSKIPPING THE MICROCODE_CTL FIX AS THE REQUIRED ENTRY IS NOT AVAILABLE IN MICROCODE CONF FILE \n")
            else:
              log_general(log,"a","\nSKIPPING THE MICROCODE_CTL FIX AS MICROCODE CONF FILE IS UNAVAILABLE ON THE MACHINE\n")
          else:
            log_general(log,"a","\nSKIPPING THE MICROCODE_CTL FIX AS MICROCODE_CTL IS UNAVAILABLE ON THE MACHINE\n")
        else:
          log_general(log,"a","\nSKIPPING THE MICROCODE_CTL FIX AS IT IS "+vm_type_output+" MACHINE\n")
      else:
        log_general(log,"a","\nSKIPPING THE MICROCODE_CTL FIX DUE TO ERROR IN EXECUTION OF DMIDECODE COMMAND\n")
    else:
      if uek == 0:
        log_general(log,"a","\nMICROCODE_CTL FIX NOT APPLICABLE FOR THE NON UEK KERNEL\n")
      else:
        log_general(log,"a","\nMICROCODE_CTL FIX NOT APPLICABLE AS THE KERNEL UEK IS "+str(uek)+"\n")    
  else:
    log_general(log,"a","\nSKIPPING THE PRE-FIX FOR MICROCODE AS FORCEFIX IS NOTAPPLIED (or) SELECTION IS CANARY\n")

#####CLEAR THE VERSION LOCK IN THE VERSION LIST FILE

def clear_version_list():
  if values.fix and not values.canary:
    log_general(log,"a","\n###INITIATING STEP CLEAR VERSION LIST\n")
    version_list_file = "/etc/yum/pluginconf.d/versionlock.list"
    ver_file_exits = os.path.isfile(version_list_file)
    if ver_file_exits == True:
      file_size = os.stat(version_list_file).st_size
      if file_size != 0:
        os.system("> "+version_list_file)
        log_general(log,"a","\nCLEARED THE VERSION LOCK LIST FILE\n")
      else:
        log_general(log,"a","\nSKIPPING AS THE VERSION LOCK LIST FILE IS EMPTY\n")
        
  else:
    log_general(log,"a","\nSKIPPING FIX TO CLEAR VERSION LIST AS FORCEFIX IS NOTAPPLED (or) SELECTION IS CANARY\n")

#####CHECK THE LATENCY THE EVERY REGION AND SELECT THE ONE OF MIN LATENCY

def ping_region_check():
    global region
    latency_output=[]
    pingable_hosts=[]
    for i in region_list:
      (exit_status,output)=commands.getstatusoutput('ping -c3 '+i)
      if exit_status == 0:
        latency = float(output.split('\n')[-1].split('/')[-3])
        pingable_hosts.append(i)
        latency_output.append(latency)
    min_value_index=latency_output.index(min(latency_output))
    region=pingable_hosts[min_value_index]


#####DATA FROM JSON FILE PROVIDED#####

def data_from_json():
 global patch_date,region_list,exclude_pkg,selected_snap
 global removal_pkg,pkg_glibc,pkg_kit,extra_rpms_optional,uek_optional,rpm_optional
 global snapshot_url,hmp_url,tools_url,gpg_url,ksplice_url,owner_email
 global uek_kernel

 if not values.canary :
   log_general(log,"a","\n###INITIATING STEP DATA FROM JSON\n")

   with open(json_file) as obj:
     info=json.load(obj)

   patch_date = info['patch_snapshot_date']
   region_list = info['urls']
   if values.exclude:
     exclude_pkg = ','.join(info['exclude_pkg'])+","+values.exclude
   else:
     exclude_pkg = ','.join(info['exclude_pkg'])
   selected_snap = info[majversion+'_snap_repos']

   removal_pkg = info[majversion+'_removal_pkg']
   pkg_glibc = info['extra_rpms_required']['pkg_glibc']
   pkg_kit = info['extra_rpms_required']['pkg_kit']
   extra_rpms_optional = info['extra_rpms_optional']
   if extra_rpms_optional:
    uek_optional = info['extra_rpms_optional']['optional_uek_kernels']
    rpm_optional = info['extra_rpms_optional'][majversion+'_optional_rpms']
   
   ping_region_check()

   snapshot_url = info['snapshot_url'].replace('<region>',region).replace('<patch_snapshot_date>',str(patch_date)).replace("<maj_version>",majversion)
   hmp_url = info['HMP_url'].replace('<region>',region).replace("<maj_version>",majversion)
   tools_url = info['tools_url'].replace('<region>',region).replace("<maj_version>",majversion)
   gpg_url = info['gpg_url'].replace('<region>',region).replace("<maj_version>",majversion)
   ksplice_url = info['ksplice_url'].replace('<region>',region).replace("<maj_version>",majversion).replace('<patch_snapshot_date>',str(patch_date))
   owner_email = os.popen("/usr/bin/curl -s -L http://devops.oraclecorp.com/host/api/"+hostname+"/data | grep -wE \'user_email\' | cut -d \"=\" -f2").read().strip()

   if uek != 0:
     uek_kernel = info['uek'+str(uek)+'_kernel']
   else:
     uek_kernel = ""

 else:
   if values.exclude:
     exclude_pkg = ','.join(info['exclude_pkg'])+","+values.exclude
   else:
     exclude_pkg = ','.join(["kernel*", "kube*"])
   owner_email = os.popen("/usr/bin/curl -s -L http://devops.oraclecorp.com/host/api/"+hostname+"/data | grep -wE \'user_email\' | cut -d \"=\" -f2").read().strip()
   log_general(log,"a","\nSKIPPING STEP DATA FROM JSON AS SELECTION IS CANARY\n")
   patch_date = "LATEST"

####CREATING LOG FILE#####

def createlogfile():
  global log,fips_status
  if values.upgrade:
    log = "/root/"+hostname+"_upgrade.log"
  else:
    log = "/root/"+hostname+"_security_patch.log"
  file_exist = os.path.isfile(log)
  if file_exist == True:
    os.system("> "+log)
  else:
    os.mknod(log)

  log_general(log,"a","\nTYPE OF PATCH SELECTED:"+selection+"\n")
  log_general(log,"a","\nSERVER "+hostname+" IS PROCEEDING WITH "+patch_type+"\n")
  log_general(log,"a","\nFORCE BUGFIX SELECTED: "+bug_fix_select+"\n")
  log_general(log,"a","\nUEK KERNEL : "+str(uek)+"\n")

  ### FIX FOR DRACUT FIPS ISSUE ###
  if values.fix: 
    log_general(log,"a","\nPROCEEDING WITH PRE-FIX FOR DRACUT FIPS ISSUE\n")
    (fips_status,fips_output)=commands.getstatusoutput("rpm -qa | grep -i dracut-fips")
    if fips_status == 0:
      fips_exist = os.path.isfile("/etc/system-fips")
      if fips_exist == False:
        create = commands.getoutput("touch /etc/system-fips")
        log_general(log,"a","\nFIX IS APPLIED. /etc/system-fips IS CREATED\n")
      else:
        log_general(log,"a","\nFIX IS ALREADY APPLIED AS /etc/system-fips IS PRESENT\n")
    else:
      log_general(log,"a","\nSKIPPING FIX AS DRACUT-FIPS RPM IS ABSENT\n") 
  else:
    log_general(log,"a","\nSKIPPING THE FIX FOR DRACUT FIPS ISSUE\n")

#####DETERMINE WHETHER CURRENT KERNEL IS UEK##########

def determine_uek_kernel():
  global uek
  (uek_status,uek_cmd_output) = commands.getstatusoutput("uname -r| grep uek")
  if uek_status == 0:
    uek_major = cur_kernel.split(".")[0]
    uek_version='.'.join(cur_kernel.split(".")[0:2])
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

#####OS & PKG DECLARATIONS#####

def os_pkg_declaration():
  global hostname,cur_kernel,os_version,majversion,minversion
  global peo_repo_name,src_root_path,peo_backup_path,yum_repo_path,repos_backup_path,tmp_path
  global min_boot_space
  global grub_conf_file,grubenv_file
  hostname = platform.node().split('.')[0].strip()
  cur_kernel = os.uname()[2]
  os_version = platform.linux_distribution()[1]
  majversion = platform.linux_distribution()[1].split('.')[0].strip()
  minversion = platform.linux_distribution()[1].split('.')[1].strip()
  peo_repo_name = "peo_update.repo"
  src_root_path = "/root"
  peo_backup_path = "/root/backup"
  yum_repo_path = "/etc/yum.repos.d"
  repos_backup_path = "/etc/yum.repos.d/old_repo"
  tmp_path = "/tmp"
  min_boot_space = 60   ####MENTION THE MIN BOOT SPACE IN MB'S
  if int(majversion) == 6:
    boot_file_exist = os.path.isfile("/boot/grub/grub.conf")
    if boot_file_exist == False:
      efi_dir_exist = os.path.isdir("/sys/firmware/efi")
      if efi_dir_exist == True:
        grub_conf_file = "/boot/efi/EFI/redhat/grub.conf"
    else:
      grub_conf_file = "/boot/grub/grub.conf"

  if int(majversion) >= 7:
    boot_file_exist = os.path.isfile("/boot/grub2/grub.cfg")
    if boot_file_exist == False:
      efi_dir_exist = os.path.isdir("/sys/firmware/efi")
      if efi_dir_exist == True:
        grub_conf_file = "/boot/efi/EFI/redhat/grub.cfg"
        grubenv_file = "/boot/efi/EFI/redhat/grubenv"
    else:
      grub_conf_file = "/boot/grub2/grub.cfg"
      grubenv_file = "/boot/grub2/grubenv"


###MAIN FUNCTION###

def main():
  os_pkg_declaration()
  determine_uek_kernel()
  createlogfile()
  if int(majversion) > 5:
    data_from_json()    ####EXCEPT CANARY, REMAINING ARE READ FROM JSON
    clear_version_list() ##EXECUTES ONLY ON FORCE FIX NOT ON CANARY 
    fix_microcode()  ##EXECUTES ONLY ON FORCE FIX NOT ON CANARY
    repo_backup()   ##EXCEPT CANARY. PROXY FIX APPLIED DURING FORCEFIX 
    create_peo_repo() ##EXCEPT CANARY
    fix_repos()      ##EXECUTES FOR OS>7 DURING FORCEFIX
    if not values.canary:
      conf_backup("/root/peo_update.repo",yum_repo_path) ##EXCEPT CANARY
    rpm_yum_check()  ##EXECUTES FOR ALL
    fix_update_qemu_libvirt() ##EXECUTES FOR OS>7 DURING FORCEFIX
    fix_removal_pkg() ##EXECUTES ON FORCEFIX BUT NOT ON CANARY
    conf_backup(grub_conf_file,tmp_path) ##EXECUTES FOR ALL
    fix_glibc_pkgkit()  ##EXCEPT CANARY, EXECUTES ON FORCEFIX AND OS > 7
    search_entry("/etc/login.defs","SYS_GID_MIN|SYS_GID_MAX") ##EXCEPT CANARY EXECUTES ON FORCEFIX
    yum_process_status()  ###EXECUTES FOR ALL
    file_system_check("/boot") ##EXECUTES FOR ALL
    fix_boot_space_clearance() ##EXCEPT CANARY, EXECUTES ON FORCEFIX
    update_ksplice() ##EXCEPT CANARY, EXECUTES > UEK3
    kernel_pkg_install() ##EXECUTES FOR ALL
    validation() ##EXECUTES FOR ALL
    bug_fixes()  ##EXECUTES ON FORCEFIX EXCEPT CANARY
    retry_block() ##EXECUTES ON SECURITY PATCH EXCEPT CANARY
    initrd_validation() ##EXECUTES FOR ALL
    set_default_grub()  ##EXECUTES ON FORCEFIX EXCEPT CANARY
    optional_pkg_install() 
    repo_restore() ##EXECUTES EXCEPT CANARY
    restore_glibc_pkgkit() ##EXECUTES EXCEPT CANARY
    #optional_pkg_install() ##EXECUTES EXCEPT CANARY
    set_file_permission("/usr/sbin/chroot","4755") ##EXECITES ON FORCEFIX EXCEPT CANARY
    remove_file("/etc/system-fips") ##EXECUTES ON FORCEFIX EXCEPT CANARY
    write_status_to_file() 
    output_to_csv()
    output_to_central()
    central_csv()
    dump_to_db()
  else:
    print ("THIS VERSION OF OL IS NOT SUPPORTED.EXITING THE SCRIPT")
    sys.exit(1) 

####DOWNLOAD THE JSON FILE###

def download_json(filename):
  json_url = "https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/"+filename
  json_file_present =  os.path.isfile("/var/tmp/%s"%(filename))
  if json_file_present == True:
     delete_json = commands.getoutput("rm -rf /var/tmp/%s"%(filename))
  try:
    (status_download,down_json) = commands.getstatusoutput("wget --no-proxy --no-check-certificate -O /var/tmp/%s  %s"%(filename,json_url))
    if status_download != 0:
      print ("EXITING THE SCRIPT AS JSONFILE IS UNABLE TO DOWNLOAD")
      sys.exit(1)
  except:
    print ("EXITING THE SCRIPT AS JSON FILE URL IS UNABLE TO ACCESS")
    sys.exit(1)

##CHECKSUM VERIFICATION FOR THE SCRIPT TO PROCEED

def verify_check_sum():
  checksum_file = "/var/tmp/olchecksum"
  checksum_url = "https://pds-chef-dr-infrastructure.us.oracle.com/dis_chef_repo/security/olchecksum"
  absolute_path_file = os.path.abspath(__file__)
  gen_checksum = commands.getoutput("md5sum "+absolute_path_file)
  result_checksum = gen_checksum.split(' ')[0].strip()
  check_sum_present = os.path.isfile(checksum_file)
  if check_sum_present == True:
    delete_checksum = commands.getoutput("rm -rf "+checksum_file)
  try:
    (status_download,down_checksum) = commands.getstatusoutput("wget --no-proxy --no-check-certificate -O %s %s "%(checksum_file,checksum_url))
    if status_download == 0:
      view_checksum = commands.getoutput("cat "+checksum_file)
      res_view = view_checksum.split(' ')[0].strip()
      if res_view == result_checksum:
        delete_checksum = commands.getoutput("rm -rf "+checksum_file)
      else:
        delete_checksum = commands.getoutput("rm -rf "+checksum_file)
        print ("EXITING THE SCRIPT AS THE CHECKSUM IS INVALID")
        sys.exit(1)
    else:
       delete_checksum = commands.getoutput("rm -rf "+checksum_file)
       print ("EXITING THE SCRIPT AS CHECK SUM IS UNABLE TO DOWNLOAD")
       sys.exit(1)
  except:
     print ("EXITING THE SCRIPT AS CHECK SUM URL IS UNABLE TO ACCESS")
     sys.exit(1)


###MAIN EXECUTION###

if __name__ == '__main__':

  global selection,patch_type,bug_fix_select,json_file 
  #verify_check_sum()

###PATCH SELECTION###
  if values.quarterly:
    selection = "QUARTERLY PATCH"
    download_json("quarterly_patch.json")
    json_file = "/var/tmp/quarterly_patch.json"
  elif values.monthly:
    selection = "MONTHLY PATCH"
    download_json("monthly_patch.json")
    json_file = "/var/tmp/monthly_patch.json"
  elif values.canary:
    selection = "EXISTING REPO USED"
    json_file = "NA"
  elif values.jsonfile:
    selection = "CUSTOM JSON FILE INPUT"
    json_file = values.jsonfile
  else:
    print ("SELECTION OF TYPE OF PATCH NOT SPECIFIED.EXITING THE SCRIPT")
    sys.exit(1)

###TYPE OF PATCH SELECTION###
  if values.security:
    patch_type = "SECURITY FIX"
  elif values.upgrade:
    patch_type = "FULL UPGRADE"
  else:
    print ("SELECTION OF PATCH TYPE IS NOT SPECIFIED.EXITING THE SCRIPT")
    sys.exit(1)

###SELECTION TO APPLY THE BUG FIX###
  if values.fix:
    bug_fix_select = "YES"
  else:
    bug_fix_select = "NO"

###CHECK FOR TYPE FOR OS AND HARDWARE###
  ostype = platform.system()
  architecture = platform.processor()
  linux_dist = platform.linux_distribution()[0]
  if ostype == "Linux":  
    ###VALIDATION OF EXA HOSTS
    (imageinfo_status,imageinfo_output) = commands.getstatusoutput("imageinfo")
    if not imageinfo_status:
      sys.exit("EXITING SINCE IT IS A EXA HOST")

    if architecture == "x86_64" or architecture == "i686" or architecture == "i386":
      if linux_dist == "Oracle Linux Server":
        main()
      elif linux_dist == "Oracle VM server":
        print ("THIS SCRIPT IS FOR ORACLE LINUX SERVER 6,7&8 PATCHING ONLY. SCRIPT IS NOT APPLICABLE FOR "+linux_dist+". EXITING THE SCRIPT")
        sys.exit(1)
      elif os.path.isfile("/etc/oracle-release"):
          main()
      else:
        print ("THIS SCRIPT IS FOR ORACLE LINUX SERVER 6,7&8 PATCHING ONLY. SCRIPT IS NOT APPLICABLE FOR "+linux_dist+". EXITING THE SCRIPT")
        sys.exit(1)
    else:
      print ("%s ARCHITECTURE IS NOT SUPPORTED FOR PATCHING.EXITING THE SCRIPT"%(architecture))
      sys.exit(1)
    
  elif ostype == "Windows":
    print ("SELECTED PATCH SCRIPT IS NOT APPLICABLE FOR WINDOWS. EXITING THE SCRIPT")
    sys.exit(1)
  else:
    print ("SELECTED PATCH SCRIPT IS NOT APPLICABLE FOR %s. EXITING THE SCRIPT"%(ostype))
    sys.exit(1) 
