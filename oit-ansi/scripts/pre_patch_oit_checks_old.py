#!/usr/bin/python
# Author : Srinivas Gadi
# Purpose : OIT Patching pre installation

import os
import sys
import getpass
import platform
import socket
import commands
import logging
import time
from collections import OrderedDict
# import argparse
import socket

# hostname = socket.gethostname()
# current_time = time.strftime('%d%m%Y_%H%m%S')
CURRENT_TIME = time.strftime('%Y%m%d_%H%m%S')

access_url="http://pd-yum-slc-01.us.oracle.com/data_files/oit/scripts"

def identity():
    if getpass.getuser() == 'root' or not os.getuid():
        logging.info('Executing with privileges')
        return True
    else:
        logging.error('Script must be executed with escalated privileges')
        return False

def kill_older_precheck_process():
    logging.info('Killing old proces')
    
    old_process_exists="ps -e -o 'pid,etimes,command' | awk '{if($2>7200) print $0}' | grep pre_patch_oit_checks"
    old_process,_= commands.getstatusoutput(old_process_exists)

    if old_process == 0:
       kill_old_process="ps -e -o 'pid,etimes,command' | awk '{if($2>7200) print $0}' | grep pre_patch_oit_checks | awk '{print $1}' | xargs kill -9"
       os.popen(kill_old_process)
    else:
      pass 

class LinuxCommands:

    # version returns the OL number like 6,7 or 8
    Version = eval(platform.dist()[1].split('.')[0])

    def execute(self, cmd):
        try:
            output = os.popen(cmd).read().strip()
            logging.info('%s => %s' % (cmd, output))
            return output
        except:
            logging.error('%s : %s =>  %s' % (socket.getfqdn(), cmd, sys.exc_info()[0]))
            return 'Error'

def reinstall_oracle_release_if_not_exists():
    logging.info('Checking /etc/oracle-release')
    # Reinstall oracle-release module if /etc/oracle-release does not exists

    if not os.path.exists('/etc/oracle-release'):
        logging.info('FILE: /etc/oracle-release does not exists, installing...')
        # print('FILE: /etc/oracle-release does not exists, installing...')

        # There two types of packages 1) oracle-release 2) oraclelinux-release, check both if one of them does not exits
        status, output = commands.getstatusoutput('rpm -qa | grep oracle-release')

        if status:
            status, output = commands.getstatusoutput('rpm -qa | grep oraclelinux-release | grep -v notes')
        

        if not status:
            logging.info('Reinstalling the %s' %output)
            # print('Reinstalling  %s' %output)
            cmd='yum reinstall %s -y' %output.strip()
            logging.info(cmd)

            status, output = commands.getstatusoutput(cmd)
            logging.info(output)

            #if Installed successfully return TRUE
            if not status:
                logging.info('Re installed %s' %output)
                return "ReInstalled"
                
            else:
                logging.error('Failed to install %s package' %output)
                return "FailedToInstalled"
                # print('Failed to install %s package' %output)
        else:
            logging.error('"oracle-release" pkg not found, trying to install')
            # print('"oracle-release" pkg not found, trying to install')
            status, output = commands.getstatusoutput('yum install oracle-release oraclelinux-release -y')
            #print(output)

            if not status:
                logging.info('Re installed %s' %output)
                return "ReInstalled"
                # print('OK')
            else:
                logging.error('Failed to install %s package' %output)
                return "FailedToInstalled"
                # print('Failed to install %s package' %output)
    else:
        logging.info('Exists: /etc/oracle-release')
        return "Exists"
        # logging.info('Exists : /etc/oracle-release')

class PreChecksPhysicalHost:
    """This class cover only specific Physical(OVM/DOM0) checks"""

    def physical_hosts_hardware_failures(self):
        """While execute this command, if there are any errors, it should show"""
        hardware_failures = {}
        hardware_info = OrderedDict()
        cmds = OrderedDict()

        cmds = OrderedDict([
               ('HardwareModel' , 'dmidecode -s system-product-name | tail -1'),
               ('IlomVersion' , "dmidecode -s bios-version|grep -v '^#'"),
               ('BiosVersion' , "ipmitool sunoem cli version|grep 'SP firmware 4'|awk '{print $NF}'")
               ])
               
        
        HardWareFailures = 'ipmitool sunoem cli "show faulty"'
        status, result = commands.getstatusoutput(HardWareFailures)
        if status != 0 and result :
           logging.info('Hardware faults found.')
           hardware_info['HardWareFailures']= 'FAIL'
        elif result:
            logging.info('%s : %s' %(HardWareFailures,result))
            hardware_info['HardWareFailures'] = 'OK'

        try:
            for cmd_type, cmd in cmds.items():
               status, result = commands.getstatusoutput(cmd)
               if status != 0 :
                  logging.info('Hardware faults found.')
                  hardware_info[cmd_type]= 'FAIL'
               elif result:
                   logging.info('%s : %s' %(cmd_type,result))
                   hardware_info[cmd_type] = result.strip()
               else:
                  logging.error(result)
                  hardware_info[cmd_type] = 'NA'

        except:
            logging.error("%s => %s" % (cmd, sys.exc_info()[0]))
            hardware_info[cmd_type] = 'FAIL'

        # Passing the headers and results in different list to record in file
        for cmd_type, state in hardware_info.items():
            record_results([cmd_type], [state])

        return hardware_failures

class PreCleanUp:
      def __init__(self):
          
          #Download boot space clener script

          #cmd_boot_space_cleaner_url="http://pd-yum-slc-01.us.oracle.com/data_files/oit/scripts/bootSpace_clear.py"
          cmd_boot_space_cleaner_url="%s/bootSpace_clear.py" %access_url
          logging.info('Downloading %s' %cmd_boot_space_cleaner_url)

          #download the script
          cmd_boot_cleaner="wget -O /tmp/bootSpace_clear.py %s" %cmd_boot_space_cleaner_url

          (state,res) = commands.getstatusoutput(cmd_boot_cleaner)
          if state != 0:
             #Executing with no-proxy tag
             cmd_boot_cleaner="cd /tmp;wget -O /tmp/bootSpace_clear.py --no-proxy --no-check-certificate %s;chmod +x /tmp/bootSpace_clear.py" %cmd_boot_space_cleaner_url
             (state,res) = commands.getstatusoutput(cmd_boot_cleaner)


      def remove_root_log_files(self):
          logs = ["/var/log/messages-2020*", 
                  "/var/cache/yum*"]

          for log in logs:
              os.popen('rm -rf %s' %log).read()

      def remove_tmp_fies(self):
          logging.info('Removed /tmp files more than 15 days')
          rm_older_15days_tmp_files = "find /tmp -mtime +15 -exec rm -rf {} \;"
          clean_cmd = commands.getoutput(rm_older_15days_tmp_files)

      
      def remove_older_kernels(self, stay):
          if os.path.exists('/tmp/bootSpace_clear.py'):
             (state,res) = commands.getstatusoutput('/tmp/bootSpace_clear.py -kc %s' %stay)
             if not state:
                logging.info('Removed older than %s kernels' %stay)
                logging.info('Kernel removals logs stores here : /tmp/kernel_cleanup.log')
                return True
                
             else:
                logging.error('Failed Boot CleanUp : %s ' %res)
                return 'FailedBootCleanUp'
          
          else:
             print('Missing bootSpace_clear.py')

class PreChecksVM:
    """ This block cover only VM related checks"""

    def is_rootfs_readonly(self):
        """ root(/) must not be in readonly mode"""
        cmd = 'cd /;touch tmp_file.txt'
        result = LinuxCommands().execute(cmd)
        # result = os.popen(cmd).read().strip()

        if 'Read-only' in result or 'cannot' in result:
            return 'ReadOnly'
        else:
            return 'OK'

    def disk_stat(self, path):
        """Get the available space in MBs"""

        disk = os.statvfs(path)
        free = (disk.f_bavail * disk.f_frsize)/(1000*1000)
        # total = (disk.f_blocks * disk.f_frsize)*(1000*1000)
        # used = (disk.f_blocks - disk.f_bfree) * disk.f_frsize
        UsedPercent = (disk.f_blocks - disk.f_bfree) * 100 / (disk.f_blocks - disk.f_bfree + disk.f_bavail) + 1

        return free, UsedPercent

    def ping(self, hostnames):
        """ this function returns 'true' if host is reachable otherwise 'false' """

        if isinstance(hostnames, str):
            hostnames = list(hostnames)

        catch_not_reachable_hosts = []

        for hostname in hostnames:
            ping_host = "ping -c 1 %s >/dev/null" % hostname
            response = os.system(ping_host)

            if response:
                catch_not_reachable_hosts.append("%s" %hostname)

        if len(catch_not_reachable_hosts):
            return catch_not_reachable_hosts
        else:
            return 'OK'


    def not_reachable_fstab_mounts(self):
        """ Get the all fstab NFS mount entries and check whether all NFS servers are reachable and return if there is any issue"""

        fstab_mounts = "cat /etc/fstab | grep -v ^# | grep ':'  | awk -F':' '{print $1}' | sort | uniq"
        # fstab_nfs_entries = os.popen(fstab_mounts).read().strip()
        fstab_nfs_entries = LinuxCommands().execute(fstab_mounts)

        if fstab_nfs_entries:
            return self.ping(fstab_nfs_entries.split('\n'))
        else:
            return 'OK'

    def find_kernel(self):
        return platform.uname()[2]

    # def yum_hosts_reachability(self):
    #     """ EIS hosts have the following YUMs
    #     http://eis-adc-yum-mirrorlist.us.oracle.com/
    #     http://eis-ucf-yum-mirrorlist.us.oracle.com/
    #
    #     GIT YUM hosts:
    #
    #     """
    #     yum_hosts = ['eis-adc-yum-mirrorlist.us.oracle.com',
    #                  'eis-ucf-yum-mirrorlist.us.oracle.com'
    #                 ]
    #
    #     return self.ping(yum_hosts)

    def fix_rpm_db_issue(self):
        logging.info('Fixing RPM DB issues')
        '''
            ==========
            cd /var/lib
            tar -zcvf /var/preserve/rpmdb-$(date +%Y-%m-%d_%H-%M-%S).tar.gz rpm
            cd /var/lib/rpm
            rm -f  __db*
            /usr/lib/rpm/rpmdb_verify Packages
            echo $?
            rpm -vv --rebuilddb
            cd /var/lib/rpm
            /usr/lib/rpm/rpmdb_verify Packages
            echo $?
        '''
        cmds=[  'cd /var/lib;tar -zcvf /var/preserve/rpmdb-$(date +%Y-%m-%d_%H-%M-%S).tar.gz rpm',
                'cd /var/lib/rpm;rm -f  __db*',
                'cd /var/lib/rpm;/usr/lib/rpm/rpmdb_verify Packages',
                'cd /var/lib/rpm;rpm -vv --rebuilddb',
                'cd /var/lib/rpm;/usr/lib/rpm/rpmdb_verify Packages',
            ]

        for cmd in cmds:
            logging.info("Executing %s " %cmd)
            status, result = commands.getstatusoutput(cmd)
            logging.info("state : %s" %status)
            # print("result %s" %result)
            if not status:
                pass
            else:
                return 'FAIL'
        logging.info('Fixed RPMDB issue.')
        return 'Fixed'


    def rpmdb_status(self):
        '''Check RPM Db status'''
        cmd_rpm = 'timeout 10 rpm -qa'
        status, result = commands.getstatusoutput(cmd_rpm)
        if status:
            rpm_db_state = self.fix_rpm_db_issue()
            # print("rpm_db_state %s" %rpm_db_state)
            return rpm_db_state
            # return 'FAIL'
        else:
            return 'OK'

    def root_space_checker(self):
        freeSpaceInMB,  Usedpert = self.disk_stat('/')
        if Usedpert > '95' or freeSpaceInMB < 1000 :
            RootFSState = 'FAIL(%sM)' %Usedpert
        else:
            RootFSState = 'OK'
        return RootFSState

    def boot_space_checker(self):
        logging.info('Checking boot space')

        boot_threshold=100
        avbl_boot_space, _ = self.disk_stat('/boot')
        if avbl_boot_space > boot_threshold:
            logging.info('OK')
            return 'OK'
        else:
            logging.error('Low boot space %s/%s' %(avbl_boot_space,boot_threshold))
            return 'FAIL(%sM)' %avbl_boot_space

    def tmp_space_checker(self):
        tmp_threshold=1000
        avbl_tmp_space, _ = self.disk_stat('/tmp')
        if avbl_tmp_space > tmp_threshold:
           tmp_space = 'OK'
           logging.info('OK')
        else:
            tmp_space = 'FAIL(%sM)' %avbl_tmp_space
            logging.error('Low /tmp space %s' %avbl_tmp_space)   
        return tmp_space

    def get_uek(self):
        #cmd='wget -O /tmp/get_host_uek.py  http://pd-yum-slc-01.us.oracle.com/data_files/oit/scripts/get_host_uek.py;python /tmp/get_host_uek.py'
        #cmd='curl http://pd-yum-slc-01.us.oracle.com/data_files/oit/scripts/get_host_uek.py | python'
        cmd='curl --silent %s/get_host_uek.py | python' %access_url
        cmd_noproy='wget -O /tmp/get_host_uek.py  --no-proxy --no-check-certificate %s/get_host_uek.py;python /tmp/get_host_uek.py' %access_url

        (uek_status,uek_output) = commands.getstatusoutput(cmd)
  
        if uek_status == 0:
           return uek_output
        else:
           (uek_status,uek_output) = commands.getstatusoutput(cmd_noproy)
           if uek_status == 0:
              return uek_output
           else:
              return 'FAIL'

    def run_all(self):
        # headers = ['RootFS', '/var', '/boot', 'RootFsRO', 'Kernel', 'YumHostsReachable', 'HardMounts', 'fstabMounts']

        # Initating the pre cleanup class
        pc = PreCleanUp()

        # validating the root  space
        RootFSState = self.root_space_checker()
        if RootFSState != 'OK':
          pc.remove_root_log_files()
        RootFSState = self.root_space_checker()

        #validating the boot space, if its below threshold it would cleanup older kernels one by one and check the space till 2
        #os.popen('rm -rf /tmp/bootSpace_clear.py').read()
        boot_space=self.boot_space_checker()
        
        logging.info('Low boot space')

        for stay_number in [3 ,2]:
            if boot_space != 'OK':
               print('stay_number : %s' %stay_number)
               logging.info('Removing older %s kernels' %stay_number)
               state = pc.remove_older_kernels(stay_number)
               if state:
                   print('Checking /boot space agina.')
                   boot_space=self.boot_space_checker()
            else:
              break            

        #validating the /tmp space
        logging.info('Checking /tmp space')
        tmp_space = self.tmp_space_checker()

        if tmp_space != 'OK':
           pc.remove_tmp_fies()

        tmp_space = self.tmp_space_checker()

        #FIXIT:
        '''need to fix yum host reachablility'''

        headers = ['RootFS', '/boot','/tmp', 'isRootFsRO','rpmdb', 'Kernel', 'fstabMounts','UEK']
        output = [

            RootFSState,
            # self.disk_stat('/var'),
            boot_space,
            tmp_space,
            self.is_rootfs_readonly(),
            self.rpmdb_status(),
            self.find_kernel(),
            # self.yum_hosts_reachability(),
            # 'OK',
            # self.not_reachable_hard_mounts(),
            self.not_reachable_fstab_mounts(),
            self.get_uek()
        ]

        # print(record_results(headers, output))
        record_results(headers, output)

        return dict(zip(headers, output))



def record_results(headers, results):
    file_writer = open(OUTPUT_FILE,'a')
    for cmd, result in zip(headers, results):
        file_writer.write("'%s' : '%s'\n" %(cmd, result))
    file_writer.close()

def display_records():

    file_reader = open(OUTPUT_FILE, 'r' )
    data = file_reader.readlines()
    data_k = []
    data_v = []
    for k in data:
        data_k.append(k.split(':')[0].strip())
        data_v.append(k.split(':')[1].strip())
    print(','.join(data_k))
    print(','.join(data_v))
       

def get_host_type():
    status, result = commands.getstatusoutput('imageinfo')
    if not status:
        sys.exit('EXIT: Its Exa host')

    status, result = commands.getstatusoutput('cat /etc/*release')
    if 'Oracle VM server release' in result or 'Oracle VM Server release' in result:
           return 'DOM0'
    elif 'Oracle Linux Server release'  in result or 'Oracle Linux Server'  in result:
           return 'DOMU'
    elif 'Solaris' in result:
          sys.exit('Its a Solaris host')

    linux_dist = platform.linux_distribution()[0]
    if linux_dist == "Oracle Linux Server":
        return 'DOMU'
    elif linux_dist == 'Oracle VM server':
        return 'DOM0'
    else:
        sys.exit('EXIT: its a %s host' %result)

def get_os_version():
    return eval(platform.dist()[1].split('.')[0])

def get_region_ip():
    '''
        if below is not the case to identify the host name
        have to refer the docs for hostname standard to get the region
        https://confluence.oraclecorp.com/confluence/display/OITSRVOPS/EIS+Hostname+Standard
    '''
    #status, result = commands.getstatusoutput('cat /etc/asset/asset.properties  | grep -i datacen | egrep -i "adc|11400NOR"')

    #return the IP respective of host region

    if os.path.exists('/etc/asset/asset.properties'):
        assert_file = open('/etc/asset/asset.properties', "r").read()
        if 'adc' in assert_file or '11400NOR' in assert_file:
            return 'adc', '140.84.158.136'
        else:
            return 'ucf', '152.69.76.67'
    else:
        if platform.uname()[1][0].startswith('a'):
            return '140.84.158.136'
        else:
            return '152.69.76.67'

def get_cache_dir():

    #check the space in /var/ and /tmp, if space is more than 1.5G then it will return respective dir for cache dir

    #Clearining the var cache befire it install
    os.popen('rm -rf /var/cache/yum').read()

    THRESHOLD = 1000

    pchk = PreChecksVM()
    var_tmp_size, _ = pchk.disk_stat('/var/tmp')
    var_size, _ = pchk.disk_stat('/tmp')

    if var_tmp_size > THRESHOLD:
        location = '/var/tmp'
    elif var_size > THRESHOLD:
        location =  '/tmp'
    else:
        logging.error('There is low (<1.GG) space either of /tmp or /var/tmp')
        sys.exit('EXIT : There is low (<1.GG) space either of /tmp or /var/tmp')

    return location

def setup_dis_git_repo(get_host_types):
    clean_cmd = commands.getoutput("yum clean all")
    # cleanup the cache
    # _,_ = commands.getstatusoutput('yum clean all')
    logging.info('Setting up DIS/GIT repo')
    # yum_download_dir='/etc/yum.repos.d'

    # YUM config file created here
    yum_download_dir = '/tmp'

    host_type = get_host_types

    if host_type == 'DOMU':

        logging.info('Its a DOMU')
        majversion = platform.linux_distribution()[1].split('.')[0].strip()
#        yum_repo_file="/root/eng_ol%s.repo" %majversion
  
        yum_repo_file='dis_ol%s.repo' %majversion

        #yum_repo_file = 'dis_ol%s.repo' % get_os_version()
        repo_file_conf = '%s/%s' % (yum_download_dir, yum_repo_file)
        repo_name = 'DIS_OL%s' % get_os_version()

        logging.info('Downloading NON-EIS repo')
        #download_repo = 'wget -O /tmp/generate_vm_repo.py http://pd-yum-slc-01.us.oracle.com/data_files/oit/scripts/repos/generate_vm_repo.py;chmod +x /tmp/generate_vm_repo.py;/tmp/generate_vm_repo.py'
        download_repo = 'curl %s/repos/generate_vm_repo.py | python' %access_url
        status, result = commands.getstatusoutput(download_repo)

        if status != 0:
           download_repo = 'wget -O /tmp/generate_vm_repo.py --no-proxy --no-check-certificate %s/repos/generate_vm_repo.py;chmod +x /tmp/generate_vm_repo.py;/tmp/generate_vm_repo.py' %access_url
           status, result = commands.getstatusoutput(download_repo)

           if status:
              logging.error('EXITING : Failed to download the repo : %s' %download_repo)
              sys.exit('EXITING : Failed to download the repo')
        logging.info(result)

    elif host_type == 'DOM0':
        logging.info('Its a DOM0')
        yum_repo_file = 'dis_ovm34.repo'
        repo_file_conf = '%s/dis_ovm34.repo' % yum_download_dir
        repo_name = 'DIS_OVM34'

        logging.info('Downloading DOM0 NON-EIS repo')
        #download_repo = 'wget --quiet http://pd-yum-slc-01.us.oracle.com/data_files/oit/scripts/repos/%s -O  %s' % (
        download_repo = 'wget %s/repos/%s -O  %s' % ( access_url, yum_repo_file, repo_file_conf)
        status, result = commands.getstatusoutput(download_repo)

        if status:
           logging.error('EXITING : Failed to download the repo : %s' %download_repo)
           logging.info(result)
           sys.exit('EXITING : Failed to download the repo')

    else:
        logging.error('Failed to identify the whether host is DOM0/DOMU')
        sys.exit('Failed to identify the whether host is DOM0/DOMU')

    # read input file
    fin = open(repo_file_conf, "r")
    # read file contents to string
    data = fin.read()
    # replace all occurrences of the required string
    # data = data.replace('region', get_region_ip())
    data = data.replace('cachedirloc', get_cache_dir())

    # close the input file
    fin.close()
    # open the input file in write mode
    fin = open(repo_file_conf, "w")
    # overrite the input file with the resulting data
    fin.write(data)
    # close the file
    fin.close()

    # _, _ = commands.getstatusoutput('yum clean all')
    logging.info('%s setup completed' % repo_file_conf)
    yum_dry_run(repo_file_conf, repo_name)


def filter_yum_log(YUM_LOG):

    # read input file
    fin = open(YUM_LOG, "r")
    # read file contents to string
    data = fin.readlines()
    # replace all occurrences of the required string

    # close the input file
    fin.close()

    new_data=[]
    for line in data:
        if line.lstrip().startswith('Repository'):
            pass
        else:
            new_data.append(line)

    # open the input file in write mode
    fin = open(YUM_LOG, "w")
    # overrite the input file with the resulting data
    # for i in new_data:
    #     fin.write("%s\n" %i)
    fin.writelines(new_data)
    # close the file
    fin.close()

    return YUM_LOG

def yum_dry_run(repo_file_conf, repo_name):
    logging.info('YUM Dry run started.')
    YUM_LOG='/var/tmp/%s.yum_dryrun.%s.txt' %(socket.gethostname(), CURRENT_TIME)

    #cmd='yum update --assumeno -c %s  &> %s' %(repo_file_conf,YUM_LOG)
    cmd='yum --setopt=reposdir= update --assumeno -c %s  --skip-broken &> %s' %(repo_file_conf,YUM_LOG)

    logging.info(cmd)
    _, _ = commands.getstatusoutput(cmd)

    # filter YUM log, remove the lines which are starting with Repository
    YUM_LOG = filter_yum_log(YUM_LOG)

    result = open(YUM_LOG).readlines()
    result_str = open(YUM_LOG).read()

    logging.info('YUM transaction logs : %s' %YUM_LOG)

    if 'Transaction Summary\n' in result:
        # print("\nDry Run Successfull")
        record_results(['YumDrynRun'], ['OK'])
        logging.info('Dry run successful.')

        for line in result:

            if "Total download size:" in line.strip():
                # print(line.split(':')[1].strip())

                download_size = eval(line.strip().split(':')[1][:-1].strip())
                measure = line.strip().split(':')[1].strip()[-1]

                #convert the size to MBs to maintain the uniform
                if measure == 'k':
                    download_size = (download_size / 1000)
                elif measure == 'G':
                    download_size = (download_size * 1000)

                # print(download_size, measure)

                # print("----------------------")
                pchk = PreChecksVM()

                var_size, _ = pchk.disk_stat('/var')

                #compare the size of the download yum size and avilable var size

                if download_size > var_size:
                    logging.error('/var space is not sufficient for downloads')
                    record_results(['/var'], ['Low space to downloads pkgs (%s)' %var_size])
                else:
                    record_results(['/var'], ['OK'])

    elif "No Packages marked for Update\n" in result:
        record_results(['YumDrynRun'], ['NoPkgs'])
        logging.info('DRY RUN -> No Packages marked for Update')

    elif 'Multilib version problems found' in result_str:
        record_results(['YumDrynRun'], ['Failed-Multilib'])

    elif "conflicts" in result_str:
         record_results(['YumDrynRun'], ['Failed-Conflts'])

    else:
        logging.error('Dry run failed')
        record_results(['YumDrynRun'], ['Failed'])

        pchk = PreChecksVM()
        var_size, _ = pchk.disk_stat('/var')

        if var_size > 1500:
            record_results(['/var'], ['OK'])
        else:
            record_results(['/var'], ['FAIL(%sM)' %var_size])
            logging.error('Low /var space (%s)' %var_size)

if __name__ == '__main__':

    hostname = socket.gethostname()
    CURRENT_TIME = time.strftime('%Y%m%d_%H%m%S')


    LOGFILE = '/tmp/pre_patching_check_%s.log' % CURRENT_TIME
    OUTPUT_FILE = '/var/tmp/pre_%s_%s.log' % (hostname, CURRENT_TIME)

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s-%(levelname)s-%(message)s',
                        filename=LOGFILE)

    print('Logging here : %s' % LOGFILE)
    print('\n\tExecuting in the background, "tailf %s" the log for live status.' % LOGFILE)
    logging.info('Logging started.')

    if identity():
        if platform.system() != 'Linux':
            logging.error('This script works for Linux only')
            sys.exit('This script works for Linux only')
    else:
        logging.error('Must be executed with elevated privileges')
        sys.exit('EXIT: Must be executed with elevated privileges')

    # removed if pre check process is alreday running on target more than 2 hours
    kill_older_precheck_process()

    #Check and install "/etc/oracle-release" file
    ora_file_status = reinstall_oracle_release_if_not_exists()
    if ora_file_status == "FailedToInstalled": 
        record_results(['oracle-release'],['FailedToInstalled'])
        sys.exit("Failed To install /etc/oracle-release")
    else:
        record_results(['oracle-release'],[ora_file_status])

    # Creating the instance of an object
    PCPh = PreChecksPhysicalHost()
    PVMChk = PreChecksVM()
    get_host_types = get_host_type()

    #Get hostname
    record_results(['Hostname'], [socket.gethostname()])
    record_results(['Type'], [get_host_types])
    record_results(['OS'], [platform.dist()[1]])


    if get_host_types == 'DOM0':
        PCPh.physical_hosts_hardware_failures()
    else:
        record_results(['HWFailures'], ['N/A'])
        record_results(['HardwareModel'], ['N/A'])
        record_results(['IlomVersion'], ['N/A'])
        record_results(['BiosVersion'], ['N/A'])

    # Calling classes

    PVMChk.run_all()

    #Exit if its OL5.
    if (platform.dist()[1]).startswith('5'):
       logging.error('EXIT: its OL5')
#       sys.exit('\nEXIT: its OL5') 
    else:
        setup_dis_git_repo(get_host_types)

    display_records()
    logging.info('Execution results stored here  : %s' %OUTPUT_FILE)
    logging.info(' - - - - END - - - -')

