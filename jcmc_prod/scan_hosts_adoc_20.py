#!/usr/local/python3/bin/python3.6
# # -*- coding: utf-8 -*-
# from __future__ import unicode_literals
import argparse
import os
import time
import subprocess
import urllib.request
import sys
import platform
import getpass
import paramiko
import shutil
import multiprocessing as mp
import re

CURRENT_TIME=time.strftime('%d%m%Y_%H%m%S')
AuthFailed=[]


def write_to_db(PID, State, Host, Result):
    print('=>%s:%s updating to JCMate -> %s' %(PID, Host, Result))
    try:
        if isinstance(Result, str):
            Result = Result.replace('"',"'")

        print('%s --Pid %s --State "%s" --Hostname "%s" --Result "%s"' % (os.path.join(os.getcwd(), 'db_connector.py'),PID, State, Host, Result))
        print('===================\n')
        os.system('%s --Pid %s --State "%s" --Hostname "%s" --Result "%s"' % (
         os.path.join(os.getcwd(),'db_connector.py'),PID, State, Host, Result))
    except Exception as e:
        sys.exit('\tError: Failed to insert to DB due to %s' %e)

def check_host_alive(host):
    import subprocess
    """Use the ping utility to attempt to reach the host. We send 3 packets
    ('-c 3') and wait 3 milliseconds ('-W 3') for a response. The function
    returns the return code from the ping utility.
    if it returns other than 0, means that host might down
    """
    return_code = subprocess.call(['ping', '-w','5','-c', '5', host],
                           stdout=open(os.devnull, 'w'),
                           stderr=open(os.devnull, 'w'))


def check_port_22_open(host):
    f = os.system('nc -vzw5 %s 22' %host)
    if f == 0:
        return True
    else:
        return False

def execute_command_at_remote(host,command):
      ''' Execute the command on give host and return the results '''
      p = subprocess.Popen(['ssh','-q',host,command],stdout=subprocess.PIPE)
      res,err = p.communicate()
      res = str(res, 'utf-8').strip() if res else res
      err = str(res, 'utf-8').strip() if err else err
      return (res,err)

def default_fucns(target_fun,host,default):
    state = True
    if default:
        lv = check_host_alive(host)
        if lv:
            writeToFile('Hosts_down',[host])
            return

        um = getUserManagedHosts(host,state)
        if um:
            return
    target_fun(host,state)

def executeWithkeys(host, username, command, isFile, results,AuthType, PasswdValue):
    # print('%s;%s;%s;%s;%s;%s;%s' % (host, username, command, isFile, results,AuthType, PasswdValue))
    print('==> username = %s, AuthType = %s, PasswdValue = %s' % (username, AuthType, PasswdValue))

    # Initialize the remote connection
    ssh = paramiko.SSHClient()
    command_exe = command

    #splitting the given command into three parts a) source dir, command , and its arguments if there are any
    source_folder = os.path.dirname(command.split(' ')[0])
    file1 = os.path.basename(command.split(' ')[0])
    arguments = command.split(' ')[1:]
    localpath = '/tmp'

    #setting whether given authentication type is password or key authentication
    if AuthType == 'KeyType':
        keyvalue = PasswdValue
        pvalue = None
    else:
        keyvalue = None
        pvalue = PasswdValue

    state = False

    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # ssh.connect(host, username=username, key_filename=SSHKey,timeout=30)
        ssh.connect(host, username=username, key_filename=keyvalue, password=pvalue ,timeout=30)
        try:
            print('==>Login OK; Started executing on remote host %s.' %host)
            os_type_in, os_type_out, os_type_err = ssh.exec_command('uname')
            os_type_out = str(os_type_out.read(), 'utf-8').strip()
            os_type_err = str(os_type_err.read(), 'utf-8').strip()

            if os_type_out in ['Darwin', 'VMkernel']:
                writeToFile('NonLinuxHost', [f'{host} > {os_type_out} > IGNORE'])
                return True

            if os_type_err and not 'chdir' in os_type_err:
                write_to_db(PID, 'Error',host,'Unable to capture the error, try manually')
                # writeToFile('Misc_issues', [f'{host} > {os_type_err} > OSERROR'])
                return True

            if isFile:
                try:
                    ftp_client=ssh.open_sftp()
                    '''if its file, copy the file from remote host to local host'''
                    ftp_client.put(os.path.join(source_folder,file1),os.path.join(localpath,file1))
                    ftp_client.close()
                except Exception as e:
                    print(f'Error while copy the file to local host : {str(e)}')

                '''get the FUll path of file to execute'''
                command_exe = os.path.join(localpath, file1)
                ssh.exec_command(f'chmod +x {command_exe}')

                if command_exe.endswith('.py'):
                    FileType = 'python'
                elif  command_exe.endswith('.sh'):
                    FileType = 'sh'
                else:
                    FileType = ''

                # command_exe = f'{command_exe}'
                command_exe = "%s %s %s" %(FileType, command_exe, ' '.join(arguments))

            # if username in ['root','opc'] :
            if username  == 'root':
                print('\n\t=> with root  ==> %s' %command_exe)
                # print(f"{command_exe}")
                given_cmd_stdin, given_cmd_out, given_cmd_stderr = ssh.exec_command(f"{command_exe}")
            else:
                print(f'\n\t=> with {username}')
                given_cmd_stdin, given_cmd_out, given_cmd_stderr= ssh.exec_command(f"echo {pvalue} |sudo -S {command_exe}")

                print('given_cmd_stdin = %s, given_cmd_out = %s, given_cmd_stderr = %s' %(given_cmd_stdin, given_cmd_out, given_cmd_stderr))

            job_exit_status = given_cmd_out.channel.recv_exit_status()

            dataout = str(given_cmd_out.read(), 'utf-8').strip()
            dataerr = str(given_cmd_stderr.read(), 'utf-8').strip()

            print('================>dataout %s' %dataout)

            '''Slice the last 4 lines and remove any whitepsace and capture last two lines to get the accurate status '''
            short_res = list(map(lambda line: line.strip(), dataout.split('\n')))
            short_err = list(map(lambda line: line.strip(), dataerr.split('\n')))


            if job_exit_status:
                print('I am here')
                write_to_db(PID, 'Error', host, str(short_err[-1]))
                # writeToFile('Error', [f'{host} > {short_err[-1]}'])

                return True

            '''Converting the res from list to str '''

            if ('incident' in dataerr or 'sorry' in dataerr) and not dataout:
                writeToFile('NoSudoAccess', [f'{host} > {short_err}'])
                state = True

            elif 'Low_disk_space' in dataout:
                writeToFile('Low_disk_space', [f'{host} > {short_res}'])
                state = True

            elif 'firewall' in dataout:
                writeToFile('Behind_firewall', [f'{host} > {short_res}'])
                state = True

            elif 'ERROR:CMA Checks failed' in dataout:
                writeToFile('CMA_failures', [f'{host} > {short_res}'])
                state = True

            else:
                match_state = 0
                if REGEX_ITEM != 'None':
                    try:
                        for res in short_res:
                            if REGEX_ITEM == 'in':
                                if REGEX_VALUE in res:
                                    writeToFile('Success', [f'{host} > {res}'])
                                    match_state += 1
                                # else:
                                #     writeToFile('NoMatch', [f'{host} > '])
                            elif eval(f'res.{REGEX_ITEM}("{REGEX_VALUE}")'):
                                writeToFile('Success', [f'{host} > {res}'])
                                match_state += 1
                            # else:
                        if not match_state:
                            writeToFile('NoMatch', [f'{host} > '])
                        state = True
                    except Exception as e:
                        print(f'Error while filtering the data : {str(e)}')

                else:
                    '''Converting the res from list to str '''
                    try:
                        # short_res=short_res[0]
                        short_res = ' '.join(short_res[-last_tripped_lines:])
                        writeToFile('Success', [f'{host} > {short_res}'])
                    except Exception as e:
                        writeToFile('ERROR', [f'{host} > {str(e)}'])
                    state = True

        except Exception  as e:
            results.append('%s > %s : Internal error' % (host, str(e)))
            state = False

    except Exception as e:
        print('key ERROR : %s > %s' % (host, str(e)))
        if 'port 22 (tcp) timed out' in str(e):
            write_to_db(PID,'SSHFail',host,'Failed to login')
        # os.system("/scratch/srgadi/jcmate/db_connector.py --Pid %s --State '%s' --Hostname '%s' --Result '%s'" % (
        #     PID, 'Error', host, str(e)))

        results.append('%s > %s' % (host, str(e)))
        state = False
    ssh.close()
    return state

def oci_hosts_exeuction(host, username , password, command, isFile, results, keys):
    '''
    1) userLDAP/passwd if not,
    1) loginuser/passwd -> opc/key,
    2) execute the given command with SUDO by passing the passwd
    '''

    # print('\n=>1.OCI: Executing with %s=>%s' %(LDAP, password))
    # state = executeWithkeys(host, LDAP, command, isFile, results, 'Ptype', password)
    # if state:
    #     return

    users = ['opc','root']

    # Get the user and keys pairs and try login
    user_combinations = [ (user, key) for user in users for key in keys ]

    for default_user, key in user_combinations:
        print('\n=1.>OCI: Executing with %s -> %s' % (default_user, key))
        state = executeWithkeys(host, default_user, command, isFile, results, 'KeyType', key)

        if state:
            return

    print('\n=>2.OCI: Executing with %s=>%s' %(LDAP, password))
    state = executeWithkeys(host, LDAP, command, isFile, results, 'Ptype', password)
    if state:
        return

    if not state:
        write_to_db(PID,'AuthFailed',host,'Authentication failed.')


def manual_execution(host,username,passwords,command,isFile):

    # print('1. =====> passwords = %s' % passwords)

    # print(f'ALL password = {passwords}')
    state=True
    results = []
    '''checking whether the host is up'''
    isHostUp = check_host_alive(host)
    if isHostUp:
        writeToFile('Hosts_down',[host])
        write_to_db(PID, 'Hosts_down', host, 'Host not pingable')
        return

    if not check_port_22_open(host):
        write_to_db(PID, 'SSHFail', host, 'SSH(port 22) disabled.')
        return

    '''Key based Authentication loop'''
    keys = [ '/root/.ssh/id_rsa',
             '/root/.ssh/id_rsa_adc01lgu',
             '/root/.ssh/id_rsa_pdit-dis-engsys-adm1',
             '/root/.ssh/id_rsa_slciayu',
             '/root/.ssh/id_rsa_ucl']

    if host.endswith('oraclevcn.com'):
        # print('2. =====> passwords = %s' % passwords)
        oci_hosts_exeuction(host, username , passwords[-1], command, isFile, results, keys)
        return

    for key in keys:
        results = []
        # print('key  = %s' % key)
        state=executeWithkeys(host,'root', command,isFile,results,'KeyType', key)

        '''if it worked with keys, the state must be True and it out from further attempts'''
        if state:
            return
            # break

    '''Passwd based Authentication enabled'''


    for password in passwords[:-1]:
        # results = []
        # print(password)
        #if len(passwords) == cnt and len(passwords) >1:
        # if passwords[-1] == password:
        #    results = []
        #    state=executeWithkeys(host,username,command,isFile,results,'Ptype',password)
        # else:
        results = []
        state = executeWithkeys(host,'root',command,isFile,results,'Ptype',password)

        '''if it worked with keys, the state must be True and it out from further attempts'''
        if state:
            # break
            return
    # If none of the above options works, its finally login with given Ldap and passwd , switch to sudo and execute the commnads.
    state = executeWithkeys(host, username,  command, isFile, results, 'Ptype', passwords[-1])

    if not state:
        AuthFailed.extend(results)
        write_to_db(PID,'AuthFailed',host,'Authentication failed.')
        writeToFile('AuthFailed',results)
    return

def terminate_on_time(PID, processes,time_out):
    print('\n\tFetching the results , please be on hold.\n')
    while len(mp.active_children()):
        print(f'Pending tasks: {len(mp.active_children())}/{len(processes)}')
        time.sleep(3)
        completed_processes = []
        for process,start_time in processes.items():
            if not process.is_alive():
                completed_processes.append(process)

            if time.time() - start_time >  time_out:
                try:
                  if process.is_alive():
                     process.terminate()
                     time.sleep(0.2)
                     print(f'{process.name} --> TimeOut > Terminated. \n')
                     write_to_db(PID,'TimeOut', process.name, 'Terminated')
                     # os.system("/scratch/srgadi/jcmate/db_connector.py --Pid %s --State '%s' --Hostname '%s' --Result '%s'" % (
                     #     PID, 'TimeOut', process.name, 'Terminated'))

                except Exception as e:
                    print(f'Error: While killing the %s:%s {PID, process.name, str(e)}')

        if completed_processes:
            for completed_process in completed_processes:
                print(f'Removed completed process {completed_process.name}')
                del processes[completed_process]

def writeToFile(FileName,data):
    time.sleep(0.3)
    print('==>data %s' %data)

    '''TagName for consolidated report'''
    TagName=FileName

    ''' Ignore Misc issues added to Consolidated_data file'''
    if not FileName == 'Misc_issues_%s.log'%CURRENT_TIME:
        with open(LOGFILE,'a') as consol ,open('%s_final' %LOGFILE,'a') as final:

            for pattern in data:
                host_data = pattern.replace('>','Sri',1).split('Sri')
                if len(host_data) > 1:
                    host, cause = host_data

                    if cause.strip() == 'TimeOut' :
                        state = cause
                        cause = ''
                    else:
                        state = TagName
                else:
                    host = pattern
                    state = TagName
                    cause = ''
                    #=========
                try:
                    re1 = re.compile(r"[<>/{}[\]~]");
                    if re1.search(cause):
                        cause = cause
                        #fFIXIT: TO BUPASS THE ILLEGAL CHANRS

                except Exception as e:
                    print(f'==> ERROR while detecting illegar character : {str(e)}')

                consol.write('%s | %s | %s\n' % (state, host, cause))
                final.write('%s | %s | %s\n' % (state, host, cause))
                print('\n=>Writing to DB')
                try:
                    print ("/scratch/srgadi/jcmate/db_connector.py --Pid %s --State '%s' --Hostname '%s' --Result '%s'" % (PID, state, host, cause))
                    write_to_db((PID, state, host, cause))
                    # os.system("/scratch/srgadi/jcmate/db_connector.py --Pid %s --State '%s' --Hostname '%s' --Result '%s'" % (PID, state, host, cause))
                except Exception as e:
                    print('===>error %s' %e)
                    print('==> Results %s' %cause)
                    write_to_db(PID, state, host, cause)
                    # os.system("/scratch/srgadi/jcmate/db_connector.py --Pid %s --State '%s' --Hostname '%s' --Result '%s'" % (PID, state, host, 'Unable to capture the results.'))

    else:
        pass
    return


def get_number_of_lines(FileName):
    return sum(1 for line in open(FileName))

def FIXIT_WriteToCsv(FileName,Consolidated_data):
    CURRENT_TIME=time.strftime('%d%m%Y_%H%m%S')
    FileName='%s_%s.csv' %(FileName,CURRENT_TIME)

    import csv
    with open(FileName, 'w') as csvfile:
        fieldnames = ['HOSTNAME', 'STATE']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in Consolidated_data:
           try:
              host,state=row.split('>')
           except:
              host=row;state=''
           writer.writerow({'HOSTNAME':host,'STATE':state})

def main():

    global LOGFILE, REGEX_ITEM, REGEX_VALUE, LDAP, PID
    logfile = f'/tmp/Consolidated_data_{CURRENT_TIME}.csv'

    parser = argparse.ArgumentParser(description='JC client dependent pkg installation')
    parser.add_argument('-clients', '--clients', nargs='*', help='Provide the clients to install pkgs')
    parser.add_argument('-f','--file', type=argparse.FileType('r'),help='Provide the list of servers in a file')
    parser.add_argument('--Pid', action="store", help='Get the PID from DB to update the process execution details')
    parser.add_argument('--enable_passwords', action="store_true", help ='It will enable the older root passwords (inbuilt) login and execute.')
    parser.add_argument('--include_passwds', nargs='+', help = 'provide the multiple passwords with comma deliminator Ex: --enable_passwords --include_passwds "passwd1,passwd2, ...,passwdn"')
    parser.add_argument('--cmd', action="store", help ='pass the command to execute')
    parser.add_argument('--timeout', default=300, help ='wait timeout seconds to kill the process, default its 300s.')
    parser.add_argument('--skip_passwd', action="store_true", help ='bypass the prompting user password')
    parser.add_argument('--ldap', action="store", help='Furnish the LDAP to login and execute the script')
    parser.add_argument('--parse_passwd', help ='Parse the user password to assit with SUDO login.')
    parser.add_argument('--logfile', default=logfile, help ='You can pass log file as your choice else default logfile will be generated. ')
    parser.add_argument('--last_lines', default=1, help ='By default, it print last 2 lines of O/P,can be modified by addition number')
    parser.add_argument('--regex_item', default="None" , help='Indicate the regex what to filter')
    parser.add_argument('--regex_value', default="None" , help='regex value to filter')

    args = parser.parse_args()
    hosts_data= ''

    TIMEOUT=int(args.timeout)

    REGEX_ITEM = args.regex_item
    REGEX_VALUE = args.regex_value
    PID = args.Pid

    LOGFILE = args.logfile

    LDAP = args.ldap

    print('LogFile:',LOGFILE)

    if args.last_lines:
        global last_tripped_lines
        last_tripped_lines = int(args.last_lines)

    # temp file, will be removed end of this script
    with open(f'{LOGFILE}_monitor','w') as tmp:pass

    #Erasing the logfile if its already created
    with open(LOGFILE,'w') as log:pass

    if args.file:
      hosts = args.file.readlines()
      #Exclude console hosts if there are any
      hosts_data = set([ host.strip() for host in hosts if not '-c.' in host])

    if args.clients:
      hosts_data = args.clients

    threads_l = []
    process_data = {}
    total_hosts=len(set(filter(None,hosts_data)))

    command = args.cmd
    isFile=False

    #Check whether provided command is linux command or file
    if os.path.exists(command.split(' ')[0]):
        command=command
        isFile = True

    elif shutil.which(command.split(' ')[0]):
        command = command
    else:
        # sys.exit(f'\tERROR: {command} does exists.\n')
        pass

    # username=os.popen('logname').read().split()[0]
    username = 'root'

    '''include_passwds should accept the password with either comma or space '''
    passwords=['']
    if args.include_passwds:
        if not args.enable_passwords:
            file_name=os.path.basename(__file__)
            sys.exit(f'\t--enable_passwords tag mandatory with --include_passwds\n\tUSAGE:{file_name} --file <FILENAME> --manualexecute --enable_passwords --include_passwds passwd1,passwd2...passwdN --cmd <COMMAND/FILE>')

    if args.enable_passwords:
        '''Inbild older passwords'''
        passwords = ['HuNAb_Ku', '$hArk13$', 'welcome1', 'S41v1@n3', 'L0ck!tup', 'welecome123', '0pnW0r1d', 'D1s@P3&0', 'welcome', 'L@n_B$cK7', '$t33L3R$', '$h@rk13$', 'Ca8ra_Ka','r00t06','L@n_B$cK7','Sy7vi@n$_p','K@z^h1r0']

        if args.include_passwds:
            passwd = args.include_passwds
            if len(passwd) == 1 and ',' in passwd[0]:
                passwd = passwd[0].split(',')

            ''' Add external prov'''
            passwords.extend(passwd)

        '''remove duplicate password entries '''
        passwords=list(set(passwords))

        ''' which will insert empty element at beginning of the list to check for the Key based Authentication and current prod and dev passwords respectively '''
        passwords.insert(0, '')
        passwords.insert(1, 'I$@Be1L$_M')
        passwords.insert(2, 'S$1v!@nE_p')
    else:
        username = input('\nLogin as : ')

    ''' append the user password to list of password to try as final option'''
    if args.skip_passwd:
        passwd=''

    if not args.parse_passwd == 'None':
        passwd = args.parse_passwd
        #passwd  = getpass.getpass(f"\n{username}@password: ")
    else:
        passwd = False

    if passwd:
        passwords.append(passwd)
    else:
        print(f'No password, Hence skipping {username}\'s login.\n')
        username='root'
        time.sleep(1)
    print(f'\n\t--> "{command}" will be executed across and get the status.')
    time.sleep(1)

    for sno,host in enumerate(set(filter(None,hosts_data))):
        print('>%s/%s. Checking on %s' %(sno+1,total_hosts,host))
        p=mp.Process(target=manual_execution, args=(host,username,passwords,command,isFile))
        p.name=host
        process_data[p] = time.time()
        p.start()
    terminate_on_time(PID, process_data, TIMEOUT)

    for thrd in threads_l:
        thrd.join()

    print('\n')
    if len(hosts_data) > 1:
        print('\nHosts break-up, out of %s :' %(len(hosts_data)))

    consolidate_file=LOGFILE
    if os.path.exists(consolidate_file):
        consolidated_file_lines = get_number_of_lines(consolidate_file)

        '''consolidated_file_lines should have more then one entry to display on screen'''
        if consolidated_file_lines > 0:
           print(f'\n\t> {consolidate_file} : {consolidated_file_lines}')

if __name__ == '__main__':
   state = True
   main()
