#!/usr/bin/env python
import os
import sys
import paramiko
import argparse
import time

CURRENT_TIME = time.strftime('%Y%m%d_%H%m%S')

try:
   import commands
except:
   import subprocess as commands


def get_dom0(DOMU):
    #import pdb;pdb.set_trace()
    devops_url="/usr/bin/curl -s -L http://devops.oraclecorp.com/host/api/%s/data  | grep parent_fqdn| awk -F '=' '{print $2}'" %DOMU.split('.')[0]
    dom0=os.popen(devops_url).read().strip()
    #print(dom0)
    return dom0


def start_vm_in_parent(DOM0,DOMU,key,cmd):
    paramiko.util.log_to_file('/tmp/paramiko.log')
    ssh = paramiko.SSHClient()

    try:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(DOM0, username='root', key_filename=key,timeout=30)
        try:
            #print("SUCCESS : Logged in to %s" %DOM0)
            #print("> Executing cmd : %s" %cmd)
            #import pdb;pdb.set_trace() 
            #1.type1
            #cmd_1='ls /etc/xen/auto/%s;echo $? '%DOMU
            #print("command %s" %cmd)
            os_type_in, os_type_out1, os_type_err = ssh.exec_command(cmd)
            
            os_type_out1 = str(os_type_out1.read(), 'utf-8').strip()
            os_type_err = str(os_type_err.read(), 'utf-8').strip()
            #print('os_type_out1 = %s' %os_type_out1)

            if '\n' in os_type_out1:
               cmd_status=os_type_out1.split('\n')[1].strip()
               #print(" cmd_status = %s" %cmd_status) 

               if cmd_status == '0':
                  vm_start='xm create %s' %os_type_out1.split('\n')[0].strip()
                  #print('vm_start =%s' %vm_start)
                  os_type_in, os_type_out2, os_type_err = ssh.exec_command(vm_start)
                  os_type_out2 = str(os_type_out2.read(), 'utf-8').strip()
                  #print(">> os_type_out2 : %s" %os_type_out2)
                  #list_to_file(success_f,[DOMU])
                  result_logger(DOMU,'OK')

                  #print('os_type_out2 = %s' %os_type_out2)
              
            else:
             #type2:
             #cmd_2='/etc/xen/domU/domU_%s' %DOMU      
             return 'failed_t'
            return True

        except Exception  as e:
            #print('1.except %s' %e)
            result_logger(DOMU,e)
            return 'OtherErr'

        ssh.close()
    except Exception  as e:
#            print('%s->%s' %(e,DOM0),DOMU)
#            result_logger('%s->%s' %(e,DOM0),DOMU)
            return 'TimeOut'

def trigger_ssh(DOM0,DOMU):
    #making it to short
    DOMU=DOMU.split('.')[0]

    keys = [ '/root/.ssh/id_rsa',
             '/root/.ssh/id_rsa_adc01lgu',
             '/root/.ssh/id_rsa_pdit-dis-engsys-adm1',
             '/root/.ssh/id_rsa_slciayu',
             '/root/.ssh/id_rsa_ucl']

    for key in keys:
        results = []
        # print('key  = %s' % key)
        cmds=[
             'ls /etc/xen/auto/%s;echo $? '%DOMU,
             'ls /etc/xen/domU/domU_%s;echo $?' %DOMU,
             'ls /etc/xen/auto/domU_%s;echo $?' %DOMU
             ]
        for cmd in cmds:
            #print('CMD=%s' %cmd)
            state=start_vm_in_parent(DOM0,DOMU,key,cmd)
            #print('state = %s' %state)

            if state == 'OtherErr':
               return

            elif state == 'TimeOut':
               result_logger(DOMU,'DOM0:%s down' %DOM0)
               return

            elif state != 'failed_t':
               print('SUCCESS : %s started on %s' %(DOMU,DOM0))
#               list_to_file(success_f,[DOMU])               
               result_logger(DOMU,'OK')
               break   
        #state=executeWithkeys(host,'root', key)
         

        if state:
            result_logger(DOMU,'FailedTogetConfig on %s' %DOM0)
            return

#import pdb
#pdb.set_trace()
#parse_hosts =  sys.argv[1:]

#if parse_hosts :
#   DOMU=parse_hosts[0]
#else:
#   sys.exit('DOMU must provided following with scriptname')

#DOM0=get_dom0(DOMU)
#if DOM0 == 'None' or DOM0 == '':
#   sys.exit("\tERROR:Failed to find parent for '%s'" %DOMU)
#print('GOT DOM0 %s' %DOM0)
#trigger_ssh(DOM0,DOMU)


def list_to_file(FileName,lists):

    with open(FileName, 'a') as f:
        for lst in lists:
            f.write('%s\n' % lst)
    return FileName

def result_logger(host,data):
    FileName='/tmp/wakeupVms_%s.log' %CURRENT_TIME

    with open(FileName, 'a') as f:
         f.write('%s : %s\n' %(data,host.split()[0]))
    #return FileName

def check_if_vm_alive(DOMUs):
    FILE= "/tmp/givenVMs_%s" %CURRENT_TIME
    hosts=list_to_file(FILE,DOMUs)
    
    status, result = commands.getstatusoutput('fping -f %s' %hosts)
    #status = 0 means, all hosts are alive and reachable
    if status != 0:

       unreachable_hosts=[]
       address_not_found_hosts=[]
       alive_hosts=[]
       other_hosts=[]

       for host in result.split('\n'):
         if 'ICMP Echo sent' not in host:
           if 'is alive' in host:
              alive_hosts.append(host.split()[0])
              result_logger(host,'AlreadyAlive')

           elif 'unreachable' in host:
              unreachable_hosts.append(host.split()[0])
              #result_logger(host,'unreachable')

           elif "address not found" in host:
              address_not_found_hosts.append(host.split()[0])             
              result_logger(host,'Invalid')

           else:
              other_hosts.append(host.split()[0])
              result_logger(host,'Other')

       return unreachable_hosts, address_not_found_hosts,alive_hosts,other_hosts
    return 'OK','OK', 'OK', 'OK'

def main():

   parser = argparse.ArgumentParser(description='Wake up VMs in bulk fasion')
   parser.add_argument('-f','--file', type=argparse.FileType('r'),help='Provide the list of DOMUs in a file')
   parser.add_argument('-domu', '--domu', nargs='*', help='Provide the DOMU to wake up')
   args = parser.parse_args()

   if args.file:
      DOMUs = args.file.readlines()
      #hosts=[host.strip() for host in f]

      #@print('file => %s' %DOMUs)
		  
   if args.domu:
      DOMUs = args.domu
      #print('domu => %s' %DOMUs)
   print('\n\tGetting the hosts status ...\n')
   unreachable_hosts, address_not_found_hosts,alive_hosts,other_hosts = check_if_vm_alive(DOMUs)

   if unreachable_hosts == 'OK':
      sys.exit('EXIT:No DOMUs are down\n')
   
   LogFile='/tmp/wakeupVms_%s.log' %CURRENT_TIME
   print('LogFile : %s' %LogFile)

   print('Breakup:')
   if len(unreachable_hosts) >0:
      print('\tUnreachable : %s' %len(unreachable_hosts))

   if len(address_not_found_hosts) >0:
      print('\tInvalid     : %s' %len(address_not_found_hosts))
  
   if len(alive_hosts) >0:
      print('\tAlive       : %s' %len(alive_hosts))

   if len(other_hosts):
      print('\tOthers      : %s' %len(other_hosts))

   print('-----------------------------------\n')
   print('Working on "Unreachable" hosts')
   #print('Unreachable : %s\n' %(unreachable_hosts))


   Success=[]
   Errors_f='/tmp/FailedToFindParent_%s' %CURRENT_TIME
   
   #import pdb;pdb.set_trace()
   for DOMU in unreachable_hosts:
       #print('=> Working on : %s' %DOMU)
       DOM0=get_dom0(DOMU.strip())
       if DOM0 == 'None' or DOM0 == '':
          print("\t>ERROR:Failed to find parent for '%s'" %DOMU)
          #list_to_file(Errors_f,[DOMU])
          result_logger(DOMU,'FailedGetParent')
          continue
       print('\n->Found DOM0 %s for %s' %(DOM0,DOMU))
        
       trigger_ssh(DOM0,DOMU)


if __name__ == '__main__':
   main()

