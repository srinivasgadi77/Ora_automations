#!/usr/bin/python
# Author : Srinivas Gadi
# Purpose : It for anisble playbook purpose
# Its is to identify the missing hosts post executig of the OIT ansible playbooks

import argparse
import platform
import os
import sys

def read_log_files(log):
    
    #Check whether file exists
    #import pdb;pdb.set_trace()
    if os.path.exists(log):
       cmd="cat %s | awk -F ':' '{print $1}' | awk -F '.' '{print $1}'" %log
       hosts=os.popen(cmd).read().split('\n')
       res=[ host.strip() for host in hosts ]
       return res
    else:
      sys.exit('\tERROR: %s does not exists' %log)
 

def list_to_file(FileName,lists):
    with open(FileName, 'w') as f:
        for lst in list(lists):
            f.write('%s\n' % lst)
    print('  Missing hosts are recorded : %s' %FileName)

def find_diff(all,res_hosts,log_file=False):
    print('\n=>Failed/Missed hosts')
    missing_hosts = (set(all) - set(res_hosts))

    if log_file:
       list_to_file(log_file,missing_hosts)

    print('\n  Missing hosts count : %s' %len(missing_hosts))
    for host in missing_hosts:
       print('\t- %s' %host)


def main():
    parser = argparse.ArgumentParser(description='Finding missing hosts')
    parser.add_argument('-a', '--actual',required=True, help='Actual host file name')
    parser.add_argument('-s', '--success', help='Success host list log file')
    #parser.add_argument('-f', '--failures', help='Failure host log file')
    parser.add_argument('-l', '--logging', help='Log the missing hosts')
    args = parser.parse_args()

    #print(args.actual)
    #print(args.success)
    #print(args.failures)

    all_hosts=read_log_files(args.actual)
    succ_hosts=read_log_files(args.success)
    #fail_hosts=read_log_files(args.failures)
    
    if args.logging:
       #find_diff(all_hosts, succ_hosts+fail_hosts,args.logging)
       find_diff(all_hosts, succ_hosts,args.logging)
    else:
       find_diff(all_hosts, succ_hosts)


if __name__ == '__main__':
   main()

