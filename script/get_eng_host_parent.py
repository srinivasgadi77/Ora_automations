#!/usr/bin/python
#Author : Srinivas Gadi
#check whether provided or current server production or nonprod
##('You can also check multiple host in one shot\nEx:\n ./host_env <Host1> <Host2> <Host3>..<Hostn>')
import time
import urllib2
import platform
import os
import sys

CURRENT_TIME=time.strftime('%d-%m-%Y_%H:%M:%S')
parse_hosts =  sys.argv[1:]
prod_hosts=[]
non_prod_hosts=[]
LJUST=30

###getting the data from API to check the host type
def get_host_region(host):
    import pdb;pdb.set_trace()
    host_API = 'https://devops.oraclecorp.com/ws/public/v1/hosts/assets/%s/properties/' %(host)
    response = urllib2.urlopen(host_API).read()
    try:
        if "error" in (eval(response)).keys():
            return 'Invalid Host'
    except:
        for region in response.split(","):
            if region.split(":")[0] == ' ""parent host""' :
                return (region.split(":")[1].replace('"','')).strip()

def WriteToFile(FileName,data):
    with open('%s' %FileName,'w') as env:
      for host in data:
        env.write(host+'\n')
#if host provided host as parameter , use this module

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Get the host environment type')
    parser.add_argument('-clients', '--clients', nargs='*', help='Provide the clients to install pkgs')
    parser.add_argument('-f','--file', type=argparse.FileType('r'),help='Provide the list of servers in a file')
    args = parser.parse_args()


    if args.file:
      hosts = args.file.readlines()
      hosts_data = [ host.strip() for host in hosts ]

    if args.clients:
      hosts_data = args.clients

    for host in hosts_data :
       if '.' in host:
          host=host.split('.')[0]
       result=get_host_region(host)

       ##if host is invalid , just ignore and print ERROR message
       if result == 'Invalid Host':
          error_data='ERROR> %s' %host
          print (error_data.ljust(LJUST,' ') +' : '+ 'is Invalid Host')
          continue

       if 'Production' in get_host_region(host):
          prod_hosts.append(host)
       else:
          non_prod_hosts.append(host)

    if prod_hosts:
      if len(prod_hosts) >1:
          WriteToFile('/tmp/Production_hosts_%s.log'%CURRENT_TIME ,prod_hosts)
          print ("Prod host list".ljust(LJUST,' ') +' : '+'/tmp/Production_hosts_%s.log' %CURRENT_TIME)
      else:
          print(prod_hosts[0].ljust(LJUST,' ') +' : '+'Production Infrastructure')

    if non_prod_hosts:
      if len(non_prod_hosts) > 1:
          WriteToFile('/tmp/NonProduction_hosts.log_%s' %CURRENT_TIME, non_prod_hosts)
          print ("Non Prod host list".ljust(LJUST,' ')+' : ' +'/tmp/NonProduction_hosts_%s.log' %CURRENT_TIME)
      else:
          print(non_prod_hosts[0].ljust(LJUST,' ')+' : ' +'Non Production Infrastructure')

#if no host provided, take current host as parameter and check
#else:
#   host=platform.uname()[1]
#   print('%s : %s' %(host,get_host_region(host)))

