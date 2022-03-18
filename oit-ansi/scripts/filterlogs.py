#!/usr/bin/python
import os
import commands
import sys

if len(sys.argv) == 2:
   pass
else:
   sys.exit('\tERROR:Please providethe log file')

LogFile=sys.argv[1]
if not os.path.exists(LogFile):
   sys.exit('\tERROR:%s does not exists' %LogFile)

OUTPUT_FILE='%s_failures.log' %LogFile

cmd='grep OL_PATCH_FAILED_DUE_TO_YUM_ISSUES %s >/tmp/%s_1' %(LogFile,LogFile)

yum_er_sts,yum_er_res=commands.getstatusoutput(cmd)

data= open(LogFile,'r').readlines()

with open(OUTPUT_FILE,'w'): pass
file_writer = open(OUTPUT_FILE,'a')

for line in data:
   host=line.split(':')[0]
   if 'OL_PATCH_FAILED_DUE_TO_YUM_ISSUES' in line:
       file_writer.write("%s : %s\n" %(host, 'OL_PATCH_FAILED_DUE_TO_YUM_ISSUES'))
   elif 'OL_KERNEL_PATCH_FAILED' in line:
       file_writer.write("%s : %s\n" %(host, 'OL_KERNEL_PATCH_FAILED'))

print('Error Log : %s' %OUTPUT_FILE)
       
      
