#!/bin/bash
host=$(hostname -s)
hst=$(echo $host | cut -d "." -f1)

tail -1 /root/$hst*.csv | grep  "OL_KERNEL_PATCH_FAILED" >/dev/nul
if [ $? == 0 ]
then
    # Check the patching log for error
        grep "which is newer than kernel" /root/${hst}_security_patch.log >/dev/null
        if [ $? == 0 ]
           then
             echo "Bug : Kernel Success"
        else
         echo "OL_KERNEL_PATCH_FAILED"
       fi
else
   echo "No Kernel issue"
   tail -1 /root/$hst*.csv | grep  "FAILED"
fi

LOG_FILE=$(ls /root/${hst}_security_patch.log)

echo "==> Reading LOG FILE : $LOG_FILE"

egrep -i "PYCURL ERROR|HTTP Error 502: notresolvable|No more mirrors to try" $LOG_FILE >/dev/null

if [ $? == 0 ]
then
    echo "Failed to download repo"
    exit
fi
egrep -i "You could try using --skip-broken|Error: Cannot retrieve repository metadata" $LOG_FILE >/dev/null
if [ $? == 0 ]
then
   echo "Broken repo"
   exit
fi

grep "Error: Missing Dependency" $LOG_FILE >/dev/null
if [ $? == 0 ]
then
   echo "Dependency issues"
   exit
fi

grep "Found 1 pre-existing rpmdb problem" $LOG_FILE >/dev/null
if [ $? == 0 ]
then
   echo "RPM DB issue"
   exit
fi

grep "Error:  Multilib version problems found" $LOG_FILE >/dev/null
if [ $? == 0 ]
then
   echo "Multilib error"
   exit
fi

#>/tmp/space
#grep -i "no space" $LOG_FILE >/tmp/space
#space_log=$(tail -1 /tmp/space)

#if [ $? == 0 ]
#then
#   echo "SPACE ISSUE : $space_log "
#   exit
#fi

echo "All OK"
