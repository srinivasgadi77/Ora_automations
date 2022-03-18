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

