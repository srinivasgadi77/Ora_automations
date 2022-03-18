#!/bin/bash
LOG_FILE=$(ls -lrt /var/tmp/$(hostname -s)*yum_dryrun*.txt | tail -1 | awk '{print $9}')
if [ $? != 0 ]
then
  echo "Pre check did not run"
else
  echo $LOG_FILE
  res=$(grep "Insufficient space in download directory" $LOG_FILE)

  if [ $? == 0 ]
  then
    echo $res
    else
      res=$(grep "Processing Conflict" $LOG_FILE)
      if [ $? == 0 ]
      then
         echo $res
      fi
  fi

fi

