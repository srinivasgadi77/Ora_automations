#!/usr/bash

ls /etc/yum.repos.d/peo_update.repo >/dev/null

if [ $? == 0 ]
then
  echo "Already exists"
  exit
else
ls /etc/yum.repos.d/old_repo/peo_update.repo  >/dev/null
if [ $? == 0 ]
then
  cp /etc/yum.repos.d/old_repo/peo_update.repo /etc/yum.repos.d/
  echo "Restored"
  exit
else
  ls /etc/yum_repo_bkp/pditrepo.repo  >/dev/null
  if [ $? == 0 ]
  then
    cp /etc/yum_repo_bkp/pditrepo.repo /etc/yum.repos.d/
    echo "Restored"
    exit
  fi
fi
fi

ls /etc/yum.repos.d/peo_update.repo  >/dev/null
if [ $? != 0 ]
then
 echo "Does not exists"
fi

