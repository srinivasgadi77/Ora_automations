#!/bin/bash
HOSTNAME=$(hostname)

if test -f /etc/oracle-release ; then
   ver=$(cat /etc/oracle-release)
   echo "$ver"

elif test -f /etc/release ; then
  echo 'Solaris'
fi

