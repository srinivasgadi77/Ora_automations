#!/bin/bash
HOSTNAME=`hostname -s`
LOG="/var/log/${HOSTNAME}_OCT_QM_2021.log"
echo "=====df -h===========" >$LOG
df -h >>$LOG
echo "=====uname===========" >>$LOG
uname -a >>$LOG
echo "=====ifconfig===========" >>$LOG
ifconfig -a >>$LOG
echo "Route Information">>$LOG
route -n >>$LOG
echo "=====/etc/fstab===========" >>$LOG
cat /etc/fstab >>$LOG
echo "=====/etc/passwd===========" >>$LOG
cat /etc/passwd >>$LOG
echo "=====/etc/group===========" >>$LOG
cat /etc/group >>$LOG
echo "===ldap_status=======" >>$LOG
service nscd status >>$LOG
service nslcd status >>$LOG
service autofs status >>$LOG
authconfig --test | grep -i ldap >>$LOG
