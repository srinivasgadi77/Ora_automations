#!/usr/bin
fileName=$1
echo $fileName
for host in $(cat $fileName)
do
echo $host
host $host | awk '{print $1}' >>${fileName}_fqdn.txt
done

echo "--> Output : ${fileName}_fqdn.txt"

