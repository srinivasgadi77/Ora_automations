#!/bin/bash
host=$(hostname -s)
hst=$(echo $host | cut -d "." -f1)

tail -1 $hst*.csv
