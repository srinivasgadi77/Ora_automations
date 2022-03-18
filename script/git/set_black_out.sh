#!/bin/bash
EMAGENT_PATH=$(ps -ef | grep emwd.pl |grep -v grep| tr -s " " | tr " " "\n" | grep bin/emwd.pl | head -1)

EMAGENT_LINE=$(echo $EMAGENT_PATH | awk -F "/" 'BEGIN {OFS="/"} {$NF=""} 1' )

EM_USER=$(ps -ef | grep emwd.pl | grep -v grep | awk '{print $1}')

echo "Executing.."
echo su $EM_USER -c "${EMAGENT_LINE}/emctl start blackout 'Patching_2021' -nodelevel -nowait -d 360"
echo -e "--------------------\n"

su $EM_USER -c "${EMAGENT_LINE}/emctl start blackout 'Patching_2021' -nodelevel -nowait -d 360"

