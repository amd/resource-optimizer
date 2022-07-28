#!/bin/bash

pid=-1
if [[ "$#" -ge 1 ]]
then
	pid=$1
fi

while :
do
	clear
	if [[ "$#" -ge 2 ]]
	then
		./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -t -T 0:0:0:0:0:1:1:0-1:1:1:0:0:1:2:0-2:2,3:5:1:0:0:0:0 
	else
		./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -t -T 0:0,1:0:0:0:0:1:0-1:2,3:0:0:0:0:0:0
	fi
done
