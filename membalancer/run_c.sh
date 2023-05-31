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
		./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -x 1 -r 2 100 -bl -U 1048576 -D 1048576
		./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -x 1 -r 2 100 -b  -U 1048576 -D 1048576
	else
		./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -x 1 -r 2 100 -l
		./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -x 1 -r 2 100
	fi
done
