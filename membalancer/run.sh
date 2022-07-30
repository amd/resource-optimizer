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
	 	./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -bl -H -U 1048576 -D 1048576
	 	./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 1048576 -D 1048576
	else
	     ./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -H -l
	     ./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100  -H
	fi
done
