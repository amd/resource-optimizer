#!/bin/bash

while getopts "P:p:" opt
do
   case "$opt" in
      P ) parentPID="$OPTARG" ;;
      p ) pid="$OPTARG" ;;
   esac
done

if [ -z "$parentPID" ] && [ -z "$pid" ]
then
	echo "Need to provide Parent PID (-P) or specific pid (-p) to balance memory.";
	exit 1
fi

while :
do
	if [ $parentPID ]
	then
		echo "The parent PID to balance memory : ${parentPID}"
		./membalancer -f 25 -u -P ${parentPID} -v1 -m 0.0001 -x 1 -r 2 100 -H -S memory -bl
		./membalancer -f 25 -u -P ${parentPID} -v1 -m 0.0001 -x 1 -r 2 100 -H -S memory -b
	else
		echo "The PID to balance memory : ${pid}"
		./membalancer -f 25 -u -p ${pid} -v1 -m 0.0001 -x 1 -r 2 100 -H -S memory -bl
		./membalancer -f 25 -u -p ${pid} -v1 -m 0.0001 -x 1 -r 2 100 -H -S memory -b
	fi
done
