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
	echo "Need to provide Parent PID (-P) or specific pid (-p) to balance.";
	exit 1
fi

while :
do
	if [ $parentPID ]
	then
		echo "The parent PID getting balanced : ${parentPID}"
		./membalancer -f 25 -u -P ${parentPID} -v1 -m 0.0001 -M 1 -r 2 100 -H -S process -b
	else
		echo "The PID getting balanced : ${pid}"
		./membalancer -f 25 -u -p ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -H -S process -b
	fi
done
