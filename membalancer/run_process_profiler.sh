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
	echo "Need to provide Parent PID (-P) or specific pid (-p) to profile.";
	exit 1
fi

while :
do
	if [ $parentPID ]
	then
		echo "The parent PID getting profiled : ${parentPID}"
		./membalancer -f 25 -u -P ${parentPID} -v1 -m 0.0001 -M 1 -r 2 100 -H -S process
	else
		echo "The PID getting profiled : ${pid}"
		./membalancer -f 25 -u -p ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -H -S process
	fi
done
