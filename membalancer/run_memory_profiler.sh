#!/bin/bash

while getopts "P:p:Z:" opt
do
   case "$opt" in
      P ) parentPID="$OPTARG" ;;
      p ) pid="$OPTARG" ;;
      Z ) zenver="$OPTARG" ;;
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
		if [ "${zenver:-0}" == 4 ]
		then
			./membalancer -f 25 -u -P ${parentPID} -v1 -m 0.0001 -M 1 -r 2 100 -H -S memory -l
		else
			./membalancer -f 25 -u -P ${parentPID} -v1 -m 0.0001 -M 1 -r 2 100 -H -S memory
		fi
	else
		echo "The PID getting profiled : ${pid}"
		if [ "${zenver:-0}" == 4 ]
		then
			./membalancer -f 25 -u -p ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -H -S memory -l
		else
			./membalancer -f 25 -u -p ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -H -S memory
		fi
	fi
done
