#!/bin/bash

while getopts "P:p:F:" opt
do
   case "$opt" in
      P ) parentPID="$OPTARG" ;;
      p ) pid="$OPTARG" ;;
      F ) frequency="$OPTARG" ;;
   esac
done

if [ -z "$parentPID" ] && [ -z "$pid" ]
then
	echo "Need to provide Parent PID (-P) or specific pid (-p) to Autotune.";
	exit 1
fi

if [ -z "$frequency" ]
then
	frequency=-1
fi


while :
do
	if [ $parentPID ]
	then
		echo "The parent PID getting balanced : ${parentPID}"
		if [ ${frequency} -lt 0 ]
		then
			echo "The Sampling frequency is default"
			./membalancer -f 25 -u -P ${parentPID} -v1 -m 0.0001 -x 1 -r 2 100 -H -S autotune
		else
			echo "The Sampling frequency is ${frequency}"
			./membalancer -f 25 -u -P ${parentPID} -v1 -m 0.0001 -x 1 -r 2 100 -H -S autotune ${frequency}
		fi
	else
		echo "The PID getting balanced : ${pid}"
		if [ ${frequency} -lt 0 ]
		then
			echo "The Sampling frequency is default"
			./membalancer -f 25 -u -p ${pid} -v1 -m 0.0001 -x 1 -r 2 100 -H -S autotune
		else
			echo "The Sampling frequency ${frequency}"
			./membalancer -f 25 -u -p ${pid} -v1 -m 0.0001 -x 1 -r 2 100 -H -S autotune ${frequency}
		fi
	fi
done
