#!/bin/bash

while getopts "P:p:" opt
do
   case "$opt" in
      P ) parentPID="$OPTARG" ;;
      p ) pid="$OPTARG" ;;
   esac
done

while :
do
	if [ $parentPID ]
	then
		echo "The parent PID to balance memory : ${parentPID}"
		./membalancer -f 25 -u -P ${parentPID} -v1 -m 0.0001 -x 1 -r 2 100 -H -S memory -bl -t ""
		./membalancer -f 25 -u -P ${parentPID} -v1 -m 0.0001 -x 1 -r 2 100 -H -S memory -b -t ""
	elif  [ $pid ]
	then
		echo "The PID to balance memory : ${pid}"
		./membalancer -f 25 -u -p ${pid} -v1 -m 0.0001 -x 1 -r 2 100 -H -S memory -bl -t ""
		./membalancer -f 25 -u -p ${pid} -v1 -m 0.0001 -x 1 -r 2 100 -H -S memory -b -t""
	else
		echo "No PID or PPID is given"
		./membalancer -f 25 -u -v1 -m 0.0001 -x 1 -r 2 100 -H -S memory -bl -t ""
		./membalancer -f 25 -u -v1 -m 0.0001 -x 1 -r 2 100 -H -S memory -b -t ""
	fi
done
