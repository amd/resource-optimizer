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
		# Memory balancer mode
		# Example for 2-tier, first with L3 filter and the second without it
		./membalancer -f 25 -u -v1 -m 0.0001 -x 1 -r 2 200 -t 0:0,1:0:0:0:1:1:0-1:2,3:10:0:0:0:0:0 -H -U1048576 -D1048576 -P ${pid} -bl
		./membalancer -f 25 -u -v1 -m 0.0001 -x 1 -r 2 200 -t 0:0,1:0:0:0:1:1:0-1:2,3:10:0:0:0:0:0 -H -U1048576 -D1048576 -P ${pid} -b

		# Example for 3-tier, first with L3 filter and the second without it
		#./membalancer -f 25 -u -v1 -m 0.0001 -x 1 -r 2 200 -t 0:0,1:0:0:0:1:1:0-1:2:10:0:0:2:2:0-2:3:10:1:0:0:0:0 -H -U1048576 -D1048576 -P ${pid} -bl
		#./membalancer -f 25 -u -v1 -m 0.0001 -x 1 -r 2 200 -t 0:0,1:0:0:0:1:1:0-1:2:10:0:0:2:2:0-2:3:10:1:0:0:0:0 -H -U1048576 -D1048576 -P ${pid} -b


	else
		# Reporter mode
		# Example for 2-tier, first with L3 filter and the second without it
		./membalancer -f 25 -u -v1 -m 0.0001 -x 1 -r 2 200 -t 0:0,1:0:0:0:1:1:0-1:2,3:10:0:0:0:0:0 -H -U1048576 -D1048576 -P ${pid} -l
		./membalancer -f 25 -u -v1 -m 0.0001 -x 1 -r 2 200 -t 0:0,1:0:0:0:1:1:0-1:2,3:10:0:0:0:0:0 -H -U1048576 -D1048576 -P ${pid}

		# Example for 3-tier, first with L3 filter and the second without it
		#./membalancer -f 25 -u -v1 -m 0.0001 -x 1 -r 2 200 -t 0:0,1:0:0:0:1:1:0-1:2:10:0:0:2:2:0-2:3:10:1:0:0:0:0 -H -U1048576 -D1048576 -P ${pid} -l
		#./membalancer -f 25 -u -v1 -m 0.0001 -x 1 -r 2 200 -t 0:0,1:0:0:0:1:1:0-1:2:10:0:0:2:2:0-2:3:10:1:0:0:0:0 -H -U1048576 -D1048576 -P ${pid}
	fi
done
