#/bin/bash

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
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 4194304 -D 4194304
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 2097152 -D 2097152
	 ./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 1048576 -D 1048576
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 524288 -D 524288
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 262144 -D 262144 
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 131072 -D 131072
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 65536 -D 65536 
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 32768 -D 32768
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 16384 -D 16384
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 8192 -D 8192
		#./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100 -b -H -U 4096 -D 4096
	else
		./membalancer -f 25 -u -P ${pid} -v1 -m 0.0001 -M 1 -r 2 100  -H
	fi
done
