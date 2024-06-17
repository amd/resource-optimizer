Different modes of running membalancer with command lines

Without the commandline option -b, the tool runs in profiler or reporter mode without making any changes in the system or application. The option -l is used for making use of L3 miss filtering which is present in certain advanced AMD microprocessors. The tool allows to pick samples of a process by giving it process identifier or pid. Alternatively a user can generate the samples of all processes of a parent process by giving the parent process identifier or ppid.

1) Memory balancer in histogram mode with L3 miss filtering
 ./membalancer -f 25 -u -[pP] <pid> -v1 -m 0.0001 -x 1 -r 2 100 -bl -H -U 1048576 -D 1048576
2) Memory balancer in histogram mode without L3 miss filter,
./membalancer -f 25 -u -[pP] <pid> -v1 -m 0.0001 -x 1 -r 2 100 -b -H -U 1048576 -D 1048576
3) Memory balancer in continuous mode with L3 miss filtering
 ./membalancer -f 25 -u -[p P] <pid> -v1 -m 0.0001 -x 1 -r 2 100 -bl -U 1048576 -D 1048576
4) Memory balancer in continuous mode without L3 miss filtering
 ./membalancer -f 25 -u -[pP] <pid> -v1 -m 0.0001 -x 1 -r 2 100 -b -U 1048576 -D 1048576
5) Memory balance in multi-tier memory mode
./membalancer -f 25 -u -v1 -m 0.0001 -x 1 -r 2 200 -t 0:0,1:0:0:0:1:1:0-1:2,3:10:0:0:0:0:0 -H -U1048576 -D1048576 -[pP] ${pid} -bl

The commandline above defines two tier memory based on NUMA distances. For exampler tier 0 consists of NUMA nodes 0 and 1, tier 1 consits of NUMA nodes  2 and 3

6) Process migration mode
 ./membalancer -f 25 -u -[pP] <pid> -v1 -m 0.0001 -x 1 -r 2 100 -H -S process -bl
In this mode, process migration is followed instead of migrating memory. Without -b option, the command runs in report or nonmodifying mode.

7) Automatic mode
./membalancer -f 25 -u -[pP] <pid> -v1 -m 0.0001 -x 1 -r 2 100 -H -S autotune
Autotune or automatic mode picks either process or memory migration mode depending the target CPU availability and the memory migration cost.


