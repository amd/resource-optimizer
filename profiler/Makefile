LIBBPF = <..>/libbpf
CLANG ?= clang
LLC ?= llc
CPU_TYPE := -DCPU_AMD_X8664
MODULE   := profiler
BIN_USER := ${MODULE}_user.o
LIB := membalancer_lib.o
NUMA := membalancer_numa.o
TIER := membalancer_tier.o
TRACER := membalancer_tracer.o
MIGRATE := membalancer_migrate.o
IPROFILER := iprofiler.o
LBR_PROFILER := lbr_profiler.o
PROFILER_MISC := profiler_misc.o
BIN_UTILS := membalancer_utils.o
MEMSTATS_USER := memstats_user.o
HEAP_USER := heap_user.o
GETPADDR := getpaddr.o
LIBS := ${LIBBPF}/src/libbpf.so -lz -lelf -lnuma -lpthread -lrt
#DEFS = -DMEMBALANCE_FORK
#DEFS = -DUSE_PAGEMAP
#DEFS = -DCCMD_SOFTWARE_SAMPLING

USR_INCLUDE := -I. \
	-I${LIBBPF}/src/ \
	-I${LIBBPF}/include/ \
	-I../membalancer/ \
	-I../include/common/ \
	-I../include/ \

all:   ${LIB} ${BIN_UTILS} ${NUMA} ${HEAP_USER} ${GETPADDR} ${MIGRATE} \
       ${TIER} ${TRACER} ${MEMSTATS_USER} ${PROFILER_MISC} \
       ${LBR_PROFILER} ${IPROFILER} ${BIN_USER}

getpaddr.o: ../membalancer/getpaddr.c
	$(CLANG) -c $<  ${USR_INCLUDE}
memstats_user.o: ../membalancer/memstats_user.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
membalancer_utils.o: ../membalancer/membalancer_utils.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
membalancer_numa.o: ../membalancer/membalancer_numa.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
membalancer_tier.o: ../membalancer/membalancer_tier.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
membalancer_tracer.o: ../membalancer/membalancer_tracer.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
membalancer_migrate.o: ../membalancer/membalancer_migrate.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
heap_user.o: ../membalancer/heap_user.c
	$(CLANG) -c $<  ${USR_INCLUDE} ${CPU_TYPE}
membalancer_lib.o: ../membalancer/membalancer_lib.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
iprofiler.o: iprofiler.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
lbr_profiler.o: lbr_profiler.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
profiler_misc.o: profiler_misc.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}

%_user.o: %_user.c
	$(CLANG) \
	./membalancer_utils.o \
	./membalancer_numa.o \
	./membalancer_tier.o \
	./membalancer_tracer.o \
	./membalancer_migrate.o \
	./memstats_user.o \
	./getpaddr.o \
	./heap_user.o \
	./iprofiler.o \
	./lbr_profiler.o \
	./profiler_misc.o \
	./membalancer_lib.o \
	${CPU_TYPE} \
	$<  ${USR_INCLUDE} -o ${MODULE} \
	${LIBS} ${DEFS} -Wall -mcmodel=large 
clean:
	rm -f *.o ${MODULE}.o ${MODULE}
