KDIR ?= <..>/linux-5.19
LIBBPF = <..>/libbpf
CLANG ?= clang
LLC ?= llc
MODULE   := profiler
BIN_USER := ${MODULE}_user.o
LIB := membalancer_lib.o
NUMA := membalancer_numa.o
TIER := membalancer_tier.o
TRACER := membalancer_tracer.o
MIGRATE := membalancer_migrate.o
IPROFILER := iprofiler.o
LBR_PROFILER := lbr_profiler.o
BIN_UTILS := membalancer_utils.o
MEMSTATS_USER := memstats_user.o
HEAP_USER := heap_user.o
GETPADDR:= getpaddr.o
LIBS  := ${LIBBPF}/src/libbpf.so -lz -lelf -lnuma -lpthread
#DEFS = -DMEMBALANCE_FORK
#DEFS = -DUSE_PAGEMAP
#DEFS = -DCCMD_SOFTWARE_SAMPLING

USR_INCLUDE := -I. \
	-I${KDIR}/tools/perf/ \
	-I${KDIR}/tools/lib/ \
	-I${KDIR}/tools/testing/selftests/bpf/ \
	-I${LIBBPF}/src/ \
	-I${LIBBPF}/include/ \
	-I../membalancer/ \
	-I../include/common/ \
	-I../include/amd \

all:   ${LIB} ${BIN_UTILS} ${NUMA} ${HEAP_USER} ${GETPADDR} ${MIGRATE} \
       ${TIER} ${TRACER} ${MEMSTATS_USER} ${LBR_PROFILER} ${IPROFILER} \
       ${BIN_USER}

getpaddr.o: ../membalancer/getpaddr.c
	$(CLANG) -c $<  ${USR_INCLUDE}
memstats_user.o: ../membalancer/memstats_user.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large
membalancer_utils.o: ../membalancer/membalancer_utils.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large
membalancer_numa.o: ../membalancer/membalancer_numa.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large
membalancer_tier.o: ../membalancer/membalancer_tier.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large
membalancer_tracer.o: ../membalancer/membalancer_tracer.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large
membalancer_migrate.o: ../membalancer/membalancer_migrate.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large
heap_user.o: ../membalancer/heap_user.c
	$(CLANG) -c $<  ${USR_INCLUDE}
membalancer_lib.o: ../membalancer/membalancer_lib.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large
iprofiler.o: iprofiler.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large
lbr_profiler.o: lbr_profiler.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large

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
	./membalancer_lib.o \
	$<  ${USR_INCLUDE} -o ${MODULE} \
	${LIBS} ${DEFS} -Wall -mcmodel=large
clean:
	rm -f *.o ${MODULE}.o ${MODULE}
