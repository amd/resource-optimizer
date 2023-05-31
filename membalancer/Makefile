KDIR ?= <..>/linux-5.19
LIBBPF = <..>/libbpf
CLANG ?= clang
LLC ?= llc
MODULE   := membalancer
CPU_TYPE := -DCPU_AMD_X8664
BIN_USER := ${MODULE}_user.o
LIB := ${MODULE}_lib.o
BIN_NUMA := ${MODULE}_numa.o
BIN_TIER := ${MODULE}_tier.o
BIN_TRACER := ${MODULE}_tracer.o
BIN_TRACER := ${MODULE}_tracer.o
BIN_UTILS := ${MODULE}_utils.o
BIN_MIGRATE := ${MODULE}_migrate.o
MEMSTATS_USER := memstats_user.o
HEAP_USER := heap_user.o
TPOOL := thread_pool.o
RATE_LIMITER := rate_limiter.o
PROCESS_STATS := processtats_user.o
GETPADDR:= getpaddr.o
LIBS  := ${LIBBPF}/src/libbpf.so -lz -lelf -lnuma -lpthread -lrt
DEFS = -DMEMBALANCE_FORK ${CPU_TYPE}
#CPU_MIG_DEF = -DCPU_LEVEL_MIG
#DEFS = -DUSE_PAGEMAP
#DEFS = -DCCMD_SOFTWARE_SAMPLING

USR_INCLUDE := -I. \
	-I${KDIR}/tools/perf \
	-I${KDIR}/tools/lib \
	-I${KDIR}/tools/testing/selftests/bpf/ \
	-I${LIBBPF}/src \
	-I${LIBBPF}/include \
	-I../include/ \
	-I../include/common/

all:   ${BIN_TRACER} ${BIN_NUMA} ${BIN_UTILS} ${BIN_TIER} \
	${HEAP_USER} ${BIN_MIGRATE} ${GETPADDR} ${TPOOL} \
	${MEMSTATS_USER} ${LIB} ${PROCESS_STATS} ${RATE_LIMITER} \
	${BIN_USER}

getpaddr.o: getpaddr.c
	$(CLANG) -c $<  ${USR_INCLUDE}
memstats_user.o: memstats_user.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
%_numa.o: %_numa.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
%_tier.o: %_tier.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
%_tracer.o: %_tracer.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
%_utils.o: %_utils.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_MIG_DEF} \
	${CPU_TYPE}
%_migrate.o: %_migrate.c
	$(CLANG) -c $<  ${USR_INCLUDE} ${CPU_MIG_DEF} ${CPU_TYPE}
heap_user.o: heap_user.c
	$(CLANG) -c $<  ${USR_INCLUDE} ${CPU_TYPE}
thread_pool.o: thread_pool.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
rate_limiter.o: rate_limiter.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
%_lib.o: %_lib.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
processtats_user.o: processtats_user.c
	$(CLANG) -c $<  ${USR_INCLUDE} -mcmodel=large ${CPU_TYPE}
%_user.o: %_user.c
	$(CLANG) \
	./membalancer_numa.o \
	./membalancer_tier.o \
	./membalancer_tracer.o \
	./membalancer_utils.o \
	./membalancer_migrate.o \
	./memstats_user.o \
	./heap_user.o \
	./getpaddr.o \
	./thread_pool.o \
	./rate_limiter.o \
	./membalancer_lib.o \
	./processtats_user.o \
	$<  ${USR_INCLUDE} -o ${MODULE} \
	${LIBS} ${DEFS} -Wall -mcmodel=large
clean:
	rm -f *.o ${MODULE}.o ${MODULE}
