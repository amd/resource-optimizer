KDIR ?= /home/skurichi/fedora
LIBBPF = /home/skurichi/libbpf
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))
MODULE   := membalancer
BIN_KERN := ${MODULE}_kern.o
BIN_USER := ${MODULE}_user.o
BIN_LOAD := bpf_load.o
BIN_NUMA := ${MODULE}_numa.o
BIN_TIER := ${MODULE}_tier.o
BIN_TRACER := ${MODULE}_tracer.o
GETPADDR:= getpaddr.o
HEAP := heap.o
LIBS  := ${LIBBPF}/src/libbpf.a -lz -lelf -lnuma -lpthread
#DEFS = -DUSE_PAGEMAP
#DEFS = -DCCMD_SOFTWARE_SAMPLING

BPF_INCLUDE := -I. \
	-I${KDIR}/tools/perf \
	-I${KDIR}/tools/lib \
	-I${KDIR}/tools/testing/selftests/bpf/ \
	-I${LIBBPF}/include

CLANG_FLAGS = -I. \
	-include $(KDIR)/include/linux/kconfig.h \
	-I$(KDIR)/include \
	-I$(KDIR)/tools/lib \
	-I$(KDIR)/include/uapi \
	-I$(KDIR)/include/generated/uapi \
	-I$(KDIR)/arch/$(ARCH)/include \
	-I$(KDIR)/arch/$(ARCH)/include/generated \
	-I$(KDIR)/arch/$(ARCH)/include/uapi \
	-I$(KDIR)/arch/$(ARCH)/include/generated/uapi \
	-I$(KDIR)/tools/testing/selftests/bpf/ \
	-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
	-DCC_USING_FENTRY \
	-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option  \
	-g -O2 -emit-llvm

all:   $(BIN_KERN) ${BIN_LOAD} \
       ${BIN_TRACER} ${BIN_NUMA} ${BIN_TIER} \
       ${HEAP} ${GETPADDR} ${BIN_USER}

%_kern.o: %_kern.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - -Wall| \
		$(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@

bpf_load.o: ${KDIR}/samples/bpf/bpf_load.c 
	$(CLANG) -c $<  ${BPF_INCLUDE}

getaddr.o: getaddr.c
	$(CLANG) -c $<  ${BPF_INCLUDE}

%_numa.o: %_numa.c
	$(CLANG) -c $<  ${BPF_INCLUDE}

%_tier.o: %_tier.c
	$(CLANG) -c $<  ${BPF_INCLUDE}
%_tracer.o: %_tracer.c
	$(CLANG) -c $<  ${BPF_INCLUDE}

heap.o: heap.c
	$(CLANG) -c $<  ${BPF_INCLUDE}

%_user.o: %_user.c
	$(CLANG) ./bpf_load.o \
	./membalancer_numa.o \
	./membalancer_tier.o \
        ./membalancer_tracer.o \
        ./getpaddr.o \
        ./heap.o \
	$<  ${BPF_INCLUDE} -o ${MODULE} \
	${LIBS} ${DEFS} -Wall 
clean:
	rm -f *.o ${MODULE}.o ${MODULE}
