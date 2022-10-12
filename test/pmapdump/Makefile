KDIR ?= /home/skurichi/fedora
LIBBPF = /home/skurichi/libbpf
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))
MODULE   := pmapdump
GETPADDR:= getpaddr.o
BIN := ${MODULE}.o
LIBS  := -lm
#DEFS = -DCCMD_SOFTWARE_SAMPLING
USR_INCLUDE := -I. \
	-I${KDIR}/tools/perf \
	-I${KDIR}/tools/lib \
	-I${KDIR}/tools/testing/selftests/bpf/ \
	-I${LIBBPF}/include -I../kernel

CLANG_FLAGS = -I. \
	-include $(KDIR)/include/linux/kconfig.h \
	-I../kernel \
	-I$(KDIR)/include \
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

all:   getpaddr.o pmapdump.o
getpaddr.o: getpaddr.c

pmapdump.o: pmapdump.c
	$(CLANG) \
	getpaddr.o \
	$<  ${USR_INCLUDE} -o ${MODULE} \
	${LIBS} ${DEFS} -Wall -g
clean:
	rm -f *.o ${MODULE}.o ${MODULE}
