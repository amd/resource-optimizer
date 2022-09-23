KDIR ?= /home/skurichi/fedora
LIBBPF = /home/skurichi/libbpf
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))
MODULE   := profiler
BIN_KERN := ${MODULE}_kern.o
BIN_USER := ${MODULE}_user.o
LIBS  := ${LIBBPF}/src/libbpf.so -lz -lelf -lnuma -lpthread
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

all:   $(BIN_KERN) ${BIN_USER}

%_kern.o: %_kern.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - -Wall| \
		$(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@

%_user.o: %_user.c
	$(CLANG) \
	$<  ${BPF_INCLUDE} -o ${MODULE} \
	${LIBS} ${DEFS} -Wall
clean:
	rm -f *.o ${MODULE}.o ${MODULE}
