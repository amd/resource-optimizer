KDIR ?= <..>/linux-5.19
LIBBPF = <..>/libbpf
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))
MODULE   := membalancer
BIN_KERN := ${MODULE}_kernel.o
#DEFS = -DUSE_PAGEMAP
#DEFS = -DCCMD_SOFTWARE_SAMPLING

CLANG_FLAGS = -I. \
	-I../../include/common \
	-I../../include/amd \
	-include $(KDIR)/include/linux/kconfig.h \
	-I../kernel \
	-I$(KDIR)/include \
	-I$(KDIR)/tools/lib \
	-I$(KDIR)/include/uapi \
	-I$(KDIR)/include/generated/uapi \
	-I$(KDIR)/arch/$(ARCH)/events \
	-I$(KDIR)/arch/$(ARCH)/include \
	-I$(KDIR)/arch/$(ARCH)/include/generated \
	-I$(KDIR)/arch/$(ARCH)/include/uapi \
	-I$(KDIR)/arch/$(ARCH)/include/generated/uapi \
	-I$(KDIR)/tools/testing/selftests/bpf/ \
	-I${LIBBPF}/src \
	-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
	-DCC_USING_FENTRY \
	-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option  \
	-g -O2 -emit-llvm

all:   $(BIN_KERN)
%_kernel.o: %_kernel.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - -Wall| \
		$(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@
clean:
	rm -f *.o ${MODULE}.o ${MODULE}
