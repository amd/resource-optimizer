LIBBPF = <..>/libbpf
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))
MODULE   := memory_profiler
BIN_KERN := ${MODULE}_kern.o
CPU_TYPE := -DCPU_AMD_X8664
#DEFS = -DUSE_PAGEMAP
#DEFS = -DCCMD_SOFTWARE_SAMPLING
VMLINUX := ../../include/arch/$(ARCH)/

CLANG_FLAGS = -I. \
	-I../../include/ \
	-I../../include/common \
	-I../../include/amd \
	-I../kernel \
	-I${LIBBPF}/src \
	-I$(VMLINUX) \
	-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
	-DCC_USING_FENTRY ${CPU_TYPE} \
	-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option  \
	-g -O2 -emit-llvm

all:   $(BIN_KERN)
%_kern.o: %_kern.c
	$(CLANG) $(CLANG_FLAGS) -target bpf -c $< -o - -Wall| \
		$(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o ../../bin/$@

clean:
	rm -f *.o ../../bin/${MODULE}_kern.o
