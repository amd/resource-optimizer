The idea behind the resource optimizer is to improve overall application performance by optimizing system resources (memory, CPU, IO, networking). This is done by observing bottlenecks using AMD telemetry, OS performance counters and making corrective actions.

The focus so far of the resource optimizer is its memory management component called memory balancer. A second part part of the optimizer is the profiler which takes advantages of IBS and LBR (last branch record) telemetry available in AMD microprocessors.

Memory balancer:
Memory balancer is a prototype tool for balancing memory across multiple tiers of memory or NUMA nodes. The tool currently supports:

1) NUMA balancing which overlaps with Linux Autonuma. However the tool is based on AMD Instruction Based Sampling (IBS)
2) User Policy Driven Multitiered Memory Architecture.
3) NUMA/Memory Tier Access Pattern Reporter with optional memory migrations

For more information such as command lines, the tools needs to be invoked with the option -h.

AMD telemetry-based simple profiler:

Profiler:
This is a simple application profiling tool which operates in two modes - IBS and LBR. The former supplies samples of Instruciton Based Sampling and the latter outputs samples last branch record (LBR).

To know more details, lauch the executable profiler with -h option.

Source Code Organization:
1) Kernel layer
Kernel functions are divided into architecture dependent and independent functions. The resource optimizer currently supports only architecture - AMD x86.  The source code is organized under kernel/arch/x86/amd where the architecture specific telemetric functions of IBS and LBR are implemented. The architecture neutral code in the kernel is located under kernel/common which are integrated with eBPF to support user space applications.

2) Header files
Header files contains structures or functions to be shared between kernel and/or application layers. The headers files can be of architecture neutral or specific. The header files are located under include/arch and include/common

3) Application layer
As of now the application layer has two applications. The memory balancer and simple profiler. The memory balancer and profiler codes are placed under membalancer and profiler directories respectively.


Build Information:

A note on external dependencies: To build memory balancer tool
1) libbpf
It requires libbpf to be downloaded from https://github.com/libbpf/libbpf. The location of libbpf needs to be mentioned in the Makefile via the variable LIBBPF. The location of kernel source code also needs to be mentioned via the variable KDIR.

2) bpftool needs to be installed for generating vmlinux.h file for core.
   Run following command for respective architecture vmlinux.h file
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./include/arch/x86/vmlinux.h

To build kernel module:
cd kernel/common
make

To build memory balancer application:
cd membalancer
make

To build profiler:
cd profiler
make

Currently the kernel part of the tool has a hard dependency with Linux kernel code. This is due to the absence of a eBPF kernel API to get parent process identifier which is required for balancing memory of progress-like multi-process application which creates processes on demand. This hard dependency maybe relaxed in future.
