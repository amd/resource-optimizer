Memory balancer is a prototype tool for balancing memory across multiple tiers of memory or NUMA nodes. The tool currently supports:

1) NUMA balancing which overlaps with Linux Autonuma. However the tool is based on AMD Instruction Based Sampling (IBS)
2) User Policy Driven Multitiered Memory Architecture.
3) NUMA/Memory Tier Access Pattern Reporter with optional memory migrations

AFor more information such as command lines, the tools needs to be invoked with the option -h.

Major Source Code Files:
1) membalancer_kern.c
Kernel functionality/eBPF hooks for collecting IBS samples
2) membalancer_user.c
CLI/user space code for extracting the statistics collected in the kernel, worker threads for implementing memory migrations.
3) membalancer_tier.c   - Backend code for memory tiering.
4) membalancer_numa.c   - Backend code for NUMA migrations
5) membalancer_tracer.c - Backend code for access tracer

Build Information:

A note on external dependencies: To build memory balancer tool, it requires libbpf to be downloaded from https://github.com/libbpf/libbpf. The location of libbpf needs to be mentioned in the Makefile via the variable LIBBPF. The location of kernel source code also needs to be mentioned via the variable KDIR.

To build memory balancer, the command needs to be run is "make".

Currently the kernel part of the tool has a hard dependency with Linux kernel code. This is due to the absence of a eBPF kernel API to get parent process identifier which is required for balancing memory of progress-like multi-process application which creates processes on demand. This hard dependency maybe relaxed in future.
