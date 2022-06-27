/*
 * Process samples from IBS or software sampler and analyze the instruction and
 * data (if available) samples.
 *
 * Copyright 2022 AMD, Inc.
 */

#ifndef _CMW_HDR_H
#define _CMW_HDR_H

#define MAX_IBS_SAMPLES	(64 * 1024)
/*
#define MAX_STORED_PAGES (MAX_IBS_SAMPLES / 4)
*/
#define MAX_STORED_PAGES (128)
#define PROCESSNAMELEN 32
#define CMW_PAGE_OFFSET 0xffff880000000000
#define MAX_CPUS 1024
#define MAX_MAPS 6
#define MAX_NUMA_NODES 8
#define MAX_PROCESS_CNT 32768

#define CCMD_PAGE_SIZE (4096)

enum {
	IBS_FETCH_EVENT,
	IBS_OP_EVENT,
};

enum {
        IBS_FETCH_CTL,
        IBS_FETCH_LINADDR,
        IBS_FETCH_PHYSADDR,
        IBSFETCH_REG_COUNT,
};

struct perf_ibs_fetch_data {
	u32		size;
	union {
		u32	data[0];	/* data buffer starts here */
		u32	caps;
	};
	
	u64		regs[IBSFETCH_REG_COUNT];
};

enum {
        IBS_OP_CTL,
        IBS_OP_RIP,
        IBS_OP_DATA,
        IBS_OP_DATA2,
        IBS_OP_DATA3,
        IBS_DC_LINADDR,
        IBS_DC_PHYSADDR,
        IBSOP_REG_COUNT,
};

#define IBS_FETCH_RAW_SIZE 36
#define IBS_OP_RAW_SIZE 68

#define IBS_FETCH_VALID_PHYSADDR (1ULL << 52)
#define IBS_FETCH_PHYSADDR_VALID(reg) (reg & IBS_FETCH_VALID_PHYSADDR)
#define IBS_OP_PHYSADDR_VALID(reg) (reg & (1UL << 18))
#define IBS_OP_LINADDR_VALID(reg) (reg & (1UL << 17))

#define IBS_KERN_SAMPLE(ip) (ip > CMW_PAGE_OFFSET)

struct value_data {
	char buffer[CCMD_PAGE_SIZE];
};

struct value_fetch {
	u64 tgid;
	volatile u32 count;
	u32 data_saved;
	u64 fetch_regs[IBSFETCH_REG_COUNT];
	volatile u32 counts[MAX_NUMA_NODES];
};

struct value_op {
	u64 tgid;
	volatile u32 count;
	u32 data_saved;
	u64 op_regs[IBSOP_REG_COUNT];
	volatile u32 counts[MAX_NUMA_NODES];
};

#define COMM_LEN 16
struct sched_wakeup {
        short type;
        char  flags;
        char  preempt_count;
        int   common_pid;
        char  comm[COMM_LEN];
        pid_t pid;
        int   prio;
        int   success;
        int   target_cpu;
};

#endif
