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
#define MAX_MAPS 7
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

enum balancer_knobs {
	CHECK_PPID,
	PER_NUMA_ACCESS_STATS,
	PER_NUMA_LATENCY_STATS,
	LAST_KNOB,
	TOTAL_KNOBS,
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
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0)
        int   success;
#endif
        int   target_cpu;
};

struct sched_exit {
        short type;
        char  flags;
        char  preempt_count;
        int   common_pid;
        char  comm[COMM_LEN];
        pid_t pid;
        int   prio;
};

#ifdef __KERNEL__ 
/*
#define ATOMIC_READ(v) __atomic_fetch_add((v), 0, __ATOMIC_SEQ_CST)
#define ATOMIC_READ(v) __sync_fetch_and_add_N((v), 0)
#define ATOMIC_READ(v) (*v)
*/
#define ATOMIC_INC(v)  __atomic_add_fetch((v), 1, __ATOMIC_SEQ_CST)
#define ATOMIC_READ(v) atomic64_read((atomic64_t *)(v))
#define ATOMIC_CMPXCHG(v, cur, new) __sync_val_compare_and_swap((v), cur, new)
#else
/*
#define ATOMIC_READ(v) __sync_fetch_and_add((v), 0)
#define ATOMIC_INC(v) __sync_fetch_and_add((v), 1)
#define ATOMIC_ADD(v, val) __sync_fetch_and_add((v), val)
*/
#ifndef atomic_t
typedef struct {
        volatile int counter;
} atomic_t;

typedef struct {
        volatile long counter;
} atomic64_t;

#define atomic64_read(v) __sync_fetch_and_add(&(v)->counter, 0)
#define atomic64_add(v, value) __sync_fetch_and_add(&(v)->counter, value)
#define atomic64_inc(v) atomic64_add(v, 1)
#define atomic64_sub(v, value) __sync_fetch_and_sub(&(v)->counter, value)
#define atomic64_dec(v) atomic64_sub(v, 1)
#define atomic_cmxchg(v, cur, new) __sync_val_compare_and_swap((v), cur, new)
#endif
#endif


#endif
