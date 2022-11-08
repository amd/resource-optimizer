/*
 * Copyright (C) 2022 Advanced Micro Devices, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Process samples from IBS or software sampler and analyze the instruction and
 * data (if available) samples.
 */

#ifndef _GENERIC_KERN_AMD
#define _GENERIC_KERN_AMD

#define MAX_IBS_SAMPLES	(64 * 1024)
/*
#define MAX_STORED_PAGES (MAX_IBS_SAMPLES / 4)
*/
#define MAX_STORED_PAGES (128)
#define PROCESSNAMELEN 32
#define CMW_PAGE_OFFSET 0xffff880000000000
#define MAX_CPUS 1024
#define MAX_MAPS 8
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
	MY_OWN_PID,
	MY_PAGE_SIZE,
	PER_NUMA_ACCESS_STATS,
	LATENCY_STATS,
	LATENCY_STATS_L3MISS,
	KERN_VERBOSE,
	USER_SPACE_ONLY,
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
#define IBS_FETCH_LLC_MISS_VAL   (1UL << 51)
#define IBS_FETCH_LLC_MISS(reg)  (reg & IBS_FETCH_LLC_MISS_VAL)
#define IBS_OP_LLC_MISS(reg) (reg & (1UL << 7))

#define IBS_KERN_SAMPLE(ip) (ip > CMW_PAGE_OFFSET)

struct value_data {
	char buffer[CCMD_PAGE_SIZE];
};

struct value_fetch {
	u64 tgid;
	u64 fetch_regs[IBSFETCH_REG_COUNT];
	volatile u32 counts[MAX_NUMA_NODES];
	volatile u32 count;
	u32 filler;
};

struct value_op {
	u64 tgid;
	u64 ip;
	u64 op_regs[IBSOP_REG_COUNT];
	volatile u32 counts[MAX_NUMA_NODES];
	volatile u32 count;
	u32 filler;
};

#define MAX_LATENCY_IDX 512
struct value_latency {
	volatile int idx;
	volatile u32 latency[MAX_LATENCY_IDX];
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
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
#define ATOMIC64_READ(v) atomic64_read((atomic64_t *)(v))
#define ATOMIC_READ(v)   atomic_read((atomic_t *)(v))
#define ATOMIC_ADD(v, val) __atomic_add_fetch((v), val, __ATOMIC_SEQ_CST)
#define ATOMIC_SET(v, val) atomic_set((atomic_t *)(v), val)
#define ATOMIC64_SET(v, val) atomic64_set((atomic64_t *)(v), val)
#define ATOMIC_CMPXCHG(v, cur, new) __sync_val_compare_and_swap((v), cur, new)
#define ATOMIC64_CMPXCHG(v, cur, new) __sync_val_compare_and_swap((v), cur, new)

#if (__clang_major__ < 14)
#define ATOMIC_INC_RETURN(v) atomic_inc_return_dummy(v)
static inline u32 atomic_inc_return_dummy(volatile u32 *v)
{
	u32 old;

	old = ATOMIC_READ(v);
	__atomic_add_fetch((v), 1, __ATOMIC_SEQ_CST);
	return old;
}

#define JUST_ONCE(v, cur, new) just_once(v)
static inline bool just_once(volatile unsigned long *v)
{
	if (ATOMIC_READ(v) != 0)
		return 1;

	ATOMIC_INC(v);
	return 0;
}

#else
#define JUST_ONCE(v, cur, new) ATOMIC_CMPXCHG(v, cur, new)
#define ATOMIC_CMPXCHG(v, cur, new) __sync_val_compare_and_swap((v), cur, new)
#define ATOMIC_INC_RETURN(v) __atomic_add_fetch((v), 1, __ATOMIC_SEQ_CST)
#endif

#else
/*
#define ATOMIC_READ(v) __sync_fetch_and_add((v), 0)
#define ATOMIC_INC(v) __sync_fetch_and_add((v), 1)
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
