/*
 * Copyright (c) 2023 Advanced Micro Devices, Inc.
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

#ifndef _MEMBALANCER_H_
#define _MEMBALANCER_H_ 
#include "generic_kern_amd.h"

#define MAX_IBS_SAMPLES	(64 * 1024)
#define PROCESSNAMELEN 32
#define MAX_CPU_CORES 1024
#define MEMB_PAGE_SIZE (4096)
#define MAX_PROCESS_STATS_IDX 1024
#define DEFER_PROCESS_CNT 8
#define L3MISS_DEFER_PROCESS_CNT 2
#define MIN_CNT 1
#define MIN_DENSE_SAMPLE_FREQ  (2 * MIN_CNT)
#define MIN_PCT 0.25
#define MIN_DENSE_SAMPLES_DATA 16
#define MIN_DENSE_SAMPLES_CODE 2

enum balancer_knobs {
	CHECK_PPID,
	MY_OWN_PID,
	MY_PAGE_SIZE,
	PER_NUMA_ACCESS_STATS,
	LATENCY_STATS,
	LATENCY_STATS_L3MISS,
	KERN_VERBOSE,
	USER_SPACE_ONLY,
	PROCESS_STATS,
	AUTO_TUNE,
	DEFER_PROCESS,
	LAST_KNOB,
	TOTAL_KNOBS,
};

struct process_stats {
	volatile u32 memory[MAX_NUMA_NODES];
	volatile u32 cpu[MAX_NUMA_NODES];
};

struct numa_range {
	u64 first_pfn;
	u64 last_pfn;
	u32 node;
	u32 tier;
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
#define ATOMIC64_ADD(v, val) __atomic_add_fetch((v), val, __ATOMIC_SEQ_CST)
#define ATOMIC_SET(v, val) atomic_set((atomic_t *)(v), val)
#define ATOMIC64_SET(v, val) atomic64_set((atomic64_t *)(v), val)
#define ATOMIC_CMPXCHG(v, cur, new) __sync_val_compare_and_swap((v), cur, new)
#define ATOMIC64_CMPXCHG(v, cur, new) __sync_val_compare_and_swap((v), cur, new)
#define VALID_NODE(n) (n >= 0 && n < MAX_NUMA_NODES)

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

#ifndef __KERNEL__
typedef __u32 u32;
typedef __u64 u64;
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif
#endif

#endif
