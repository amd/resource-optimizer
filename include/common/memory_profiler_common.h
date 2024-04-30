/*
 * Copyright (c) 2023-2024 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _MEMORY_PROFILER_COMMON_H_
#define _MEMORY_PROFILER_COMMON_H_

#include "resource_manager_types.h"

#ifndef __KERNEL__
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif
#endif

#define MAX_NUMA_NODES 64
#define KERN_PAGE_OFFSET 0xffff880000000000
#define MAX_LATENCY_IDX 128

#define KERN_SAMPLE(ip) (ip > KERN_PAGE_OFFSET)
#define MAX_SAMPLES	(64 * 1024)
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

enum memory_profiler_knobs {
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

struct code_sample {
	u64 tgid;
	u64 ip;
	u64 vaddr;
	u64 paddr;
	u64 lat;
	volatile u32 count;
	u32 filler;
	volatile u32 counts[MAX_NUMA_NODES];
	volatile u32 latency[MAX_LATENCY_IDX];
};

struct data_sample {
	u64 tgid;
	u64 ip;
	u64 vaddr;
	u64 paddr;
	u64 lat;
	volatile u32 count;
	u32 filler;
	volatile u32 counts[MAX_NUMA_NODES];
	volatile u32 latency[MAX_LATENCY_IDX];
};

#define INVALID_LATENCY (u32)-1

#ifdef __KERNEL__
/*
#define ATOMIC_READ(v) __atomic_fetch_add((v), 0, __ATOMIC_SEQ_CST)
#define ATOMIC_READ(v) __sync_fetch_and_add_N((v), 0)
#define ATOMIC_READ(v) (*v)
*/
#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define atomic_read(v) ((v)->counter)
#define atomic_set(v,i) (((v)->counter) = (i))
#define atomic64_set(v,i) (((v)->counter) = (i))
#define atomic64_read(v) __sync_fetch_and_add(&(v)->counter, 0)

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
#define ATOMIC_INC_RETURN(v) atomic_inc_return_dummy(v)
static inline u32 atomic_inc_return_dummy(volatile u32 *v)
{
	u32 old;

	old = ATOMIC_READ(v);
	__atomic_add_fetch((v), 1, __ATOMIC_SEQ_CST);
	return old;
}


#if (__clang_major__ < 14)
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
