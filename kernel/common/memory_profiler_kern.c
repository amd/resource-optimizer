/*
 * Copyright (c) 2023-2024 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * code and data sampler : Architectural independent functions for code and
 * data sampling.
 */

#include "vmlinux.h"
#include <bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "memory_profiler_arch.h"
#include "memory_profiler_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, pid_t);
	__uint(max_entries, 8192);
} ppid_include  SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, pid_t);
	__uint(max_entries, 8192);
} pid_include  SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, pid_t);
	__uint(max_entries, 8192);
} pid_exclude SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, TOTAL_KNOBS);
} knobs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, MAX_CPU_CORES);
} cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} code_samples_counter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} data_samples_counter SEC(".maps");

static int check_ppid = -1;
static bool per_numa_access_stats = true;
static bool latency_stats = false;
static bool latency_stats_l3miss = false;
static unsigned long config_done = 0;
static unsigned int kern_verbose;
static pid_t my_own_pid;
static bool user_space_only = false;
unsigned long my_page_size;
unsigned int defer_cnt;

static volatile u64 code_samples_cnt, data_samples_cnt;
static bool processtats;

static void save_node_usage(volatile u32 counts[MAX_NUMA_NODES]);
static void load_numa_ranges(void);

static void init_function(void)
{
	int i, j, *valuep;

	if (JUST_ONCE(&config_done, 0, 1) != 0)
		return;

	for (i = CHECK_PPID; i < TOTAL_KNOBS; i++) {
		j = i;
		valuep = bpf_map_lookup_elem(&knobs, (const int *)&j);

		if (i == CHECK_PPID)  {
			if ((valuep != NULL) && (*valuep == 1))
				check_ppid = 1;
			else
				check_ppid = 0;
			continue;
		}

		if (i == MY_PAGE_SIZE)  {
			if ((valuep != NULL) && (*valuep != 0))
				my_page_size = *valuep;
			continue;
		}

		if (i == PER_NUMA_ACCESS_STATS) {
			if (valuep != NULL && (*valuep == 1))
				per_numa_access_stats = true;
			else
				per_numa_access_stats = false;
			continue;

		}

		if (i == LATENCY_STATS) {
			if (valuep != NULL && (*valuep == 1))
				latency_stats = true;
			else
				latency_stats = false;
			continue;
		}

		if (i == LATENCY_STATS_L3MISS) {
			if (valuep != NULL && (*valuep == 1))
				latency_stats_l3miss = true;
			else
				latency_stats_l3miss = false;
			continue;
		}

		if (i == KERN_VERBOSE) {
			if (valuep != NULL && (*valuep > 0))
				kern_verbose = *valuep;
			continue;
		}

		if (i == MY_OWN_PID) {
			if (valuep != NULL && (*valuep > 0))
				my_own_pid = *valuep;
			continue;
		}

		if ((i == PROCESS_STATS) || (i == AUTO_TUNE)) {
			if (valuep != NULL && (*valuep > 0)) {
				load_numa_ranges();
			}
			if (i == PROCESS_STATS)
				processtats = true;
		}

		if (i == USER_SPACE_ONLY)
			user_space_only = true;

		if (i == DEFER_PROCESS) {
			if (valuep != NULL && (*valuep > 0))
				defer_cnt = *valuep;
		}
	}

	if (check_ppid == 1) {
		pid_t nilpid = -1;
		if (bpf_map_lookup_elem(&ppid_include, &nilpid))
			check_ppid = 0;
	}
}

static inline void inc_code_samples(int val)
{
	int key = 0;
	u64 value;

	ATOMIC64_ADD(&code_samples_cnt, val);
	value = ATOMIC64_READ(&code_samples_cnt);
	bpf_map_update_elem(&code_samples_counter, &key, &value, BPF_ANY);
}

static inline void inc_data_samples(int val)
{
	int key = 0;
	u64 value;

	ATOMIC64_ADD(&data_samples_cnt, val);
	value = ATOMIC64_READ(&data_samples_cnt);
	bpf_map_update_elem(&data_samples_counter, &key, &value, BPF_ANY);
}

int cpu_node_get(void)
{
	int cpu, *nodep;

	cpu = bpf_get_smp_processor_id();
	if (cpu < 0)
		return -1;

	nodep = bpf_map_lookup_elem(&cpu_map, &cpu);
	if (!nodep)
		return -1;

	return *nodep;
}

static bool valid_pid_with_task(pid_t pid, struct task_struct *mytask)
{
	pid_t nilpid;

	if ((my_own_pid != 0) && (my_own_pid == pid))
		return false;

	nilpid = -1;

	/*
	 * Parent process ID check is expensive. Hence the following code block
	 * is invoked once to set whether ppid check is required afterwads or
	 * not.
	 */
	if (unlikely(check_ppid == -1)) {
		if (bpf_map_lookup_elem(&ppid_include, &nilpid)) {
			check_ppid = 0;
		} else {
			check_ppid = 1;
		}
	}

	/* Parent process case */
	if (check_ppid == 1) {
		struct task_struct *task, *parent;
		pid_t ppid;

		if (mytask)
			task = mytask;
		else
			task = (struct task_struct *)bpf_get_current_task();

		bpf_core_read(&parent, sizeof(parent), &task->parent);
		if (parent) {
			bpf_core_read(&pid, sizeof(pid), &task->pid);
			bpf_core_read(&ppid, sizeof(ppid), &parent->pid);
			if (bpf_map_lookup_elem(&ppid_include, &ppid))
				return true;
		}

		return false;
	}

	/* Check if the given pid needs to be excluded from sampling */
	if (bpf_map_lookup_elem(&pid_exclude, &pid))
		return false;

	/* Check if the given pid needs to be sampled */
	if (bpf_map_lookup_elem(&pid_include, &nilpid))
		return true;

	/*
	 * Finally, the check whether to sample every pid in the system or
	 * not.
	 */
	if (bpf_map_lookup_elem(&pid_include, &pid))
		return true;

	return false;
}

static bool valid_pid(pid_t pid)
{
	return valid_pid_with_task(pid, NULL);
}

#ifdef CPU_AMD_X8664
#include "../arch/x86/amd/memory_profiler.c"
#include "../arch/x86/amd/lbr_profiler.c"
#else
#include "../arch/x86/others/memory_profiler.c"
#include "../arch/x86/others/lbr_profiler.c"
#endif
#include "profiler_kern_common.c"
#include "memstats_kern.c"
#include "processtats_kern.c"
#include "lbr_kern.c"
#include "profiler_kern.c"
#include "heap_kern.c"

char _license[] SEC("license") = "GPL";
