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
 * IBS sampler : Arm IBS fetch and op sampling, collect both kernel and
 * process samples.
 */
#include <linux/version.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <bpf/bpf_helpers.h>
#include <linux/perf_event.h>
#include <bpf/bpf_helpers.h>
#include <generic_kern_amd.h>

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
	__type(key, u64);
	__type(value, struct value_fetch);
	__uint(max_entries, MAX_IBS_SAMPLES);
} ibs_fetch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct value_op);
	__uint(max_entries, MAX_IBS_SAMPLES);
} ibs_op_map SEC(".maps");

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
	__uint(max_entries, MAX_CPUS);
} cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, int);
	__uint(max_entries, MAX_IBS_SAMPLES);
} pid_node_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, int);
        __type(value, u64);
        __uint(max_entries, 1);
} fetch_counter SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, int);
        __type(value, u64);
        __uint(max_entries, 1);
} op_counter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct value_latency);
	__uint(max_entries, MAX_IBS_SAMPLES);
} latency_map SEC(".maps");

static int check_ppid = -1;
static bool per_numa_access_stats = true;
static bool latency_stats = false;
static bool latency_stats_l3miss = false;
static unsigned long config_done = 0;
static unsigned int kern_verbose;
static pid_t my_own_pid;
static bool user_space_only = false;
static unsigned long my_page_size;

static volatile u64 ibs_fetches, ibs_ops;
static bool processtats;

static void save_fetch_latency(u64 reg, u64 addr, int idx);
static void save_op_latency(u64 reg, u64 addr, int idx);
static void save_node_usage(pid_t pid,
                     volatile u32 counts[MAX_NUMA_NODES]);
static int process_fetch_samples(u64 tgid,
				 struct value_fetch *fetch_data,
                                 u64 ip, u32 page_size);
static int process_op_samples(u64 tgid,
			      struct value_op *op_data,
			      u64 ip, u32 page_size);

static void load_numa_ranges(void);
static void update_process_statistics(u64 tgid, u64 address,
				      bool fetch);

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

		if (i == PROCESS_STATS) {
			if (valuep != NULL && (*valuep > 0)) {
				processtats = true;
				load_numa_ranges();
			}
		}

		if (i == USER_SPACE_ONLY)
			user_space_only = true;

	}

	if (check_ppid == 1) {
		pid_t nilpid = -1;
		if (bpf_map_lookup_elem(&ppid_include, &nilpid))
			check_ppid = 0;
	}
}

static inline void inc_ibs_fetch_samples(void)
{
        int key = 0;
	u64 value;

	ATOMIC_INC(&ibs_fetches);
	value = ATOMIC64_READ(&ibs_fetches);
        bpf_map_update_elem(&fetch_counter, &key, &value, BPF_ANY);
}

static inline void inc_ibs_op_samples(void)
{
        int key = 0;
	u64 value;

	ATOMIC_INC(&ibs_ops);
	value = ATOMIC64_READ(&ibs_ops);
        bpf_map_update_elem(&op_counter, &key, &value, BPF_ANY);
}

static inline int cpu_node_get(pid_t pid)
{
	int *nodep;

	nodep = bpf_map_lookup_elem(&pid_node_map, &pid);
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

		bpf_probe_read(&parent, sizeof(parent), &task->parent);
		if (parent) {
			bpf_probe_read(&pid, sizeof(pid), &task->pid);
			bpf_probe_read(&ppid, sizeof(ppid), &parent->pid);
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

SEC("perf_event")
int ibs_fetch_event(struct bpf_perf_event_data *ctx)
{
	struct value_fetch init_val;
	u64 ip;
	struct bpf_perf_event_data_kern *kern_ctx;
	struct perf_sample_data *data = NULL;
	struct perf_raw_record *raw = NULL;
	struct perf_ibs_fetch_data *ibs_data;
	struct perf_raw_frag frag;
	void *addr;
	u64 tgid, key;

	init_function();

	tgid = bpf_get_current_pid_tgid();
	if (!valid_pid(tgid >> 32))
		return 0;

	/* Collect samples from IBS Fetch registers */
	kern_ctx = (struct bpf_perf_event_data_kern *)ctx;

	bpf_probe_read(&data, sizeof(data), &(kern_ctx->data));
	bpf_probe_read(&raw, sizeof(raw), &(data->raw));
	bpf_probe_read(&frag, sizeof(frag), &(raw->frag));

	ibs_data = (struct perf_ibs_fetch_data *)frag.data;
	addr     = &ibs_data->data[0];
	
	bpf_probe_read(&init_val.fetch_regs, sizeof(init_val.fetch_regs), addr);

	if (!IBS_FETCH_PHYSADDR_VALID(init_val.fetch_regs[IBS_FETCH_CTL]))
			return 0;

	/* For IBS Fetch sample , the kernel gets the instruction pointer ip
	 * from the register IBS_FETCH_LINADDR. So there is no need to read
	 * the same again from perf raw data.
	 */
	ip = PT_REGS_IP(&ctx->regs);

	if (user_space_only && IBS_KERN_SAMPLE(ip))
		return 0;

	if (processtats == false)
		return process_fetch_samples(tgid, &init_val,
					      ip, my_page_size);

#ifdef MEMB_USE_VA
	key = init_val.fetch_regs[IBS_FETCH_LINADDR];
#else
	key = init_val.fetch_regs[IBS_FETCH_PHYSADDR];
#endif

	update_process_statistics(tgid, key, true);
	return 0;
}

SEC("perf_event")
int ibs_op_event(struct bpf_perf_event_data *ctx)
{
	struct bpf_perf_event_data_kern *kern_ctx;
	struct perf_sample_data *data = NULL;
	struct perf_raw_record *raw = NULL;
	struct perf_ibs_fetch_data *ibs_data;
	struct perf_raw_frag frag;
	u64 ip;
	void *addr;
	struct value_op init_val;
	u64 tgid, key;

	init_function();

	tgid = bpf_get_current_pid_tgid();
	if (!valid_pid(tgid >> 32))
		return 0;

	ip = PT_REGS_IP(&ctx->regs);
	if (user_space_only && IBS_KERN_SAMPLE(ip))
		return 0;

	/* Collect samples from IBS Fetch registers */
	kern_ctx = (struct bpf_perf_event_data_kern *)ctx;

	bpf_probe_read(&data, sizeof(data), &(kern_ctx->data));
	bpf_probe_read(&raw, sizeof(raw), &(data->raw));
	bpf_probe_read(&frag, sizeof(frag), &(raw->frag));

	ibs_data = (struct perf_ibs_fetch_data *)frag.data;
	addr     = &ibs_data->data[0];
	
	bpf_probe_read(&init_val.op_regs[0], sizeof(init_val.op_regs),
			addr);


	if (!IBS_OP_LINADDR_VALID(init_val.op_regs[IBS_OP_DATA3]))
		return 0;

	if (!IBS_OP_PHYSADDR_VALID(init_val.op_regs[IBS_OP_DATA3]))
		return 0;

	if (processtats == false)
		return process_op_samples(tgid, &init_val, ip, my_page_size);

#ifdef MEMB_USE_VA
	key = init_val.op_regs[IBS_DC_LINADDR];
#else
	key = init_val.op_regs[IBS_DC_PHYSADDR];
#endif
	update_process_statistics(tgid, key, false);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
SEC("tracepoint/sched/sched_waking")
int save_process_cpu(struct sched_wakeup *wakeup)
{
        int cpu = 0, node, *nodep = NULL;
        pid_t pid = wakeup->pid;

	init_function();

        if (!valid_pid(pid))
                return 0;

        cpu = wakeup->target_cpu;

        nodep = bpf_map_lookup_elem(&cpu_map, &cpu);
        if (nodep) {
                node = *nodep;

                bpf_map_update_elem(&pid_node_map, &pid, &node, BPF_ANY);
        }

	if (kern_verbose >= 5) {
        	if (nodep) {
                	char msg[] = "PID %d cpu %d node %d";
                	bpf_trace_printk(msg, sizeof(msg), pid, cpu, node);
		} else {
                	char msg[] = "bpf_map_lookup_elem failed pid %d cpu %d";
                	bpf_trace_printk(msg, sizeof(msg), pid, cpu);
		}
        }

	return 0;
}
#else
SEC("kprobe/finish_task_switch")
int save_process_cpu(struct pt_regs *ctx)
{
        pid_t pid;
        int cpu = 0, node, *nodep = NULL;
        struct task_struct *task = (void *) PT_REGS_PARM1(ctx);

        if (!task)
		return 0;

	bpf_probe_read(&pid, sizeof(pid), &task->pid);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,19,0)
	bpf_probe_read(&cpu, sizeof(cpu), &task->cpu);
#else
	bpf_probe_read(&cpu, sizeof(cpu), &task->on_cpu);
#endif

        if (!valid_pid_with_task(pid, task))
                return 0;

        init_function();

        nodep = bpf_map_lookup_elem(&cpu_map, &cpu);
        if (nodep) {
                node = *nodep;

                bpf_map_update_elem(&pid_node_map, &pid, &node, BPF_ANY);
	}

	if (kern_verbose >= 5) {
        	if (nodep) {
                	char msg[] = "PID %d cpu %d node %d";
                	bpf_trace_printk(msg, sizeof(msg), pid, cpu, node);
		} else {
                	char msg[] = "bpf_map_lookup_elem failed pid %d cpu %d";
                	bpf_trace_printk(msg, sizeof(msg), pid, cpu);
		}
        }

        return 0;
}
#endif

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(struct sched_exit *exit)
{
        pid_t pid = exit->pid;

        if (!valid_pid(pid))
                return 0;

        bpf_map_delete_elem(&pid_node_map, &pid);

        return 0;
}
#include "memstats_kern.c"
#include "processtats_kern.c"


char _license[] SEC("license") = "GPL";
