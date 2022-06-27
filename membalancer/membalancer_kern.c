/*
 * IBS sampler : Arm IBS fetch and op sampling, collect both kernel and
 * process samples.
 *
 * Copyright 2022 AMD, Inc.
 */
#include <linux/version.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <bpf/bpf_helpers.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/socket.h>
#include <bpf/bpf_endian.h>
#include <linux/perf_event.h>

#include "membalancer.h"

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
	__type(key, u64);
	__type(value, struct value_data);
	__uint(max_entries, MAX_STORED_PAGES);
} op_page SEC(".maps");

/*
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct value_cmd);
	__uint(max_entries, 16384);
} cmd_map SEC(".maps");
*/

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

static int check_ppid = -1;

static volatile u64 ibs_fetches, ibs_ops;
unsigned long __atomic_fetch_add_N(volatile u64 *ptr, u64 val, int ordering);

/*
#define ATOMIC_READ(v) __atomic_fetch_add((v), 0, __ATOMIC_SEQ_CST)
#define ATOMIC_READ(v) __sync_fetch_and_add_N((v), 0)
#define ATOMIC_READ(v) (*v)
*/
#define ATOMIC_INC(v)  __atomic_add_fetch((v), 1, __ATOMIC_SEQ_CST)
#define ATOMIC_READ(v) atomic64_read((atomic64_t *)(v))

static inline void inc_ibs_fetch_samples(void)
{
        int key = 0;
	u64 value;

	ATOMIC_INC(&ibs_fetches);
	value = ATOMIC_READ(&ibs_fetches);
        bpf_map_update_elem(&fetch_counter, &key, &value, BPF_ANY);
}

static inline void inc_ibs_op_samples(void)
{
        int key = 0;
	u64 value;

	ATOMIC_INC(&ibs_ops);
	value = ATOMIC_READ(&ibs_ops);
        bpf_map_update_elem(&op_counter, &key, &value, BPF_ANY);
}

static bool valid_pid(pid_t pid)
{
	pid_t nilpid;

	nilpid = -1;

	if (unlikely(check_ppid == -1)) {
		if (bpf_map_lookup_elem(&ppid_include, &nilpid)) {
			check_ppid = 0;
		} else {
			check_ppid = 1;
		}
	}

	if (check_ppid == 1) {
		struct task_struct *task, *parent;
		pid_t ppid;

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

	if (bpf_map_lookup_elem(&pid_exclude, &pid))
		return false;

	if (bpf_map_lookup_elem(&pid_include, &nilpid))
		return true;

	if (bpf_map_lookup_elem(&pid_include, &pid))
		return true;

	return false;
}

#if 1
#define INC_COUNTER(counts, node, i) \
	if (node == i)  {    \
		ATOMIC_INC(&counts[i]); \
		return;      \
	}
#else
#define INC_COUNTER(counts, node, i) \
	if (node == i)  {    \
		counts[i]++; \
		return;      \
	}
#endif

#define INC_8_COUNTERS(counts, node) \
	INC_COUNTER(counts, node, 0); \
	INC_COUNTER(counts, node, 1); \
	INC_COUNTER(counts, node, 2); \
	INC_COUNTER(counts, node, 3); \
	INC_COUNTER(counts, node, 4); \
	INC_COUNTER(counts, node, 5); \
	INC_COUNTER(counts, node, 6); \
	INC_COUNTER(counts, node, 7); \
	INC_COUNTER(counts, node, MAX_NUMA_NODES-1); \

static void save_node_usage(pid_t pid, volatile u32 *counts)
{
	int *nodep, node;

        nodep = bpf_map_lookup_elem(&pid_node_map, &pid);
	if (!nodep)
		return;

	node = *nodep;

	/*
	if (node >=  MAX_NUMA_NODES)
		return;

	counts[node]++;
	*/

	INC_8_COUNTERS(counts, node);
}

SEC("perf_event")
int ibs_fetch_event(struct bpf_perf_event_data *ctx)
{
	struct value_fetch init_val, *value;
	u64 ip, key;
	struct bpf_perf_event_data_kern *kern_ctx;
	struct perf_sample_data *data = NULL;
	struct perf_raw_record *raw = NULL;
	struct perf_ibs_fetch_data *ibs_data;
	struct perf_raw_frag frag;
	void *addr;
	u64 tgid;

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

	if (IBS_KERN_SAMPLE(ip))
		return 0;
#ifdef MEMB_USE_VA
	key = init_val.fetch_regs[IBS_FETCH_LINADDR];
#else
	key = init_val.fetch_regs[IBS_FETCH_PHYSADDR];
#endif
	key &= ~(CCMD_PAGE_SIZE - 1);

	value = bpf_map_lookup_elem(&ibs_fetch_map, &key);
	if (value) {
		/*
		++value->count;
		*/
		ATOMIC_INC(&value->count);
		if (IBS_KERN_SAMPLE(ip) && !value->data_saved) {
			value->data_saved = 1;
		}

		save_node_usage(tgid, value->counts);

		inc_ibs_fetch_samples();
	} else {
		int i;
		init_val.data_saved = 0;
		init_val.count = 1;
		init_val.tgid = tgid;

		for (i = 0; i < MAX_NUMA_NODES; i++)
			init_val.counts[i] = 0;

		save_node_usage(tgid, init_val.counts);

		/* If its is akernel sample or user sample with process id
		 * then record it.
		 */
		if ((IBS_KERN_SAMPLE(ip) || init_val.tgid)) {
			bpf_map_update_elem(&ibs_fetch_map, &key, &init_val,
					    BPF_NOEXIST);
			inc_ibs_fetch_samples();
		}
	}

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
	u64 key, ip;
	void *addr;
	struct value_op init_val, *value;
	u64 tgid;

	tgid = bpf_get_current_pid_tgid();
	if (!valid_pid(tgid >> 32))
		return 0;

	ip = PT_REGS_IP(&ctx->regs);
	if (IBS_KERN_SAMPLE(ip))
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

#ifdef MEMB_USE_VA
	key = init_val.op_regs[IBS_DC_LINADDR];
#else
	key = init_val.op_regs[IBS_DC_PHYSADDR];
#endif
	key &= ~(CCMD_PAGE_SIZE - 1);
	value = bpf_map_lookup_elem(&ibs_op_map, &key);
	if (value) {
		/*
		if ((value->op_regs[IBS_DC_PHYSADDR] &
			(~(CCMD_PAGE_SIZE - 1))) !=
		     (init_val.op_regs[IBS_DC_PHYSADDR] &
			(~(CCMD_PAGE_SIZE - 1)))) {
			return 0;
		}
		*/

		ATOMIC_INC(&value->count);
		/*
		++value->count;
		*/
		if (IBS_KERN_SAMPLE(ip) && !value->data_saved) {
			value->data_saved = 1;
		}
		save_node_usage(tgid, value->counts);
		inc_ibs_op_samples();
	} else {
		int i;

		init_val.data_saved = 0;
		init_val.count = 1;
		init_val.tgid = tgid;

		for (i = 0; i < MAX_NUMA_NODES; i++)
			init_val.counts[i] = 0;

		save_node_usage(tgid, init_val.counts);
		/*
		init_val.op_regs[IBS_OP_CTL] = regs[IBS_OP_CTL];
		init_val.op_regs[IBS_OP_RIP] = regs[IBS_OP_RIP];
		init_val.op_regs[IBS_OP_DATA] = regs[IBS_OP_DATA];
		init_val.op_regs[IBS_OP_DATA2] = regs[IBS_OP_DATA2];
		init_val.op_regs[IBS_OP_DATA3] = regs[IBS_OP_DATA3];
		init_val.op_regs[IBS_DC_LINADDR] = regs[IBS_DC_LINADDR];
		init_val.op_regs[IBS_DC_PHYSADDR] = regs[IBS_DC_PHYSADDR];
		*/

		/* If its is akernel sample or user sample with process id
		 * then record it.
		 */
		if (init_val.op_regs[IBS_DC_PHYSADDR] != (u64)-1 &&
			(IBS_KERN_SAMPLE(ip) || init_val.tgid)) {
			bpf_map_update_elem(&ibs_op_map, &key, &init_val,
					    BPF_NOEXIST);
			inc_ibs_op_samples();
		}
	}
	
	return 0;
}

SEC("tracepoint/sched/sched_waking")
int sched_wakeup(struct sched_wakeup *wakeup)
{
        int cpu = 0, node, *nodep = NULL;
        pid_t pid = wakeup->pid;

        if (!valid_pid(pid))
                return 0;

        cpu = wakeup->target_cpu;

        nodep = bpf_map_lookup_elem(&cpu_map, &cpu);
        if (nodep) {
                node = *nodep;

                bpf_map_update_elem(&pid_node_map, &pid, &node, BPF_ANY);
        }

	return 0;
}

char _license[] SEC("license") = "GPL";
