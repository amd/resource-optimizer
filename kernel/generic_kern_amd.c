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
	__type(key, u64);
	__type(value, struct value_data);
	__uint(max_entries, MAX_STORED_PAGES);
} op_page SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, TOTAL_KNOBS);
} knobs SEC(".maps");

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
static bool per_numa_access_stats = true;
static bool per_numa_latency_stats = false;
static unsigned long config_done = 0;
static unsigned int kern_verbose;
static pid_t my_own_pid;
static bool user_space_only = false;
static unsigned long my_page_size;

static volatile u64 ibs_fetches, ibs_ops;
unsigned long __atomic_fetch_add_N(volatile u64 *ptr, u64 val, int ordering);

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
		}

		if (i == MY_PAGE_SIZE)  {
			if ((valuep != NULL) && (*valuep != 0))
				my_page_size = *valuep;
		}

		if (i == PER_NUMA_ACCESS_STATS) {
			if (valuep != NULL && (*valuep == 1))
				per_numa_access_stats = true;
			else
				per_numa_access_stats = false;

		}

		if (i == PER_NUMA_LATENCY_STATS) {
			if (valuep != NULL && (*valuep == 1))
				per_numa_latency_stats = true;
			else
				per_numa_latency_stats = false;
		}

		if (i == KERN_VERBOSE) {
			if (valuep != NULL && (*valuep > 0))
				kern_verbose = *valuep;
		}

		if (i == MY_OWN_PID) {
			if (valuep != NULL && (*valuep > 0))
				my_own_pid = *valuep;
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

	if (!per_numa_access_stats)
		return;

        nodep = bpf_map_lookup_elem(&pid_node_map, &pid);
	if (!nodep) {
		if (kern_verbose >= 5) {
			/*
			char msg[] = "NODE not found pid %d node %p";
			bpf_trace_printk(msg, sizeof(msg), pid, nodep);
			*/
		}
		return;
	}

	if (kern_verbose >= 5) {
		char msg[] = "NODE FOUND pid %d node %d";
		bpf_trace_printk(msg, sizeof(msg), pid, *nodep);
	}


	node = *nodep;

	/*
	if (node >=  MAX_NUMA_NODES)
		return;

	counts[node]++;
	*/

	INC_8_COUNTERS(counts, node);
}

#ifdef MEMBALANCER_USER_CLZ
static unsigned int int_log2(unsigned int n)
{
	unsigned int leading_zeroes;

	if (n <= 0)
		return n;

	if (n == 1)
		return 0;

	if (n == 2)
		return 1;

	leading_zeroes = __builtin_clz(n);
	/*
	 * Check if the bit that follows the leading non-zero bit is set it. If
	 * so, round the result to the next integer by adding 1 to the result.
	 */
	n <<= leading_zeroes;
	n &= (1 << 31);

	if (!n)
		return sizeof(n) * 8 - leading_zeroes - 1;

	return sizeof(n) * 8 - leading_zeroes;
}
#else
static int int_log2(int value)
{
	int i, n;

	n = value;

	i = 0;

	n /= 2;
	while (n > 0) {
		i++;
		n >>= 1;
	}

	if (i > 1) {
		if (((1 << i) + (1 << (i - 1))) < value)
			i++;
	}

	return i;
}
#endif

static inline void save_latency(u32 latency, volatile u32 *latency_arr, bool op)
{
	int idx;

	idx = int_log2(latency);
	if (1) {
                char msg[] = "OP latency %d idx %d op %d";
                bpf_trace_printk(msg, sizeof(msg), latency, idx, op);
	}

	if ((idx < 0) || (idx >= MAX_LATENCY_IDX))
                return;

	ATOMIC_INC(&latency_arr[idx]);
}

static void save_fetch_latency(u64 reg, struct value_fetch *valuep)
{
	u32 latency;

	if (!per_numa_latency_stats)
		return;

	if (!IBS_FETCH_LLC_MISS(reg))
		return;

	latency = reg >> 32;
	latency &= (latency << 16) >> 16;
	save_latency(latency, valuep->latency, false);
}

static void save_op_latency(u64 reg, struct value_op *valuep)
{
	u32 latency;

	if (!per_numa_latency_stats)
		return;

	if (!IBS_OP_LLC_MISS(reg))
		return;

	latency = reg >> 32;
	latency &= (latency << 16) >> 16;
	save_latency(latency, valuep->latency, true);
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

#ifdef MEMB_USE_VA
	key = init_val.fetch_regs[IBS_FETCH_LINADDR];
#else
	key = init_val.fetch_regs[IBS_FETCH_PHYSADDR];
#endif
	if (my_page_size > 0)
		key &= ~(my_page_size - 1);

	value = bpf_map_lookup_elem(&ibs_fetch_map, &key);
	if (value) {
		ATOMIC_INC(&value->count);
		if (IBS_KERN_SAMPLE(ip) && !value->data_saved) {
			value->data_saved = 1;
		}

		save_node_usage(tgid >> 32,  value->counts);

		inc_ibs_fetch_samples();
		save_fetch_latency(init_val.fetch_regs[IBS_FETCH_CTL], value);
	} else {
		int i;
		init_val.data_saved = 0;
		init_val.count = 1;
		init_val.tgid = tgid;

		for (i = 0; i < MAX_NUMA_NODES; i++)
			init_val.counts[i] = 0;

		for (i = 0; i < MAX_LATENCY_IDX; i++)
			init_val.latency[i] = 0;

		save_node_usage(tgid >> 32, init_val.counts);

		/* If its is akernel sample or user sample with process id
		 * then record it.
		 */
		if ((IBS_KERN_SAMPLE(ip) || init_val.tgid)) {
			bpf_map_update_elem(&ibs_fetch_map, &key, &init_val,
					    BPF_NOEXIST);
			inc_ibs_fetch_samples();
			save_fetch_latency(init_val.fetch_regs[IBS_FETCH_CTL],
					   &init_val);
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

#ifdef MEMB_USE_VA
	key = init_val.op_regs[IBS_DC_LINADDR];
#else
	key = init_val.op_regs[IBS_DC_PHYSADDR];
#endif
	if (my_page_size > 0)
		key &= ~(my_page_size - 1);

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
		if (IBS_KERN_SAMPLE(ip) && !value->data_saved) {
			value->data_saved = 1;
		}
		save_node_usage(tgid >> 32, value->counts);
		save_op_latency(value->op_regs[IBS_OP_DATA3], value);
		/*
		inc_ibs_op_samples();
		*/
	} else {
		int i;

		init_val.data_saved = 0;
		init_val.count = 1;
		init_val.tgid = tgid;
		init_val.ip = ip;

		for (i = 0; i < MAX_NUMA_NODES; i++)
			init_val.counts[i] = 0;

		for (i = 0; i < MAX_LATENCY_IDX; i++)
			init_val.latency[i] = 0;



		save_node_usage(tgid >> 32, init_val.counts);
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
			save_op_latency(init_val.op_regs[IBS_OP_DATA3],
					&init_val);

		}
	}
	
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

char _license[] SEC("license") = "GPL";
