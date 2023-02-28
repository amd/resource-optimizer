/*
 * membalancer_user.c - Automatic NUMA memory balancer Based on IBS sampler
 *
 * Copyright (c) 2015 The Libbpf Authors. All rights reserved.
 * Copyright (c) 2023 Advanced Micro Devices, Inc.
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

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <perf-sys.h>
#include <trace_helpers.h>
#include <assert.h>
#include <numa.h>
#include <numaif.h>
#include <time.h>
#include <pthread.h>
#include <limits.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/wait.h>
#include <ctype.h>
#include <search.h>
#include <sched.h>

#include "membalancer_common.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"
#include "membalancer_migrate.h"
#include "heap_user.h"
#include "membalancer_user.h"

#define MEMB_CLOCK 25 
#define MEMB_INTVL 100
#define MIN_IBS_CLASSIC_SAMPLES 200
#define MIN_IBS_L3MISS_SAMPLES  200
#define MIN_IBS_SAMPLES min_ibs_samples
#define MIN_IBS_FETCH_SAMPLES (MIN_IBS_SAMPLES / 4)
#define MIN_IBS_OP_SAMPLES    (MIN_IBS_SAMPLES / 2)
#define MIN_CNT 1
#define MIN_PCT 1.75
#define MIN_MIGRATED_PAGES 	1024
#define MIN_MIGRATED_PAGES_TIER 4096

static int nr_cpus;
static double min_pct = 0.01;
static bool user_space_only = false;
int verbose = 2;

bool do_migration = false;
enum tuning_mode tuning_mode = MEMORY_MOVE;

bool histogram_format = false;
static float maximizer_mode = 0.2;
int report_frequency = 1;
static char *trace_dir;
bool tracer_physical_mode = true;
static unsigned int min_ibs_samples = MIN_IBS_CLASSIC_SAMPLES;
static int migration_timeout_sec = 60;
static int min_migrated_pages = MIN_MIGRATED_PAGES;

static char cmd_args[]  = "c:f:F:P:p:r:m:M:v:U:T:t:D:L:B:uhcbHVlS::";
static int ibs_fetch_device = -1;
static int ibs_op_device    = -1;
#define FETCH_CONFIG        57
#define FETCH_CONFIG_L3MISS 59
#define OP_CONFIG           19
#define OP_CONFIG_L3MISS    16

static int ibs_fetch_config;
static int ibs_op_config;
static unsigned int cpu_nodes;
static pid_t mypid;
static bool l3miss = false;

static u32 sampling_interval_cnt = 100;
static u32 sampling_iter;
bool proc_data_sampling_done = false;
u32 curr_proc_data_map_idx;

static int min_freemem_pct = 10;

static atomic64_t fetch_cnt, op_cnt, pages_migrated;

#define IBS_FETCH_DEV "/sys/devices/ibs_fetch/type"
#define IBS_OP_DEV    "/sys/devices/ibs_op/type"

struct ibs_fetch_sample fetch_samples[MAX_NUMA_NODES][MAX_IBS_SAMPLES];
unsigned long fetch_samples_max[MAX_NUMA_NODES];
unsigned long fetch_samples_cnt[MAX_NUMA_NODES];


#define PAGES_PER_CALL 32
#define MAX_PAGES_PER_CALL 65536
#define PAGE_MOVERS 8

struct page_list {
	struct page_list *next;
	int pages;
	pid_t pid;
	unsigned long pagelist[PAGES_PER_CALL];
	int           nodelist[PAGES_PER_CALL];
	int           status[PAGES_PER_CALL];
};

struct page_mover {
	pthread_mutex_t   mtx;
	pthread_cond_t    cv;
	struct page_list *head;
	struct page_list *tail;
	pthread_t         thread;
	int stop;
};

struct ibs_sample_worker {
	pthread_mutex_t   mtx;
	pthread_cond_t    cv;
	pthread_t         thread;
	int stop;
	int *map_fd;
	int msecs;
	int worker;
};

#define IBS_SAMPLE_WORKERS 1

static struct page_mover page_mover[PAGE_MOVERS];
static struct ibs_sample_worker ibs_worker[IBS_SAMPLE_WORKERS];
static atomic64_t ibs_workers;
static atomic64_t ibs_pending_fetch_samples;
static atomic64_t ibs_pending_op_samples;

 struct ibs_op_sample op_samples[MAX_NUMA_NODES][MAX_IBS_SAMPLES];
unsigned long op_samples_max[MAX_NUMA_NODES];
unsigned long op_samples_cnt[MAX_NUMA_NODES];

static void * page_move_function(void *arg);
static unsigned long upgrade_align   = 256 * PAGE_SIZE; 
static unsigned long downgrade_align = 256 * PAGE_SIZE; 

static void usage(const char *cmd)
{
	printf("USAGE: %s [-f freq] [-p <pid,..>] [-P <parent pid,..>] "
			"[-u] [-h] [-H] [-V] [-l] [-M]"
			"[-T <numa tier information> ] [-b]"
			"[-{autotune, memory, process} <sampling count>]"
			"[-m <percentage>] "
			"[-v <verbose>] [-U <Upgrade size in bytes] "
			"[-D <Downgrade size in bytes] "
			"[duration]\n", cmd);
	printf("       -f <freq>    # sample frequency (Hertz), default %d Hz\n",
			MEMB_CLOCK);
	printf("       -p <pid> Process ID to be tracked\n");
	printf("       -P <pid> Parent Process ID to be tracked\n");
	printf("       -c list of cpus to collect samples on <comma separated"
			"or range with hyphen>\n");
	printf("       -u Only user space samples\n");
	printf("       -h help, displays this information\n");
	printf("       -H show histograms\n");
	printf("       -V <level>, Verbose level\n");
	printf("       -l Collects only l3miss IBS samples\n");
	printf("       -m Minimum percentage of samples to be considered\n"
			"          for processing hot pages, default %4.2lf\n",
			min_pct);
	printf("       -M Maximizer mode to increase "
			"the frequency of samples' collection\n");
	printf("        -T <tier information> where\n"
			"         the teir information defines two or more "
			"tiers with a tuple for \n"
			"         each tier\n\n"
			"        <tier_num>:"
			" <comma seperated nodes in the tier>:\n"
			"        <promote_pct>:<tier_num_for_promotion>:"
			" <promotion_cap_in_bytes>:\n"
			"        <demote_pct>:<tier_num_for_demotion>:"
			" <deomotion_cap_in_bytes>\n"
			"        [-<tier_num>:<...>]\n");
	printf("       -F minimum percentage of free memory in a node "
			"to perform migraitons to it\n");
	printf("       <duration> Interval in milliseconds, "
	       "default %d\n", MEMB_INTVL);

	printf("\nExamples\n\n");
	printf("1. Example for a 3-tier memory configuration\n");
	printf("%s -f 25 -u -P 1234 -v1 -m 0.0001 -M 1 -r 2 100 -b\n"
	      "-T 0:0:0:0:0:1:1:0-1:1:1:0:0:1:2:0-2:2,3:5:1:0:0:0:0\n"
	      "-H -U 1048576 -D 1048576\n", cmd);
	printf("Where the tiers 0, 1 and 2 contain "
		"the nodes {0}, {1}, {2, 3} respectively.\n");
	printf("\n");
	printf("2. Example for NUMA balancer configuration:\n");
	printf("%s -f 25 -u -P 1234 -v1 -m 0.0001 -M 1 -r 2 100 -S memory -b\n"
	       "-H -U 1048576 -D 1048576\n", cmd);
	printf("\n");
	printf("3. Example for memory access pattern\n");
	printf("%s -f 25 -u -P 1234 -v1 -m 0.0001 -M 1 -r 2 100 -S memory\n",
	       cmd);
	printf("\n");
	printf("4. Example for Process migration configuration:\n");
	printf("%s -f 25 -u -P 1234 -v1 -m 0.0001 -M 1 -r 2 1000 "
	       "-H -S process -b\n", cmd);
	printf("\n");
	printf("5. Example for Process cpu and memory access pattern\n");
	printf("%s -f 25 -u -P 1234 -v1 -m 0.0001 -M 1 -r 2 1000"
	       "-H -S process\n", cmd);
	printf("\n");
	printf("6. Example for Auto-tuning configuration:\n");
	printf("%s -f 25 -u -P 1234 -v1 -m 0.0001 -M 1 -r 2 1000 -H\n"
	       "-S autotune 200\n"
	       "default sampling count %u\n", cmd, sampling_interval_cnt);
	printf("\n");
	printf("7. Example for memory access tracer or pattern analyzer\n");
	printf("%s -f 25 -u -P 99053 -v1 -m 0.0001 -M 1 -r 2 1000 -L /tmp/ \n",
	       cmd);
	printf("8. Example for list of cpus\n");
	printf("%s -u -P 99053 -c 1,2,3,10-20,30-40\n",cmd);
	printf("\n");
}

struct tune_mode {
	int mode_enum;
	char* mode_str;
};

#define MAX_MODES 3

static
struct tune_mode mode_array[MAX_MODES] = { { AUTOTUNE, "autotune" },
                                           { MEMORY_MOVE, "memory" },
                                           { PROCESS_MOVE, "process"} };
static int get_balancing_mode(char *mode_str)
{
	int i = 0;
	for (i = 0; i < MAX_MODES; i++) {
		if (strcasecmp(mode_str, mode_array[i].mode_str) == 0) {
			return mode_array[i].mode_enum;
		}
	}
	return -1;
}

int freemem_threshold(void)
{
	return min_freemem_pct;
}

static int get_ibs_device_type(const char *dev)
{
	int fd, ret;
	char buffer[32];

	fd = open(dev, O_RDONLY);
	if (fd < 0)
		return -1;

	memset(buffer, 0, sizeof(buffer));
	ret = read(fd, &buffer, sizeof(buffer));
	close(fd);

	if (ret < 0)
		return -1;

	return atoi(buffer);
}

static void open_ibs_devices(void)
{
	ibs_fetch_device = get_ibs_device_type(IBS_FETCH_DEV);
	ibs_op_device    = get_ibs_device_type(IBS_OP_DEV);
}

static int add_pid(int fd,  char *pid_string)
{
	int i, j;
	pid_t pid, from_pid, to_pid;
	char *hyphen, *from, *to;

	hyphen = strchr(pid_string, '-');
	if (hyphen) {
		*hyphen = 0;
		from = pid_string;
		to   =  ++hyphen;

		from_pid = atoi(from);
		to_pid = atoi(to);

		for (i = from_pid; i <= to_pid; i++)
			bpf_map_update_elem(fd, &i, &i, BPF_NOEXIST);

		return 0;
	}

	i = 0;
	while (pid_string[i]) {
		j = i;
		
		while (pid_string[j] != ',' && pid_string[j] != 0)
			j++;

		if (pid_string[j] == ',') {
			pid_string[j] = 0;
			j++;
		}
		
		pid = atoi(&pid_string[i]);
		if (!mypid)
			mypid = pid;
		bpf_map_update_elem(fd, &pid, &pid, BPF_NOEXIST);
		i = j;
	}

	close(fd);

	return 0;
}

static int process_include_pids(struct bpf_object *obj, char *pid_string,
				bool ppid)
{
	int fd, pid;

	if (ppid)
		fd = bpf_object__find_map_fd_by_name(obj, "ppid_include");
	else
		fd = bpf_object__find_map_fd_by_name(obj, "pid_include");

	if (fd < 0) {
		fprintf(stderr, "Cannot open pid filter map\n");
		return -EINVAL;
	}

	if (pid_string == NULL) {
		pid = -1;
		bpf_map_update_elem(fd, &pid, &pid, BPF_NOEXIST);
		close(fd);
		return 0;
	}

	return add_pid(fd, pid_string);
}

static bool is_cpu_online(int cpu)
{
	int fd, ret;
	char online;
	char dev[1024];

	snprintf(dev, sizeof(dev),
		"/sys/devices/system/cpu/cpu%d/online", cpu);
	fd = open(dev, O_RDONLY);
	if (fd < 0)
		return false;

	online = 0;
	ret = read(fd, &online, sizeof(online));
	close(fd);

	if (ret < 0)
		return false;

	return online;
}

static const char *next_token(const char *q,  int sep)
{
	q = strchr(q, sep);
	if (q)
		q++;

	return q;
}

static int next_number(const char *str, char **end, unsigned int *result)
{
	unsigned int ret;
	errno = 0;
	if (str == NULL || *str == '\0' || !isdigit(*str))
		return -EINVAL;

	ret = (unsigned int) strtoul(str, end, 10);
	if (errno)
		return -errno;
	if (str == *end)
		return -EINVAL;

	*result = ret;

	return 0;
}

static int attach_perfevent(cpu_set_t *cpusetp, struct bpf_link *links[],
		struct bpf_program *prog, struct perf_event_attr *perf) {
	int pmu_fd;
	int cpu = 0;

	while( cpu < nr_cpus ) {

		if(!CPU_ISSET(cpu, cpusetp)) {
			cpu++;
			continue;
		}
		pmu_fd = sys_perf_event_open(perf, -1, cpu, -1, 0);
		if (pmu_fd < 0) {
			fprintf(stderr, "Cannot arm software sampling\n");
			return 1;
		}
		links[cpu] = bpf_program__attach_perf_event(prog, pmu_fd);
		if (libbpf_get_error(links[cpu])) {
			fprintf(stderr, "ERROR: Attach perf event\n");
			links[cpu] = NULL;
			close(pmu_fd);
			return 1;
		}
		cpu++;
	}
	return 0;
}

static int parse_cpulist(const char* cpu_list, cpu_set_t *cpusetp,
		size_t set_size)
{
	const char *p, *q;
	char *end = NULL;
	unsigned int from; /* start of range */
	unsigned int to; /* end of range */
	const char *c1,*c2;
	int err;


	q = cpu_list;
	p = q;
	while (p) {
		q = next_token(q,',');
		err = next_number(p, &end, &from);
		if (err)
			return err;
		to = from;
		p = end;

		c1 = next_token(p, '-');
		c2 = next_token(p, ',');

		if (c1 != NULL && (c2 == NULL || c1 < c2)) {
			err = next_number(c1, &end, &to);
			if (err)
				return err;
		}
		if (from > to)
			return -EINVAL;

		while (from <= to) {
			if (from >= nr_cpus)
				return -EINVAL;
			if (!is_cpu_online(from)) {
				from++;
				continue;
			}
			CPU_SET_S(from, set_size, cpusetp);
			from++;
		}
		p = q;
	}

	return 0;
}

static int perf_sampling_begin(int freq, struct bpf_program *prog,
				struct bpf_link *links[],
				cpu_set_t *cpusetp)
{
	struct perf_event_attr perf = {
		.freq = 1,
		.type = PERF_TYPE_SOFTWARE,
		.sample_period = freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
		.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_CPU,
		.disabled = 1,
		.inherit = 1,
		.size = sizeof(struct perf_event_attr),
		.exclude_kernel = 0,
		.exclude_user = 0,
		.exclude_idle = 0,
		.exclude_hv = 0,
		.exclude_host = 0,
		.exclude_guest = 0,
		.pinned = 0,
		.precise_ip = 0,
		.mmap = 1,
		.comm = 1,
		.task = 1,
		.sample_id_all = 1,
		.comm_exec = 1,
		.read_format = 0,
	};

	if (attach_perfevent(cpusetp, links, prog, &perf)){
		return 1;
	}

	return 0;
}

static int ibs_fetch_sampling_begin(int freq, struct bpf_program *prog,
				    struct bpf_link *links[],
				    cpu_set_t *cpusetp)
{
	struct perf_event_attr ibs_fetch = {
		.freq = 1,
		.type = ibs_fetch_device,
		.sample_period = freq,
		.config = (1ULL << ibs_fetch_config),
		.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_CPU,
				/*
				PERF_SAMPLE_ADDR | PERF_SAMPLE_ADDR |
				PERF_SAMPLE_PHYS_ADDR,
				*/
		.disabled = 1,
		.inherit = 1,
		.size = sizeof(struct perf_event_attr),
		.exclude_kernel = 0,
		.exclude_user = 0,
		.exclude_idle = 0,
		.exclude_hv = 0,
		.exclude_host = 0,
		.exclude_guest = 0,
		.pinned = 0,
		.precise_ip = 0,
		.mmap = 1,
		.comm = 1,
		.task = 1,
		.sample_id_all = 1,
		.comm_exec = 1,
		.read_format = 0,
	};

	if (ibs_fetch_device < 0)
		return -1;

	if (attach_perfevent(cpusetp, links, prog, &ibs_fetch)){
		return 1;
	}

	return 0;
}

static void ibs_sampling_end(struct bpf_link *links[])
{
	int i;
	int pmu_fd;

	for (i = 0; i < nr_cpus; i++) {
		if (links[i] == NULL)
			continue;

		pmu_fd = bpf_link__fd(links[i]);
		close(pmu_fd);
		bpf_link__destroy(links[i]);
		links[i] = NULL;
	}
}

static void ibs_fetchop_config_set(void)
{
	ibs_fetch_config = (l3miss) ? FETCH_CONFIG_L3MISS : FETCH_CONFIG;
	ibs_op_config    = (l3miss) ? OP_CONFIG_L3MISS : OP_CONFIG;
	min_ibs_samples  = (l3miss) ? MIN_IBS_L3MISS_SAMPLES :
			   MIN_IBS_CLASSIC_SAMPLES;
}


int ibs_op_sampling_begin(int freq, struct bpf_program *prog,
				struct bpf_link *links[],
				cpu_set_t *cpusetp)
{
	struct perf_event_attr ibs_op  = {
		.freq = 1,
		.type = ibs_op_device,
		.sample_period = freq,
		.config = (1ULL << ibs_op_config),
		.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_CPU,
		.disabled = 1,
		.inherit = 1,
		.size = sizeof(struct perf_event_attr),
		.exclude_kernel = 0,
		.exclude_user = 0,
		.exclude_idle = 0,
		.exclude_hv = 0,
		.exclude_host = 0,
		.exclude_guest = 0,
		.pinned = 0,
		.precise_ip = 0,
		.mmap = 1,
		.comm = 1,
		.task = 1,
		.sample_id_all = 1,
		.comm_exec = 1,
		.read_format = 0,
	};

	if (ibs_op_device < 0)
		return -1;

	if (attach_perfevent(cpusetp, links, prog, &ibs_op)){
		return 1;
	}

	return 0;
}

static int read_cpu_node(int cpu, char *buffer, int buffer_size)
{
	char filename[PATH_MAX];
	int fd, bytes;

	snprintf(filename, sizeof(filename),
		 "/sys/devices/system/node/node%d/cpumap", cpu);
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -EINVAL;

	bytes = read(fd, buffer, buffer_size);
	close(fd);

	return bytes;
}

static int populate_cpu_map(struct bpf_object *obj, int fd, int node,
			    char *cpu_map, int buflen)
{
	unsigned char next_cpuset;
	int next_cpu, i, j;
	int k;

	k = 0;
	CPU_ZERO(&node_cpumask[node]);

	for (i = buflen - 1; i >= 0; i--) {
		next_cpuset = (unsigned char)cpu_map[i];
		if (next_cpuset == '0') {
			k++;
			continue;
		}

		if (next_cpuset == ',')
			continue;

		assert(next_cpuset == 'f');
	
		for (j = 0; j < 4; j++) {
			next_cpu = k * 4 + j;
			CPU_SET(next_cpu, &node_cpumask[node]);
			bpf_map_update_elem(fd, &next_cpu, &node, BPF_NOEXIST);
		}
		k++;
	}


	return 0;
}

static int fill_cpu_nodes(struct bpf_object *obj)
{
	char cpu_map[1024];
	int node, fd, bytes;

	fd = bpf_object__find_map_fd_by_name(obj, "cpu_map");
	if (fd < 0)
		return -EINVAL;

	for (node = 0;; node++) {
		bytes = read_cpu_node(node, cpu_map, sizeof(cpu_map));
		if (bytes <= 1)
			break;

		populate_cpu_map(obj, fd, node, cpu_map, bytes - 1);
	}

	return node;
}

static int init_page_mover(void)
{
	int i, err;

	for (i = 0; i < PAGE_MOVERS; i++) {
		pthread_mutex_init(&page_mover[i].mtx, NULL);
		pthread_cond_init(&page_mover[i].cv, NULL);
		page_mover[i].head = NULL;
		page_mover[i].tail = NULL;
		page_mover[i].stop = 0;

		if (pthread_create(&page_mover[i].thread, NULL,
				   page_move_function, (void *)(long)i)) {
			err = -ENOMEM;
		}
	}

	if (i == PAGE_MOVERS)
		return 0;

	while (i >= 0) {
		pthread_mutex_lock(&page_mover[i].mtx);
		page_mover[i].stop = 1;
		pthread_cond_signal(&page_mover[i].cv);
		pthread_mutex_unlock(&page_mover[i].mtx);
	}

	return err;
}

static void page_mover_enqueue(struct page_list *page)
{
	static int next_queue;
	int next;
	struct page_mover *mover;

	next = next_queue;
	mover = &page_mover[next];

	++next_queue;
	next_queue %= PAGE_MOVERS;

	assert(page->next == NULL);

	pthread_mutex_lock(&mover->mtx);
	if (mover->head == NULL) {
		//assert(mover->tail == NULL);
		mover->head = mover->tail = page;
	} else {
		mover->tail->next = page;
		mover->tail = page;
	}
	pthread_cond_signal(&mover->cv);
	pthread_mutex_unlock(&mover->mtx);
}

static void page_mover_parallel_enqueue(struct page_list *list,
					unsigned long alignment)
{
	struct page_list *newlist;
	int i, j, k, pages;
	unsigned long page;

	if (alignment / PAGE_SIZE > MAX_PAGES_PER_CALL) {
		page_mover_enqueue(list);
		return;
	}

	for (i = 0; i < list->pages; i++) {
		page = list->pagelist[i] & ~(alignment - 1);
		pages = alignment / PAGE_SIZE;

		k = 0;
		newlist = malloc(sizeof(*newlist));
		assert(newlist);
		for (j = 0; j < pages; j++) {	

			newlist->pagelist[k] = page + j * PAGE_SIZE;
			newlist->nodelist[k] = list->nodelist[i];
			newlist->status[k] = 0;

			if (++k <= (PAGES_PER_CALL - 1))
				continue;

			newlist->pages = k;
			newlist->next = NULL;
			newlist->pid = list->pid;
			page_mover_enqueue(newlist);
			k = 0;
			newlist = malloc(sizeof(*newlist));
			assert(newlist);
		}
	}

	free(list);
}

static unsigned long milliseconds_elapsed(struct timeval *start,
					struct timeval *end)
{
	unsigned long milliseconds;

	milliseconds = (end->tv_sec - start->tv_sec) * 1000UL;
	milliseconds += (end->tv_usec - start->tv_usec) / 1000;

	return milliseconds;
}

static void * page_move_function(void *arg)
{
	int queue = (int)(long)arg;
	int count = 0;
	int err __attribute__((unused));
	struct page_mover *mover;
	struct page_list *page;
	struct timeval start, end;

	mover = &page_mover[queue];

	pthread_mutex_lock(&mover->mtx);
	do {
		while (!mover->head && !mover->stop) {
			pthread_cond_wait(&mover->cv, &mover->mtx);
			gettimeofday(&start, NULL);
		}

		if (!mover->head && mover->stop)
			break;

		assert(mover->head);
		page = mover->head;
		
		if (mover->head == mover->tail) {
			mover->head = mover->tail = NULL;
		} else {
			mover->head = mover->head->next;
		}
		pthread_mutex_unlock(&mover->mtx);

		assert(page->pages);

		err = move_pages(page->pid,  page->pages,
				(void **)&page->pagelist,
				page->nodelist,
				page->status,
				MPOL_MF_MOVE_ALL);
		count++;

		if (!(count % 10)) {
			gettimeofday(&end, NULL);
			if (milliseconds_elapsed(&start, &end) >= 100) {
				end = start;
				usleep(50000);
			}
		}
		{
			int i;
			for (i = 0; i < page->pages; i++) {
				if (page->status[i] == 0)
					atomic64_inc(&pages_migrated);
			}
		}

#ifdef DEBUG_ON	
		assert(err >= 0);
		{
			int i;
			for (i = 0; i < page->pages; i++) {
				if (page->status[i] == -EFAULT)
					continue;
				if (page->status[i] != page->nodelist[i])
					printf("Error %d-%d\n",
						page->status[i],
						page->nodelist[i]);
	
				assert(page->status[i] == page->nodelist[i]);
			}
		}	
#endif
		free(page);
		pthread_mutex_lock(&mover->mtx);

	} while (mover->head || !mover->stop);

	pthread_mutex_unlock(&mover->mtx);

	return NULL;
}

static int fetch_cmp(const void *p1, const void *p2)
{
	const struct ibs_fetch_sample *s1 = p1, *s2 = p2;
	
	return s1->count - s2->count;
}

static char * get_process(__u64 tgid)
{
	return "";
}

static unsigned long peek_ibs_samples(int fd, unsigned long old,
				      unsigned long *new)
{
	unsigned long messages, new_value;
	int key = 0;


	new_value = old;
	bpf_map_lookup_elem(fd, &key, &new_value);

	if (new_value  == old)
		return 0;

	if (new_value > old)
		messages = new_value - old;
	else
		messages = old - new_value + 1;

	*new = new_value;

	return messages;
}

static int get_ibs_fetch_samples(int fd,  __u64 *total_freq)
{
	__u64 key, next_key;
	struct value_fetch value;
	int i, j, max, node;
	long total = 0;
	unsigned long paddr;

	for (i = 0; i < max_nodes; i++) {
		fetch_samples_max[i] = 0;
		fetch_samples_cnt[i] = 0;
	}

	/* Process fetch samples from the map*/
	key = 0;
	i = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);

		atomic64_inc(&fetch_cnt);
#ifdef USE_PAGEMAP
		paddr = get_physaddr((pid_t)value.tgid,	
				value.fetch_regs[IBS_FETCH_LINADDR]);
		if (paddr == (unsigned long)-1) {
			key = next_key;
			bpf_map_delete_elem(fd, &next_key);
			continue;
		}

		paddr *= PAGE_SIZE;
		/*
		assert(paddr == (value.fetch_regs[IBS_FETCH_PHYSADDR] &
				 ~(MEMB_PAGE_SIZE - 1)));
		*/
#else
		paddr = value.fetch_regs[IBS_FETCH_PHYSADDR];
#endif

		node = get_current_node(paddr);
		assert(node >= -1 && node < (long)max_nodes);
		if (node < 0 || node >= (long)max_nodes) {
			bpf_map_delete_elem(fd, &next_key);
			key = next_key;
			continue;
		}

		if (i >= MAX_IBS_SAMPLES /*|| value.count < MIN_CNT*/) {
			bpf_map_delete_elem(fd, &next_key);
			key = next_key;
			continue;
		}


		fetch_samples[node][i].ip    = next_key;
		fetch_samples[node][i].count = value.count;
		fetch_samples[node][i].tgid  = value.tgid;

		for (j = 0; j < max_nodes; j++)
			fetch_samples[node][i].counts[j] = value.counts[j];

		if (!IBS_KERN_SAMPLE(fetch_samples[node][i].ip))
			snprintf(fetch_samples[node][i].process,
				sizeof(fetch_samples[node][i].process),
					"%s",
					get_process(value.tgid));

		fetch_samples[node][i].fetch_regs[IBS_FETCH_CTL] =
				value.fetch_regs[IBS_FETCH_CTL];
		fetch_samples[node][i].fetch_regs[IBS_FETCH_LINADDR] =
				value.fetch_regs[IBS_FETCH_LINADDR];
		fetch_samples[node][i].fetch_regs[IBS_FETCH_PHYSADDR] =
				value.fetch_regs[IBS_FETCH_PHYSADDR];
		
		total += fetch_samples[node][i].count;
		fetch_samples_max[node] += fetch_samples[node][i].count;
		i++;
		
		fetch_samples_cnt[node]++;
		key = next_key;
		bpf_map_delete_elem(fd, &next_key);
	}

	max = i;

	/* sort samples */
       for (node = 0; node < max_nodes; node++)
                qsort(fetch_samples[node], fetch_samples_max[node],
                      sizeof(struct ibs_fetch_sample), fetch_cmp);

	if (max >= MAX_IBS_SAMPLES) 
		printf("Processed maximum samples. "
		       "Likely to have dropped some. Increase the value of "
		       "MAX_IBS_SAMPLES\n");

	*total_freq = total;

	return max;
}

static void cleanup_fetch_samples(int fd)
{
	__u64 key, next_key;
	struct value_fetch value;
	int i, j;

	for (i = 0; i < max_nodes; i++) {
		fetch_samples_max[i] = 0;
		fetch_samples_cnt[i] = 0;
	}

	/* Process fetch samples from the map*/
	key = 0;
	i = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);

		bpf_map_delete_elem(fd, &next_key);
		key = next_key;

		for (j = 0; j < max_nodes; j++)
			fetch_samples[j][i].count = 0;

	}
}

#define MAX_BST_PAGES 8192
struct bst_node_dummy {
	pid_t pid;
	int pages;
};
struct bst_node {
	pid_t pid;
	int pages;
	bool upgrade;
	struct {
		int to_node;
		unsigned long addr;
	} page[MAX_BST_PAGES];
};


int bst_cmp(const void *firstp, const void *secondp)
{
	struct bst_node_dummy *first  = (struct bst_node_dummy *)firstp;
	struct bst_node_dummy *second = (struct bst_node_dummy *)secondp;

	if (first->pid < second->pid)
		return -1;

	if (first->pid > second->pid)
		return 1;

	return 0;
}

static int bst_init_page(pid_t pid, int to_node, unsigned long addr,
			 bool upgrade, struct bst_node *node)
{
	if (node->pages >= MAX_BST_PAGES)
		return -ENOMEM;

	node->upgrade   = true;
	node->page[node->pages].to_node   = to_node;
	node->page[node->pages].addr      = addr;
	node->pages++;

	return 0;
}

int bst_add_page(pid_t pid, int to_node, unsigned long addr,
		 bool upgrade, struct bst_node **root)
{
	struct bst_node *node, *new_node, **nodepp;
	struct bst_node_dummy dummy;

	dummy.pid = pid;
	dummy.pages = 0;

	if (*root) {
		nodepp = tfind(&dummy, (void **)root, bst_cmp);
		if (nodepp) {
			node = *nodepp;
			assert(node->pid == pid);
			return bst_init_page(pid, to_node, addr,
					     upgrade, node);
		}
	}

	new_node = malloc(sizeof(*new_node));
	if (!new_node)
		return -ENOMEM;

	new_node->pid = pid;
	new_node->pages = 0;

	(void)bst_init_page(pid, to_node, addr, upgrade, new_node);

	nodepp = tsearch(new_node, (void **)root, bst_cmp);
	if (nodepp) {
		assert(new_node == *nodepp);
		/*
		node = *nodepp;
		assert(node->pid == pid);
		if (new_node != node) {
			free(new_node);
			bst_init_page(pid, to_node, addr, upgrade, node);
		}
		*/
	}
	
	return 0;
}

static int perform_move_pages(struct bst_node *node, int alignment)
{
	struct page_list *list;
	int moved_pages, i , j;

	if (!node->pages)
		return 0;
	
	moved_pages = 0;
	i = 0;

	while (i  < node->pages) {
		list = malloc(sizeof(*list));
		if (!list) 
			return -ENOMEM;

		memset(list, 0, sizeof(*list));

		j = 0;

		while (j < PAGES_PER_CALL) {
			list->pagelist[j] = ~(MEMB_PAGE_SIZE -1) &
					    node->page[i].addr;
			list->pid = node->pid;
			list->nodelist[j] = node->page[i].to_node;
			list->status[j]   = 0;
			list->pages++;
			moved_pages++;

			j++;
			i++;
			if (i >= node->pages)
				break;
		}

		if (j > 0) {
			if (alignment == PAGE_SIZE)
				page_mover_enqueue(list);
			else
				page_mover_parallel_enqueue(list, alignment);
		} else {
			free(list);
		}

	}

	return moved_pages;
}

static void bst_process_pages_int(const void *nodepp, VISIT which,
				  int depth)
{
	struct bst_node *node = *(struct bst_node **)nodepp;

	switch(which) {
	case preorder:
	case endorder:
	default:
		break;

	case postorder:
	case leaf:
		if (node->upgrade)
			perform_move_pages(node, upgrade_align);
		else
			perform_move_pages(node, downgrade_align);
		break;	
	}
}

static void bst_process_pages(struct bst_node *root)
{
	if (!root)
		return;

	twalk(root, bst_process_pages_int);
	tdestroy(root, free);
}

static void process_ibs_fetch_samples(struct bst_node **rootpp,
				      unsigned long total)
{
	if (trace_dir)
		process_ibs_fetch_samples_tracer(rootpp, total, user_space_only);
	else if (tier_mode)
		process_ibs_fetch_samples_tier(rootpp, total,
		                               do_migration,
		                               user_space_only);
	else
		process_ibs_fetch_samples_numa(rootpp,  total,
		                               do_migration,
		                               user_space_only);
}

static int op_cmp(const void *p1, const void *p2)
{
	const struct ibs_op_sample *s1 = p1, *s2 = p2;

	return s1->count - s2->count;
}

static int get_ibs_op_samples(int fd, __u64 *total_freq)
{
	__u64 key, next_key;
	struct value_op value;
	int i, j, max, node;
	long total = 0;
	unsigned long paddr;

	for (i = 0; i < max_nodes; i++)
		op_samples_max[i] = 0;

	/* Process op samples from the map*/
	key = 0;
	 i = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);

		atomic64_inc(&op_cnt);
#ifdef USE_PAGEMAP
		paddr = get_physaddr((pid_t)value.tgid,	
				value.op_regs[IBS_DC_LINADDR]);
		if (paddr == (unsigned long)-1) {
			key = next_key;
			bpf_map_delete_elem(fd, &next_key);
			continue;
		}

		paddr *= PAGE_SIZE;

		/*
		assert(paddr == (value.op_regs[IBS_DC_PHYSADDR] &
				 ~(MEMB_PAGE_SIZE - 1)));
		*/
#else
		paddr = value.op_regs[IBS_DC_PHYSADDR];
#endif

		node = get_current_node(paddr);
		assert(node >= -1 && node < (long)max_nodes);
		if (node < 0 || node >= (long)max_nodes) {
			key = next_key;
			bpf_map_delete_elem(fd, &next_key);
			continue;
		}

		if (i >= MAX_IBS_SAMPLES /*|| value.count < MIN_CNT*/) {
			bpf_map_delete_elem(fd, &next_key);
			key = next_key;
			continue;
		}

		op_samples[node][i].key   = next_key;
		op_samples[node][i].count = value.count;
		op_samples[node][i].tgid  = value.tgid;

		for (j = 0; j < max_nodes; j++)
			op_samples[node][i].counts[j] = value.counts[j];

		if (!IBS_KERN_SAMPLE(value.op_regs[IBS_OP_RIP]))
			snprintf(op_samples[node][i].process,
				sizeof(op_samples[node][i].process),
				"%s",
				get_process(op_samples[node][i].tgid));

		op_samples[node][i].op_regs[IBS_OP_CTL] =
				value.op_regs[IBS_OP_CTL];
		op_samples[node][i].op_regs[IBS_OP_RIP] =
				value.op_regs[IBS_OP_RIP];
		op_samples[node][i].op_regs[IBS_OP_DATA] =
				value.op_regs[IBS_OP_DATA];
		op_samples[node][i].op_regs[IBS_OP_DATA2] =
				value.op_regs[IBS_OP_DATA2];
		op_samples[node][i].op_regs[IBS_OP_DATA3] =
				value.op_regs[IBS_OP_DATA3];
		op_samples[node][i].op_regs[IBS_DC_LINADDR] =
				value.op_regs[IBS_DC_LINADDR];
		op_samples[node][i].op_regs[IBS_DC_PHYSADDR] =
				value.op_regs[IBS_DC_PHYSADDR];
		
		total += op_samples[node][i].count;
		op_samples_max[node] += op_samples[node][i].count;
		i++;

		op_samples_cnt[node]++;
		key = next_key;
		bpf_map_delete_elem(fd, &next_key);
	}
	max = i;

	/* sort */
	for (node = 0; node < max_nodes; node++)
		qsort(op_samples[node], op_samples_max[node],
		      sizeof(struct ibs_op_sample), op_cmp);

	if (max >= MAX_IBS_SAMPLES) 
		printf("Processed maximum samples. "
		       "Likely to have dropped some. Increase the value of "
		       "MAX_IBS_SAMPLES\n");

	*total_freq = total;

	return max;
}

static void cleanup_op_samples(int fd)
{
	__u64 key, next_key;
	struct value_op value;
	int i, j;

	/* Process op samples from the map*/
	key = 0;
	 i = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);
		key = next_key;
		bpf_map_delete_elem(fd, &next_key);


		for (j = 0; j < max_nodes; j++)
			op_samples[j][i].count = 0;
	}
}

static void process_ibs_op_samples(struct bst_node **rootpp,
				   unsigned long total)
{
	if (trace_dir)
		process_ibs_op_samples_tracer(rootpp, total, user_space_only);
	else if (tier_mode)
		process_ibs_op_samples_tier(rootpp, total,
		                            do_migration,
		                            user_space_only);
	else
		process_ibs_op_samples_numa(rootpp, total,
		                            do_migration,
		                            user_space_only);
}

static void print_memory_access_summary_histogram(unsigned long code,
						  unsigned long data,
						  unsigned long *fetchsamples,
						  unsigned long *opsamples,
						  int nodes)
{
	int i;
	double pct;

	printf("\f");
	printf("%s%s%s", BRIGHT, BCYAN, ULINE);
	for (i = 0; i < 20; i++)
		printf("%c", 32);
	if (tier_mode)
		printf("%-40s", "MULTI-TIER MEMORY ACCESS PATTERNS "
			"for CODE and DATA");
	else
		printf("%-40s", "NUMA MEMORY ACCESS PATTERN for CODE and DATA");

	for (i = 0; i < 20; i++)
		printf("%c", 32);
	printf("\n\n");
	printf("%s", NORM);

	for (i = 0; i < nodes; i++) {
		if (fetchsamples[i] <= 0 || !code)
			pct = 0.0;
		else
			pct = (((double)fetchsamples[i]) * 100) / code;

		print_bar(i, true, false, false, pct);
	}
	printf("\n");

	for (i = 0; i < nodes; i++) {
		if (opsamples[i] <= 0 || !data)
			pct = 0.0;
		else
			pct = (((double)opsamples[i]) * 100) / data;

		print_bar(i, false, false, false, pct);
	}
}

static void print_memory_access_summary_in_text(unsigned long code,
						unsigned long data,
						unsigned long *fetchsamples,
						unsigned long *opsamples,
						int nodes)
{
	int i;
	static unsigned long counter;
	double pct;
	char buf[15];
	char *title;

	if (tier_mode)
		title = "TIER";
	else
		title = "NUMA";

	if (!(counter++ % 20)) {
		for (i = 0;  i < nodes; i++) {
			snprintf(buf, sizeof(buf), "%s%d_CODE", title, i);
			printf("%s%s%-12s", BRIGHT, MAGENTA, buf);
		}

		for (i = 0; i < nodes; i++) {
			snprintf(buf, sizeof(buf), "%s%d_DATA", title, i);
			printf("%-12s", buf);
		}
		printf("%s\n", NORM);
	}

	for (i = 0; i < nodes; i++) {
		if (fetchsamples[i] <= 0 || !code)
			pct = 0.0;
		else
			pct = (((double)fetchsamples[i]) * 100) / code;
		if (pct >= 75.0)
			printf("%s", BRED);
		else if (pct >= 50.0)
			printf("%s", BMAGENTA);
		else if (pct >= 25.0)
			printf("%s", BBLUE);
		else if (pct >= 10.0)
			printf("%s", CYAN);
		else
			printf("%s", WHITE);

		printf("%-12.2lf", pct);
		printf("%s", NORM);
	}

	for (i = 0; i < nodes; i++) {
		if (opsamples[i] <= 0 || !data)
			pct = 0.0;
		else
			pct = (((double)opsamples[i]) * 100) / data;
		if (pct >= 75.0)
			printf("%s", BRED);
		else if (pct >= 50.0)
			printf("%s", BMAGENTA);
		else if (pct >= 25.0)
			printf("%s", BBLUE);
		else if (pct >= 10.0)
			printf("%s", CYAN);
		else
			printf("%s", WHITE);

		printf("%-12.2lf", pct);
		printf("%s", NORM);
	}

	printf("\n");
}

static void get_sample_statistics(bool fetch, unsigned long **samples, int *count)
{
	if (tier_mode)
		get_sample_statistics_tier(fetch, samples, count);
	else
		get_sample_statistics_numa(fetch, samples, count);
}

static void print_memory_access_summary(void)
{
	unsigned long data, code;
	int i, nodes;
	static struct timeval start;
	struct timeval end;
	static int print_summary;
	unsigned long *fetchsamples;
	unsigned long *opsamples;

	if (atomic_cmxchg(&print_summary, 0, 1))
		return;

	if (start.tv_sec == 0 && start.tv_sec == 0)
		gettimeofday(&start, NULL);

	gettimeofday(&end, NULL);
	if (seconds_elapsed(&start, &end) < report_frequency) {
		assert(atomic_cmxchg(&print_summary, 1, 0) == 1);
		return;
	}

	start = end;

	get_sample_statistics(true, &fetchsamples, &nodes);
	get_sample_statistics(false, &opsamples, &nodes);

	data = 0;
	code = 0;
	for (i = 0; i < nodes; i++) {
		data += opsamples[i];
		code += fetchsamples[i];
	}

	if (!code && !data) {
		assert(atomic_cmxchg(&print_summary, 1, 0) == 1);
		return;
	}

	if (!histogram_format) {
		print_memory_access_summary_in_text(code, data,
				fetchsamples, opsamples, nodes);
	} else {
		print_memory_access_summary_histogram(code, data,
				fetchsamples, opsamples, nodes);
	}

	assert(atomic_cmxchg(&print_summary, 1, 0) == 1);
}

static int parse_additional_bpf_programs(struct bpf_object *bpfobj)
{
        int  i,  error = 0;
        char progname[1024];

        for (i = 0; i < ADDITIONAL_PROGRAMS; i++) {
                if (!additional_programs_name[i])
                        break;

                snprintf(progname, 1024, "%s", additional_programs_name[i]);
                additional_programs[i] = bpf_object__find_program_by_name(
						bpfobj, progname);
                if (!additional_programs[i]) {
                        puts(progname);
                        error = -EINVAL;
                        break;
                }
        }

        addtional_program_count = i;

        return error;
}

static int launch_additional_bpf_programs(void)
{
        int i;

        for (i = 0; i < addtional_program_count; i++) {
                additional_bpflinks[i] = bpf_program__attach(
						additional_programs[i]);
                if (!additional_bpflinks[i])
                        return -EINVAL;
        }

        return 0;
}

static int terminate_additional_bpf_programs(void)
{
        int i;

        for (i = 0; i < addtional_program_count; i++)
                bpf_link__destroy(additional_bpflinks[i]);

        return 0;
}

void update_sample_statistics(unsigned long *samples, bool fetch)
{
	if (trace_dir)
		update_sample_statistics_tracer(samples, fetch);
	else if (tier_mode)
		update_sample_statistics_tier(samples, fetch);
	else
		update_sample_statistics_numa(samples, fetch);
}

static void process_samples(int *map_fd, int msecs, int fetch)
{
	struct bst_node *root = NULL;
	__u64 total_freq_fetch, total_freq_op;
	unsigned long fetch_cnt;
	unsigned long op_cnt;

	if (fetch) {
		fetch_cnt = atomic64_read(&ibs_pending_fetch_samples);
		op_cnt    = 0;
		atomic64_sub(&ibs_pending_fetch_samples, fetch_cnt);
	} else {
		op_cnt    = atomic64_read(&ibs_pending_op_samples);
		fetch_cnt = 0;
		atomic64_sub(&ibs_pending_op_samples, op_cnt);
	}

	if (update_per_node_freemem() != 0) {
		fprintf(stderr, "Cannot load per-node freemem information\n");
		return;
	}

	if (tuning_mode == PROCESS_MOVE) {
		if ((fetch_cnt >= MIN_IBS_FETCH_SAMPLES) ||
			(op_cnt >= MIN_IBS_OP_SAMPLES))
			process_migrate_processes(map_fd[PROC_STAT_MAP]);
		return;
	}

	if (tuning_mode == AUTOTUNE && !proc_data_sampling_done) {
		/* Capture and update the process run data
		 * till the sampling_interval_cnt.
		 */
		if (sampling_interval_cnt && sampling_iter % sampling_interval_cnt) {
			printf("Capturing process run data :"
				"sampling_iter=%u/%u\n", sampling_iter,
				sampling_interval_cnt);
			update_process_run_data(map_fd[PROC_STAT_MAP]);
			return;
        } else {
			printf("Done capturing data."
				"Analyzing and setting process tuning.\n");
			analyze_and_set_autotune_params(&curr_proc_data_map_idx);
			proc_data_sampling_done = true;
		}

	}

	if (tuning_mode == AUTOTUNE) {
		if (curr_proc_data_map_idx) {
			assert(proc_data_sampling_done == true);
			move_process(curr_proc_data_map_idx, false);

			/* set to indicate no valid entry */
			curr_proc_data_map_idx = 0;
			return;
		}

		/* Setting memory tuning for rest of the processes */
		tuning_mode |= MEMORY_MOVE;
	}

	total_freq_fetch = 0;
	total_freq_op = 0;

	if (fetch_cnt >= MIN_IBS_FETCH_SAMPLES) {
		fetch_cnt = get_ibs_fetch_samples(map_fd[IBS_FETCH_MAP],
						  &total_freq_fetch);
		if (fetch_cnt) {
			update_sample_statistics(fetch_samples_max, true);
			process_ibs_fetch_samples(&root, total_freq_fetch);
		}
	}

	if (op_cnt >= MIN_IBS_OP_SAMPLES) {
		op_cnt = get_ibs_op_samples(map_fd[IBS_OP_MAP], &total_freq_op);
		if (op_cnt) {
			update_sample_statistics(op_samples_max, false);
			process_ibs_op_samples(&root, total_freq_op);
		}
	}

	if (!fetch_cnt && !op_cnt) 
		return;

	if (trace_dir)
		report_tracer_statistics();
	else
		print_memory_access_summary();

	bst_process_pages(root);
	
}

static bool ibs_pending_samples(void)
{
	unsigned long fetch_samples, op_samples;
	
	fetch_samples = atomic64_read(&ibs_pending_fetch_samples);
	op_samples = atomic64_read(&ibs_pending_op_samples);

	if (fetch_samples >= MIN_IBS_SAMPLES &&
	    op_samples >= MIN_IBS_OP_SAMPLES)
		return true;

	if (op_samples >= MIN_IBS_SAMPLES &&
	    fetch_samples >= MIN_IBS_FETCH_SAMPLES)
		return true;

	if ((fetch_samples >= 2 * MIN_IBS_SAMPLES) ||
	    (op_samples >= 2 * MIN_IBS_SAMPLES))
		return true;


	return false;
}

static void * ibs_sample_worker_function(void *arg)
{
	struct ibs_sample_worker *worker = arg;
	int counter = 0;

	atomic64_inc(&ibs_workers);
	pthread_mutex_lock(&worker->mtx);
	do {
		while (!ibs_pending_samples() && !worker->stop) {
			pthread_cond_wait(&worker->cv, &worker->mtx);
			counter = 0;
		}

		if (!ibs_pending_samples() && worker->stop)
			break;
		pthread_mutex_unlock(&worker->mtx);

		if (IBS_SAMPLE_WORKERS == 1)
			process_samples(worker->map_fd, worker->msecs, 0);

		process_samples(worker->map_fd, worker->msecs, worker->worker);

		counter++;
		if (counter == 4) { 
			usleep(worker->msecs * 1000 / 4);
			counter = 0;
		}
		pthread_mutex_lock(&worker->mtx);

	} while(1);
	pthread_mutex_unlock(&worker->mtx);

	atomic64_dec(&ibs_workers);

	pthread_mutex_lock(&worker[0].mtx);
	pthread_cond_signal(&worker[0].cv);
	pthread_mutex_unlock(&worker[0].mtx);


	return NULL;
}

static void deinit_ibs_sample_worker(int workers)
{
	int i = 0;

	for (i = 0; i < workers; i++) {
		pthread_mutex_lock(&ibs_worker[i].mtx);
		ibs_worker[i].stop = 1;
		pthread_cond_signal(&ibs_worker[i].cv);
		pthread_mutex_unlock(&ibs_worker[i].mtx);
	}

	while (atomic64_read(&ibs_workers) > 0) {
		pthread_mutex_lock(&ibs_worker[0].mtx);
		pthread_cond_wait(&ibs_worker[0].cv, &ibs_worker[0].mtx);
		pthread_mutex_unlock(&ibs_worker[0].mtx);
	}
}

static int init_ibs_sample_worker(int *map_fd,
				   int msecs)
{
	int i;

	static_assert(IBS_SAMPLE_WORKERS >= 1 && IBS_SAMPLE_WORKERS <= 2,
		     "IBS_SAMPLE_WORKERS can either 1 or 2");

	for (i = 0; i < IBS_SAMPLE_WORKERS; i++) {
		pthread_mutex_init(&ibs_worker[i].mtx, NULL);
		pthread_cond_init(&ibs_worker[i].cv, NULL);
		ibs_worker[i].map_fd = map_fd;
		ibs_worker[i].msecs  = msecs;
		ibs_worker[i].worker = IBS_SAMPLE_WORKERS - i;

		if (pthread_create(&ibs_worker[i].thread, NULL, 
				    ibs_sample_worker_function,
				    (void *)&ibs_worker[i]))
			break;
	}

	if (i == IBS_SAMPLE_WORKERS)
		return 0;

	deinit_ibs_sample_worker(i);

	return -1;
}

static void ibs_process_samples(struct ibs_sample_worker *worker,
				unsigned long fetch_cnt, unsigned long op_cnt)
{
	int i;

	atomic64_add(&ibs_pending_fetch_samples, fetch_cnt);
	atomic64_add(&ibs_pending_op_samples, op_cnt);

	for (i = 0; i < IBS_SAMPLE_WORKERS; i++) {
		pthread_mutex_lock(&worker[i].mtx);
		pthread_cond_signal(&worker[i].cv);
		pthread_mutex_unlock(&worker[i].mtx);
	}
	/* Increment the sampling count,be it fetch or op */
	sampling_iter++;
}

static void print_migration_status(void)
{
	printf("MODE : %-13s Fetch_Samples :%-10ld OP_Samples :%-10ld Migrated_Pages :%-10ld\n",
		(l3miss) ? "IBS_L3MISS":"IBS_CLASSIC",
		atomic64_read(&fetch_cnt),
		atomic64_read(&op_cnt),
		atomic64_read(&pages_migrated));
}

static void interrupt_signal(int sig)
{
	print_migration_status();
	exit(0);
}

/*
 * pages_migration_status:
 * Returns 0 if migrations are happening
 * Returns ETIMEDOUT if migrations stops for the last N seconds;
 */
static int pages_migration_status(int msecs,
				  struct timeval*start,
				  unsigned long *ibs_samples_old,
				  unsigned long *pages_migrated_old)
{
	int max_secs;
	struct timeval end;

	if (!(tuning_mode & MEMORY_MOVE) ||
	    !do_migration)
		return 0;

	if (migration_timeout_sec <= 0)
		return 0;

	gettimeofday(&end, NULL);
	max_secs = migration_timeout_sec;
	if (seconds_elapsed(start, &end) >= max_secs) {
		if ((atomic64_read(&op_cnt) + atomic64_read(&fetch_cnt)) <=
			((*ibs_samples_old + MIN_IBS_SAMPLES))) {
			return ETIMEDOUT;
		}

		*ibs_samples_old = atomic64_read(&op_cnt) +
				   atomic64_read(&fetch_cnt);

		if (atomic64_read(&pages_migrated) <
			MIN_MIGRATED_PAGES + *pages_migrated_old) {
			return ETIMEDOUT;
		}
		/*
		printf("migrated_pages %ld pages_migrated_old %ld secs %d\n",
			atomic64_read(&pages_migrated),
			*pages_migrated_old,
			seconds_elapsed(start, &end));
		*/

		gettimeofday(start, NULL);

		*pages_migrated_old = atomic64_read(&pages_migrated);
	}

	return 0;
}

static void balancer_cleanup(int fetch_fd, int op_fd)
{
	cleanup_fetch_samples(fetch_fd);
	cleanup_op_samples(op_fd);
}

static void set_knob(int fd, int knob, int value)
{
	bpf_map_update_elem(fd, &knob, &value, BPF_NOEXIST);
}

static int load_bpf_programs(struct bpf_program **prog,
			     struct bpf_object *obj,
			     char **prog_names,
			     short prog_count)
{
	int  sts = 0;
	int i;

	for (i=0; i< prog_count; i++) {
		if (!prog_names[i]) {
			continue;
		}
		/* No need to clean up any stale pointers.
		 * They will be overridden anyway.
		 */
		prog[i] = bpf_object__find_program_by_name(obj,
							   prog_names[i]);
		if (!prog[i]) {
			fprintf(stderr, "BPF cannot find program %s "
				"to load.\n", prog_names[i]);
			sts = -EINVAL;
			break;
		}

		if (verbose >= 5)
			printf("loaded program =%s\n", prog_names[i]);
	}

	return sts;
}

static int load_perf_fd_bpf_maps(int *map_fd, struct bpf_object *obj,
				char **map_names, short map_count)
{
	int sts = 0;

	for (int i=0; i< map_count; i++) {
		/* We do not 'overload' the index for maps.
		 * The relative index defined in map_enum has to be maintaied,
		 * so that rest of the code can continue with their respective
		 * fds specific to a profile template(memory or process).
		 */
		if (map_names[i] == NULL) {
			/* This index of map fd is not required for profiling.
			 * Just we no need to do anything here.
			 */
			if (verbose >= 5)
				printf("Map fd for index %d is skipped\n",i);
			continue;
		}

		map_fd[i] = bpf_object__find_map_fd_by_name(obj, map_names[i]);

		if ((map_fd[i]) < 0) {
			fprintf(stderr, "BPF cannot find %s\n", map_names[i]);
			sts = -EINVAL;
			break;
		}
		if (verbose >= 5)
			printf("Map fd is set for map: %s\n", map_names[i]);
	}

	return sts;
}

static void close_perf_fd_bpf_maps(int *map_fd,
				   enum tuning_profile profile_to_open)
{
	char **profile_map_fd_names = NULL;

	if (profile_to_open == MEMORY)
		profile_map_fd_names = memory_map_fd_names;
	else if (profile_to_open == PROCESS)
		profile_map_fd_names = process_map_fd_names;

	assert(profile_map_fd_names != NULL);

	for (int i=0; i< TOTAL_MAPS; i++) {
		if ((map_fd[i] != -1) && (profile_map_fd_names[i] == NULL)) {
			close(map_fd[i]);
			map_fd[i] = -1;
			if (verbose >= 5)
				printf("Map fd is closed for map index: %d\n",
					i);
		}
	}
}

static int init_and_load_bpf_programs(struct bpf_program **prog,
				      int *map_fd,
				      struct bpf_object *obj,
				      enum tuning_profile profile)
{
	int sts = 0;

	switch(profile) {
		case MEMORY:
			if (verbose >= 5)
				printf("Loading bpf programs and maps for "
					"memory profile\n");
			sts = load_bpf_programs(prog, obj,
						memory_profile_program_names,
						TOTAL_BPF_PROGRAMS);
			if (sts)
				break;
			sts = load_perf_fd_bpf_maps(map_fd, obj,
						memory_map_fd_names, TOTAL_MAPS);
			break;
        case PROCESS:
			if (verbose >= 5)
				printf("Loading bpf programs and maps for "
					"process profile\n");
			sts = load_bpf_programs(prog, obj,
						process_profile_program_names,
						TOTAL_BPF_PROGRAMS);
			if (sts)
				break;

			sts = load_perf_fd_bpf_maps(map_fd, obj,
						process_map_fd_names, TOTAL_MAPS);
			break;
		default:
			printf("Invalid profile for tuning\n");
			sts = -EINVAL;
	}

	return sts;
}

static int balancer_function_int(const char *kernobj, int freq, int msecs,
				 char  *include_pids, char *include_ppids,
				 cpu_set_t *cpusetp)
{
	int msecs_nap;
	int err = -1;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog[TOTAL_BPF_PROGRAMS];
	struct bpf_link **fetch_links = NULL, **op_links = NULL;
	struct bpf_link **perf_links = NULL;
	char filename[256];
	int map_fd[TOTAL_MAPS];
	unsigned long fetch_cnt, op_cnt;
	unsigned long fetch_cnt_old, op_cnt_old;
	unsigned long fetch_cnt_new, op_cnt_new;
	unsigned long ibs_samples_old = 0, pages_migrated_old = 0;
	enum tuning_mode tuning_mode_old = tuning_mode;
	struct timeval start;

	fetch_links = calloc(nr_cpus, sizeof(struct bpf_link *));
	if (!fetch_links) {
		fprintf(stderr, "ERROR: malloc of links\n");
		goto cleanup;
	}

	op_links = calloc(nr_cpus, sizeof(struct bpf_link *));
	if (!op_links) {
		fprintf(stderr, "ERROR: malloc of links\n");
		goto cleanup;
	}

	perf_links = calloc(nr_cpus, sizeof(struct bpf_link *));
	if (!perf_links) {
		fprintf(stderr, "ERROR: malloc of links\n");
		goto cleanup;
	}

	snprintf(filename, sizeof(filename), "%s_kernel.o", kernobj);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		obj = NULL;
		goto cleanup;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	/* Resetting BPF map fd list */
	memset(map_fd, -1, TOTAL_MAPS * sizeof(int));

	if (tuning_mode == MEMORY_MOVE) {
		err = init_and_load_bpf_programs(prog, map_fd, obj, MEMORY);
		if (err) {
			/* We really nothing much to clean up here,
			 * as we need to exit our application!
			 */
			fprintf(stderr, "ERROR:(%d)Could not load all"
				"the required programs and maps!!\n", err);
			goto cleanup;
		}
	} else {
		assert((tuning_mode == AUTOTUNE) || (tuning_mode == PROCESS_MOVE));
		err = init_and_load_bpf_programs(prog, map_fd, obj, PROCESS);
		if (err) {
			/* We really nothing much to clean up here,
			 * as we need to exit our application!
			 */
			fprintf(stderr, "ERROR:(%d)Could not load all"
				"the required programs and maps!!\n", err);
			goto cleanup;
		}
	}

	cpu_nodes = fill_cpu_nodes(obj);
	if (cpu_nodes <= 0)
		goto cleanup;

	if (process_include_pids(obj, include_pids, false))
		goto cleanup;

	if (process_include_pids(obj, include_ppids, true))
		goto cleanup;

	if (include_ppids)
		set_knob(map_fd[KNOBS], CHECK_PPID, 1);

	if (tier_mode ==  false)
		set_knob(map_fd[KNOBS], PER_NUMA_ACCESS_STATS, 1);

	if (user_space_only)
		set_knob(map_fd[KNOBS], USER_SPACE_ONLY, 1);

	fill_value_latency_buffers(obj);

	/*
	set_knob(map_fd[KNOBS], PER_NUMA_LATENCY_STATS, 1);
	*/
	set_knob(map_fd[KNOBS], MY_PAGE_SIZE, MEMB_PAGE_SIZE);
	set_knob(map_fd[KNOBS], MY_OWN_PID, getpid());
	set_knob(map_fd[KNOBS], KERN_VERBOSE, verbose);

	if (l3miss)
		set_knob(map_fd[KNOBS], DEFER_PROCESS,
			 L3MISS_DEFER_PROCESS_CNT);
	else
		set_knob(map_fd[KNOBS], DEFER_PROCESS, DEFER_PROCESS_CNT);

	if (tuning_mode == PROCESS_MOVE ||
		tuning_mode == AUTOTUNE) {
		if (fill_numa_address_range_map(obj) <= 0) {
			err = -EINVAL;
			goto cleanup;
		}

		if (tuning_mode == PROCESS_MOVE)
			set_knob(map_fd[KNOBS], PROCESS_STATS, 1);
		else
			set_knob(map_fd[KNOBS], AUTO_TUNE, 1);
	}

	set_knob(map_fd[KNOBS], LAST_KNOB, 1);

	err = init_heap(obj);
	if (err != 0)
		goto cleanup;

	err = parse_additional_bpf_programs(obj);
	if (err) {
		goto cleanup;
	}
	
	err = launch_additional_bpf_programs();
	if (err) {
		goto cleanup;
	}

	printf("\f");
	printf("%s%s", BRIGHT, BMAGENTA);
	printf("Collecting IBS %s samples .....\n",
		(l3miss) ? "MISS Filter" : "CLASSIC");
	printf("%s", NORM);

	err = init_ibs_sample_worker(map_fd, msecs);
	assert(err == 0);

	if (trace_dir) {
		err = tracer_init(trace_dir);
		assert(err == 0);
	} else {
		err = init_page_mover();
		assert(err == 0);
	}

	fetch_cnt_old = 0;
	fetch_cnt_new = 0;
	op_cnt_old = 0;
	op_cnt_new = 0;

	signal(SIGINT, interrupt_signal);
	gettimeofday(&start, NULL);


	while (!err) {

		if (tuning_mode_old != tuning_mode) {
			/* There is change in tuning_mode value;
			 * due to MEMORY_MOVE set with AUTOTUNE after
			 * process sampling.
			 */
			assert(tuning_mode == (AUTOTUNE | MEMORY_MOVE));
			assert(tuning_mode_old == AUTOTUNE );

			/* Close the map fds which are not required
			 * anymore for this profile.
			 * For bpf programs, nothing to close.
			 * The new program pointers will override them.
			 */

			/* Passing profile to open */
			close_perf_fd_bpf_maps(map_fd, MEMORY);
			err = init_and_load_bpf_programs(prog, map_fd, obj,
							 MEMORY);
			if (err) {
				/* We really nothing much to clean up here,
				 * as we need to exit our application!
				 */
				fprintf(stderr, "ERROR:(%d)Could not load"
						"all the required programs "
						"and maps!!\n", err);
				goto cleanup;
			}

			tuning_mode_old = tuning_mode;
        	}

		if (ibs_op_sampling_begin(freq, prog[IBS_DATA_SAMPLER],
					op_links, cpusetp) != 0) {
			if (l3miss)
				fprintf(stderr,
					"IBS OP L3 miss fitlering "
					"not supported\n");
			else
				fprintf(stderr,
					"IBS OP sampling not supported\n");
		}

		if (ibs_fetch_sampling_begin(freq, prog[IBS_CODE_SAMPLER],
					     fetch_links, cpusetp) != 0) {
			if (l3miss)
				fprintf(stderr,
					"IBS Fetch L3 miss filtering "
					"not supported\n");

			else
				fprintf(stderr,
					"IBS Fetch sampling not supported\n");

			if (perf_sampling_begin(freq,
						prog[NON_IBS_CODE_SAMPLER],
						perf_links, cpusetp) != 0)
				goto cleanup;
		}

		for (; ;)  {
			fetch_cnt = peek_ibs_samples(map_fd[FETCH_COUNTER_MAP],
						     fetch_cnt_old,
						     &fetch_cnt_new);

			op_cnt    = peek_ibs_samples(map_fd[OP_COUNTER_MAP],
						     op_cnt_old, &op_cnt_new);

			if ((fetch_cnt >= MIN_IBS_SAMPLES)) {
				fetch_cnt_old = fetch_cnt_new;
				if (op_cnt >= MIN_IBS_OP_SAMPLES) {
					op_cnt_old = op_cnt_new;
					break;
				}
				break;
			}

			if ((op_cnt >= MIN_IBS_SAMPLES)) {
				op_cnt_old = op_cnt_new;
				if (fetch_cnt >= MIN_IBS_FETCH_SAMPLES) {
					fetch_cnt_old = fetch_cnt_new;
					break;
				}
				break;
			}

			if ((op_cnt >= 2 * MIN_IBS_SAMPLES) ||
			    (fetch_cnt >= 2 * MIN_IBS_SAMPLES)) {
				op_cnt_old    = op_cnt_new;
				fetch_cnt_old = fetch_cnt_new;
				break;
			}

			msecs_nap = msecs * 1000 / 10;
			if (msecs_nap < 1000)
				msecs_nap = 1000;

			usleep(msecs_nap);
			/*
			 * Check if migration is making progress. If not
			 * break out of the processing loop.
			 */
			err = pages_migration_status(msecs,
						     &start,
						     &ibs_samples_old,
						     &pages_migrated_old);
			if (err)
				break;
		}

		if (fetch_links)
			ibs_sampling_end(fetch_links); /* IBS fetch */

		if (op_links)
			ibs_sampling_end(op_links);    /* IBS op */


		ibs_process_samples(ibs_worker, fetch_cnt, op_cnt);

		usleep(msecs * 1000 / maximizer_mode);
	}
	balancer_cleanup(map_fd[IBS_FETCH_MAP], map_fd[IBS_OP_MAP]);

cleanup:
	deinit_ibs_sample_worker(atomic64_read(&ibs_workers));
	terminate_additional_bpf_programs();
	if (fetch_links)
		ibs_sampling_end(fetch_links); /* IBS fetch */

	if (op_links)
		ibs_sampling_end(op_links);    /* IBS op */

	free(fetch_links);
	free(op_links);
	free(perf_links);
	bpf_object__close(obj);


	return err;
}

static int balancer_function(const char *kernobj, int freq, int msecs,
			     char *include_pids, char *include_ppids,
			     cpu_set_t *cpusetp)
{
	if (trace_dir) {
		 return balancer_function_int(kernobj, freq, msecs,
					include_pids, include_ppids, cpusetp);
	}

	/*
	 * Creating a process to handle an unknown problem where the samples
	 * are limited to the migrated pages after several minutes. The root
	 * cause is still unknown. The workaroud until the problem is resolved
	 * is to run balanacer under a new process and terminate the process
	 * when the migration logic stops making forward progress.
	 */
#ifdef MEMBALANCE_FORK
	int status;
	pid_t pid;
	int pipefd[2];
	enum tuning_mode curr_tuning_mode;

	if (pipe(pipefd) == -1)
		return -EINVAL;

	pid = fork();
	if (pid == 0) {
		close(pipefd[0]);
		status = balancer_function_int(kernobj, freq, msecs,
					include_pids, include_ppids, cpusetp);
		write(pipefd[1], &tuning_mode, sizeof(enum tuning_mode));
		close(pipefd[1]);
		exit(status);
	}

	close(pipefd[1]);
	if (read(pipefd[0], &curr_tuning_mode, sizeof(enum tuning_mode)) > 0) {
		if (verbose >= 5)
			printf("tuning_mode was %d and"
				"curr tuning mode =%d\n",tuning_mode,
				curr_tuning_mode);
	}

	close(pipefd[0]);

	if (curr_tuning_mode & MEMORY_MOVE)
		tuning_mode = MEMORY_MOVE;

	wait(&status);

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return -EINVAL;
#else
	return balancer_function_int(kernobj, freq, msecs,
			include_pids, include_ppids, cpusetp);
#endif
}

int main(int argc, char **argv)
{
	int base_page_size;
	int opt;
	int freq = MEMB_CLOCK;
	int msecs = MEMB_INTVL;
	int err = -1;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	char *tier_args = NULL;
	int sampling_count;
	char *include_pids = NULL;
	char *include_ppids = NULL;
	char *include_cpus = NULL;
	char buffer[256];
	cpu_set_t *cpusetp;
	size_t size;

	nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);

	if (!cpuvendor_supported()) {
		printf("CPU vendor not supported\n");
		return -1;
	}
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return -1;
	}

	while ((opt = getopt(argc, argv, cmd_args)) != -1) {
		switch (opt) {
		case 'B':
			base_page_size = atoi(optarg);
			if (base_page_size % PAGE_SIZE) {
				printf("Base page size should be "
					"a  multiple of %d\n", PAGE_SIZE);
				return -1;
			}
			set_base_page_size(base_page_size);
			break;
		case 'V':
			tracer_physical_mode = false;
			break;
		case 'T':
			min_migrated_pages = MIN_MIGRATED_PAGES_TIER;
			tier_args = optarg;
			tier_mode = true;
			break;
		case 'l':
			l3miss = true;
			break;
		case 'b':
			do_migration = true;
			break;
		case 'm':
			min_pct = atof(optarg);
			break;
		case 't':
			migration_timeout_sec = atoi(optarg);
			break;
		case 'r':
			report_frequency = atoi(optarg);
			if (report_frequency < 1)
				report_frequency = 1;
			
			break;
		case 'M':
			maximizer_mode = atof(optarg);
			if (maximizer_mode < 0.01)
				maximizer_mode = 0.01;
			else if (maximizer_mode > 10)
				maximizer_mode = 10;
			break;
		case 'f':
			freq = atoi(optarg);
			break;
		case 'F':
			min_freemem_pct = atoi(optarg);
			if (min_freemem_pct < 0 || min_freemem_pct > 100) {
				printf("Invalid freemem threshold %d\n",
					min_freemem_pct);
				usage(argv[0]);
				return -1;
			}
			break;
		case 'p':
			include_pids = optarg;
			if (include_ppids) {
				printf("Only pid or ppid, not both\n");
				usage(argv[0]);
				return -1;
			}
			break;
		case 'P':
			include_ppids = optarg;
			if (include_pids) {
				printf("Only pid or ppid, not both\n");
				usage(argv[0]);
				return -1;
			}
			break;
		case 'c':
			include_cpus = optarg;
			break;
		case 'v':
			verbose = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		case 'H':
			histogram_format = true;
			break;
		case 'u':
			user_space_only = true;
			break;
		case 'U':
			upgrade_align = atol(optarg);
			if (upgrade_align % PAGE_SIZE) {
				printf("Upgrade alignment should be "
					"a  multiple of %d\n", PAGE_SIZE);
				return -1;
			}
			break;
		case 'D':
			downgrade_align = atol(optarg);
			if (downgrade_align % PAGE_SIZE) {
				printf("Upgrade alignment should be "
					"a  multiple of %d\n", PAGE_SIZE);
				return -1;
			}
			break;
		case 'L':
			trace_dir = optarg;
			break;
		case 'S':
			tuning_mode = get_balancing_mode(argv[optind++]);
			if (tuning_mode == -1) {
				printf("Invalid balancing mode\n");
				usage(argv[0]);
				return -1;
			}
			if (tuning_mode == AUTOTUNE) {
				do_migration = true;
				if (argv[optind]) {
					sampling_count = atoi(argv[optind++]);
					if (sampling_count >= 0)
						sampling_interval_cnt = sampling_count;
				}
			}
			break;
		default:
			usage(argv[0]);
			return -1;
		}
	}

	if (argc - optind > 1) {
		usage(argv[0]);
		return -1;
	}

	if (argc - optind == 1)
		msecs = atoi(argv[optind]);

	if (freq == 0 || msecs == 0) {
		usage(argv[0]);
		return -1;
	}

	ibs_fetchop_config_set();

	fill_numa_table();
	if (tier_mode) {
		err  = init_tier(tier_args);
		if (err)
			return err;
	}

	if (!include_cpus) {
		/*
		 * Perf event will be attached to all the cpus by default
		 */
		snprintf(buffer, sizeof(buffer), "%d-%d", 0, nr_cpus - 1);
		include_cpus = buffer;
	}

	cpusetp = CPU_ALLOC(nr_cpus);
	if (cpusetp == NULL) {
		perror("CPU_ALLOC");
		exit(EXIT_FAILURE);
	}
	size = CPU_ALLOC_SIZE(nr_cpus);
	CPU_ZERO_S(size, cpusetp);
	if (include_cpus) {
		err = parse_cpulist(include_cpus, cpusetp, size);
		if (err) {
			usage(argv[0]);
			CPU_FREE(cpusetp);
			return err;
		}
	}

	open_ibs_devices();

	do {
		err = balancer_function(argv[0], freq, msecs,
					include_pids, include_ppids, cpusetp);
	}  while(err == ETIMEDOUT);

	CPU_FREE(cpusetp);

	return err;
}
