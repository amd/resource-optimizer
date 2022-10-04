/*
 * Automatic NUMA memory balancer Based on IBS sampler
 *
 * Copyright 2022 AMD, Inc.
 */
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

#define __USE_GNU
#include <search.h>
typedef __u32 u32;
typedef __u64 u64;
/*
#ifndef atomic_t
typedef struct {
        volatile int counter;
} atomic_t;

typedef struct {
        volatile long counter;
} atomic64_t;

#endif
*/

#include "profiler.h"
#include "profiler_utils.h"
#ifdef DEBUG_ON	
#include "pmap.h"
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#define MEMB_CLOCK 25 
#define MEMB_INTVL 100
#define MIN_IBS_SAMPLES 5000
#define MIN_IBS_FETCH_SAMPLES (MIN_IBS_SAMPLES / 4)
#define MIN_IBS_OP_SAMPLES    (MIN_IBS_SAMPLES / 4)
#define MIN_CNT 1
#define MIN_PCT 1.75

static int nr_cpus;
static double min_pct = 0.01;
static bool user_space_only = false;
int verbose = 2;
static int report_frequency = 1;

static char *obj_filename;

static char cmd_args[]  = "f:F:P:p:r:m:M:v:l::uhs";
static int ibs_fetch_device = -1;
static int ibs_op_device    = -1;

#define FETCH_CONFIG        57
#define FETCH_CONFIG_L3MISS 59
#define OP_CONFIG           19
#define OP_CONFIG_L3MISS    16

static int ibs_fetch_config;
static int ibs_op_config;
static unsigned int cpu_nodes;
static bool summary_report;
static bool l3miss;
static pid_t mypid;
static int min_cnt;

#define ADDITIONAL_PROGRAMS 2

static struct bpf_program *additional_programs[ADDITIONAL_PROGRAMS];
static int addtional_program_count;
static struct bpf_link *additional_bpflinks[ADDITIONAL_PROGRAMS];
static char * additional_programs_name[ADDITIONAL_PROGRAMS] = {
	"save_process_cpu",
	NULL,
};

#define IBS_FETCH_DEV "/sys/devices/ibs_fetch/type"
#define IBS_OP_DEV    "/sys/devices/ibs_op/type"

struct ibs_fetch_sample fetch_samples[MAX_IBS_SAMPLES];
unsigned long fetch_samples_max;
unsigned long fetch_samples_cnt;
struct ibs_op_sample op_samples[MAX_IBS_SAMPLES];
unsigned long op_samples_max;
unsigned long op_samples_cnt;

static struct list_of_functions functions[MAX_IBS_SAMPLES];
static char function_names[MAX_IBS_SAMPLES][MAX_FUNC_NAME];
static unsigned int cnt_functions;

static void usage(void)
{
	printf("USAGE: profile [-f freq] [-p <pid,..>] [-P <parent pid,..>] "
	       "-F <object file> -M <minimum samples> [duration]\n");
	printf("       -P pid Parent Process ID to be tracked\n");
	printf("       -p pid Process ID to be tracked\n");
	printf("       -f freq    # sample frequency (Hertz), "
	       "default %d\n", MEMB_CLOCK);
	printf("       -u Only user space samples\n");
	printf("       -F object file for symbols\n");
	printf("       -M minimum samples. Ignore samples less than this frequency\n");
	printf("       duration   #  interval in milliseconds, "
	       "default %d\n", MEMB_INTVL);
	printf("\n");
	printf("Example for profiling an application for 1000 milliseconds\n");
	printf("profiler -P 238511 -F XSBench/openmp-threading/XSBench -u 1000\n");
}

static void skip_space(char *buffer, int *next, int size)
{
	int i = *next;

	while (i < size && ((buffer[i] == ' ') || (buffer[i] == '\t') ||
		(buffer[i] == '\n')))
		i++;

	*next = i;
}

static char *  next_field(char *buffer, int *next, int size)
{
	int i = *next;
	char *field;

	if (i >= size)
		return NULL;

	while (i < size && ((buffer[i] != ' ') && (buffer[i] != '\t') &&
		(buffer[i] != '\n') && (buffer[i] != 0)))
		i++;

	buffer[i] = 0;

	i++;

	field = &buffer[*next];

	*next = i;

	return field;
}

static int load_function_names(const char *obj_file, 
			       struct list_of_functions *func,
			       int max)
{
	FILE *fp;
	char buffer[1024];
	char cmd[1024];
	char *field;
	char *tmp;
	int i = 0, j, next;
	unsigned long addr, size;

	snprintf(cmd, sizeof(cmd) - 1, 
		"/usr/bin/objdump -t %s|grep \" F .text\"", obj_file);

	fp = popen(cmd, "r");
	if (!fp)
		return -EINVAL;

	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
                if (i >= max)
                        break;
		next = 0;
		field = next_field(buffer, &next, 1024);
		if (!field)
			break;

		addr = strtoul(field, &tmp, 16);
		for (j = 0;  j < 3; j++) {
			skip_space(buffer, &next, 1024);
			field = next_field(buffer, &next, 1024);
			if (!field)
				break;
		}

		if (!field)
			break;

		skip_space(buffer, &next, 1024);
		field = next_field(buffer, &next, 1024);
		if (!field)
			break;

		size = strtoul(field, &tmp, 16);;
		if (size == 0)
			continue;

		skip_space(buffer, &next, 1024);
		field = next_field(buffer, &next, 1024);
		func[i].ip = addr;
		func[i].size = size;
		func[i].ref = 0;
		func[i].name = i;
		snprintf(function_names[i], sizeof(function_names[i]),
				"%s", field);
		i++;
        }
	fclose(fp);

	return i;
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

static int perf_sampling_begin(int freq, struct bpf_program *prog,
				struct bpf_link *links[])
{
	int i, pmu_fd;

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

	for (i = 0; i < nr_cpus; i++) {
		if (!is_cpu_online(i)) {
			links[i] = NULL;
			continue;
		}

		pmu_fd = sys_perf_event_open(&perf, -1, i, -1, 0);
		if (pmu_fd < 0) {
			fprintf(stderr, "Cannot arm software sampling\n");
			return 1;
		}
		links[i] = bpf_program__attach_perf_event(prog, pmu_fd);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "ERROR: Attach perf event\n");
			links[i] = NULL;
			close(pmu_fd);
			return 1;
		}
	}

	return 0;
}

static int ibs_fetch_sampling_begin(int freq, struct bpf_program *prog,
				    struct bpf_link *links[])
{
	int i, pmu_fd;

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

	for (i = 0; i < nr_cpus; i++) {
		if (!is_cpu_online(i)) {
			links[i] = NULL;
			continue;
		}
		pmu_fd = sys_perf_event_open(&ibs_fetch, -1, i, -1, 0);
		if (pmu_fd < 0) {
			fprintf(stderr, "Cannot arm IBS FETCH sampling\n");
			return 1;
		}
		links[i] = bpf_program__attach_perf_event(prog, pmu_fd);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "ERROR: Attach perf event\n");
			links[i] = NULL;
			close(pmu_fd);
			return 1;
		}
	}

	return 0;
}

static void ibs_sampling_end(struct bpf_link *links[])
{
	int i;

	for (i = 0; i < nr_cpus; i++)
		bpf_link__destroy(links[i]);
}

static void ibs_fetchop_config_set(void)
{
        ibs_fetch_config = (l3miss) ? FETCH_CONFIG_L3MISS : FETCH_CONFIG;
        ibs_op_config    = (l3miss) ? OP_CONFIG_L3MISS : OP_CONFIG;
}

int ibs_op_sampling_begin(int freq, struct bpf_program *prog,
				struct bpf_link *links[])
{
	int i, pmu_fd;

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

	for (i = 0; i < nr_cpus; i++) {
		if (!is_cpu_online(i)) {
			links[i] = NULL;
			continue;
		}
		pmu_fd = sys_perf_event_open(&ibs_op, -1, i, -1, 0);
		if (pmu_fd < 0) {
			fprintf(stderr, "Cannot arm IBS OP sampling\n");
			return 1;
		}
		links[i] = bpf_program__attach_perf_event(prog, pmu_fd);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "ERROR: Attach perf event\n");
			links[i] = NULL;
			close(pmu_fd);
			return 1;
		}
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


static char * get_process(__u64 tgid)
{
	return "";
}

static int get_ibs_fetch_samples(int fd,  __u64 *total_freq)
{
	__u64 key, next_key;
	struct value_fetch value;
	int i, max;
	long total = 0;

	/* Process fetch samples from the map*/
	key = 0;
	i = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);

		if (i >= MAX_IBS_SAMPLES /*|| value.count < MIN_CNT*/) {
			bpf_map_delete_elem(fd, &next_key);
			key = next_key;
			continue;
		}

		fetch_samples[i].ip     = next_key;
		fetch_samples[i].count  = value.count;
		fetch_samples[i].tgid   = value.tgid;

		if (!IBS_KERN_SAMPLE(fetch_samples[i].ip))
			snprintf(fetch_samples[i].process,
				sizeof(fetch_samples[i].process),
					"%s",
					get_process(value.tgid));

		fetch_samples[i].fetch_regs[IBS_FETCH_CTL] =
				value.fetch_regs[IBS_FETCH_CTL];
		fetch_samples[i].fetch_regs[IBS_FETCH_LINADDR] =
				value.fetch_regs[IBS_FETCH_LINADDR];
		fetch_samples[i].fetch_regs[IBS_FETCH_PHYSADDR] =
				value.fetch_regs[IBS_FETCH_PHYSADDR];
		
		total += fetch_samples[i].count;
		fetch_samples_max += fetch_samples[i].count;
		i++;
		
		fetch_samples_cnt++;
		key = next_key;
		bpf_map_delete_elem(fd, &next_key);
	}

	max = i;

	if (max >= MAX_IBS_SAMPLES) 
		printf("Processed maximum samples. "
		       "Likely to have dropped some. Increase the value of "
		       "MAX_IBS_SAMPLES\n");

	*total_freq = total;

	return max;
}

static const char * get_function_name(u64 addr)
{
	int i;

	for (i = 0; i < cnt_functions; i++) {
		if ((addr >= functions[i].ip) &&
		    (addr <= functions[i].ip + functions[i].size))
			return function_names[functions[i].name];
	}

	return "";
}

static void process_function_names(u64 addr, u64 count)
{
	int i;

	for (i = 0; i < cnt_functions; i++) {
		if ((addr >= functions[i].ip) &&
		    (addr <= functions[i].ip + functions[i].size))
			functions[i].ref += count;
	}
}

static int fetch_cmp(const void *p1, const void *p2);
static void print_fetch_statistics_summary(u64 samples)
{
	int i, j;

	if (!samples)
		return;

	qsort(functions, cnt_functions,
	      sizeof(struct list_of_functions), fetch_cmp);

	printf("\f\r");

	printf("%-3s %-32s %-10s %-10s %-10s\n",
		"No", "FUNCTION", "COUNT", "PERCENT", "MODE");

	j = 0;

	for (i = 0; i < cnt_functions; i++) {
		if (functions[i].ref <= 0)
			continue;

		if (((functions[i].ref * 100) / samples) < 1)
			continue;

		printf("%-3d %-32s %-10ld %-10ld %-10s\n",
			++j, 
			function_names[functions[i].name],
			(unsigned long)functions[i].ref,
			(unsigned long)((functions[i].ref * 100) / samples),
			IBS_KERN_SAMPLE(functions[i].ip) ? "KERNEL" : "USER");

		functions[i].ref = 0;
	}

}

static void print_fetch_statistics_detailed(u64 samples)
{
	int i, j, pct;
	u64 addr, paddr;
	u64 total;
	char func[21];

	if (!samples)
		return;

	qsort(fetch_samples, samples, sizeof(struct ibs_fetch_sample), fetch_cmp);
	printf("\f\r");

	j = 0;

	total = 0;
	for (i = 0; i < samples; i++)
		total += fetch_samples[i].count;

	for (i = 0; i < samples; i++) {
		if (fetch_samples[i].count == 0)
			continue;

		if (fetch_samples[i].count < min_cnt)
			continue;


		addr  = fetch_samples[i].fetch_regs[IBS_FETCH_LINADDR];
		if (user_space_only && (IBS_KERN_SAMPLE(addr)))
			continue;

		if (j == 0) {
			printf("%-3s %-20s %-20s %-20s %-10s %-10s %-10s %4s\n",
				"No", "FUNCTION", "VA", "PA", "COUNT", "PERCENT", "MODE", "TYPE");
		}

		paddr = fetch_samples[i].fetch_regs[IBS_FETCH_PHYSADDR];
		pct   = fetch_samples[i].count * 100 / total;
		snprintf(func, sizeof(func), "%s", get_function_name(addr));
		printf("%-3d %-20s %-20p %-20p %-10d %-10d %-10s %4s\n",
			++j,
			func,
			(void *)addr,
			(void *)paddr,
			fetch_samples[i].count,
			pct,
			IBS_KERN_SAMPLE(addr) ? "KERNEL" : "USER",
			"CODE");
		fetch_samples[i].count = 0;
	}
	fflush(stdout);
}

static void print_fetch_statistics(u64 samples)
{
	if (summary_report)
		print_fetch_statistics_summary(samples);
	else
		print_fetch_statistics_detailed(samples);
}

static int fetch_cmp(const void *p1, const void *p2)
{
        const struct ibs_fetch_sample *s1 = p1, *s2 = p2;

        return s2->count - s1->count;
}

static void process_ibs_fetch_samples(unsigned long total)
{
	unsigned long i;
	u64 addr, samples = 0;

	if (!total)
		return;

	for (i = 0; i < total; i++) {
		if (fetch_samples[i].count < 1) {
			fetch_samples[i].count = 0;
			continue;
		}

		addr =  fetch_samples[i].fetch_regs[IBS_FETCH_LINADDR];
		process_function_names(addr, fetch_samples[i].count);
		samples += fetch_samples[i].count;

		/*
			fetch_samples[i].count = 0;
		*/
	}

	print_fetch_statistics(samples);
}

static int op_cmp(const void *p1, const void *p2)
{
        const struct ibs_op_sample *s1 = p1, *s2 = p2;

        return s2->count - s1->count;
}

static int get_ibs_op_samples(int fd, __u64 *total_freq)
{
	__u64 key, next_key;
	struct value_op value;
	int i, max;
	long total = 0;
	unsigned long paddr;

	/* Process op samples from the map*/
	key = 0;
	 i = 0;
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);

#ifdef DEBUG_ON	
		paddr = get_pfn((pid_t)value.tgid,	
				value.op_regs[IBS_DC_LINADDR]);
		if (paddr == (unsigned long)-1) {
			key = next_key;
			bpf_map_delete_elem(fd, &next_key);
			continue;
		}
		paddr *= PAGE_SIZE;
#else
		paddr = value.op_regs[IBS_DC_PHYSADDR];
#endif

		if (i >= MAX_IBS_SAMPLES /*|| value.count < MIN_CNT*/) {
			bpf_map_delete_elem(fd, &next_key);
			key = next_key;
			continue;
		}

		op_samples[i].key   = next_key;
		op_samples[i].count = value.count;
		op_samples[i].tgid  = value.tgid;

		if (!IBS_KERN_SAMPLE(value.op_regs[IBS_OP_RIP]))
			snprintf(op_samples[i].process,
				sizeof(op_samples[i].process),
				"%s",
				get_process(op_samples[i].tgid));

		op_samples[i].ip = value.ip;
		op_samples[i].op_regs[IBS_OP_CTL] =
				value.op_regs[IBS_OP_CTL];
		op_samples[i].op_regs[IBS_OP_RIP] =
				value.op_regs[IBS_OP_RIP];
		op_samples[i].op_regs[IBS_OP_DATA] =
				value.op_regs[IBS_OP_DATA];
		op_samples[i].op_regs[IBS_OP_DATA2] =
				value.op_regs[IBS_OP_DATA2];
		op_samples[i].op_regs[IBS_OP_DATA3] =
				value.op_regs[IBS_OP_DATA3];
		op_samples[i].op_regs[IBS_DC_LINADDR] =
				value.op_regs[IBS_DC_LINADDR];
		op_samples[i].op_regs[IBS_DC_PHYSADDR] =
				value.op_regs[IBS_DC_PHYSADDR];
		
		total += op_samples[i].count;
		op_samples_max += op_samples[i].count;
		i++;

		op_samples_cnt++;
		key = next_key;
		bpf_map_delete_elem(fd, &next_key);
	}
	max = i;

	if (max >= MAX_IBS_SAMPLES) 
		printf("Processed maximum samples. "
		       "Likely to have dropped some. Increase the value of "
		       "MAX_IBS_SAMPLES\n");

	*total_freq = total;

	return max;
}

static void print_op_statistics(unsigned long samples)
{
	int i, j, pct;
	u64 addr, paddr, ip;
	u64 total;
	char func[21];

	if (!samples)
		return;

	qsort(op_samples, samples, sizeof(struct ibs_op_sample), op_cmp);
	//printf("\f\r");


	j = 0;

	total = 0;
	for (i = 0; i < samples; i++)
		total += op_samples[i].count;

	for (i = 0; i < samples; i++) {
		if (op_samples[i].count == 0)
			continue;

		if (op_samples[i].count < min_cnt)
			continue;

		ip    = op_samples[i].ip;

		if (user_space_only && (IBS_KERN_SAMPLE(ip)))
			continue;

		if (j == 0) {
			printf("%-3s %-20s %-20s %-20s %-10s %-10s %-10s %4s\n",
				"No", "FUNCTION", "VA", "PA", "COUNT", "PERCENT", "MODE", "TYPE");
		}

		addr  = op_samples[i].op_regs[IBS_DC_LINADDR];
		paddr = op_samples[i].op_regs[IBS_DC_PHYSADDR];
		pct   = op_samples[i].count * 100 / total;
		snprintf(func, sizeof(func), "%s", get_function_name(ip));
		printf("%-3d %-20s %-20p %-20p %-10d %-10d %-10s %4s\n",
			++j,
			func,
			(void *)addr,
			(void *)paddr,
			op_samples[i].count,
			pct,
			IBS_KERN_SAMPLE(ip) ? "KERNEL" : "USER",
			"DATA");

		op_samples[i].count = 0;
	}
	fflush(stdout);
}

static void process_ibs_op_samples(unsigned long total)
{
	if(summary_report)
		return;

	if (!total)
		return;

	qsort(op_samples, total, sizeof(struct ibs_op_sample), op_cmp);

	print_op_statistics(total);
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

static void process_samples(int fetch_fd, int op_fd)
{
	u64 fetch_cnt, op_cnt, total_freq_fetch, total_freq_op;

	fetch_cnt = get_ibs_fetch_samples(fetch_fd, &total_freq_fetch);
	if (fetch_cnt) {
		process_ibs_fetch_samples(total_freq_fetch);
	}

	op_cnt = get_ibs_op_samples(op_fd, &total_freq_op);
	if (op_cnt) {
		process_ibs_op_samples(total_freq_op);
	}

}

int main(int argc, char **argv)
{
	int opt;
	int freq = MEMB_CLOCK;
	int msecs = MEMB_INTVL;
	int err = -1;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog[3] = {NULL, NULL, NULL};
	struct bpf_link **fetch_links = NULL, **op_links = NULL;
	struct bpf_link **perf_links = NULL;
	char filename[256];
        struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	int map_fd[MAX_MAPS];
	char *include_pids = NULL;
	char *include_ppids = NULL;
	unsigned long fetch_cnt_old, op_cnt_old;
	unsigned long fetch_cnt_new, op_cnt_new;

        if (setrlimit(RLIMIT_MEMLOCK, &r)) {
                perror("setrlimit(RLIMIT_MEMLOCK)");
                return 1;
        }

	while ((opt = getopt(argc, argv, cmd_args)) != -1) {
		switch (opt) {
		case 'm':
			min_pct = atof(optarg);
			break;
		case 'M':
			min_cnt = atoi(optarg);
			break;
		case 'r':
			report_frequency = atoi(optarg);
			if (report_frequency < 1)
				report_frequency = 1;
			
			break;
		case 'f':
			freq = atoi(optarg);
			break;
		case 'F':
			obj_filename = optarg;
			break;
		case 'p':
			include_pids = optarg;
			if (include_ppids) {
				printf("Only pid or ppid, not both\n");
				usage();
				return -1;
			}
			break;
		case 'P':
			include_ppids = optarg;
			if (include_pids) {
				printf("Only pid or ppid, not both\n");
				usage();
				return -1;
			}
			break;
		case 'v':
			verbose = atoi(optarg);
			break;
		case 'h':
			usage();
			return 0;
		case 'u':
			user_space_only = true;
			break;
		case 'l':
			l3miss = true;
			break;
		case 's':
			summary_report = true;
			break;
		default:
			usage();
			return -1;
		}
	}

	if (argc - optind > 1) {
		usage();
		return -1;
	}

	if (argc - optind == 1)
		msecs = atoi(argv[optind]);

	if (freq == 0 || msecs == 0) {
		usage();
		return 1;
	}

	cnt_functions = load_function_names(obj_filename, functions,
					    MAX_IBS_SAMPLES);
	if (cnt_functions <= 0) {
		fprintf(stderr, "Cannot load symbols from object file\n");
		return -1;
	}

	open_ibs_devices();
	ibs_fetchop_config_set();
	/* initialize kernel symbol translation */
	/*
	if (load_kallsyms()) {
		fprintf(stderr, "ERROR: loading /proc/kallsyms\n");
		return -EINVAL;
	}
	*/

	/* create perf FDs for each CPU */
	nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
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

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		obj = NULL;
		goto cleanup;
	}


	prog[0] = bpf_object__find_program_by_name(obj, "ibs_fetch_event");
	if (!prog[0]) {
		fprintf(stderr, "BPF cannot find ibs_trace_event program\n");
		goto cleanup;
	}

	prog[1] = bpf_object__find_program_by_name(obj, "ibs_op_event");
	if (!prog[1]) {
		fprintf(stderr, "BPF cannot find ibs_op_event program\n");
		goto cleanup;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	cpu_nodes = fill_cpu_nodes(obj);
	if (cpu_nodes <= 0)
		goto cleanup;

	if (process_include_pids(obj, include_pids, false))
		goto cleanup;

	if (process_include_pids(obj, include_ppids, true))
		goto cleanup;

	map_fd[0] = bpf_object__find_map_fd_by_name(obj, "ibs_fetch_map");
	if (map_fd[0] < 0) {
		fprintf(stderr, "BPF cannot find ibs_fetch_map\n");
		goto cleanup;
	}

	map_fd[1] = bpf_object__find_map_fd_by_name(obj, "ibs_op_map");
	if (map_fd[1] < 0) {
		fprintf(stderr, "BPF cannot find ibs_op_map\n");
		goto cleanup;
	}

	map_fd[3] = bpf_object__find_map_fd_by_name(obj, "op_page");
	if (map_fd[3] < 0) {
		fprintf(stderr, "BPF cannot find op_map\n");
		goto cleanup;
	}

        map_fd[4] = bpf_object__find_map_fd_by_name(obj, "fetch_counter");
        if (map_fd[4] < 0) {
                fprintf(stderr, "BPF cannot find map_cmd\n");
                goto cleanup;
        }

        map_fd[5] = bpf_object__find_map_fd_by_name(obj, "op_counter");
        if (map_fd[5] < 0) {
                fprintf(stderr, "BPF cannot find map_cmd\n");
                goto cleanup;
        }

	err = parse_additional_bpf_programs(obj);
	if (err) {
		goto cleanup;
	}
	
	err = launch_additional_bpf_programs();
	if (err) {
		goto cleanup;
	}

	//printf("\f");
	assert(err == 0);

	fetch_cnt_old = 0;
	fetch_cnt_new = 0;
	op_cnt_old = 0;
	op_cnt_new = 0;

	while (!err) {

		if (ibs_fetch_sampling_begin(freq, prog[0], fetch_links) != 0) {
			fprintf(stderr, "IBS Fetch sampling not supported, "
				"falling back to software sampling\n");
			if (perf_sampling_begin(freq, prog[2], perf_links) != 0)
				goto cleanup;
		}

		if (ibs_op_sampling_begin(freq, prog[1], op_links) != 0) {
			fprintf(stderr, "IBS OP sampling not supported, "
				"Will not be able to sample hot data\n");
		}

		usleep(msecs * 1000);

		if (fetch_links)
			ibs_sampling_end(fetch_links); /* IBS fetch */

		if (op_links)
			ibs_sampling_end(op_links);    /* IBS op */

		process_samples(map_fd[0], map_fd[1]);
	}

cleanup:
	terminate_additional_bpf_programs();
	if (fetch_links)
		ibs_sampling_end(fetch_links); /* IBS fetch */

	if (op_links)
		ibs_sampling_end(op_links);    /* IBS op */

	free(fetch_links);
	bpf_object__close(obj);

	return err;
}
