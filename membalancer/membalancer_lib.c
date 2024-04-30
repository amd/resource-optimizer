/*
 * membalancer_lib.c - Automatic NUMA memory balancer library functions.
 *
 * Copyright (c) 2015 The Libbpf Authors. All rights reserved.
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

#define _GNU_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <sys/resource.h>
#include <assert.h>
#include <limits.h>
#include <sys/time.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "memory_profiler_common.h"
#include "memory_profiler_arch.h"
#include "thread_pool.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"
#include "membalancer_migrate.h"
#include "heap_user.h"

static int ibs_fetch_device = -1;
static int ibs_op_device    = -1;
#define FETCH_CONFIG        57
#define FETCH_CONFIG_L3MISS 59
#define OP_CONFIG           19
#define OP_CONFIG_L3MISS    16

static int ibs_fetch_config;
static int ibs_op_config;
bool l3miss = false;

#define IBS_FETCH_DEV "/sys/devices/ibs_fetch/type"
#define IBS_OP_DEV    "/sys/devices/ibs_op/type"

int get_ibs_device_type(const char *dev)
{
	int fd, ret;
	char buffer[32];

	fd = open(dev, O_RDONLY);
	if (fd < 0)
		return -errno;

	memset(buffer, 0, sizeof(buffer));
	ret = read(fd, &buffer, sizeof(buffer));
	close(fd);

	if (ret < 0)
		return -errno;

	return atoi(buffer);
}

void open_ibs_devices(void)
{
	ibs_fetch_device = get_ibs_device_type(IBS_FETCH_DEV);
	ibs_op_device    = get_ibs_device_type(IBS_OP_DEV);
	ibs_fetch_config = (l3miss) ? FETCH_CONFIG_L3MISS : FETCH_CONFIG;
	ibs_op_config    = (l3miss) ? OP_CONFIG_L3MISS : OP_CONFIG;
}

void close_ibs_devices(void)
{
	if (ibs_fetch_device > 0)
		close(ibs_fetch_device);

	if (ibs_op_device > 0)
		close(ibs_op_device);
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
		bpf_map_update_elem(fd, &pid, &pid, BPF_NOEXIST);
		i = j;
	}

	close(fd);

	return 0;
}

int process_include_pids(struct bpf_object *obj, char *pid_string, bool ppid)
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

	return online - '0';
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
			    struct bpf_program *prog,
			    struct perf_event_attr *perf)
{
	int pmu_fd;
	int cpu = 0;
	int err;


	while( cpu < nr_cpus ) {

		if(!CPU_ISSET(cpu, cpusetp)) {
			cpu++;
			continue;
		}

		pmu_fd = syscall(SYS_perf_event_open, perf, -1, cpu, -1, 0);

		if (pmu_fd < 0) {
			fprintf(stderr, "Cannot arm sampling cpu %d,"
					"error %s\n", cpu, strerror(errno));
			return -errno;
		}

		links[cpu] = bpf_program__attach_perf_event(prog, pmu_fd);
		if ((err = libbpf_get_error(links[cpu]))) {
			fprintf(stderr, "ERROR: Attach perf event\n");
			links[cpu] = NULL;
			close(pmu_fd);
			return err;
		}

		cpu++;
	}
	return 0;
}

int parse_cpulist(const char *cpu_list, cpu_set_t *cpusetp, size_t set_size)
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

		/* CPU 0 can't be disabled */
		if (from++ == 0) CPU_SET_S(0, set_size, cpusetp);

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

int perf_sampling_begin(int freq, struct bpf_program *prog,
			struct bpf_link *links[], cpu_set_t *cpusetp)
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
		.pinned = 0,
		.precise_ip = 0,
		.mmap = 1,
		.comm = 1,
		.task = 1,
		.sample_id_all = 1,
		.comm_exec = 1,
		.read_format = 0,
	};

	return attach_perfevent(cpusetp, links, prog, &perf);
}

int ibs_fetch_sampling_begin(int freq, struct bpf_program *prog,
			     struct bpf_link *links[], cpu_set_t *cpusetp)
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

	return attach_perfevent(cpusetp, links, prog, &ibs_fetch);

}

int lbr_sampling_begin(int freq, struct bpf_program *prog,
		       struct bpf_link *links[], cpu_set_t *cpusetp)
{
	struct perf_event_attr attr = {
		.freq = 1,
		.type = PERF_TYPE_HARDWARE,
		.sample_period = freq,
		.config = PERF_COUNT_HW_CPU_CYCLES,
		.sample_type = PERF_SAMPLE_IP|PERF_SAMPLE_TID|
				PERF_SAMPLE_TIME|PERF_SAMPLE_ID|
				PERF_SAMPLE_PERIOD|PERF_SAMPLE_BRANCH_STACK,
				/*
				PERF_SAMPLE_ADDR | PERF_SAMPLE_ADDR |
				PERF_SAMPLE_PHYS_ADDR,
				*/
		/*
		.branch_sample_type = PERF_SAMPLE_BRANCH_USER|
					PERF_SAMPLE_BRANCH_HV|
					PERF_SAMPLE_BRANCH_ANY,
		*/
		.branch_sample_type = PERF_SAMPLE_BRANCH_ANY|
				      PERF_SAMPLE_BRANCH_USER,
		.disabled = 1,
		.inherit = 1,
		.size = sizeof(struct perf_event_attr),
		.exclude_kernel = 0,
		.exclude_user = 0,
		.exclude_idle = 0,
		.exclude_hv = 0,
		.exclude_host = 0,
		.pinned = 0,
		.precise_ip = 0,
		.mmap = 1,
		.comm = 1,
		.task = 1,
		.sample_id_all = 1,
		.comm_exec = 1,
		.read_format = 0,
	};

	return attach_perfevent(cpusetp, links, prog, &attr);

}

void ibs_sampling_end(struct bpf_link *links[], int *fd, int max_fd)
{
	int i;
	int pmu_fd;

	for (i = 0; i < nr_cpus; i++) {
		if (links[i] == NULL)
			continue;

		pmu_fd = bpf_link__fd(links[i]);
		assert(pmu_fd > 0);
		close(pmu_fd);
		bpf_link__destroy(links[i]);
		links[i] = NULL;
	}
}

int ibs_op_sampling_begin(int freq, struct bpf_program *prog,
			  struct bpf_link *links[], cpu_set_t *cpusetp)
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

	return attach_perfevent(cpusetp, links, prog, &ibs_op);
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
	int cpu_cnt = 0;

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

		for (j = 0; j < 4; j++) {
			next_cpu = k * 4 + j;
			CPU_SET(next_cpu, &node_cpumask[node]);
			bpf_map_update_elem(fd, &next_cpu, &node, BPF_NOEXIST);
			numa_node_cpu[node].cpu_list[cpu_cnt++] = next_cpu;
			/* Keeping a simple lookup table for cpu to node */
			numa_cpu[next_cpu]  = node;
		}
		k++;
	}
	numa_node_cpu[node].cpu_cnt = cpu_cnt;

	return 0;
}

int fill_cpu_nodes(struct bpf_object *obj)
{
	char cpu_map[1024];
	int node, fd, bytes;

	fd = bpf_object__find_map_fd_by_name(obj, "cpu_map");
	if (fd < 0)
		return -EINVAL;

	memset(numa_cpu, -1, MAX_CPU_CORES * sizeof(int));

	for (node = 0;; node++) {
		bytes = read_cpu_node(node, cpu_map, sizeof(cpu_map));
		if (bytes <= 1)
			break;

		populate_cpu_map(obj, fd, node, cpu_map, bytes - 1);
	}

	return node;
}
