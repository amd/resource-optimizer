/*
 * profiler_user.c - IBS/LBR profiler user space functions
 *
 * Copyright (c) 2015 The Libbpf Authors. All rights reserved.
 * Copyright (c) 2023 Advanced Micro Devices, Inc. All Rights Reserved.
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
#include "membalancer_lib.h"
#include "profiler_pvt.h"

#define MEMB_CLOCK 25
#define MEMB_INTVL 100
#define MIN_MIGRATED_PAGES 	1024
#define MIN_MIGRATED_PAGES_TIER 4096

#undef MIN_IBS_CLASSIC_SAMPLES
#undef MIN_IBS_L3MISS_SAMPLES
#undef MIN_IBS_SAMPLES
#undef MIN_IBS_FETCH_SAMPLES
#undef MIN_IBS_OP_SAMPLES
#define MIN_IBS_CLASSIC_SAMPLES 100
#define MIN_IBS_L3MISS_SAMPLES  50
#define MIN_IBS_SAMPLES min_ibs_samples
#define MIN_IBS_FETCH_SAMPLES (MIN_IBS_SAMPLES / 2)
#define MIN_IBS_OP_SAMPLES    (MIN_IBS_SAMPLES / 2)

int nr_cpus;
static double min_pct = 0.01;
bool user_space_only = false;
int verbose = 2;
unsigned int cpu_nodes;
float maximizer_mode = 0.2;
bool tracer_physical_mode = true;
int report_frequency = 1;
unsigned int min_ibs_samples = MIN_IBS_CLASSIC_SAMPLES;
int timer_clock = 1;

static char cmd_args[]  = "c:f:P:p:r:M:o:v:t:D:L:B:I:L:uhcbVlS::";

char * ebpf_object_dir = "../kernel/common/";
atomic64_t fetch_cnt, op_cnt;

#define IBS_FETCH_DEV "/sys/devices/ibs_fetch/type"
#define IBS_OP_DEV    "/sys/devices/ibs_op/type"

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
	printf("       -f <freq>   # sample frequency (Hertz), default %d Hz\n",
			MEMB_CLOCK);
	printf("       -p <pid> Process ID to be tracked\n");
	printf("       -P <pid> Parent Process ID to be tracked\n");
	printf("       -c list of cpus to collect samples on <comma separated"
			"or range with hyphen>\n");
	printf("       -u Only user space samples\n");
	printf("       -h help, displays this information\n");
	printf("       -V <level>, Verbose level\n");
	printf("       -l Collects only l3miss IBS samples\n");
	printf("       -M Maximizer mode to increase "
			"the frequency of samples' collection\n");
	printf("       -o <eBPF kernel module location, default is ");
	printf("../kern/common\n");
	printf("       <duration> Interval in milliseconds, "
	       "default %d\n", MEMB_INTVL);

	printf("\nExamples\n");
	printf("Example 1: For instructiona and data profiling ...\n");
	printf("%s -f 25 -u  -v4 -M 1 -r 2 5000  -I5 -r2 [P|p pid[,pid2]\n",
		cmd);
	printf("\nExample 2: For last branch record (LBR) ...\n");
	printf("%s -f 25 -u  -v4 -M 1 -r 2 5000  -L5 -r2 [P|p pid[,pid2]\n",
		cmd);
	printf("\n");
}

/* Remove this function after library cleanup */
int freemem_threshold(void)
{
	return 0;
}

static void ibs_fetchop_config_set(void)
{
	min_ibs_samples  = (l3miss) ? MIN_IBS_L3MISS_SAMPLES :
			   MIN_IBS_CLASSIC_SAMPLES;
}

unsigned long peek_ibs_samples(int fd, unsigned long old, unsigned long *new)
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


int bst_add_page(pid_t pid, int to_node, unsigned long addr,
		 bool upgrade, struct bst_node **root)
{
	return 0;
}

int parse_additional_bpf_programs(struct bpf_object *bpfobj)
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

int launch_additional_bpf_programs(void)
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

int terminate_additional_bpf_programs(void)
{
	int i;

	for (i = 0; i < addtional_program_count; i++)
		bpf_link__destroy(additional_bpflinks[i]);

	return 0;
}

void profiler_cleanup(int fetch_fd, int op_fd)
{
	cleanup_code_samples(fetch_fd);
	cleanup_data_samples(op_fd);
}

void set_knob(int fd, int knob, int value)
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

int init_and_load_bpf_programs(struct bpf_program **prog, int *map_fd,
			       struct bpf_object *obj, char **program_names,
			       char **map_fd_names)

{
	int sts = 0;

	if (verbose >= 5)
		printf("Loading bpf programs and maps for profiler\n");

	sts = load_bpf_programs(prog, obj, program_names, TOTAL_BPF_PROGRAMS);
	if (sts)
		return sts;

	sts = load_perf_fd_bpf_maps(map_fd, obj, map_fd_names, TOTAL_MAPS);
	return sts;
}

int main(int argc, char **argv)
{
	int base_page_size;
	int opt;
	int freq = MEMB_CLOCK;
	int msecs = MEMB_INTVL;
	int err = -1;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
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
		case 'l':
			l3miss = true;
			break;
		case 'm':
			min_pct = atof(optarg);
			break;
		case 'I':
			iprofiler = atof(optarg);
			break;
		case 'L':
			lbr_profiler = atof(optarg);
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
		case 'u':
			user_space_only = true;
			break;
		case 'o':
			ebpf_object_dir = optarg;
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

	do {
		if (iprofiler)
			err = iprofiler_function(argv[0], freq, msecs,
						 include_pids, include_ppids,
						 cpusetp);
		else
			err = lbr_profiler_function(argv[0], freq, msecs,
						    include_pids, include_ppids,
						    cpusetp);

	}  while(err == ETIMEDOUT);

	CPU_FREE(cpusetp);

	return err;
}
