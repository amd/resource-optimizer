/*
 * membalancer_tracer.c - Automatic NUMA memory balancer Based on IBS sampler
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
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <numa.h>
#include <numaif.h>
#include <stdbool.h>
#include <sys/mman.h>
#define __USE_GNU
#include <search.h>
#include "memory_profiler_common.h"
#include "memory_profiler_arch.h"
#include "thread_pool.h"
#include "membalancer_utils.h"
#include "membalancer_numa.h"

static unsigned long code_overall_samples[MAX_NUMA_NODES];
static unsigned long data_overall_samples[MAX_NUMA_NODES];
static char *tracer_dir;

#define NUMA_NODE_INFO "/sys/devices/system/node"

#define MAX_BASE_PAGE_SIZE (32 * 1024 * 1024)
#define BASE_PAGE_SIZE     (1024 * 1024)
#define MAX_PAGES_PER_NODE (MAX_BASE_PAGE_SIZE / PAGE_SIZE)
static unsigned long base_page_size = BASE_PAGE_SIZE;

struct page_ref {
	unsigned int pages_4k;
	unsigned int filler;
	unsigned long access_count;
	unsigned long access_count2;
};

struct page {
	unsigned long vaddr;
	unsigned long paddr;
	unsigned long pageref;
};

struct bst_node {
	unsigned long basepage;
	struct page page[MAX_PAGES_PER_NODE];
	unsigned long count;
	int pages;
	int type;
};

struct bst_node_dummy {
	unsigned long basepage;
};

static char *title[] = {
	">= 10%",
	">= 5%",
	">= 4%",
	">= 3%",
	">= 2%",
	">= 1%",
	">= 0.5%",
	">= 0.4%",
	">= 0.3%",
	">= 0.2%",
	">= 0.1%",
	">= 0.01%",
	"< 0.01%",
};

enum {
	GTEQ_10_PCT,
	GTEQ_5_PCT,
	GTEQ_4_PCT,
	GTEQ_3_PCT,
	GTEQ_2_PCT,
	GTEQ_1_PCT,
	GTEQ_P5_PCT,
	GTEQ_P4_PCT,
	GTEQ_P3_PCT,
	GTEQ_P2_PCT,
	GTEQ_P1_PCT,
	GTEQ_P01_PCT,
	BELOW_P01_PCT,
	SAMPLE_PCTS,
};

struct tracer_stats {
	unsigned long unique_pages;
	unsigned long samples;
	struct {
		unsigned int ccount[SAMPLE_PCTS];
		unsigned int count[SAMPLE_PCTS];
		unsigned int used_count[];
	};
};

static struct bst_node *code_nodes_array;
static struct bst_node *data_nodes_array;
static unsigned long max_code_nodes = (1024 * 1024);
static unsigned long max_data_nodes = (1024 * 1024);
static unsigned long cur_code_nodes;
static unsigned long cur_data_nodes;

enum {
	CODE_ENTRY,
	DATA_ENTRY,
};

struct tracer_entry {
	int type;
	int count;
	unsigned long vaddr;
	unsigned long paddr;
};

void update_sample_statistics_tracer(unsigned long *samples, bool fetch)
{
	int i;

	if (fetch) {
		for (i = 0; i < max_nodes; i++)
			code_overall_samples[i] = samples[i];
	} else {
		for (i = 0; i < max_nodes; i++)
			data_overall_samples[i] = samples[i];
	}
}

void get_sample_statistics_tracer(bool code, unsigned long **samples,
				  int *count)
{
	*count   = max_nodes;
	*samples = (code) ? code_overall_samples : data_overall_samples;
}

static int tracer_open_file(const char *file)
{
	int fd;
	char filename[1024];

	snprintf(filename, sizeof(filename), "%s/%s", tracer_dir, file);

	return open(filename, O_APPEND|O_RDWR);
}


static int tracer_log_entry(int fd, int type, unsigned long vaddr,
			    unsigned long paddr, int count)
{
	struct tracer_entry entry;
	const int size = sizeof(entry);
	int bytes;


	entry.type  = type;
	entry.count = count;
	entry.vaddr = vaddr;
	entry.paddr = paddr;

	if (write(fd, &entry, size) != size) {
		printf("tracer_log_entry failed\n");
		return -EIO;
	}

	return 0;
}

void process_code_samples_tracer(struct bst_node **rootpp,
				 unsigned long total,
				 bool user_space_only)
{
	int i, j, node, logfd;
	unsigned long count;


	if (!total)
		return;

	logfd = tracer_open_file("fetch");
	if (logfd < 0) {
		printf("Cannot open file %s/fetch", tracer_dir);
		return;
	}

	for (node = 0; node < max_nodes; node++) {
		for (i = code_samples_cnt[node] - 1; i > -1; i--) {
			float pct;

			if (!code_samples[node][i].count)
				continue;

			count = 0;
			for (j = 0; j < max_nodes; j++)
				count += code_samples[node][i].counts[j];

			pct  = (float)code_samples[node][i].count * 100;
			pct /= total;

			/*
			if (pct < min_pct || count < MIN_CNT) {
				code_samples[node][i].count = 0;
				continue;
			}
			*/

			if (user_space_only &&
				KERN_SAMPLE(code_samples[node][i].ip)) {
				code_samples[node][i].count = 0;
				continue;
			}

			tracer_log_entry(logfd, CODE_ENTRY,
					 code_samples[node][i].vaddr,
					 code_samples[node][i].paddr,
					 code_samples[node][i].count);

			code_samples[node][i].count = 0;
		}
	}

	fdatasync(logfd);
	close(logfd);
}

void process_data_samples_tracer(struct bst_node **rootpp,
				 unsigned long total,
				 bool user_space_only)
{
	int i, j, node, logfd;
	unsigned long count;

	logfd = tracer_open_file("op");
	if (logfd < 0) {
		printf("Cannot open file %s/fetch", tracer_dir);
		return;
	}

	for (node = 0; node < max_nodes; node++) {
		for (i = data_samples_cnt[node] - 1; i > -1; i--) {
			float pct;

			if (!data_samples[node][i].count)
				continue;

			count = 0;
			for (j = 0; j < max_nodes; j++)
				count += data_samples[node][i].counts[j];

			pct  = (float)data_samples[node][i].count * 100;
			pct /= total;
			/*
			if (pct < min_pct || count < MIN_CNT) {
				data_samples[node][i].count = 0;
				continue;
			}
			*/

			if (!user_space_only &&
				IBS_KERN_SAMPLE(
				data_samples[node][i].ip)) {
				data_samples[node][i].count = 0;
				continue;
			}

			tracer_log_entry(logfd, DATA_ENTRY,
					 data_samples[node][i].vaddr,
					 data_samples[node][i].paddr,
					 data_samples[node][i].count);

			data_samples[node][i].count = 0;
		}
	}

	fdatasync(logfd);
	close(logfd);
}

static int tracer_create_file(const char *dir, const char *file)
{
	char filename[1024];
	int fd;

	snprintf(filename, sizeof(filename), "%s/%s", dir, file);

	fd = open(filename, O_CREAT|O_TRUNC, 0640);
	if (fd < 0)
		return -errno;

	close(fd);

	return 0;
}

static void trace_remove_file(const char *dir, const char *file)
{
	char filename[1024];

	snprintf(filename, sizeof(filename), "%s/%s", dir, file);
	unlink(filename);
}

void tracer_deinit(void)
{
	trace_remove_file(tracer_dir, "fetch");
	trace_remove_file(tracer_dir, "op");
}

int tracer_init(const char *path)
{
	int err;

	if (!path)
		tracer_dir = "/tmp";
	else
		tracer_dir = (char *)path;

	err = tracer_create_file(tracer_dir, "fetch");
	if (err)
		return err;

	err = tracer_create_file(tracer_dir, "op");
	if (err) {
		trace_remove_file(tracer_dir, "fetch");
		return err;
	}

	return 0;
}

static void init_node(int type, unsigned long baseaddr, unsigned long vaddr,
		      unsigned long paddr, int refcnt, struct bst_node *node,
		      bool physical_mode)
{
	int idx;

	if (physical_mode) {
		idx      = (paddr - baseaddr) / PAGE_SIZE;
	} else {
		idx      = (vaddr - baseaddr) / PAGE_SIZE;
	}

	assert(idx >= 0 && idx < MAX_PAGES_PER_NODE);

	node->basepage = baseaddr;
	node->type     = type;

	if (physical_mode) {
		node->page[idx].paddr = paddr;
	} else {
		node->page[idx].vaddr = vaddr;
	}

	node->page[idx].pageref = refcnt;
	node->count = refcnt;
}

static void update_node(int type, unsigned long baseaddr, unsigned long vaddr,
			unsigned long paddr, int refcnt, struct bst_node *node,
			bool physical_mode)
{
	int idx;

	assert(baseaddr == node->basepage);

	if (physical_mode) {
		idx      = (paddr - baseaddr) / PAGE_SIZE;
	} else {
		idx      = (vaddr - baseaddr) / PAGE_SIZE;
	}
	assert(idx >= 0 && idx < MAX_PAGES_PER_NODE);

	if (physical_mode) {
		node->page[idx].paddr = paddr;
	} else {
		node->page[idx].vaddr = vaddr;
	}

	node->page[idx].pageref = refcnt;
	node->count += refcnt;
}


static int bst_cmp(const void *firstp, const void *secondp)
{
	struct bst_node *first  = (struct bst_node *)firstp;
	struct bst_node *second = (struct bst_node *)secondp;

	if (first->basepage < second->basepage)
		return -1;

	if (first->basepage > second->basepage)
		return 1;

	return 0;
}

/*
static void dealloc_node(int type, struct bst_node *node)
{
	if (type == CODE_ENTRY)
		--cur_code_nodes;
	else
		--cur_data_nodes;
}
*/

static struct bst_node * alloc_node(int type)
{
	struct bst_node *node;
	if (type == CODE_ENTRY) {
		if (!code_nodes_array) {
			code_nodes_array = malloc(sizeof(*node) *
						  max_code_nodes);
			if (!code_nodes_array)
				return NULL;
		}

		if (cur_code_nodes >= max_code_nodes) {
			code_nodes_array = realloc(code_nodes_array,
						   sizeof(*node) * 2 *
						   max_code_nodes);
			if (!code_nodes_array)
				return NULL;

			max_code_nodes *= 2;
		}
		node = &code_nodes_array[cur_code_nodes];
		cur_code_nodes++;

		return node;
	}

	if (!data_nodes_array)
		data_nodes_array = malloc(sizeof(*node) * max_data_nodes);

	if (!data_nodes_array)
		return NULL;

	if (cur_data_nodes >= max_data_nodes) {
		data_nodes_array = realloc(data_nodes_array, sizeof(*node) *
					 max_data_nodes * 2);
		if (!data_nodes_array)
			return NULL;

		max_data_nodes *= 2;
	}
	node = &data_nodes_array[cur_data_nodes];
	cur_data_nodes++;

	return node;
}

static int add_to_bst(struct bst_node **root, int type, unsigned vaddr,
		      unsigned paddr, int refcnt, bool physical_mode)
{
	struct bst_node *node, *new_node, **nodepp;
	struct bst_node_dummy dummy;

	dummy.basepage = (physical_mode) ? paddr : vaddr;
	dummy.basepage &= ~(base_page_size - 1);
	if (*root) {
		nodepp = tfind(&dummy, (void **)root, bst_cmp);
		if (nodepp) {
			node = *nodepp;
			update_node(type, dummy.basepage, vaddr, paddr, refcnt,
				node, physical_mode);
			return 0;
		}
	}

	new_node = alloc_node(type);
	if (!new_node)
		return -ENOMEM;

	init_node(type, dummy.basepage, vaddr, paddr, refcnt, new_node,
		  physical_mode);
	nodepp = tsearch(new_node, (void **)root, bst_cmp);
	if (nodepp) {
		node = *nodepp;
		assert(*nodepp == new_node);
		/*
		assert(new_node->basepage == node->basepage);
		if (new_node != node) {
			assert(0);
			update_node(type, dummy.basepage, vaddr, paddr, refcnt,	
				    node, physical_mode);
			dealloc_node(type, new_node);
		}
		*/
	}

	return 0;
}

static int map_file(const char *file, int *fdp, void **addr,
		    unsigned long *size)
{
	char filename[1024];
	int fd;
	struct stat st;
	void *mapaddr;

	snprintf(filename, sizeof(filename), "%s/%s", tracer_dir, file);

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -errno;

	if (fstat(fd, &st)) {
		close(fd);
		return -errno;
	}
	
	if (st.st_size == 0) {
		close(fd);
		return -ENOENT;
	}

	mapaddr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!mapaddr) {
		close(fd);
		return -EFAULT;
	}

	*addr = mapaddr;
	*fdp  = fd;
	*size = st.st_size;

	return 0;
}

static void unmap_file(int fd, void *addr, unsigned long size)
{
	munmap(addr, size);
	close(fd);
}

static int node_cmp(const void *p1, const void *p2)
{
	const struct bst_node *n1 = p1;
	const struct bst_node *n2 = p2;

	if (n1->count > n2->count)
		return -1;

	if (n1->count < n2->count)
		return 1;

	return 0;
}

static unsigned long collect_code_statistics(
				struct bst_node **code_root,
				bool physical_mode)
{
	int fd, err;
	void *addr;
	unsigned long size, recs, i;
	struct tracer_entry *entry;
	unsigned long count = 0;

	err = map_file("fetch", &fd, &addr, &size);
	assert(!err || err == -ENOENT);

	if (err)
		return 0;

	entry = addr;

	assert(*code_root == NULL);

	for (i = 0; i < size /sizeof(*entry); i++) {
		err = add_to_bst(code_root, CODE_ENTRY, entry->vaddr,
				 entry->paddr, entry->count,
				 physical_mode);
		if (err)
			break;
		count += entry->count;
		entry++;
	}

	qsort(code_nodes_array, cur_code_nodes, sizeof(*code_nodes_array),
	      node_cmp);

	unmap_file(fd, addr, size);

	return count;
}

static unsigned long collect_data_statistics(struct bst_node **data_root,
					   bool physical_mode)
{
	int fd, err;
	void *addr;
	unsigned long size, recs, i;
	struct tracer_entry *entry;
	unsigned long count = 0;

	err = map_file("op", &fd, &addr, &size);
	assert(!err || err == -ENOENT);

	if (err)
		return 0;

	entry = addr;

	assert(*data_root == NULL);
	for (i = 0; i < size /sizeof(*entry); i++) {
		err = add_to_bst(data_root, DATA_ENTRY, entry->vaddr,
				 entry->paddr, entry->count,
				 physical_mode);
		if (err)
			break;
		count += entry->count;
		entry++;
	}

	qsort(data_nodes_array, cur_data_nodes, sizeof(*data_nodes_array),
		node_cmp);

	unmap_file(fd, addr, size);

	return count;
}

static void do_nothing(void *arg)
{
}

static void update_stats(unsigned total, unsigned long count,
			 struct tracer_stats  *stats)
{

	if ((count * 100 / total) >= 10) {
		stats->ccount[GTEQ_10_PCT] += count;
		stats->count[GTEQ_10_PCT]++;
	} else if ((count * 100 / total) >= 5) {
		stats->ccount[GTEQ_5_PCT] += count;
		stats->count[GTEQ_5_PCT]++;
	} else if ((count * 100 / total) >= 4) {
		stats->ccount[GTEQ_4_PCT] += count;
		stats->count[GTEQ_4_PCT]++;
	} else if ((count * 100 / total) >= 3) {
		stats->ccount[GTEQ_3_PCT] += count;
		stats->count[GTEQ_3_PCT]++;
	} else if ((count * 100 / total) >= 2) {
		stats->ccount[GTEQ_2_PCT] += count;
		stats->count[GTEQ_2_PCT]++;
	} else if ((count * 100 / total) >= 1) {
		stats->ccount[GTEQ_1_PCT] += count;
		stats->count[GTEQ_1_PCT]++;
	} else if ((count * 100 * 10 / total) >= 5) {
		stats->ccount[GTEQ_P5_PCT] += count;
		stats->count[GTEQ_P5_PCT]++;
	} else if ((count * 100 * 10 / total) >= 4) {
		stats->ccount[GTEQ_P4_PCT] += count;
		stats->count[GTEQ_P4_PCT]++;
	} else if ((count * 100 * 10 / total) >= 3) {
		stats->ccount[GTEQ_P3_PCT] += count;
		stats->count[GTEQ_P3_PCT]++;
	} else if ((count * 100 * 10 / total) >= 2) {
		stats->ccount[GTEQ_P2_PCT] += count;
		stats->count[GTEQ_P2_PCT]++;
	} else if ((count * 100 * 10 / total) >= 1) {
		stats->ccount[GTEQ_P1_PCT] += count;
		stats->count[GTEQ_P1_PCT]++;
	} else if ((count * 100 * 100 / total) >= 1) {
		stats->ccount[GTEQ_P01_PCT] += count;
		stats->count[GTEQ_P01_PCT]++;
	} else {
		stats->ccount[BELOW_P01_PCT] += count;
		stats->count[BELOW_P01_PCT]++;
	}
}

static void process_page_ref(struct page *page,
			     int count,
			     struct page_ref *pages_used,
			     struct page_ref *pages_unused)
{
	int i, num_pages;
	bool references;

	if (page[i].pageref)
		references = true;
	else
		references = false;

	num_pages = 1;

	for (i = 1; i < count; i++) {
		if (references) {
			if (page[i].pageref) {
				num_pages++;
			} else {
				pages_used[num_pages - 1].access_count++;
				num_pages = 1;
				references = false;
			}
		} else {
			if (!page[i].pageref)
				num_pages++;
			else {
				pages_unused[num_pages - 1].access_count++;
				num_pages = 1;
				references = true;
			}
		}
	}

	if (num_pages) {
		if (references)
			pages_used[num_pages - 1].access_count++;
		else
			pages_unused[num_pages - 1].access_count++;
	}
}

static void process_code_statistics(struct bst_node *code_root,
				     unsigned long count,
				     struct tracer_stats *stats,
				     struct page_ref *pages_used,
				     struct page_ref *pages_unused,
				     int pages)
{
	unsigned long i;

	if (!cur_code_nodes)
		return;
	if (!count)
		return;

	stats->unique_pages = cur_code_nodes;
	stats->samples      = count;

	for (i = 0; i < cur_code_nodes; i++) {
		update_stats(count, code_nodes_array[i].count, stats);
		if (code_nodes_array[i].count)
			process_page_ref(code_nodes_array[i].page,
					 pages, pages_used, pages_unused);
	}

	free(code_nodes_array);
	cur_code_nodes = 0;
	code_nodes_array = NULL;

	//tdestroy(code_root, do_nothing);
	code_root = NULL;
}

static void process_data_statistics(struct bst_node *data_root,
				  unsigned long count,
				  struct tracer_stats *stats,
				  struct page_ref *pages_used,
				  struct page_ref *pages_unused,
				  int pages)
{
	unsigned long i;

	if (!cur_data_nodes)
		return;

	if (!count)
		return;

	stats->unique_pages = cur_data_nodes;
	stats->samples      = count;

	for (i = 0; i < cur_data_nodes; i++) {
		update_stats(count, data_nodes_array[i].count, stats);
		if (data_nodes_array[i].count)
			process_page_ref(data_nodes_array[i].page,
					pages, pages_used, pages_unused);
	}

	free(data_nodes_array);
	cur_data_nodes = 0;
	data_nodes_array = NULL;

	//tdestroy(data_root, do_nothing);
	data_root = NULL;
}

static void print_stats(struct tracer_stats *stats, bool text)
{
	int i;
	char *type;
	float pct;

	if (!stats->samples)
		return;

	printf("\f");

	if (text)
		type = "CODE";
	else
		type = "DATA";

 	if (text)
		printf("%s%s%s", BRIGHT, MAGENTA, ULINE);
	else
		printf("%s%s%s", BRIGHT, CYAN, ULINE);

  
	printf("%-10s %-10s %-12s %-10s\n",
		"TYPE",
		"BUCKET",
		"UNIQUE PAGES",
		"PERCENTAGE");
	printf("%s", NORM);

	for (i = GTEQ_10_PCT; i < SAMPLE_PCTS; i++) {
		if (stats->count[i] == 0)
			continue;
		pct = (float)(stats->ccount[i] * 100) / stats->samples;

		if (pct >= 10.0)
			printf("%s%s", BRIGHT, BRED);
		else if (pct >= 5.0)
			printf("%s", BRED);
		else if (pct >= 2.0)
			printf("%s%s", BRIGHT, BMAGENTA);
		else if (pct >= 1.0)
			printf("%s%s", BRIGHT, BBLUE);
		else if (pct >= 0.1)
			printf("%s", BBLUE);
		else
			printf("%s", BCYAN);

		printf("%-10s %-10s %-12d %5.2f%%",
			type,
			title[i],
			stats->count[i],
			pct);
		printf("%s", NORM);
		printf("\n");
	}
	printf("%s", NORM);
	printf("\n");

	/*
	for (i = 0; i < 50; i++)
		printf("-");

	printf("\n");
 	if (text)
		printf("%s%s", BRIGHT, MAGENTA);
	else
		printf("%s%s", BRIGHT, CYAN);

	printf("Total %s samples %ld base page size %lu\n",
		type, stats->samples, base_page_size);
	printf("%s", NORM);
	printf("\n");
	*/
}

static int pageref_cmp(const void *arg1, const void *arg2)
{
	const struct page_ref *p1 = arg1;
	const struct page_ref *p2 = arg2;

	if (p1->access_count > p2->access_count)
		return -1;

	if (p1->access_count < p2->access_count)
		return 1;

	return 0;
}

static int pageref_cmp2(const void *arg1, const void *arg2)
{
	const struct page_ref *p1 = arg1;
	const struct page_ref *p2 = arg2;

	if (p1->access_count2 > p2->access_count2)
		return -1;

	if (p1->access_count2 < p2->access_count2)
		return 1;

	return 0;
}

static void print_pagerefs(struct page_ref *used, struct page_ref *unused,
			   int max_index, unsigned long total_pages)
{
	int i;
	unsigned long pages_used, pages_unused;
	char msg[15];

	pages_used   = 0;
	pages_unused = 0;

	for (i = 0; i < max_index; i++) {
		used[i].access_count2   = used[i].access_count *
					  used[i].pages_4k;
		pages_used += used[i].access_count2;

		unused[i].access_count2 = unused[i].access_count * 
					  unused[i].pages_4k;
		pages_unused += unused[i].access_count2;
	}

	qsort(unused, max_index, sizeof(*unused), pageref_cmp2);
	qsort(used, max_index, sizeof(*used), pageref_cmp2);

	printf("%s%s%s", BRIGHT, MAGENTA, ULINE);
	printf("%-12s %-10s %-12s %-10s\n",
		"Used Pages",   "Percentage",
		"Unused Pages", "Percentage");
	printf("%s", NORM);

	if (max_index > 10)
		max_index = 10; 

	for (i = 0; i < max_index; i++) {
		float pct;

		snprintf(msg, sizeof(msg), "%dx4K Pages",
			 used[i].pages_4k);

		if (pages_used)
			pct = ((float)used[i].access_count2 * 100) / pages_used;
		else
			pct = 0;

		printf("%-12s %5.2f%% %4c", msg, pct, ' ');

		if (pages_unused)
			pct = ((float)unused[i].access_count2 * 100) / pages_unused;
		else
			pct = 0;

		snprintf(msg, sizeof(msg), "%dx4K Pages",
			 unused[i].pages_4k);

		printf("%-11s %5.2f%% %4c\n", msg, pct, ' ');
	}

}

void report_tracer_statistics(void)
{
	bool physical_mode = tracer_physical_mode;
	struct bst_node *code_root = NULL;
	struct bst_node *data_root = NULL;
	unsigned long code_cnt, data_cnt;
	struct tracer_stats code_stats, data_stats;
	struct page_ref *pages_used, *pages_unused;
	int i, pages;

	pages = base_page_size / PAGE_SIZE;

	memset(&code_stats, 0, sizeof(code_stats));
	memset(&data_stats, 0, sizeof(data_stats));

	pages_used = malloc(sizeof(*pages_used) * pages);
	if (!pages_used)
		return;

	pages_unused = malloc(sizeof(*pages_unused) * pages);
	if (!pages_unused) {
		free(pages_used);
		return;
	}

	for (i = 0; i < pages; i++) {
		pages_used[i].pages_4k = i + 1;
		pages_used[i].filler = 0;
		pages_used[i].access_count = 0;
		pages_used[i].access_count2 = 0;

		pages_unused[i].pages_4k = i + 1;
		pages_unused[i].filler = 0;
		pages_unused[i].access_count = 0;
		pages_unused[i].access_count2 = 0;
	}

	code_cnt = collect_code_statistics(&code_root, physical_mode);
	data_cnt = collect_data_statistics(&data_root, physical_mode);

	if (!code_cnt && !data_cnt) {
		free(pages_used);
		free(pages_unused);
		return;
	}

	process_code_statistics(code_root, code_cnt, &code_stats,
				 pages_used, pages_unused, pages);
	process_data_statistics(data_root, data_cnt, &data_stats,
			      pages_used, pages_unused, pages);

	qsort(pages_unused, pages, sizeof(*pages_unused), pageref_cmp);
	qsort(pages_used, pages, sizeof(*pages_used), pageref_cmp);

	print_stats(&code_stats, true);
	print_stats(&data_stats, false);
	print_pagerefs(pages_used, pages_unused, pages,
		       code_cnt + data_cnt);

	free(pages_used);
	free(pages_unused);

}

void set_base_page_size(unsigned long base_pagesz)
{
	if (base_pagesz > MAX_BASE_PAGE_SIZE)
		base_page_size = MAX_BASE_PAGE_SIZE;
	else
		base_page_size = base_pagesz;

}
