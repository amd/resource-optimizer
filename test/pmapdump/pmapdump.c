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
#include <assert.h>
#include <math.h>

#define MAX_IDX 32

struct vma {
	unsigned long addr;
	unsigned long vss;
	unsigned long rss;
	unsigned long pages;
};
static unsigned long distribution[MAX_IDX];

#define MAP_SIZE 1024
#define PAGE_SIZE getpagesize()

static void usage(const char *cmd)
{
	printf("Usag : %s <pid>\n", cmd);
}

unsigned long get_physaddr(pid_t pid, unsigned long vaddr);
static void count_pages_in_vma(pid_t pid, struct vma *vma, int vmas,
				unsigned long *pagesp,
				unsigned long *vss_pagesp,
				unsigned long *rss_pagesp)
{
	int i, j, k, idx;
	const int page_size = PAGE_SIZE;
	unsigned long pages = 0, rss_pages = 0, vss_pages = 0;
	unsigned long pa, next_pa;
	unsigned long cons_pages = 1;

	for (i = 0; i < vmas; i++) {
		vma[i].pages = 0;
		j = 0;

		while (j < vma[i].vss / page_size)  {

			pa = get_physaddr(pid,
					  vma[i].addr + (j * page_size));
			if (pa == (unsigned long)-1) {
				j++;
				continue;
			}

			pages++;
			vma[i].pages++;

			k = j + 1;

			while (k < vma[i].vss / page_size) {
				next_pa = get_physaddr(pid, vma[i].addr +
							(k * page_size));

				if ((next_pa == (unsigned long)-1) ||
				    (next_pa != pa + page_size))
					break;

				pa = next_pa;
				cons_pages++;
				k++;
			}

			idx = (int)log2(cons_pages);
			cons_pages = 1;
			assert(idx < MAX_IDX);
			distribution[idx]++;

			j = k;
		}

		rss_pages += vma[i].rss / page_size;
		vss_pages += vma[i].vss / page_size;
	}

	*pagesp = pages;
	*rss_pagesp = rss_pages;
	*vss_pagesp = vss_pages;
}

static void print_vma(struct vma *vma, int vmas)
{
	int i;
	const int page_size = PAGE_SIZE;

	printf("%-5s %-20s %-15s %-15s %-15s\n",
		"", "ADDRESS", "VSS(PAGES)","RSS(PAGES)", "PAGES(PHYSICAL)");

	for (i = 0; i < vmas; i++) {
		if (vma[i].vss == 0)
			continue;

		printf("%-5d 0x%-18lx %-15lu %-15lu %-15lu\n",
			i,
			vma[i].addr,
			vma[i].vss / page_size,
			vma[i].rss / page_size,
			vma[i].pages);
	}


}

static int fill_vma(pid_t pid, struct vma **vmapp, int *vmas)
{
	struct vma *vma;
	int size = MAP_SIZE, i, j, err;
	char buffer[1024];
	FILE *fp;
	char *token;
	int token_len;

	snprintf(buffer, sizeof(buffer), "/usr/bin/pmap -x %d", pid);

	fp = popen(buffer, "r");
	if (!fp) {
		printf("Cannot open maps for pid %d\n", pid);
		return errno;
	}

	vma = malloc(sizeof(vma) * size);
	if (!vma) {
		fclose(fp);
		return ENOMEM;
	}

	i = 0;

	err = 0;

	do {
		if  (!fgets(buffer, sizeof(buffer) - 1, fp)) {
			err = errno;
			break;
		}

		if  (!fgets(buffer, sizeof(buffer) - 1, fp)) {
			err = errno;
			break;
		}

		while  (fgets(buffer, sizeof(buffer) - 1, fp)) {
			token = strtok(buffer, " ");
			if (!token) {
				err = EINVAL;
				break;
			}

			if (i > size) {
				struct vma *newvma;

				size = size * 2;

				newvma = realloc(vma, size);
				if (newvma == NULL) {
					err = ENOMEM;
					break;
				}

				vma = newvma;
			}

			token_len = strlen(token);
			vma[i].addr = strtoul(token, NULL , 16);
			vma[i].vss = vma[i].rss = vma[i].pages = 0;

			j = token_len + 1;

			while (buffer[j] == ' ')
				j++;

			token = strtok(&buffer[j], " ");
			if (!token) {
				err = EINVAL;
				break;
			}

			vma[i].vss = strtoul(token, NULL , 10) * 1024;
			token_len = strlen(token);
			j += token_len + 1;

			while (buffer[j] == ' ')
				j++;

			token = strtok(&buffer[j], " ");
			if (token) {
				vma[i].rss = strtoul(token, NULL , 10) * 1024;
			}

			/* How RSS can be greater than VSS. But it happens
			 * sometimes. Maybe be for shared pages.
			 * Need to check.
			 */
			if (vma[i].rss > vma[i].vss)
				vma[i].rss = vma[i].vss;


			/*
			printf("%d Addr %lx vss %lu rss %lu\n",
				i + 1, vma[i].addr, vma[i].vss, vma[i].rss);
			*/
			i++;

		}
	} while (0);

	fclose(fp);
	if (err) {
		free(vma);
	} else {
		*vmapp = vma;
		*vmas  = i;
	}

	return err;
}

int main(int argc, char *argv[])
{
	struct vma *vma = NULL;
	pid_t pid;
	int err, vmas = 0;
	int i;
	unsigned long pages, rss_pages, vss_pages;

	if (argc != 2) {
		usage(argv[0]);
		return -1;
	}

	pid = atoi(argv[1]);

	err = fill_vma(pid, &vma, &vmas);
	if (err) {
		printf("Unable to get maps in the address space of pid %d\n", pid);
		return -err;
	}

	count_pages_in_vma(pid, vma, vmas, &pages, &vss_pages, &rss_pages);

	print_vma(vma, vmas);
	printf("Total VSS(pages) %lu RSS(pages) %lu Physical_pages %lu\n",
		vss_pages, rss_pages, pages);

	for (i = 0; i < MAX_IDX; i++) {
		if (distribution[i])
			printf("%d x 4K : %lu\n", i + 1, distribution[i]);
	}

	return -1;

}
