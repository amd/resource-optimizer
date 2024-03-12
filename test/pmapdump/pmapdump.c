/*
 * Automatic NUMA memory balancer Based on IBS sampler
 *
 * Copyright 2023-2024 AMD, Inc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <stdbool.h>

typedef unsigned int __u32, u32;
typedef unsigned long __u64, u64;

#define MAX_BUCKET_SZ 64
#define START_BUCKET_SZ 16

struct vma {
	__u64	addr;
	__u64	vss;
	__u64	rss;
	bool	isHugeMap;
	__u32	pages;
};

static __u64 *distribution4k;
static unsigned bucket_idx_4k = START_BUCKET_SZ;

static __u64 *distribution2m;
static unsigned bucket_idx_2m = START_BUCKET_SZ;

static __u64 *distribution1g;
static unsigned bucket_idx_1g = START_BUCKET_SZ;

#define MAP_SIZE 1024
#define KB 1024
#define PAGE_SIZE getpagesize()
#define page_4kb 4*KB
#define page_2mb 2*KB*KB
#define page_1gb KB*KB*KB

static void usage(const char *cmd)
{
	printf("Usag : %s <pid>\n", cmd);
}

__u64 get_physaddr(pid_t pid, __u64 vaddr);

int getHugePageSize()
{
	const char cmd[] = "/usr/bin/grep Hugepagesize /proc/meminfo";
	char buf[128];
	int hugePageSz = 0;
	__u32 sz;
	char  ch;
	FILE *fp;

	fp = popen(cmd, "r");

	if (!fp)
		return -EINVAL;

	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "Hugepagesize: %u %c", &sz, &ch) == 2) {
			assert(ch=='k');
			hugePageSz = sz * KB;
			break;
		}
	}

	return hugePageSz;
}

static int alloc_page_bucket(__u64 **bucketp, unsigned bucket_idx)
{
    *bucketp = calloc(bucket_idx, sizeof(__u64));
    if (!*bucketp)
        return ENOMEM;

    return 0;
}

static int resize_page_bucket(__u64 **bucketp, int page_size, unsigned  bucket_idx, unsigned new_idx)
{
    if (new_idx > MAX_BUCKET_SZ)
        return ENOMEM;

    *bucketp = realloc(*bucketp, sizeof(__u64) * new_idx);
    if (!*bucketp)
        return ENOMEM;
    memset((*bucketp + bucket_idx), 0 , sizeof(__u64) * (new_idx - bucket_idx));

    return 0;
}

static int init_page_buckets()
{
    if (!distribution4k) {
        if (alloc_page_bucket(&distribution4k, bucket_idx_4k))
            return ENOMEM;
    }
    if (!distribution2m) {
        if (alloc_page_bucket(&distribution2m, bucket_idx_2m))
            return ENOMEM;
    }
    if (!distribution1g) {
        if (alloc_page_bucket(&distribution1g,bucket_idx_1g))
            return ENOMEM;
    }

    return 0;
}

static void free_page_buckets()
{
    if (!distribution4k)
        free(distribution4k);
    if (!distribution2m)
        free(distribution2m);
    if (!distribution1g)
        free(distribution1g);
}

static int update_page_bucket(__u64 cons_pages, int page_sz)
{
    int sts = 0;
    unsigned  idx;

    idx = (__u64)log2(cons_pages); /* Probably It's ok to be not very accurate here.
                                      Will be off by any pages between two consecutive exponents.
                                    */
    if (page_sz == page_4kb) {
        if ((idx+1) > bucket_idx_4k) {
            sts = resize_page_bucket(&distribution4k, page_sz, bucket_idx_4k, (idx+1));
            if (sts)
                return sts;
            bucket_idx_4k = idx+1;
        }
        distribution4k[idx]++;
    } else if (page_sz == page_2mb) {
        if ((idx+1) > bucket_idx_2m) {
            sts = resize_page_bucket(&distribution2m, page_sz, bucket_idx_2m, (idx+1));
            if (sts)
                return sts;
            bucket_idx_2m = idx+1;
        }
        distribution2m[idx]++;
    } else {
        if ((idx+1) > bucket_idx_1g) {
            sts = resize_page_bucket(&distribution1g, page_sz, bucket_idx_1g, (idx+1));
            if (sts)
                return sts;
            bucket_idx_1g = idx+1;
        }
        distribution1g[idx]++;
    }

    return sts;
}

static int count_pages_in_vma(pid_t pid, struct vma *vma, int vmas,
				__u64 *pagesp,
				__u64 *vss_pagesp,
				__u64 *rss_pagesp)
{
	__u64 i, j, k;   /* Making it u64 to avoid int overflow with 1gb page size. */
	__u64 pages = 0, rss_pages = 0, vss_pages = 0;
	__u64 pa, next_pa, pa_gap;
	__u64 cons_pages = 1;
	int page_size;
	int sts = 0;

	sts = init_page_buckets();
	if (sts) {
		printf("Page bucket alloc failure\n");
		free_page_buckets();
		return sts;
	}

	for (i = 0; i < vmas; i++) {
		vma[i].pages = 0;
		j = 0;

		if (vma[i].isHugeMap)
		{
			/* We got hugetlb section. Get the page size */
			page_size = getHugePageSize();

			assert(page_size > 0); /* we must get the Huge Page Size. */

		} else {
			page_size = PAGE_SIZE;
		}

		while (j < vma[i].vss / page_size) {
			pa = get_physaddr(pid,
					  vma[i].addr + (j * page_size));
			if (pa == (__u64)-1) {
				j++;
				continue;
			}
			pa *= PAGE_SIZE;

			pages++;
			vma[i].pages++;

			k = j + 1;

			while (k < vma[i].vss / page_size) {
				next_pa = get_physaddr(pid, vma[i].addr +
							(k * page_size));

				if (next_pa == (__u64)-1)
					break;
				next_pa *= PAGE_SIZE;

				pa_gap = next_pa > pa ? (next_pa - pa):(pa - next_pa);

				if (pa_gap != page_size) {
					/* Not contiguous */
					break;
				}

				if (vma[i].isHugeMap)
				{
					/*
					 * We are continuing with phisically contiguous pages.
					 * For Huge pages, we better count them individually
					 * as mapped pages.
					 * For Huge page, RSS will be 0. so get clearer picture.
					 */
					pages++;
					vma[i].pages++;
				}

				pa = next_pa;
				cons_pages++;
				k++;
			}

            sts = update_page_bucket(cons_pages, page_size);
            if (sts) {
                free_page_buckets();
                return sts;
            }
			cons_pages = 1;
			j = k;
		}

		rss_pages += vma[i].rss / page_size;
		vss_pages += vma[i].vss / page_size;
	}

	*pagesp = pages;
	*rss_pagesp = rss_pages;
	*vss_pagesp = vss_pages;

    return sts;
}

static void print_vma(struct vma *vma, int vmas)
{
	int i;
	int page_size;
	char buf[100];

	printf("%-5s %-20s %-15s %-15s %-15s %-15s\n",
		"", "ADDRESS", "VSS(PAGES)","RSS(PAGES)", "PAGES(PHYSICAL)", "HUGETLB");

	for (i = 0; i < vmas; i++) {

		if (vma[i].vss == 0)
			continue;

		if (vma[i].isHugeMap)
		{
			page_size = getHugePageSize();

		} else {
			page_size = PAGE_SIZE;
		}

		sprintf(buf, "page_size: %d", page_size);

		printf("%-5d 0x%-18lx %-15lu %-15lu %-15u %-15s %-15s\n",
			i,
			vma[i].addr,
			vma[i].vss / page_size,
			vma[i].rss / page_size,
			vma[i].pages,
			vma[i].isHugeMap? "True":"",
			vma[i].isHugeMap? buf:"");
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

			/*
			 * parsing the fields in below format:
			 * Address           Kbytes     RSS   Dirty Mode  Mapping
			 */

			token = strtok(buffer, " ");
			if (!token) {
				err = EINVAL;
				break;
			}

			if (strstr(token, "-----------"))
				break; /* reached last line */

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
			token_len = strlen(token);
			j += token_len + 1;

			if (token) {
				vma[i].rss = strtoul(token, NULL , 10) * 1024;
			}

			while (buffer[j] == ' ')
				j++;

			token = strtok(&buffer[j], " ");
			token_len = strlen(token);
			j += token_len + 1;

			while (buffer[j] == ' ')
				j++;

			token = strtok(&buffer[j], " ");
			token_len = strlen(token);
			j += token_len + 1;

			while (buffer[j] == ' ')
				j++;
			token = strtok(&buffer[j], " ");

			vma[i].isHugeMap = false;

			if (strstr(token, "huge")) {
				/* huge mapping */
				vma[i].isHugeMap = true;
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
	__u64 pages, rss_pages, vss_pages;

	if (argc != 2) {
		usage(argv[0]);
		return -1;
	}

	pid = atoi(argv[1]);

	err = fill_vma(pid, &vma, &vmas);
	if (err) {
		printf("Unable to get maps of address space of pid %d\n", pid);
		return -err;
	}

    err = count_pages_in_vma(pid, vma, vmas, &pages, &vss_pages, &rss_pages);
    if (err) {
        printf("Failed to process pages in the address space of pid %d:error=%d\n", pid, err);
        return -err;
    }

    print_vma(vma, vmas);
    printf("Total VSS(pages %lu RSS(pages) %lu Physical_pages %lu\n",
        vss_pages, rss_pages, pages);

    for (i = 0; i < bucket_idx_4k; i++) {
        if (distribution4k[i])
            printf(">=%.0f x 4K : %lu\n", pow(2,i), distribution4k[i]);
    }
    for (i = 0; i < bucket_idx_2m; i++) {
        if (distribution2m[i])
            printf(">=%.0f x 2MB : %lu\n", pow(2,i), distribution2m[i]);
    }
    for (i = 0; i < bucket_idx_1g; i++) {
        if (distribution1g[i])
            printf(">=%.0f x 1GB : %lu\n", pow(2,i), distribution1g[i]);
    }

    return -1;

}
