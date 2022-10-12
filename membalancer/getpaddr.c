
/*
 * Automatic NUMA memory balancer Based on IBS sampler
 *
 * Copyright 2022 AMD, Inc.
 */
#include<sys/param.h>
#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>
#define PHYSADDR_BYTES 8

/* If bit 63 is set, then it is a valid physical address */
#define IS_PHYSADDR_VALID(addr) (addr & ((unsigned long)1 << 63)) >> 63

unsigned long get_physaddr(pid_t pid, unsigned long vaddr)
{
	char path[MAXPATHLEN];
	int fd;
	int i;
	unsigned long offset;
	unsigned long paddr = 0;
	char buffer[PHYSADDR_BYTES];

	snprintf(path, MAXPATHLEN, "/proc/%d/pagemap", pid);

	offset = vaddr / getpagesize() * PHYSADDR_BYTES;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	if (pread(fd, buffer, sizeof(buffer), offset) != sizeof(buffer)) {
		close(fd);
		return -1;
	}

	for (i = 0; i < PHYSADDR_BYTES; i++)
		paddr = (paddr << 8) + (0xff & buffer[PHYSADDR_BYTES - i - 1]);

	close(fd);

	if (IS_PHYSADDR_VALID(paddr)) {
		unsigned long mask = (unsigned long)-1;
		mask <<= 1;
		mask >>= 1;
		mask >>= 8;
		return paddr & mask;
	}

	return -1;
}

