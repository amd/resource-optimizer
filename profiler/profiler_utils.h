/*
 * Process samples from IBS or software sampler and analyze the instruction and
 * data (if available) samples.
 *
 * Copyright 2021 AMD, Inc.
 */

#ifndef MEMBALANCER_UTILS_H
#define MEMBALANCER_UTILS_H

#define MAX_NUMA 64
#define MAX_FUNC_NAME 32

struct list_of_functions {
	long ref;
	long size;
	long name;
        u64  ip;
};

struct ibs_fetch_sample {
        unsigned long ip;
        unsigned int count;
        unsigned long tgid;
	char  process[PROCESSNAMELEN];
        unsigned long fetch_regs[IBSFETCH_REG_COUNT];
};

struct ibs_op_sample {
        unsigned long key;
        unsigned long ip;
        unsigned int count;
        unsigned long tgid;
        char          process[PROCESSNAMELEN];
        unsigned long op_regs[IBSOP_REG_COUNT];
};

struct bst_node;
int bst_add_page(pid_t pid, int to_node, unsigned long addr,
	         bool upgrade, struct bst_node **root);

int tracer_init(const char *path);
void update_sample_statistics_tracer(unsigned long *samples,
				     bool fetch);
void process_ibs_op_samples_tracer(struct bst_node **rootpp,
                                   unsigned long total,
				   bool balancer_mode,
                                   bool user_space_only);

void process_ibs_fetch_samples_tracer(struct bst_node **rootpp,
                                    unsigned long total,
				    bool balancer_mode,
                                    bool user_space_only);
void report_tracer_statistics(void);
void set_base_page_size(unsigned long base_pagesz);

#define BRIGHT   "\x1b[1m"
#define MAGENTA  "\x1B[35m"
#define BLUE     "\x1B[34m"
#define BMAGENTA "\x1B[45m"
#define BBLUE     "\x1B[44m"
#define RED      "\x1B[31m"
#define BRED      "\x1B[41m"
#define GREEN    "\x1B[33m"
#define BGREEN    "\x1B[43m"
#define BCYAN   "\x1B[46m"
#define ULINE   "\x1B[4m"
#define CYAN     "\x1B[36m"
#define NORM     "\x1B[0m"
#define BLACK    "\x1B[30m"
#define BWHITE   "\x1B[47m"
#define WHITE   "\x1B[37m"

#endif
