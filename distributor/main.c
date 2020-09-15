/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2017 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_debug.h>
#include <rte_prefetch.h>
#include <rte_distributor.h>
#include <rte_pause.h>
#include <rte_power.h>

/* Main function, does initialization and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
	/* init EAL */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	/* Start rx core */
	int *pr = rte_malloc(NULL, sizeof(*pr), 0);
	if (!pr)
		rte_panic("malloc failure\n");
        printf("-------- pr addr %llx \n ",(long long) pr);
        pr[0] = 9999;
        printf("-------- *pr %d \n ",*pr);
	rte_free(pr);

	return 0;
}
