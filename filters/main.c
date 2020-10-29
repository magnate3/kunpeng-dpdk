/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/time.h>                                                           
#include <time.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "stats.h"

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define PKT_ACCEPT_QUEUE 0
#define PKT_DROP_QUEUE 127


struct rte_fdir_conf fdir_conf = {
	.mode = RTE_FDIR_MODE_PERFECT,                                                 
	.pballoc = RTE_FDIR_PBALLOC_64K,                                            
	.status = RTE_FDIR_REPORT_STATUS,
	.mask = {
		.ipv4_mask = {
			.dst_ip = 0xFFFFFFFF,
			//.src_ip = 0xFFFFFFFF,
			//.proto = 0xFF,
		},
		//.dst_port_mask = 0xFFFF,
		.dst_port_mask = 0x0001,
		//.src_port_mask = 0xFFFF,
	},
	.drop_queue = PKT_DROP_QUEUE,
};

static struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN, },
	/*.fdir_conf = {
		.mode = RTE_FDIR_MODE_PERFECT,                                                 
		.pballoc = RTE_FDIR_PBALLOC_64K,                                            
		.status = RTE_FDIR_REPORT_STATUS,
		.mask = {
			.ipv4_mask = {
				.dst_ip = 0xFFFFFFFF,
				//.proto = 0xFF,
			},
			//.dst_port_mask = 0xFFFF,
			.dst_port_mask = 0,
		},
		.drop_queue = PKT_DROP_QUEUE,
	},*/
};

/* dropped packets */
#define NTUPLE_DROP_ADDR "10.0.0.1"
#define FDIR_DROP_ADDR "10.0.0.2"

/* accepted packets */
#define NTUPLE_ACCEPT_ADDR "10.0.0.3"
#define FDIR_ACCEPT_ADDR "10.0.0.4"

#define TCP_PORT	179

	static inline void
fdir_filter_add(uint8_t port_id, const char *addr, enum rte_eth_fdir_behavior behavior, uint32_t soft_id)
{
	struct rte_eth_fdir_filter entry;
	uint32_t fdir_ip_addr;
	int ret = 0;

	ret = rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_FDIR);
	if (ret < 0) {
		printf("flow director is not supported on port %u.\n",
				port_id);
		return;
	}

	memset(&entry, 0, sizeof(struct rte_eth_fdir_filter));

	ret = inet_pton(AF_INET, addr, &fdir_ip_addr);
	if (ret <= 0) {
		if (ret == 0) {
			printf("Error: %s is not in presentation format\n", addr);
			return;
		} else if (ret == -1) {
			perror("inet_pton");
			return;
		}
	}

	//printf("%d\n", behavior);
	//printf("%s, %u\n", addr, fdir_ip_addr);

	entry.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_TCP;
	//entry.input.flow_type = RTE_ETH_FLOW_IPV4;
	entry.input.flow.ip4_flow.dst_ip = fdir_ip_addr;
	//entry.input.flow.udp4_flow.src_port = rte_cpu_to_be_16(TCP_PORT);
	//entry.input.flow.udp4_flow.dst_port = rte_cpu_to_be_16(TCP_PORT);
	entry.input.flow.udp4_flow.dst_port = rte_cpu_to_be_16(0);

	entry.input.flow_ext.is_vf = 0;
	entry.action.behavior = behavior;
	entry.action.flex_off = 0;
	entry.action.report_status = RTE_ETH_FDIR_REPORT_ID;

	if (behavior == RTE_ETH_FDIR_ACCEPT)
		entry.action.rx_queue = PKT_ACCEPT_QUEUE;
	else
		entry.action.rx_queue = PKT_DROP_QUEUE;

	entry.soft_id = soft_id;

	ret = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR,
			RTE_ETH_FILTER_ADD, &entry);
	if (ret < 0)
		printf("flow director programming error: (%s)\n",
				strerror(-ret));
	
	entry.soft_id = soft_id + 100;
	entry.input.flow.udp4_flow.dst_port = rte_cpu_to_be_16(0x1);
	ret = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR,
			RTE_ETH_FILTER_ADD, &entry);
	if (ret < 0)
		printf("flow director programming error: (%s)\n",
				strerror(-ret));
	
}

	static inline int
ntuple_filter_add(uint8_t port, const char *addr, uint8_t queue_id)
{
	int ret = 0;
	uint32_t ntuple_ip_addr;

	ret = inet_pton(AF_INET, addr, &ntuple_ip_addr);
	if (ret <= 0) {
		if (ret == 0) {
			printf("Error: %s is not in presentation format\n", addr);
		} else if (ret == -1) {
			perror("inet_pton");
		}
		return ret;
	}

	struct rte_eth_ntuple_filter filter = {
		.flags = RTE_5TUPLE_FLAGS,
		.dst_ip = ntuple_ip_addr, /* Big endian */
		.dst_ip_mask = UINT32_MAX, /* Enable */
		.src_ip = 0,
		.src_ip_mask = 0, /* Disable */
		.dst_port = 0,
		.dst_port_mask = 0, /* Disable */
		.src_port = 0,
		.src_port_mask = 0, /* Disable */
		.proto = 0,
		.proto_mask = 0, /* Disable */
		.tcp_flags = 0,
		.priority = 1, /* Lowest */
		.queue = queue_id,
	};

	return rte_eth_dev_filter_ctrl(port,
			RTE_ETH_FILTER_NTUPLE,
			RTE_ETH_FILTER_ADD,
			&filter);
}

/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */
	static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	port_conf_default.fdir_conf = fdir_conf;
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	//port_conf.rxmode.hw_vlan_strip = 0;
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	retval  = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct rte_ether_addr addr;

	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	rte_eth_promiscuous_enable(port);
	return 0;
}

/*
 * Main thread that does the work, reading from INPUT_PORT
 * and writing to OUTPUT_PORT
 */
	static  __attribute__((noreturn)) void
lcore_main(void)
{
	uint8_t port = 0;

	if (rte_eth_dev_socket_id(port) > 0 &&
			rte_eth_dev_socket_id(port) !=
			(int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
				"polling thread.\n\tPerformance will "
				"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	for (;;) {
		struct rte_mbuf *bufs[BURST_SIZE];
		const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
				bufs, BURST_SIZE);
		uint16_t buf;

		if (unlikely(nb_rx == 0))
			continue;

		for (buf = 0; buf < nb_rx; buf++) {
			struct rte_mbuf *mbuf = bufs[buf];
			unsigned int len = rte_pktmbuf_data_len(mbuf);
			rte_pktmbuf_dump(stdout, mbuf, len);
			rte_pktmbuf_free(mbuf);
		}
	}
}

	static  __attribute__((noreturn)) void
lcore_stats(void)
{
	uint8_t port = 0;

	while (1) {
		sleep(30);
		nic_stats_display(port);
		nic_xstats_display(port);

		printf("\n$$$$$$$$$$$$$$reset the stats$$$$$$$$$$$$$\n");
		nic_stats_clear(port);
		nic_xstats_clear(port);
	}
}

/* Main function, does initialisation and calls the per-lcore functions */
	int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint8_t portid = 0;

	/* init EAL */
	int ret = rte_eal_init(argc, argv);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	argc -= ret;
	argv += ret;

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
			NUM_MBUFS, MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* initialize all ports */
	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
				portid);

	stats_mapping_setup(portid);

	fdir_filter_add(portid, FDIR_DROP_ADDR, RTE_ETH_FDIR_REJECT, 0);
	fdir_filter_add(portid, FDIR_ACCEPT_ADDR, RTE_ETH_FDIR_ACCEPT, 1);

	ntuple_filter_add(portid, NTUPLE_DROP_ADDR, PKT_DROP_QUEUE);
	ntuple_filter_add(portid, NTUPLE_ACCEPT_ADDR, PKT_ACCEPT_QUEUE);

	fdir_get_infos(portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too much enabled lcores - "
				"App uses only 1 lcore\n");

	lcore_stats();

	/* call lcore_main on master core only */
	//lcore_main();

	return 0;
}
