/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ip.h>
#include <rte_string_fns.h>

#include <rte_ip_frag.h>
#define TEST_UDP_SRC_PORT 4444
#define TEST_UDP_DST_PORT 4444
#define RTE_LOGTYPE_IP_FRAG RTE_LOGTYPE_USER1
#define IP_PROTO_UDP     17
/* allow max jumbo frame 9.5 KB */
#define JUMBO_FRAME_MAX_SIZE	0x2600
#define DEBUGARP
#define	ROUNDUP_DIV(a, b)	(((a) + (b) - 1) / (b))
#define IP_PADDING_LEN 28
#define PADDED_IPV4_HDR_SIZE (sizeof(struct rte_ipv4_hdr) + IP_PADDING_LEN)
/*
 * Default byte size for the IPv6 Maximum Transfer Unit (MTU).
 * This value includes the size of IPv6 header.
 */
#define	IPV4_MTU_DEFAULT	RTE_ETHER_MTU
#define	IPV6_MTU_DEFAULT	RTE_ETHER_MTU

/*
 * The overhead from max frame size to MTU.
 * We have to consider the max possible overhead.
 */
#define MTU_OVERHEAD	\
	(RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + \
		2 * sizeof(struct rte_vlan_hdr))
#define RTE_LOGTYPE_IP_RSMBL RTE_LOGTYPE_USER1
/*
 * Default payload in bytes for the IPv6 packet.
 */
#define	IPV4_DEFAULT_PAYLOAD	(IPV4_MTU_DEFAULT - sizeof(struct rte_ipv4_hdr))
#define	IPV6_DEFAULT_PAYLOAD	(IPV6_MTU_DEFAULT - sizeof(struct rte_ipv6_hdr))

/*
 * Max number of fragments per packet expected - defined by config file.
 */
#define	MAX_PACKET_FRAG RTE_LIBRTE_IP_FRAG_MAX_FRAG

#define NB_MBUF   8192
#define MEMPOOL_CACHE_SIZE 256
#define	BUF_SIZE	RTE_MBUF_DEFAULT_DATAROOM
#define	MBUF_DATA_SIZE	RTE_MBUF_DEFAULT_BUF_SIZE
#define	IP_FRAG_TBL_BUCKET_ENTRIES	16
#define	MAX_FLOW_NUM	UINT16_MAX
#define	MIN_FLOW_NUM	1
#define	DEF_FLOW_NUM	0x1000
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3
#define IP_PROTO_UDP     17
/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

#ifndef IPv4_BYTES
#define IPv4_BYTES_FMT "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define IPv4_BYTES(addr) \
		(uint8_t) (((addr) >> 24) & 0xFF),\
		(uint8_t) (((addr) >> 16) & 0xFF),\
		(uint8_t) (((addr) >> 8) & 0xFF),\
		(uint8_t) ((addr) & 0xFF)
#endif

#ifndef IPv6_BYTES
#define IPv6_BYTES_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"\
                       "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define IPv6_BYTES(addr) \
	addr[0],  addr[1], addr[2],  addr[3], \
	addr[4],  addr[5], addr[6],  addr[7], \
	addr[8],  addr[9], addr[10], addr[11],\
	addr[12], addr[13],addr[14], addr[15]
#endif

#define IPV6_ADDR_LEN 16
/* mask of enabled ports */
static int enabled_port_mask = 0;

static int rx_queue_per_lcore = 1;
#define MAX_FRAG_NUM RTE_LIBRTE_IP_FRAG_MAX_FRAG
#define MAX_PKT_BURST 2
/* TTL numbers are in ms. */
#define	MAX_FLOW_TTL	(3600 * MS_PER_S)
#define	MIN_FLOW_TTL	1
#define	DEF_FLOW_TTL	MS_PER_S


static uint32_t max_flow_num = DEF_FLOW_NUM;
static uint32_t max_flow_ttl = DEF_FLOW_TTL;

struct rte_ether_addr my_eth_addr;	// My ethernet address
uint32_t my_ip;			// My IP Address in network order

#define MBUF_TABLE_SIZE  (2 * MAX(MAX_PKT_BURST, MAX_PACKET_FRAG))

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MBUF_TABLE_SIZE];
};

struct psd_hdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
} __attribute__((packed));
struct rx_queue {
        struct rte_ip_frag_tbl *frag_tbl;
        //struct rte_mempool *pool;
	struct rte_mempool *direct_pool;
	struct rte_mempool *indirect_pool;
	struct rte_lpm *lpm;
	struct rte_lpm6 *lpm6;
	uint16_t portid;
};

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 8
struct lcore_queue_conf {
	uint16_t n_rx_queue;
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
        struct rte_ip_frag_death_row death_row;
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.max_rx_pkt_len = JUMBO_FRAME_MAX_SIZE,
		.split_hdr_size = 0,
		.offloads = (DEV_RX_OFFLOAD_CHECKSUM |
			     DEV_RX_OFFLOAD_SCATTER |
			     DEV_RX_OFFLOAD_JUMBO_FRAME),
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
		.offloads = (DEV_TX_OFFLOAD_IPV4_CKSUM |
			     DEV_TX_OFFLOAD_MULTI_SEGS),
	},
};

static void print_ethaddr(const char *name, struct rte_ether_addr *eth_addr);
static void print_ethaddr_i(const struct rte_mbuf * m);
/*
 * IPv4 forwarding table
 */
struct l3fwd_ipv4_route {
	uint32_t ip;
	uint8_t  depth;
	uint8_t  if_out;
};

struct l3fwd_ipv4_route l3fwd_ipv4_route_array[] = {
		{RTE_IPV4(100,10,0,0), 16, 0},
		{RTE_IPV4(100,20,0,0), 16, 1},
		{RTE_IPV4(100,30,0,0), 16, 2},
		{RTE_IPV4(100,40,0,0), 16, 3},
		{RTE_IPV4(100,50,0,0), 16, 4},
		{RTE_IPV4(100,60,0,0), 16, 5},
		{RTE_IPV4(100,70,0,0), 16, 6},
		{RTE_IPV4(100,80,0,0), 16, 7},
};

/*
 * IPv6 forwarding table
 */

struct l3fwd_ipv6_route {
	uint8_t ip[IPV6_ADDR_LEN];
	uint8_t depth;
	uint8_t if_out;
};

static struct l3fwd_ipv6_route l3fwd_ipv6_route_array[] = {
	{{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, 48, 0},
	{{2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, 48, 1},
	{{3,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, 48, 2},
	{{4,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, 48, 3},
	{{5,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, 48, 4},
	{{6,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, 48, 5},
	{{7,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, 48, 6},
	{{8,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1}, 48, 7},
};

#define LPM_MAX_RULES         1024
#define LPM6_MAX_RULES         1024
#define LPM6_NUMBER_TBL8S (1 << 16)

struct rte_lpm6_config lpm6_config = {
		.max_rules = LPM6_MAX_RULES,
		.number_tbl8s = LPM6_NUMBER_TBL8S,
		.flags = 0
};

static struct rte_mempool *socket_direct_pool[RTE_MAX_NUMA_NODES];
static struct rte_mempool *socket_indirect_pool[RTE_MAX_NUMA_NODES];
static struct rte_lpm *socket_lpm[RTE_MAX_NUMA_NODES];
static struct rte_lpm6 *socket_lpm6[RTE_MAX_NUMA_NODES];


void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
} 
static inline void
read_and_print_ipv4_info(struct rte_mbuf *m)
{

        uint32_t ip_dst;
        uint32_t ip_src; //20170830
        uint16_t total_len; //20170902 16 bits unsign int total_length
        struct rte_ether_hdr * eth_h = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    /* Read the ipv4 ip (i.e. ip_dst, ip_src) from the input packet */
        struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr *)(struct rte_ipv4_hdr *)(eth_h + 1);;

        uint16_t flag_offset, ip_ofs, ip_flag;
	flag_offset = rte_be_to_cpu_16(ip_hdr->fragment_offset);
	ip_ofs = (uint16_t)(flag_offset & RTE_IPV4_HDR_OFFSET_MASK);
	ip_flag = (uint16_t)(flag_offset & RTE_IPV4_HDR_MF_FLAG);
        ip_dst = rte_be_to_cpu_32(ip_hdr->dst_addr);
        printf("ip_dst: "); //20170904
        print_ip(ip_dst); //20170904 uint32_t to ip address

        ip_src = rte_be_to_cpu_32(ip_hdr->src_addr);//20170830
        printf("ip_src: "); //20170904
        print_ip(ip_src); //20170904 uint32_t to ip address

        total_len = rte_cpu_to_be_16(ip_hdr->total_length);//20170831 rte_cpu_to_be_16

        //printf("ip_dst: ");
        //printf("%" PRIu32 "\n" ,ip_dst);//20170830
        //printf("ip_src: ");
        //printf("%" PRIu32 "\n" ,ip_src);//20170830
        printf("total_length: ");
        printf("%" PRIu16 "\n" ,total_len);//20170831
        printf("more frag: ");
        printf("%" PRIu16 "\n" ,ip_flag);//20170831
        
        printf("\n");


}
static void show_udp(struct rte_mbuf *m)
{
    int                l2_len;
    uint16_t           eth_type;
    struct rte_udp_hdr    *udp_h;
    struct rte_ipv4_hdr   *ip_h;
    struct rte_vlan_hdr   *vlan_h;
    struct rte_ether_hdr  *eth_h;
    char * data;
    struct rte_mbuf *cur = m;
    int first = 1;
    //printf("pkt len %u,data len  %u \n", rte_pktmbuf_pkt_len(m) , rte_pktmbuf_data_len(m));
    while(cur)
    {
        /*
           mo = rte_ipv4_frag_reassemble_packet
           only first mbuf has ehter + ip + udp header
        */
	if (first)
	{
	    eth_h = rte_pktmbuf_mtod(cur, struct rte_ether_hdr *);
            eth_type = rte_be_to_cpu_16(eth_h->ether_type);
            l2_len = sizeof(*eth_h);
	     /* frames in VPC come in with ethertype 0x8100, i.e. they are 802.1q VLAN tagged */
            if (eth_type == RTE_ETHER_TYPE_VLAN) {
            vlan_h = (struct rte_vlan_hdr *) ((char *) eth_h + l2_len);
            eth_type = rte_be_to_cpu_16(vlan_h->eth_proto);
            l2_len += sizeof(*vlan_h);
            }
            if (eth_type != RTE_ETHER_TYPE_IPV4) {
                return ;
            }
            ip_h = (struct rte_ipv4_hdr *) ((char *) eth_h + l2_len);
            if (ip_h->next_proto_id != IP_PROTO_UDP) {
                return ;
             }
	     udp_h = (struct udp_hdr *) ((char *) ip_h + sizeof(*ip_h));
	     data = (char *) ip_h + sizeof(*ip_h) + sizeof(struct rte_udp_hdr);
             first = 0;
	}
	else
	{
		data = rte_pktmbuf_mtod(cur, char *);
	}
	printf("udp packet %s \n", data);
	cur = cur->next;
	}
}

static inline int process_arp(struct rte_mbuf *mbuf, struct rte_ether_hdr *eh,uint16_t port)
{
	uint32_t   lcore_id;
    struct lcore_queue_conf *qconf;
	int len=rte_pktmbuf_data_len(mbuf);
	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];
	struct rte_arp_hdr *ah = (struct rte_arp_hdr *)((unsigned char *)eh + RTE_ETHER_HDR_LEN);
	if (len < (int)(sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr))) {
#ifdef DEBUGICMP
		printf("len = %d is too small for arp packet??\n", len);
#endif
		return 0;
	}
	if (rte_cpu_to_be_16(ah->arp_opcode) != RTE_ARP_OP_REQUEST) {	// ARP request
		return 0;
	}
	if (my_ip == ah->arp_data.arp_tip) {
#ifdef DEBUGARP
		printf("ARP asking me....\n");
#endif
		rte_memcpy((unsigned char *)&eh->d_addr, (unsigned char *)&eh->s_addr, 6);
		rte_memcpy((unsigned char *)&eh->s_addr, (unsigned char *)&my_eth_addr, 6);
		ah->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
		ah->arp_data.arp_tha = ah->arp_data.arp_sha;
		rte_memcpy((unsigned char *)&ah->arp_data.arp_sha, (unsigned char *)&my_eth_addr,
			   6);
		ah->arp_data.arp_tip = ah->arp_data.arp_sip;
		ah->arp_data.arp_sip = my_ip;
#ifdef DEBUGARP
		printf("I will reply following \n");
		//dump_arp_packet(eh);
#endif
		if (likely(1 == rte_eth_tx_burst(port, qconf->tx_queue_id[port], &mbuf, 1))) {
			return 1;
		}
	}
	return 0;
}




/* Send burst of packets on an output interface */
static inline int
send_burst(struct lcore_queue_conf *qconf, uint16_t n, uint16_t port)
{
	struct rte_mbuf **m_table;
	int ret;
	uint16_t queueid;
        int i = 0;
	queueid = qconf->tx_queue_id[port];
	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;
        for(; i < n; ++i)
        {
             print_ethaddr_i(m_table[i]);
             read_and_print_ipv4_info(m_table[i]);
        }
	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	if (unlikely(ret < n)) {
		do {
                        printf("rte_eth_tx_burst send erros \n");
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}
uint16_t multiple_of_32(uint16_t num)
{
   uint16_t div =  num/32;
   return div ?  (div + 1)*32 : num;
}
static void mbuf_dump(struct rte_mbuf* m)
{
    printf("RTE_PKTMBUF_HEADROOM: %u\n", RTE_PKTMBUF_HEADROOM);
    printf("sizeof(mbuf): %lu\n", sizeof(struct rte_mbuf));
    printf("m: %p\n", m);
    printf("m->refcnt: %u\n", m->refcnt);
    printf("m->buf_addr: %p\n", m->buf_addr);
    printf("m->data_off: %u\n", m->data_off);
    printf("m->buf_len: %u\n", m->buf_len);
    printf("m->pkt_len: %u\n", m->pkt_len);
    printf("m->data_len: %u\n", m->data_len);
    printf("m->nb_segs: %u\n", m->nb_segs);
    printf("m->next: %p\n", m->next);
    printf("m->buf_addr+m->data_off: %p\n", (char*)m->buf_addr+m->data_off);
    printf("rte_pktmbuf_mtod(m): %p\n", rte_pktmbuf_mtod(m, char*));
    printf("rte_pktmbuf_data_len(m): %u\n", rte_pktmbuf_data_len(m));
    printf("rte_pktmbuf_pkt_len(m): %u\n", rte_pktmbuf_pkt_len(m));
    printf("rte_pktmbuf_headroom(m): %u\n", rte_pktmbuf_headroom(m));
    printf("rte_pktmbuf_tailroom(m): %u\n", rte_pktmbuf_tailroom(m));
}

static inline void
frag_simple_forward(struct rte_mbuf *m, struct lcore_queue_conf *qconf,
		uint8_t queueid, uint16_t port_in)
{
	struct rx_queue *rxq;
	uint32_t i, len, next_hop;
	uint16_t port_out, ether_type;
	int32_t len2;
	uint64_t ol_flags;
	struct rte_ether_hdr *eth,ethh_copy;
	uint32_t dst_ip;
	 unsigned char *orig_ip_payload;
        struct rte_ether_addr eth_d_addr;
	ol_flags = 0;
	rxq = &qconf->rx_queue_list[queueid];

	/* by default, send everything back to the source port */
	port_out = port_in;

	/* save ether type of the incoming packet */
	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth->ether_type);
        rte_memcpy((unsigned char *)&eth_d_addr, (unsigned char *)&eth->s_addr, 6);
        rte_memcpy(&ethh_copy, eth, sizeof(struct rte_ether_hdr));
        struct rte_ipv4_hdr   *ip_h;
	ip_h = (struct rte_ipv4_hdr *) ((char *) eth + sizeof(struct rte_ether_hdr));
        dst_ip = ip_h->src_addr;
	if (ip_h->next_proto_id != IP_PROTO_UDP ||  0 == rte_be_to_cpu_32(ip_h->src_addr) || ip_h->dst_addr != my_ip ) {
		rte_pktmbuf_free(m); 
        return ;
    }
	
	uint16_t udp_total_len =rte_be_to_cpu_16(ip_h->total_length) - sizeof(struct rte_udp_hdr) -((ip_h->version_ihl & 0x0F)<<2) ;
	struct rte_udp_hdr    *udp_origin_h = (struct rte_udp_hdr*)((char *) ip_h + ((ip_h->version_ihl & 0x0F)<<2));
        mbuf_dump(m);
	/* Remove the Ethernet header and trailer from the input packet */
        printf("======= udp_total_len %u \n", udp_total_len);
#ifndef    TEST_ERROR_FRAG
	udp_origin_h->src_port = htons(TEST_UDP_SRC_PORT);
	udp_origin_h->dst_port = htons(TEST_UDP_DST_PORT);
        udp_origin_h->dgram_cksum = 0;
        udp_origin_h->dgram_cksum = rte_ipv4_udptcp_cksum(ip_h, (const void *)udp_origin_h);
#endif
	if (udp_origin_h->dgram_cksum == 0)
			udp_origin_h->dgram_cksum = 0xFFFF;
	rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));
    orig_ip_payload = rte_pktmbuf_mtod_offset(m, unsigned char *,
                                              sizeof(struct rte_ipv4_hdr));

        /* Build transmission burst */
        len = qconf->tx_mbufs[port_out].len;
	/* if this is an IPv4 packet */
        if (RTE_ETHER_TYPE_IPV4 == ether_type) {
		/* Build transmission burst for new port */
		/* if we don't need to do any fragmentation */
		if (likely (IPV4_MTU_DEFAULT >= m->pkt_len)) {
			rte_pktmbuf_free(m); 
            return ;
		} else {
			len2 = rte_ipv4_fragment_packet(m,
				&qconf->tx_mbufs[port_out].m_table[len],
				(uint16_t)(MBUF_TABLE_SIZE - len),
				IPV4_MTU_DEFAULT,
				rxq->direct_pool, rxq->indirect_pool);
          
			/* Free input packet */
			//rte_pktmbuf_free(m);

			/* request HW to regenerate IPv4 cksum */
			ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);

			/* If we fail to fragment the packet */
			if (unlikely (len2 < 0))
				return;
		}
	}
	/* else, just forward the packet */
       	else {
		rte_pktmbuf_free(m); 
        return ;
	}

        uint16_t orig_data_offset = 0;
        uint16_t first_udp_len = 0;
	for (i = len; i < len + len2; i ++) {
        struct rte_ipv4_hdr   *ip_h_seg;
	struct rte_udp_hdr    *udp_h;
       
	struct rte_mbuf * m_seg = qconf->tx_mbufs[port_out].m_table[i];
        mbuf_dump(m_seg);
                //eth_hdr	
	struct rte_ether_hdr *eth_hdr_seg = (struct rte_ether_hdr *)
			rte_pktmbuf_prepend(m_seg,
				(uint16_t)sizeof(struct rte_ether_hdr));
                //show_udp(m_seg);
		if (eth_hdr_seg == NULL) {
			rte_panic("No headroom in mbuf.\n");
		}
	struct rte_mbuf *del_mbuf = m_seg->next;
        while (del_mbuf != NULL) {
          rte_pktmbuf_free_seg(del_mbuf);
          del_mbuf = del_mbuf->next;
        }
        read_and_print_ipv4_info(m_seg);
        m_seg->l2_len = sizeof(struct rte_ether_hdr);
        m_seg->data_len = m_seg->pkt_len;
        m_seg->nb_segs = 1;
        m_seg->next = NULL;
	ip_h_seg = (struct rte_ipv4_hdr *) ((char *) eth_hdr_seg + sizeof(*eth_hdr_seg));
	    unsigned char *ip_payload =
            (unsigned char *)((unsigned char *)ip_h_seg +
                              ((ip_h_seg->version_ihl & RTE_IPV4_HDR_IHL_MASK)
                               << 2));
        uint16_t ip_payload_len =
            m_seg->pkt_len - sizeof(struct rte_ether_hdr) -
            ((ip_h_seg->version_ihl & RTE_IPV4_HDR_IHL_MASK) << 2);
        printf("m_seg->pkt_len: %u, ip_payload_len: %u, next_proto_id :%u \n", m_seg->pkt_len, ip_payload_len, ip_h_seg->next_proto_id);
         if (i == len)
         {
              printf("m_seg origin udp : %s \n", (char *)(orig_ip_payload + orig_data_offset + sizeof(struct rte_udp_hdr) ) );
              printf("m_seg udp : %s \n", (char *)(ip_payload  + sizeof(struct rte_udp_hdr) ) );
         }
         else
         {
              printf("m_seg origin udp : %s \n", (char *)(orig_ip_payload + orig_data_offset ) );
              printf("m_seg udp : %s \n", (char *)(ip_payload));
         }
#ifdef TEST_PAD
        /* if total frame size is less than minimum transmission unit, add IP
         * padding */
        if (unlikely(ip_payload_len + sizeof(struct rte_ipv4_hdr) +
                         sizeof(struct rte_ether_hdr) + RTE_ETHER_CRC_LEN <
                     RTE_ETHER_MIN_LEN)) {
          /* update ip->ihl first */
          uint8_t origin_iph_len = (ip_h_seg->version_ihl & 0x0F)<<2;
          printf("new_iph_len : %u \n", origin_iph_len);
          ip_h_seg->version_ihl |=
              (RTE_IPV4_HDR_IHL_MASK & (PADDED_IPV4_HDR_SIZE >> 2));
          uint8_t new_iph_len = (ip_h_seg->version_ihl & 0x0F) <<2;
          printf("new_iph_len : %u \n", new_iph_len);
          /* update ip->tot_len */
         uint8_t pad_len = new_iph_len -origin_iph_len;
          ip_h_seg->total_length = ntohs(ip_payload_len + new_iph_len);
          /* update l3_len */
          printf("sizeof(struct rte_ipv4_hdr) %u \n", sizeof(struct rte_ipv4_hdr));
          m_seg->l3_len = sizeof(struct rte_ipv4_hdr) + pad_len;
          /* update data_len & pkt_len */
          m_seg->data_len = m_seg->pkt_len = m_seg->pkt_len + pad_len;
          /* ip_payload is currently the place you would add 0s */
          memset(ip_payload, 0, pad_len);

          /* re-set ip_payload to the right `offset` (location) now */
          ip_payload += pad_len;
        }
#endif
        rte_memcpy(ip_payload, orig_ip_payload + orig_data_offset,
                   ip_payload_len);
        orig_data_offset += ip_payload_len;
        ip_h_seg->dst_addr = dst_ip;
        ip_h_seg->src_addr = my_ip;
        rte_memcpy(eth_hdr_seg, &ethh_copy, sizeof(struct rte_ether_hdr));
        rte_memcpy((unsigned char *)&eth_hdr_seg->d_addr, (unsigned char *)&eth_d_addr, 6);
	rte_memcpy((unsigned char *)&eth_hdr_seg->s_addr, (unsigned char *)&my_eth_addr, 6);
#ifdef TEST_ERROR_FRAG
        if (i == len)
        {
                       
		udp_h = (struct rte_udp_hdr *) ((char *) ip_h_seg + sizeof(*ip_h_seg));
                printf("======= udp_total_len %u equal to udp_h->dgram_len %u ? \n", udp_total_len, rte_be_to_cpu_16(udp_h->dgram_len));
               
                udp_origin_h->dgram_len = htons(udp_total_len);
		udp_origin_h->src_port = htons(TEST_UDP_SRC_PORT);
		udp_origin_h->dst_port = htons(TEST_UDP_DST_PORT);
                udp_origin_h->dgram_cksum = 0;
		udp_origin_h->dgram_cksum = rte_ipv4_udptcp_cksum(ip_h, (const void *)udp_origin_h);
		if (udp_origin_h->dgram_cksum == 0)
			udp_origin_h->dgram_cksum = 0xFFFF;
                udp_h->dgram_len = htons(udp_total_len);
		udp_h->src_port = htons(TEST_UDP_SRC_PORT);
		udp_h->dst_port = htons(TEST_UDP_DST_PORT);
                udp_h->dgram_cksum = 0;
		udp_h->dgram_cksum = udp_origin_h->dgram_cksum;
        }
#endif 
        //ip checksum not need ip playload
        ip_h_seg->hdr_checksum = 0;
        ip_h_seg->hdr_checksum = rte_ipv4_cksum((struct rte_ipv4_hdr *)ip_h_seg);
        //mbuf->ol_flags = ol_flags;
      }
	//Free input packet 
	rte_pktmbuf_free(m);
	len += len2;

	if (likely(len < MAX_PKT_BURST)) {
		qconf->tx_mbufs[port_out].len = (uint16_t)len;
		return;
	}
        printf("Transmit packets： %u \n", len);
	/* Transmit packets */
	send_burst(qconf, (uint16_t)len, port_out);
	qconf->tx_mbufs[port_out].len = 0;
}

static inline void
reassemble(struct rte_mbuf *m, uint16_t portid, uint32_t queue,
	struct lcore_queue_conf *qconf, uint64_t tms)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ip_frag_tbl *tbl;
	struct rte_ip_frag_death_row *dr;
	struct rx_queue *rxq;

	rxq = &qconf->rx_queue_list[queue];

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    //uint16_t eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    uint16_t eth_type = eth_hdr->ether_type;


	/* if packet is IPv4 */
	if (rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) == eth_type) {
         //if (eth_hdr->ether_type == htons(0x0800)) {
         //printf("************ ipv4 packet recv \n");
#if 1
		struct rte_ipv4_hdr *ip_hdr;

		ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

		 /* if it is a fragmented packet, then try to reassemble. */
		if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr)) {
			printf("packet is frag ,and no packet to send out \n ");
                        read_and_print_ipv4_info(m);
			struct rte_mbuf *mo;

			tbl = rxq->frag_tbl;
			dr = &qconf->death_row;

			/* prepare mbuf: setup l2_len/l3_len. */
			m->l2_len = sizeof(*eth_hdr);
			m->l3_len = sizeof(*ip_hdr);

                        //show_udp(m);
			/* process this fragment. */
			mo = rte_ipv4_frag_reassemble_packet(tbl, dr, m, tms, ip_hdr);
			if (mo == NULL)
                        {
				printf("packet is frag ,and no packet to send out \n ");
				return;
                        }
                        printf("reassembled\n");
                        printf("before linearize m pkt len %u,data len  %u \n", rte_pktmbuf_pkt_len(m) , rte_pktmbuf_data_len(m));
                        printf("before linearize mo pkt len %u,data len  %u \n", rte_pktmbuf_pkt_len(mo) , rte_pktmbuf_data_len(mo));
                        //show_udp(mo);
                        rte_pktmbuf_linearize(mo);
                        printf("after linearize mo pkt len %u,data len  %u \n", rte_pktmbuf_pkt_len(mo) , rte_pktmbuf_data_len(mo));

			/* we have our packet reassembled. */
			if (mo != m) {
				m = mo;
				eth_hdr = rte_pktmbuf_mtod(m,
					struct rte_ether_hdr *);
				ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
			}
                        //show_udp(m);
			
		}
		frag_simple_forward(m, qconf, queue, portid); 
#endif
	} 
	else if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {	// ARP protocol
				 process_arp(m, eth_hdr,portid);
					return;
			}
 
}

/* main processing loop */
static int
main_loop(__attribute__((unused)) void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	int i, j, nb_rx;
	uint16_t portid;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	prev_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, IP_FRAG, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, IP_FRAG, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {

		portid = qconf->rx_queue_list[i].portid;
		RTE_LOG(INFO, IP_FRAG, " -- lcoreid=%u portid=%d\n", lcore_id,
				portid);
	}

	while (1) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			/*
			 * This could be optimized (use queueid instead of
			 * portid), but it is not called so often
			 */
			for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				send_burst(&lcore_queue_conf[lcore_id],
					   qconf->tx_mbufs[portid].len,
					   portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; i++) {

			portid = qconf->rx_queue_list[i].portid;
			nb_rx = rte_eth_rx_burst(portid, i, pkts_burst,
						 MAX_PKT_BURST);

                        if(nb_rx > 0)
                        {
                            //printf("portid %d, queue id %d and recv pks %d \n", portid,i,nb_rx);
                        }
			/* Prefetch first packets */
			for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
				rte_prefetch0(rte_pktmbuf_mtod(
						pkts_burst[j], void *));
			}

			/* Prefetch and forward already prefetched packets */
			for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
				rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[
						j + PREFETCH_OFFSET], void *));
				reassemble(pkts_burst[j], portid,i, qconf, cur_tsc);
			}

			/* Forward remaining prefetched packets */
			for (; j < nb_rx; j++) {
				reassemble(pkts_burst[j], portid,i, qconf, cur_tsc);
			}
			rte_ip_frag_free_death_row(&qconf->death_row,
                                PREFETCH_OFFSET);
		}
	}
}

/* display usage */
static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n",
	       prgname);
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static int
parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n == 0)
		return -1;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return -1;

	return n;
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:q:",
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask < 0) {
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			rx_queue_per_lcore = parse_nqueue(optarg);
			if (rx_queue_per_lcore < 0) {
				printf("invalid queue number\n");
				print_usage(prgname);
				return -1;
			}
			break;

		/* long options */
		case 0:
			print_usage(prgname);
			return -1;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (enabled_port_mask == 0) {
		printf("portmask not specified\n");
		print_usage(prgname);
		return -1;
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

static void
print_ethaddr(const char *name, struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s\n", name, buf);
}

static void
print_ethaddr_i(const struct rte_mbuf *m)
{
     /* save ether type of the incoming packet */
     struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
     print_ethaddr(" dst Address:", &eth_hdr->d_addr);
     print_ethaddr(" src Address:", &eth_hdr->s_addr);
}
/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up .Speed %u Mbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("\ndone\n");
		}
	}
}

/* Check L3 packet type detection capablity of the NIC port */
static int
check_ptype(int portid)
{
	int i, ret;
	int ptype_l3_ipv4 = 0, ptype_l3_ipv6 = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return 0;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i) {
		if (ptypes[i] & RTE_PTYPE_L3_IPV4)
			ptype_l3_ipv4 = 1;
		if (ptypes[i] & RTE_PTYPE_L3_IPV6)
			ptype_l3_ipv6 = 1;
	}

	if (ptype_l3_ipv4 == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV4\n", portid);

	if (ptype_l3_ipv6 == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV6\n", portid);

	if (ptype_l3_ipv4 && ptype_l3_ipv6)
		return 1;

	return 0;

}

/* Parse packet type of a packet by SW */
static inline void
parse_ptype(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = eth_hdr->ether_type;
	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
	else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
		packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;

	m->packet_type = packet_type;
}

/* callback function to detect packet type for a queue of a port */
static uint16_t
cb_parse_ptype(uint16_t port __rte_unused, uint16_t queue __rte_unused,
		   struct rte_mbuf *pkts[], uint16_t nb_pkts,
		   uint16_t max_pkts __rte_unused,
		   void *user_param __rte_unused)
{
	uint16_t i;

	for (i = 0; i < nb_pkts; ++i)
		parse_ptype(pkts[i]);

	return nb_pkts;
}

static int
init_routing_table(void)
{
	struct rte_lpm *lpm;
	struct rte_lpm6 *lpm6;
	int socket, ret;
	unsigned i;

	for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) {
		if (socket_lpm[socket]) {
			lpm = socket_lpm[socket];
			/* populate the LPM table */
			for (i = 0; i < RTE_DIM(l3fwd_ipv4_route_array); i++) {
				ret = rte_lpm_add(lpm,
					l3fwd_ipv4_route_array[i].ip,
					l3fwd_ipv4_route_array[i].depth,
					l3fwd_ipv4_route_array[i].if_out);

				if (ret < 0) {
					RTE_LOG(ERR, IP_FRAG, "Unable to add entry %i to the l3fwd "
						"LPM table\n", i);
					return -1;
				}

				RTE_LOG(INFO, IP_FRAG, "Socket %i: adding route " IPv4_BYTES_FMT
						"/%d (port %d)\n",
					socket,
					IPv4_BYTES(l3fwd_ipv4_route_array[i].ip),
					l3fwd_ipv4_route_array[i].depth,
					l3fwd_ipv4_route_array[i].if_out);
			}
		}

		if (socket_lpm6[socket]) {
			lpm6 = socket_lpm6[socket];
			/* populate the LPM6 table */
			for (i = 0; i < RTE_DIM(l3fwd_ipv6_route_array); i++) {
				ret = rte_lpm6_add(lpm6,
					l3fwd_ipv6_route_array[i].ip,
					l3fwd_ipv6_route_array[i].depth,
					l3fwd_ipv6_route_array[i].if_out);

				if (ret < 0) {
					RTE_LOG(ERR, IP_FRAG, "Unable to add entry %i to the l3fwd "
						"LPM6 table\n", i);
					return -1;
				}

				RTE_LOG(INFO, IP_FRAG, "Socket %i: adding route " IPv6_BYTES_FMT
						"/%d (port %d)\n",
					socket,
					IPv6_BYTES(l3fwd_ipv6_route_array[i].ip),
					l3fwd_ipv6_route_array[i].depth,
					l3fwd_ipv6_route_array[i].if_out);
			}
		}
	}
	return 0;
}
static int
setup_queue_tbl(struct rx_queue *rxq, uint32_t lcore, uint32_t queue)
{
	int socket;
	uint32_t nb_mbuf;
	uint64_t frag_cycles;
	char buf[RTE_MEMPOOL_NAMESIZE];

	socket = rte_lcore_to_socket_id(lcore);
	if (socket == SOCKET_ID_ANY)
		socket = 0;

	frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S *
		max_flow_ttl;

	if ((rxq->frag_tbl = rte_ip_frag_table_create(max_flow_num,
			IP_FRAG_TBL_BUCKET_ENTRIES, max_flow_num, frag_cycles,
			socket)) == NULL) {
		RTE_LOG(ERR, IP_RSMBL, "ip_frag_tbl_create(%u) on "
			"lcore: %u for queue: %u failed\n",
			max_flow_num, lcore, queue);
		return -1;
	}

	/*
	 * At any given moment up to <max_flow_num * (MAX_FRAG_NUM)>
	 * mbufs could be stored int the fragment table.
	 * Plus, each TX queue can hold up to <max_flow_num> packets.
	 */

	nb_mbuf = RTE_MAX(max_flow_num, 2UL * MAX_PKT_BURST) * MAX_FRAG_NUM;
	nb_mbuf *= (port_conf.rxmode.max_rx_pkt_len + BUF_SIZE - 1) / BUF_SIZE;
	nb_mbuf *= 2; /* ipv4 and ipv6 */
	nb_mbuf += nb_rxd + nb_txd;

	nb_mbuf = RTE_MAX(nb_mbuf, (uint32_t)NB_MBUF);

	snprintf(buf, sizeof(buf), "mbuf_pool_%u_%u", lcore, queue);
/*
	rxq->pool = rte_pktmbuf_pool_create(buf, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
					    MBUF_DATA_SIZE, socket);
	if (rxq->pool == NULL) {
		RTE_LOG(ERR, IP_RSMBL,
			"rte_pktmbuf_pool_create(%s) failed", buf);
		return -1;
	}
*/
	return 0;
}
static int
init_mem(void)
{
	char buf[PATH_MAX];
	struct rte_mempool *mp;
	struct rte_lpm *lpm;
	struct rte_lpm6 *lpm6;
	struct rte_lpm_config lpm_config;
	int socket;
	unsigned lcore_id;

	/* traverse through lcores and initialize structures on each socket */

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		socket = rte_lcore_to_socket_id(lcore_id);

		if (socket == SOCKET_ID_ANY)
			socket = 0;

		if (socket_direct_pool[socket] == NULL) {
			RTE_LOG(INFO, IP_FRAG, "Creating direct mempool on socket %i\n",
					socket);
			snprintf(buf, sizeof(buf), "pool_direct_%i", socket);

			mp = rte_pktmbuf_pool_create(buf, NB_MBUF, 32,
				0, RTE_MBUF_DEFAULT_BUF_SIZE, socket);
			if (mp == NULL) {
				RTE_LOG(ERR, IP_FRAG, "Cannot create direct mempool\n");
				return -1;
			}
			socket_direct_pool[socket] = mp;
		}

		if (socket_indirect_pool[socket] == NULL) {
			RTE_LOG(INFO, IP_FRAG, "Creating indirect mempool on socket %i\n",
					socket);
			snprintf(buf, sizeof(buf), "pool_indirect_%i", socket);

			mp = rte_pktmbuf_pool_create(buf, NB_MBUF, 32, 0, 0,
				socket);
			if (mp == NULL) {
				RTE_LOG(ERR, IP_FRAG, "Cannot create indirect mempool\n");
				return -1;
			}
			socket_indirect_pool[socket] = mp;
		}

		if (socket_lpm[socket] == NULL) {
			RTE_LOG(INFO, IP_FRAG, "Creating LPM table on socket %i\n", socket);
			snprintf(buf, sizeof(buf), "IP_FRAG_LPM_%i", socket);

			lpm_config.max_rules = LPM_MAX_RULES;
			lpm_config.number_tbl8s = 256;
			lpm_config.flags = 0;

			lpm = rte_lpm_create(buf, socket, &lpm_config);
			if (lpm == NULL) {
				RTE_LOG(ERR, IP_FRAG, "Cannot create LPM table\n");
				return -1;
			}
			socket_lpm[socket] = lpm;
		}

		if (socket_lpm6[socket] == NULL) {
			RTE_LOG(INFO, IP_FRAG, "Creating LPM6 table on socket %i\n", socket);
			snprintf(buf, sizeof(buf), "IP_FRAG_LPM_%i", socket);

			lpm6 = rte_lpm6_create(buf, socket, &lpm6_config);
			if (lpm6 == NULL) {
				RTE_LOG(ERR, IP_FRAG, "Cannot create LPM table\n");
				return -1;
			}
			socket_lpm6[socket] = lpm6;
		}
	}

	return 0;
}

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	struct rx_queue *rxq;
	int socket, ret;
	uint16_t nb_ports;
	uint16_t queueid = 0;
	unsigned lcore_id = 0, rx_lcore_id = 0;
	uint32_t n_tx_queue, nb_lcores;
	uint16_t portid;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eal_init failed");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid arguments");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No ports found!\n");
    	struct rte_ether_addr addr;
	rte_eth_macaddr_get(0, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
	       " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
	       0, addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], addr.addr_bytes[3],
	       addr.addr_bytes[4], addr.addr_bytes[5]);

	my_eth_addr = addr;
	my_ip = rte_cpu_to_be_32(RTE_IPV4(10,10,103,229));
	nb_lcores = rte_lcore_count();

	/* initialize structures (mempools, lpm etc.) */
	if (init_mem() < 0)
		rte_panic("Cannot initialize memory structures!\n");

	/* check if portmask has non-existent ports */
	if (enabled_port_mask & ~(RTE_LEN2MASK(nb_ports, unsigned)))
		rte_exit(EXIT_FAILURE, "Non-existent ports in portmask!\n");

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_rxconf rxq_conf;

		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %d\n", portid);
			continue;
		}

		qconf = &lcore_queue_conf[rx_lcore_id];

		/* limit the frame size to the maximum supported by NIC */
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		local_port_conf.rxmode.max_rx_pkt_len = RTE_MIN(
		    dev_info.max_rx_pktlen,
		    local_port_conf.rxmode.max_rx_pkt_len);

		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       qconf->n_rx_queue == (unsigned)rx_queue_per_lcore) {

			rx_lcore_id ++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");

			qconf = &lcore_queue_conf[rx_lcore_id];
		}

		socket = (int) rte_lcore_to_socket_id(rx_lcore_id);
		if (socket == SOCKET_ID_ANY)
			socket = 0;

		rxq = &qconf->rx_queue_list[qconf->n_rx_queue];
		rxq->portid = portid;
		rxq->direct_pool = socket_direct_pool[socket];
		rxq->indirect_pool = socket_indirect_pool[socket];
		rxq->lpm = socket_lpm[socket];
		rxq->lpm6 = socket_lpm6[socket];
		
        if (setup_queue_tbl(rxq, rx_lcore_id, queueid) < 0)
			rte_exit(EXIT_FAILURE, "Failed to set up queue table\n");
		qconf->n_rx_queue++;
		/* init port */
		printf("Initializing port %d on lcore %u...", portid,
		       rx_lcore_id);
		fflush(stdout);

		n_tx_queue = nb_lcores;
		if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
			n_tx_queue = MAX_TX_QUEUE_PER_PORT;
		ret = rte_eth_dev_configure(portid, 1, (uint16_t)n_tx_queue,
					    &local_port_conf);
		if (ret < 0) {
			printf("\n");
			rte_exit(EXIT_FAILURE, "Cannot configure device: "
				"err=%d, port=%d\n",
				ret, portid);
		}

		/* set the mtu to the maximum received packet size */
		ret = rte_eth_dev_set_mtu(portid,
			local_port_conf.rxmode.max_rx_pkt_len - MTU_OVERHEAD);
		if (ret < 0) {
			printf("\n");
			rte_exit(EXIT_FAILURE, "Set MTU failed: "
				"err=%d, port=%d\n",
			ret, portid);
		}

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
					    &nb_txd);
		if (ret < 0) {
			printf("\n");
			rte_exit(EXIT_FAILURE, "Cannot adjust number of "
				"descriptors: err=%d, port=%d\n", ret, portid);
		}

		/* init one RX queue */
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     socket, &rxq_conf,
					     socket_direct_pool[socket]);
		if (ret < 0) {
			printf("\n");
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: "
				"err=%d, port=%d\n",
				ret, portid);
		}

		ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		if (ret < 0) {
			printf("\n");
			rte_exit(EXIT_FAILURE,
				"rte_eth_macaddr_get: err=%d, port=%d\n",
				ret, portid);
		}

		print_ethaddr(" Address:", &ports_eth_addr[portid]);
		printf("\n");

		/* init one TX queue per couple (lcore,port) */
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		queueid = 0;
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			if (queueid >= dev_info.nb_tx_queues)
				break;

			socket = (int) rte_lcore_to_socket_id(lcore_id);
			printf("txq=%u,%d ", lcore_id, queueid);
			fflush(stdout);

			txconf = &dev_info.default_txconf;
			txconf->offloads = local_port_conf.txmode.offloads;
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
						     socket, txconf);
			if (ret < 0) {
				printf("\n");
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: "
					"err=%d, port=%d\n", ret, portid);
			}

			qconf = &lcore_queue_conf[lcore_id];
			qconf->tx_queue_id[portid] = queueid;
			queueid++;
		}

		printf("\n");
	}

	printf("\n");

	/* start ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n",
				ret, portid);

		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_promiscuous_enable: err=%s, port=%d\n",
				rte_strerror(-ret), portid);

		if (check_ptype(portid) == 0) {
			rte_eth_add_rx_callback(portid, 0, cb_parse_ptype, NULL);
			printf("Add Rx callback function to detect L3 packet type by SW :"
				" port = %d\n", portid);
		}
	}

	if (init_routing_table() < 0)
		rte_exit(EXIT_FAILURE, "Cannot init routing table\n");

	check_all_ports_link_status(enabled_port_mask);

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}
