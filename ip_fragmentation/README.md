# nic

```
[root@centos7 test]# ethtool -l enp6s0
Channel parameters for enp6s0:
Pre-set maximums:
RX:             16
TX:             16
Other:          0
Combined:       0
Current hardware settings:
RX:             8
TX:             8
Other:          0
Combined:       0
```

# bind dpdk
```shell
[root@centos7 dpdk-19.11]# ./usertools/dpdk-devbind.py  -u 0000:05:00.0
Warning: routing table indicates that interface 0000:05:00.0 is active. Skipping unbind
[root@centos7 dpdk-19.11]# ip l set enp5s0 down
[root@centos7 dpdk-19.11]# ./usertools/dpdk-devbind.py  -u 0000:05:00.0
[root@centos7 dpdk-19.11]# ./usertools/dpdk-devbind.py   --bind=vfio-pci  0000:05:00.0
[root@centos7 dpdk-19.11]# 
```
# make
```shell
export RTE_SDK=/data1/dpdk-19.11
export EXTRA_CFLAGS='-g -O0'
send_burst
./build/app/ip_fragmentation  -l 1 -n 4 -- -p 1 -q 1
```


```text
 注意:
(1) 这里使用了一个 lcore, 如果使用多个lcore, 由于 某种原因 同一条流的分片可能被2个 lcore 处理, 造成重组失败
(2) maxflows 需要设置的小一点, 不然会消耗大量内存, 虚拟机配置的大页内存可能会不够
 ```
```text
frag example : https://github.com/omec-project/upf-epc/blob/330ac5ee1f4633c361a8b569fc2aaea7c1b79dbc/core/modules/ip_frag.cc
https://github.com/omec-project/ngic-rtc-tmo/blob/c75fc60d9f97fea7fbc76731d2bae6a86ff6fcc6/dp/pkt_engines/epc_ul.c
https://github.com/open-ness/edgenode/blob/3e44cdd0969af90568ddfde36b4daa7bc1c099e6/internal/nts/daemon/io/nes_dev_port.c
o = rte_ipv4_frag_reassemble_packet(self->frag_tbl,
				&self->death_row, self->rx_pkts[i], cur_tsc, ipv4_hdr);
			/* check if all packet are gathering */
			if (mo == NULL)
				continue;
			rte_pktmbuf_linearize(mo);
			/* packet reassembled */
			if (mo != self->rx_pkts[i]) {
				self->rx_pkts[i] = mo;
				eth_hdr = rte_pktmbuf_mtod(self->rx_pkts[i], struct ether_hdr *);

				ipv4_hdr = (struct ipv4_hdr *)((uint8_t*)(eth_hdr + 1) + l2_off);
			}
			ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
```
# sever
```
10.10.103.229
port = 4444
#define TEST_UDP_SRC_PORT 4444
#define TEST_UDP_DST_PORT 4444
```

```Shell
 ./build/app/ip_fragmentation  -l 1 -n 4 -- -p 1 -q 1
EAL: Detected 128 lcore(s)
EAL: Detected 4 NUMA nodes
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: No available hugepages reported in hugepages-2048kB
EAL: Probing VFIO support...
EAL: VFIO support initialized
EAL: PCI device 0000:05:00.0 on NUMA socket 0
EAL:   probe driver: 19e5:200 net_hinic
EAL:   using IOMMU type 1 (Type 1)
net_hinic: Initializing pf hinic-0000:05:00.0 in primary process
net_hinic: Device 0000:05:00.0 hwif attribute:
net_hinic: func_idx:0, p2p_idx:0, pciintf_idx:0, vf_in_pf:0, ppf_idx:0, global_vf_id:15, func_type:2
net_hinic: num_aeqs:4, num_ceqs:4, num_irqs:32, dma_attr:2
net_hinic: Get public resource capability:
net_hinic: host_id: 0x0, ep_id: 0x0, intr_type: 0x0, max_cos_id: 0x7, er_id: 0x0, port_id: 0x0
net_hinic: host_total_function: 0xf2, host_oq_id_mask_val: 0x8, max_vf: 0x78
net_hinic: pf_num: 0x2, pf_id_start: 0x0, vf_num: 0xf0, vf_id_start: 0x10
net_hinic: Get share resource capability:
net_hinic: host_pctxs: 0x0, host_cctxs: 0x0, host_scqs: 0x0, host_srqs: 0x0, host_mpts: 0x0
net_hinic: Get l2nic resource capability:
net_hinic: max_sqs: 0x10, max_rqs: 0x10, vf_max_sqs: 0x4, vf_max_rqs: 0x4
net_hinic: Initialize 0000:05:00.0 in primary successfully
EAL: PCI device 0000:06:00.0 on NUMA socket 0
EAL:   probe driver: 19e5:200 net_hinic
EAL: PCI device 0000:7d:00.0 on NUMA socket 0
EAL:   probe driver: 19e5:a222 net_hns3
EAL: PCI device 0000:7d:00.1 on NUMA socket 0
EAL:   probe driver: 19e5:a221 net_hns3
EAL: PCI device 0000:7d:00.2 on NUMA socket 0
EAL:   probe driver: 19e5:a222 net_hns3
EAL: PCI device 0000:7d:00.3 on NUMA socket 0
EAL:   probe driver: 19e5:a221 net_hns3
Port 0 MAC: 44 a1 91 a4 9c 0b
IP_FRAG: Creating direct mempool on socket 0
IP_FRAG: Creating indirect mempool on socket 0
IP_FRAG: Creating LPM table on socket 0
IP_FRAG: Creating LPM6 table on socket 0
USER1: rte_ip_frag_table_create: allocated of 33554688 bytes at socket 0
Initializing port 0 on lcore 1...net_hinic: Disable vlan filter succeed, device: hinic-0000:05:00.0, port_id: 0
net_hinic: Disable vlan strip succeed, device: hinic-0000:05:00.0, port_id: 0
net_hinic: Set port mtu, port_id: 0, mtu: 9596, max_pkt_len: 9614
 Address:44:A1:91:A4:9C:0B

txq=1,0 

net_hinic: Set new mac address 44:a1:91:a4:9c:0b

net_hinic: Disable promiscuous, nic_dev: hinic-0000:05:00.0, port_id: 0, promisc: 0
net_hinic: Disable allmulticast succeed, nic_dev: hinic-0000:05:00.0, port_id: 0
net_hinic: Enable promiscuous, nic_dev: hinic-0000:05:00.0, port_id: 0, promisc: 0
Add Rx callback function to detect L3 packet type by SW : port = 0
IP_FRAG: Socket 0: adding route 100.10.0.0/16 (port 0)
IP_FRAG: Socket 0: adding route 100.20.0.0/16 (port 1)
IP_FRAG: Socket 0: adding route 100.30.0.0/16 (port 2)
IP_FRAG: Socket 0: adding route 100.40.0.0/16 (port 3)
IP_FRAG: Socket 0: adding route 100.50.0.0/16 (port 4)
IP_FRAG: Socket 0: adding route 100.60.0.0/16 (port 5)
IP_FRAG: Socket 0: adding route 100.70.0.0/16 (port 6)
IP_FRAG: Socket 0: adding route 100.80.0.0/16 (port 7)
IP_FRAG: Socket 0: adding route 0101:0101:0101:0101:0101:0101:0101:0101/48 (port 0)
IP_FRAG: Socket 0: adding route 0201:0101:0101:0101:0101:0101:0101:0101/48 (port 1)
IP_FRAG: Socket 0: adding route 0301:0101:0101:0101:0101:0101:0101:0101/48 (port 2)
IP_FRAG: Socket 0: adding route 0401:0101:0101:0101:0101:0101:0101:0101/48 (port 3)
IP_FRAG: Socket 0: adding route 0501:0101:0101:0101:0101:0101:0101:0101/48 (port 4)
IP_FRAG: Socket 0: adding route 0601:0101:0101:0101:0101:0101:0101:0101/48 (port 5)
IP_FRAG: Socket 0: adding route 0701:0101:0101:0101:0101:0101:0101:0101/48 (port 6)
IP_FRAG: Socket 0: adding route 0801:0101:0101:0101:0101:0101:0101:0101/48 (port 7)

Checking link status
done
Port0 Link Up .Speed 40000 Mbps - full-duplex
IP_FRAG: entering main loop on lcore 1
IP_FRAG:  -- lcoreid=1 portid=0
ARP asking me....
I will reply following 
```

## hinic driver

```Shell
(gdb) bt
#0  0x000000000057efe4 in rte_pci_register ()
#1  0x00000000009401e4 in __libc_csu_init ()
#2  0x0000ffffbe4a16c8 in __libc_start_main (main=0x48617c <main>, argc=10, argv=0xfffffffff3f8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=<optimized out>) at libc-start.c:225
#3  0x00000000004822dc in _start ()
(gdb) c
```

```
/** Helper for PCI device registration from driver (eth, crypto) instance */
#define RTE_PMD_REGISTER_PCI(nm, pci_drv) \
RTE_INIT(pciinitfn_ ##nm) \
{\
        (pci_drv).driver.name = RTE_STR(nm);\
        rte_pci_register(&pci_drv); \
} \
RTE_PMD_EXPORT_NAME(nm, __COUNTER__)
```
```C
#define RTE_PRIO(prio) \
        RTE_PRIORITY_ ## prio

/**
 * Run function before main() with high priority.
 *
 * @param func
 *   Constructor function.
 * @param prio
 *   Priority number must be above 100.
 *   Lowest number is the first to run.
 */
#ifndef RTE_INIT_PRIO /* Allow to override from EAL */
#define RTE_INIT_PRIO(func, prio) \
static void __attribute__((constructor(RTE_PRIO(prio)), used)) func(void)
#endif

/**
 * Run function before main() with low priority.
 *
 * The constructor will be run after prioritized constructors.
 *
 * @param func
 *   Constructor function.
 */
#define RTE_INIT(func) \
        RTE_INIT_PRIO(func, LAST)
```

# client

```
#!/usr/bin/python

from scapy.all import *
sip="10.10.103.81"
dip="10.10.103.229"
payload="A"*496+"B"*500 + "c"*500
packet=IP(src=sip,dst=dip,id=12345)/UDP(sport=4444,dport=4444)/payload

frags=fragment(packet,fragsize=500)
counter=1
for fragment in frags:
    print "Packet no#"+str(counter)
    print "==================================================="
    fragment.show() #displays each fragment
    counter+=1
    send(fragment)
```
