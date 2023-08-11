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
