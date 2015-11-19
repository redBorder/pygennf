#!/usr/bin/env python2

import scapy
from scapy.all import *
from rb_netflow import *

# Netflow5
nfh = NetflowHeader(version=5)
# No need the count field! see rb_netflow.py:post_build
nf5h = NetflowHeaderV5(\
	sysUptime = 0x3e80,\
	unixSecs = 0x52d3af70,\
	unixNanoSeconds = 0x04bdb6f0,\
	flowSequence = 48,\
	engineType = 0,\
	engineID = 0,\
	samplingInterval = 0)

# wireshark File -> export specified packet dissections -> as plain text

records = [
	NetflowRecordV5(\
        src = "192.168.0.17",dst="8.8.8.8",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=1,dOctets=72,\
        first=1,last=2,srcport=49622,\
        dstport=53,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "10.10.0.110",dst="62.42.230.24",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=1,dOctets=59,\
        first=1,last=2,srcport=61969,\
        dstport=53,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "10.10.0.99",dst="192.168.150.53",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=4,dOctets=1829,\
        first=1,last=2,srcport=2080,\
        dstport=80,pad1=0,tcpFlags=0x1a,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.0.6",dst="10.10.0.110",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=2,dOctets=140,\
        first=1,last=2,srcport=49376,\
        dstport=53,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.70.3",dst="192.168.4.28",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=2,dOctets=88,\
        first=1,last=2,srcport=4074,\
        dstport=139,pad1=0,tcpFlags=0x06,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "1.1.1.1",dst="        192.168.212.56",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=1,dOctets=40,\
        first=1,last=2,srcport=444,\
        dstport=18134,pad1=0,tcpFlags=0x04,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "157.56.52.45",dst="172.23.5.36",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=1,dOctets=1288,\
        first=1,last=2,srcport=40007,\
        dstport=47109,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.150.53",dst="10.10.0.99",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=3,dOctets=128,\
        first=1,last=2,srcport=80,\
        dstport=1934,pad1=0,tcpFlags=0x16,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.0.17",dst="192.43.172.30",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=1,dOctets=59,\
        first=1,last=2,srcport=60350,\
        dstport=53,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "172.23.5.84",dst="178.236.7.220",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=12,dOctets=3342,\
        first=1,last=2,srcport=49362,\
        dstport=443,pad1=0,tcpFlags=0x1b,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "172.23.5.84",dst="178.236.6.3",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=1204,dOctets=1753032,\
        first=1,last=2,srcport=49780,\
        dstport=443,pad1=0,tcpFlags=0x1b,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.150.53",dst="10.10.0.99",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=3,dOctets=128,\
        first=1,last=2,srcport=80,\
        dstport=2444,pad1=0,tcpFlags=0x16,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.0.6",dst="10.10.0.110",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=2,dOctets=140,\
        first=1,last=2,srcport=50572,\
        dstport=53,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "10.10.0.99",dst="        192.168.150.53",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=4,dOctets=1829,\
        first=1,last=2,srcport=2471,\
        dstport=80,pad1=0,tcpFlags=0x1a,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.40.5",dst="192.168.4.28",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=6,dOctets=1039,\
        first=1,last=2,srcport=4386,\
        dstport=445,pad1=0,tcpFlags=0x1b,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.43.172.30",dst="192.168.0.17",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=1,dOctets=148,\
        first=1,last=2,srcport=53,\
        dstport=59714,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "65.55.53.190",dst="172.23.4.126",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=5,dOctets=805,\
        first=1,last=2,srcport=80,\
        dstport=36639,pad1=0,tcpFlags=0x1b,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "10.10.0.113",dst="192.168.160.203",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=6,dOctets=288,\
        first=1,last=2,srcport=1925,\
        dstport=6007,pad1=0,tcpFlags=0x02,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "10.10.0.110",dst="172.24.192.5",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=185,dOctets=60921,\
        first=1,last=2,srcport=67,\
        dstport=67,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "1.1.1.1",dst="        192.168.212.56",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=2,dOctets=80,\
        first=1,last=2,srcport=444,\
        dstport=13693,pad1=0,tcpFlags=0x04,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.4.28",dst="192.168.70.3",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=1,dOctets=48,\
        first=1,last=2,srcport=139,\
        dstport=4258,pad1=0,tcpFlags=0x12,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.150.53",dst="10.10.0.99",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=3,dOctets=128,\
        first=1,last=2,srcport=80,\
        dstport=1899,pad1=0,tcpFlags=0x16,\
        prot=6,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.0.6",dst="10.10.0.110",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=2,dOctets=140,\
        first=1,last=2,srcport=58475,\
        dstport=53,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "64.34.121.1",dst="192.168.0.17",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=1,dOctets=270,\
        first=1,last=2,srcport=53,\
        dstport=55229,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.0.6",dst="10.10.0.110",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=2,dOctets=138,\
        first=1,last=2,srcport=54075,\
        dstport=53,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.0.6",dst="10.10.0.110",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=2,dOctets=148,\
        first=1,last=2,srcport=64113,\
        dstport=53,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.0.6",dst="10.10.0.110",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=2,dOctets=138,\
        first=1,last=2,srcport=59700,\
        dstport=53,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "192.168.0.17",dst="192.43.172.30",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=1,dOctets=59,\
        first=1,last=2,srcport=58025,\
        dstport=53,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "8.8.8.8",dst="192.168.0.17",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=1,dOctets=57,\
        first=1,last=2,srcport=53,\
        dstport=49320,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0),
	NetflowRecordV5(\
        src = "10.10.0.110",dst="192.168.150.52",nexthop="0.0.0.0",\
        input=0,output=0,dpkts=5,dOctets=380,\
        first=1,last=2,srcport=64189,\
        dstport=53,pad1=0,tcpFlags=0x00,\
        prot=17,tos=0x00,src_as=0,dst_as=0,\
        src_mask=0,dst_mask=0,pad2=0)
]

data = Ether()/IP()/UDP(sport=60000,dport=2055)/nfh/nf5h
for r in records:
    data/=r

wrpcap('5.pcap',data)

## Netflow9

#nf9fs = NetflowV9Flowset()
#nf9fs.addfield(MACField("ClientMac","00:16:6f:35:25:61"))
