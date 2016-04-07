#!/usr/bin/env python2
#
#  pygennf: UDP packets producer with scapy.
#  Copyright (C) 2015-2016  Ana Rey <anarey@redborder.com>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.
#
#  You should have received a copy of the GNU Affero General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse

import scapy
from scapy.all import *

import rb_netflow.rb_netflow as rbnf

# Netflow9

parser = argparse.ArgumentParser(description='UDP packets producer with scapy')
parser.add_argument('-s', '--source-ip', dest='src_ip',
                    help='IP source')
parser.add_argument('-sp', '--source-port', dest='src_port',
                    help='Port dst')
parser.add_argument('-d', '--dst-ip', dest='dst_ip',
                    help='IP source')
parser.add_argument('-dp', '--dst-port', dest='dst_port',
                    help='Port dst')

args = parser.parse_args()

if args.src_ip:
    IP_SRC = args.src_ip
else:
    IP_SRC = "10.0.203.2"

if args.dst_ip:
    IP_DST = args.dst_ip
else:
    IP_DST = "10.0.30.89"

if args.src_port:
    PORT_SRC = args.src_port
else:
    PORT_SRC = 2056

if args.dst_port:
    PORT_DST = args.dst_port
else:
    PORT_DST = 2055

header_v9 = rbnf.Netflow_Headerv9(version=9, count= 2, SysUptime=0x000069d7, Timestamp=1392292623, FlowSequence= 0,SourceId= 243)


flowSet_header_v9 = rbnf.FlowSet_Header_v9(FlowSet_id= 0, FlowSet_length=80)


flowset_id_v9 = rbnf.FlowTemplate_ID_v9(template_id=258,count=18)

template = [
    rbnf.NetFlowTemplatev9Field(type_template=1, length= 4),
    rbnf.NetFlowTemplatev9Field(type_template=2, length= 4),
    rbnf.NetFlowTemplatev9Field(type_template=4, length= 1),
    rbnf.NetFlowTemplatev9Field(type_template=5, length= 1),
    rbnf.NetFlowTemplatev9Field(type_template=6, length= 1),
    rbnf.NetFlowTemplatev9Field(type_template=7, length= 2),
    rbnf.NetFlowTemplatev9Field(type_template=10, length= 2),
    rbnf.NetFlowTemplatev9Field(type_template=11, length= 2),
    rbnf.NetFlowTemplatev9Field(type_template=14, length= 2),
    rbnf.NetFlowTemplatev9Field(type_template=16, length= 4),
    rbnf.NetFlowTemplatev9Field(type_template=17, length= 4),
    rbnf.NetFlowTemplatev9Field(type_template=21, length= 4),
    rbnf.NetFlowTemplatev9Field(type_template=22, length= 4),
    rbnf.NetFlowTemplatev9Field(type_template=27, length= 16),
    rbnf.NetFlowTemplatev9Field(type_template=28, length= 16),
    rbnf.NetFlowTemplatev9Field(type_template=29, length= 1),
    rbnf.NetFlowTemplatev9Field(type_template=30, length= 1),
    rbnf.NetFlowTemplatev9Field(type_template=62, length= 16)
    ]

flowSet_2_header = rbnf.FlowSet_Header_v9(FlowSet_id= 258, FlowSet_length=92)


flows = [
    rbnf.Flow_v9(\
        Packets=826, Protocol=17, IP_ToS=0x00, TCP_Flags=0x00, Octets=113162,\
        SrcPort=2416, InputInt=0, DstPort=53, OutputInt=0, SrcAS=0, DstAS=0,\
        StartTime=0x000069b5, EndTime=0x00000002,\
        SrcAddr="3ffe:507:0:1:200:86ff:fe05:80da",\
        DstAddr="3ffe:501:4819::42", SrcMask=0, DstMask=0, NextHop="::", 
        Padding=3)
    ]


data = IP(dst=IP_DST)/UDP(sport=PORT_SRC,dport=PORT_DST)
data/=header_v9/flowSet_header_v9/flowset_id_v9

for t in template:
    data/=t

data/=flowSet_2_header

for f in flows:
    data/=f


wrpcap('v9.pcap', data)
send(data)
