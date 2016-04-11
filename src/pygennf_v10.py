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
import time
import scapy
import signal


from scapy.all import *

import rb_netflow.rb_netflow as rbnf

signal_received = 0

def preexec():
    os.setpgrp()  # Don't forward signals

def signal_handler(signal, frame):
    global signal_received
    signal_received = 1

def main():
    if os.getuid() != 0:
        print "You need to be root to run this, sorry."
        return

    parser = argparse.ArgumentParser(description='UDP packets producer with scapy')
    parser.add_argument('-s', '--source-ip', dest='src_ip',
                        help='IP source')
    parser.add_argument('-sp', '--source-port', dest='src_port',
                        help='Port dst')
    parser.add_argument('-d', '--dst-ip', dest='dst_ip',
                        help='IP source')
    parser.add_argument('-dp', '--dst-port', dest='dst_port',
                        help='Port dst')
    parser.add_argument('-t', '--time-interval', dest='time_interval',
                        help='Time interval to wait to send other messages.')
    
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
        PORT_SRC = int(args.src_port)
    else:
        PORT_SRC = int(2056)
    
    if args.dst_port:
        PORT_DST = int(args.dst_port)
    else:
        PORT_DST = int(2055)
    
    if args.time_interval:
        TIME_INTERVAL = args.time_interval
    else:
        TIME_INTERVAL = 0

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Netflow10
    header_v10 = rbnf.NetflowHeaderv10(version=10, length=0, ExportTime=1380127358,\
                                  FlowSequence=11268, ObservationDomainId = 256)
    
    set_header_1 = rbnf.Flow_Set_v10(FlowSet_id= 2, FlowSet_Length=100)
    
    template_id = rbnf.FlowTemplate_ID_v10(template_id=269, count=19)

    template = [
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=8,length=4),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=12,length=4),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=60,length=1),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=4,length=1),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=7,length=2),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=11,length=2),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=136,length=1),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=239,length=1),
    
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=48,length=1),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=280,length=8),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=95,length=4),
        rbnf.NetFlowTemplatev10FieldPEN(),
        rbnf.NetFlowTemplatev10FieldPEN(),
        rbnf.NetFlowTemplatev10FieldPEN(),
        rbnf.NetFlowTemplatev10FieldPEN(),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=1,length=8),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=2,length=4),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=22,length=4),
        rbnf.NetFlowTemplatev10Field(Pen_provided=0,type=21,length=4)
    ]
    
    set_header_2 = rbnf.Flow_Set_v10(FlowSet_id= 269, FlowSet_Length=392)
    
    
    flows = [
        rbnf.Flow_v10(\
             src="192.168.210.154", dst="10.13.91.211", IPVersion=4,prot=6,\
             srcport=9090, dstport=2284, FER=3, biflow_direction=1, SamplerID=0,\
             EPE_A=0x8f53b990, EPE_B=0x00010000, applicationID_id=13,\
             applicationID_type=1,\
             length1=6, EPE1_A=0x030000, EPE1_B=0x503401,\
             length2=6, EPE2_A=0x030000, EPE2_B=0x503402,\
             length3=6, EPE3_A=0x030000, EPE3_B=0x503403,\
             length4=6, EPE4_A=0x030000, EPE4_B=0x503404,\
             Octects=40, packets=1, startTime=0x7a581bc0, EndTime=0x7a581bc0),
        rbnf.Flow_v10(\
             src="192.168.210.154", dst="10.13.91.211", IPVersion=4,prot=6,\
             srcport=9090, dstport=2336, FER=3, biflow_direction=1, SamplerID=0,\
             EPE_A=0x8f492490, EPE_B=0x00010000, applicationID_id=13,\
             applicationID_type=1,\
             length1=6, EPE1_A=0x030000, EPE1_B=0x503401,\
             length2=6, EPE2_A=0x030000, EPE2_B=0x503402,\
             length3=6, EPE3_A=0x030000, EPE3_B=0x503403,\
             length4=6, EPE4_A=0x030000, EPE4_B=0x503404,\
             Octects=40, packets=1, startTime=0x7a581c00, EndTime=0x7a581c00),
        rbnf.Flow_v10(\
             src="184.28.16.177", dst="10.25.31.220", IPVersion=4,prot=6,\
             srcport=443, dstport=55886, FER=3, biflow_direction=1, SamplerID=0,\
             EPE_A=0x8f518c50, EPE_B=0x00010000, applicationID_id=13,\
             applicationID_type=1,\
             length1=6, EPE1_A=0x030000, EPE1_B=0x503401,\
             length2=6, EPE2_A=0x030000, EPE2_B=0x503402,\
             length3=6, EPE3_A=0x030000, EPE3_B=0x503403,\
             length4=6, EPE4_A=0x030000, EPE4_B=0x503404,\
             Octects=60, packets=1, startTime=0x7a581d60,\
             EndTime=0x7a581d60), #3 #4
        rbnf.Flow_v10(\
             src="192.168.210.154", dst="10.13.91.211", IPVersion=4,prot=6,\
             srcport=9090, dstport=2339, FER=3, biflow_direction=1, SamplerID=0,\
             EPE_A=0x8f53b990, EPE_B=0x00010000, applicationID_id=13,\
             applicationID_type=1,\
             length1=6, EPE1_A=0x030000, EPE1_B=0x503401,\
             length2=6, EPE2_A=0x030000, EPE2_B=0x503402,\
             length3=6, EPE3_A=0x030000, EPE3_B=0x503403,\
             length4=6, EPE4_A=0x030000, EPE4_B=0x503404,\
             Octects=40, packets=1, startTime=0x7a581e60,\
             EndTime=0x7a581e60), #4 #5
        rbnf.Flow_v10(\
             src="192.168.210.154", dst="10.13.102.120", IPVersion=4,prot=6,\
             srcport=9090, dstport=50185, FER=3, biflow_direction=1, SamplerID=0,\
             EPE_A=0x8f53b990, EPE_B=0x00010000,applicationID_id=13,\
             applicationID_type=1,\
             length1=6, EPE1_A=0x030000, EPE1_B=0x503401,\
             length2=6, EPE2_A=0x030000, EPE2_B=0x503402,\
             length3=6, EPE3_A=0x030000, EPE3_B=0x503403,\
             length4=6, EPE4_A=0x030000, EPE4_B=0x503404,\
             Octects=40, packets=1, startTime=0x7a582020,\
             EndTime=0x7a582020) #5 #6
    ]

    data = IP(dst=IP_DST)/UDP(sport=PORT_SRC,dport=PORT_DST)
    data/=header_v10/set_header_1/template_id
    
    for t in template:
        data/=t
    
    data/=set_header_2
    
    for f in flows:
        print "aaaaa"
        data/=f
    
    wrpcap('v10.pcap', data)
    send(data)
    
    while TIME_INTERVAL is not 0:
        if signal_received == 1:
            print "\nSignal received. Stopping and Exitting..."
            sys.exit(0)
        time.sleep(float(TIME_INTERVAL))
        send(data)

if __name__ == '__main__':
    main()
