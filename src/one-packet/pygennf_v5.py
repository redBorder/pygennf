#!/usr/bin/env python2

#  pygennf: UDP packets producer with scapy.
#  Copyright (C) 2015-2016  Eugenio Perez <eugenio@redborder.com>
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
import datetime
import signal
import time

import scapy
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
    
    if args.time_interval:
        TIME_INTERVAL = args.time_interval
    else:
        TIME_INTERVAL = 0
    
    
    if args.dst_port:
        PORT_DST = int(args.dst_port)
    else:
        PORT_DST = int(2055)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    #Current timestamp in seconds
    tnow=(datetime.datetime.utcnow()-datetime.datetime(1970,1,1)).seconds


    # Netflow5
    nfh = rbnf.NetflowHeader(version=5)
    # No need the count field! see rb_netflow.py:post_build
    nf5h = rbnf.NetflowHeaderV5(\
        sysUptime = 0x3e80,\
        unixSecs = tnow,\
        unixNanoSeconds = 0x04bdb6f0,\
        flowSequence = 48,\
        engineType = 0,\
        engineID = 0,\
        samplingInterval = 0)
    
    # wireshark File -> export specified packet dissections -> as plain text

    records = [
        rbnf.NetflowRecordV5(\
            src = IP_SRC,dst=IP_DST,nexthop="0.0.0.0",\
            input=0,output=0,dpkts=1,dOctets=72,\
            first=1,last=2,srcport=PORT_SRC,\
            dstport=PORT_DST,pad1=0,tcpFlags=0x00,\
            prot=17,tos=0x00,src_as=0,dst_as=0,\
            src_mask=0,dst_mask=0,pad2=0)
 
    ]
    
    data = IP(dst=IP_DST, version=4)/UDP(dport=PORT_DST)/nfh/nf5h
    for r in records:
        data/=r

    wrpcap('5.pcap',data)

    send(data)

    while TIME_INTERVAL is not 0:
        if signal_received == 1:
            print "\nSignal received. Stopping and Exitting..."
            sys.exit(0)
        time.sleep(float(TIME_INTERVAL))
        send(data)


if __name__ == '__main__':
    main()


## Netflow9

#nf9fs = NetflowV9Flowset()
#nf9fs.addfield(MACField("ClientMac","00:16:6f:35:25:61"))
