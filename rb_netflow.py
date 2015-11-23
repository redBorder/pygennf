## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license
## Netflow V5 appended by spaceB0x and Guillaume Valadon

"""
Cisco NetFlow protocol v1 and v5
"""


from scapy.fields import *
from scapy.packet import *
from scapy.data import IP_PROTOS
from scapy.layers.inet6 import *


class NetflowHeader(Packet):
    name = "Netflow Header"
    fields_desc = [ ShortField("version", 1) ]


###########################################
### Netflow Version 1
###########################################


class NetflowHeaderV1(Packet):
    name = "Netflow Header v1"
    fields_desc = [ ShortField("count", 0),
                    IntField("sysUptime", 0),
                    IntField("unixSecs", 0),
                    IntField("unixNanoSeconds", 0)]


class NetflowRecordV1(Packet):
    name = "Netflow Record v1"
    fields_desc = [ IPField("ipsrc", "0.0.0.0"),
                    IPField("ipdst", "0.0.0.0"),
                    IPField("nexthop", "0.0.0.0"),
                    ShortField("inputIfIndex", 0),
                    ShortField("outpuIfIndex", 0),
                    IntField("dpkts", 0),
                    IntField("dbytes", 0),
                    IntField("starttime", 0),
                    IntField("endtime", 0),
                    ShortField("srcport", 0),
                    ShortField("dstport", 0),
                    ShortField("padding", 0),
                    ByteField("proto", 0),
                    ByteField("tos", 0),
                    IntField("padding1", 0),
                    IntField("padding2", 0) ]


bind_layers( NetflowHeader,   NetflowHeaderV1, version=1)
bind_layers( NetflowHeaderV1, NetflowRecordV1 )
bind_layers( NetflowRecordV1, NetflowRecordV1 )


#########################################
### Netflow Version 5
#########################################


class NetflowHeaderV5(Packet):
    name = "Netflow Header v5"
    fields_desc = [ ShortField("count", 0),
                    IntField("sysUptime", 0),
                    IntField("unixSecs", 0),
                    IntField("unixNanoSeconds", 0),
                    IntField("flowSequence",0),
                    ByteField("engineType", 0),
                    ByteField("engineID", 0),
                    ShortField("samplingInterval", 0) ]

    # TODO use FieldListField??
    def post_build(self, p, pay):
        if self.count == 0:
            sizeof_NetflowRecordV5 = 48
            count = len(pay)/sizeof_NetflowRecordV5
            p = chr(count>>8) + chr(count%256) + p[2:]
        return p+pay


class NetflowRecordV5(Packet):
    name = "Netflow Record v5"
    fields_desc = [ IPField("src", "127.0.0.1"),
                    IPField("dst", "127.0.0.1"),
                    IPField("nexthop", "0.0.0.0"),
                    ShortField("input", 0),
                    ShortField("output", 0),
                    IntField("dpkts", 1),
                    IntField("dOctets", 60),
                    IntField("first", 0),
                    IntField("last", 0),
                    ShortField("srcport", 0),
                    ShortField("dstport", 0),
                    ByteField("pad1", 0),
                    FlagsField("tcpFlags", 0x2, 8, "FSRPAUEC"),
                    ByteEnumField("prot", IP_PROTOS["tcp"], IP_PROTOS),
                    ByteField("tos",0),
                    ShortField("src_as", 0),
                    ShortField("dst_as", 0),
                    ByteField("src_mask", 0),
                    ByteField("dst_mask", 0),
                    ShortField("pad2", 0)]

bind_layers( NetflowHeader,   NetflowHeaderV5, version=5)
bind_layers( NetflowHeaderV5, NetflowRecordV5 )
bind_layers( NetflowRecordV5, NetflowRecordV5 )

#########################################
### Netflow Version 10
#########################################

class NetflowHeaderv10(Packet):
    name = "Netflow Header V10"
    fields_desc = [
                    ShortField("version", 10),
                    ShortField("length", 508),
                    IntField("ExportTime", 1380127358),
                    IntField("FlowSequence", 0),
                    IntField("ObservationDomainId", 256)
    ]


class Flow_Set_v10(Packet):
    name = "Netflow flow header"
    fields_desc = [ ShortField("FlowSet_id", 269),
                    ShortField("FlowSet_Length",392)
    ]


class FlowTemplate_ID_v10(Packet):
    name = "Netflow header template"
    fields_desc = [ ShortField("template_id", 269),
                    ShortField("count", 0)
    ]


class NetFlowTemplatev10Field(Packet):
    name = "Netflow Template v10 pen provided 0"
    fields_desc = [ BitField("Pen_provided", 0, 1),
                    BitFieldLenField("type", 0 , 15),
                    ShortField('length', 4)]


class NetFlowTemplatev10FieldPEN(Packet):
    name = "Netflow Template v10 pen provided 1"
    fields_desc = [ BitField("Pen_provided", 1, 1),
                    BitFieldLenField("type", 12235 ,15),
                    ShortField('length', 65535),
                    IntField("pen", 9)]



class Flow_v10(Packet):
    name = "Element flow (v10)"
    fields_desc = [
                    IPField("src", "127.0.0.1"),
                    IPField("dst", "127.0.0.1"),
                    ByteField("IPVersion", 4),
                    ByteField("prot", 6),
                    ShortField("srcport", 9090),
                    ShortField("dstport", 2284),
                    ByteField("FER", 3),
                    ByteField("biflow_direction",1),
                    ByteField("SamplerID", 0),
                    XIntField("EPE_A", 0x8f53b990),
                    XIntField("EPE_B", 0x00010000), # ERROROR: HEX ???
                    IntField('applicationID', 13),
                    ByteField('length1', 6),
                    X3BytesField("EPE1_A",0x03401),
                    X3BytesField("EPE1_B",0x03000),
                    ByteField('length2', 6),
                    X3BytesField("EPE2_A",0x03000),
                    X3BytesField("EPE2_B",0x03402),
                    ByteField('length3', 6),
                    X3BytesField("EPE3_A",0x03000),
                    X3BytesField("EPE3_B",0x03403),
                    ByteField('length4', 6),
                    X3BytesField("EPE4_A",0x03000),
                    X3BytesField("EPE4_B",0x03404),
                    BitFieldLenField("Octects", 40 , 64),
                    IntField("packets", 1),
                    IEEEFloatField("startTime", 2052594),
                    IEEEFloatField("EndTime", 2052594),
    ]


bind_layers( NetFlowTemplatev10Field,   NetFlowTemplatev10FieldPEN, version=5)
#bind_layers( NetflowHeaderV5, NetflowRecordV5 )
#bind_layers( NetflowRecordV5, NetflowRecordV5 )

#########################################
### Netflow Version 9
#########################################

class Netflow_Headerv9(Packet):
    name = "Netflow Header V9"
    fields_desc = [
                    ShortField("version", 10),
                    ShortField("count", 3),
                    IEEEFloatField("SysUptime", 27.027095000),
                    IntField("Timestamp",1392292623),
                    IntField("FlowSequence", 0),
                    IntField("SourceId", 243)
    ]

## FlowSet 1
class FlowSet_Header_v9(Packet): #FlowSet 1
    name = "Netflow flow header"
    fields_desc = [ ShortField("FlowSet_id", 0),
                    ShortField("FlowSet_length",156)
    ]

### Template (Id 258) (header de template)
class FlowTemplate_ID_v9(Packet):
    name = "Netflow header template"
    fields_desc = [ ShortField("template_id", 258),
                    ShortField("count", 18)
    ]

#### Field (1/18) Tipo de los templates
class NetFlowTemplatev9Field(Packet):
    name = "Netflow Template v9 pen provided 0"
    fields_desc = [ShortField("type_template", 0),
                   ShortField('length', 4),
    ]


class Flow_header_v9(Packet):
    name = "Netflow Template v9 pen provided 1"
    fields_desc = [ BitFieldLenField("type", 12235, 15),
                    ShortField('length', 65535),
    ]


## FlowSet_Header_v9 (Ya definido)


class Flow_v9(Packet):
    name = "Element flow (v9)"
    fields_desc = [IntField("Octets", 113162),
            IntField("Packets", 826),
            ByteField("Protocol", 17),
            XByteField("IP_ToS", 0x00),
            XByteField("TCP_Flags", 0x00),
            ShortField("SrcPort", 2416),
            ShortField("InputInt", 0),
            ShortField("DstPort", 53),
            ShortField("OutputInt", 0),
            IntField("SrcAS", 0),
            IntField("DstAS", 0),
            IEEEFloatField("StartTime", 0.002000000),
            IEEEFloatField("EndTime", 27.061000000),
            IP6Field("SrcAddr", "3ffe:507:0:1:200:86ff:fe05:80da"),
            IP6Field("DstAddr", "3ffe:501:4819::42"),
            ByteField("SrcMask", 0),
            ByteField("DstMask", 0),
            IP6Field("NextHop", "::"),
            BitFieldLenField("Padding", 0,24)
        ]


bind_layers( NetFlowTemplatev10Field,   NetFlowTemplatev10FieldPEN, version=5)
#bind_layers( NetflowHeaderV5, NetflowRecordV5 )
#bind_layers( NetflowRecordV5, NetflowRecordV5 )
