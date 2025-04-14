from ipaddress import IPv4Network

from router_flowspec_parser import (
    Action,
    Between,
    Eq,
    FlowSpec,
    Fragment,
    parse_flow_spec_arista_eos,
    parse_flow_spec_cisco_ios,
    parse_flow_spec_juniper_junos,
)

JUNIPER_JUNOS_STDOUT = """
Filter: __flowspec_default_inet__                              
Counters:
Name                                                                          Bytes              Packets
39.244.131.7,*,dstport=443,tcp-flag:18,len=180                                395784             6780
134.34.2.128/25,*,proto=17,dstport>=1026&<=65499,srcport>=1026&<=65499        213018385651       204410643
Policers:
Name                                                                           Bytes              Packets
6291K_11.194.71.7,*,dstport=40,=50,=60,>=70&<=80                               100568357          94618
"""

CISCO_IOS_STDOUT = """
Fri Feb 21 12:00:00.000 IST

AFI: IPv4
  Flow           :Dest:27.146.73.155/32,Proto:=6,DPort:=443,TCPFlags:~0x10,Length:=52,Frag:~IsF
    Actions      :Traffic-rate: 5242880 bps  (bgp.1)
    Statistics                        (packets/bytes)
      Matched             :                1376/63296              
      Transmitted         :                1376/63296              
      Dropped             :                   0/0      
  Flow           :Dest:238.39.240.142/32,DPort:=22
    Actions      :Traffic-rate: 0 bps  (bgp.1)
    Statistics                        (packets/bytes)
      Matched             :                   1/64                 
      Transmitted         :                   0/0                  
      Dropped             :                   1/64                 
  Flow           :Dest:210.255.11.198/32,Source:161.221.128.55/32,Proto:=6,DPort:=20174,SPort:=443,TCPFlags:~0x18
    Actions      :transmit  (bgp.1)
    Statistics                        (packets/bytes)
      Matched             :                  21/1968               
      Transmitted         :                  21/1968               
      Dropped             :                   0/0                  
"""

ARISTA_EOS_STDOUT = """
Flow specification rules for VRF default
Configured on: Ethernet1, Ethernet2
Applied on: Ethernet1, Ethernet2
  Flow-spec rule: 52.34.134.250/32;*;IP:=17;DP:=743;FRAG:2;
    Rule identifier: 140278744221840
    Matches:
      Destination prefix: 52.34.134.250/32
      Next protocol: 17
      Destination port: 743
      Fragment flags: is-fragment:1
    Actions:
      Drop
    Status:
      Installed: yes
      Counter: 100 packets, 230 bytes
"""


def test_parse_flow_spec_juniper_junos():
    entries = parse_flow_spec_juniper_junos(
        JUNIPER_JUNOS_STDOUT, "show firewall filter detail __flowspec_default_inet__"
    )

    assert entries == [
        FlowSpec(
            dst_addr=IPv4Network("39.244.131.7"),
            dst_port=[Eq(443)],
            tcp_flags=0x18,
            length=[Eq(180)],
            matched_bytes=395784,
            matched_packets=6780,
            dropped_bytes=395784,
            dropped_packets=6780,
            action=Action.DISCARD,
        ),
        FlowSpec(
            dst_addr=IPv4Network("134.34.2.128/25", strict=False),
            proto=[Eq(17)],
            dst_port=[Between(1026, 65499)],
            src_port=[Between(1026, 65499)],
            matched_bytes=213018385651,
            matched_packets=204410643,
            dropped_bytes=213018385651,
            dropped_packets=204410643,
            action=Action.DISCARD,
        ),
        FlowSpec(
            dst_addr=IPv4Network("11.194.71.7"),
            dst_port=[Eq(40), Eq(50), Eq(60), Between(70, 80)],
            matched_bytes=100568357,
            matched_packets=94618,
            dropped_bytes=100568357,
            dropped_packets=94618,
            action=Action.RATE_LIMIT,
            rate_limit_bps=6291000,
        ),
    ]


def test_parse_flow_spec_cisco_ios():
    entries = parse_flow_spec_cisco_ios(
        CISCO_IOS_STDOUT, "show flowspec vrf all ipv4 detail"
    )

    assert entries == [
        FlowSpec(
            dst_addr=IPv4Network("27.146.73.155/32"),
            proto=[Eq(6)],
            dst_port=[Eq(443)],
            tcp_flags=0x10,
            fragment=Fragment.IS_FRAGMENT,
            length=[Eq(52)],
            matched_bytes=63296,
            matched_packets=1376,
            transmitted_bytes=63296,
            transmitted_packets=1376,
            dropped_bytes=0,
            dropped_packets=0,
            action=Action.RATE_LIMIT,
            rate_limit_bps=5242880,
        ),
        FlowSpec(
            dst_addr=IPv4Network("238.39.240.142/32"),
            dst_port=[Eq(22)],
            matched_bytes=64,
            matched_packets=1,
            transmitted_bytes=0,
            transmitted_packets=0,
            dropped_bytes=64,
            dropped_packets=1,
            action=Action.DISCARD,
        ),
        FlowSpec(
            dst_addr=IPv4Network("210.255.11.198/32"),
            src_addr=IPv4Network("161.221.128.55/32"),
            proto=[Eq(6)],
            dst_port=[Eq(20174)],
            src_port=[Eq(443)],
            tcp_flags=0x18,
            matched_bytes=1968,
            matched_packets=21,
            transmitted_bytes=1968,
            transmitted_packets=21,
            dropped_bytes=0,
            dropped_packets=0,
            action=Action.ACCEPT,
        ),
    ]


def test_parse_flow_spec_arista_eos():
    entries = parse_flow_spec_arista_eos(ARISTA_EOS_STDOUT, "show flow-spec ipv4")

    assert entries == [
        FlowSpec(
            dst_addr=IPv4Network("52.34.134.250/32"),
            proto=[Eq(17)],
            dst_port=[Eq(743)],
            fragment=Fragment.IS_FRAGMENT,
            matched_bytes=230,
            matched_packets=100,
            dropped_bytes=230,
            dropped_packets=100,
            action=Action.DISCARD,
        )
    ]
