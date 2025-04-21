from ipaddress import IPv4Network

from src.flowspec import Action, Eq, FlowSpec, Fragment
from src.routers.cisco_ios import parse_flow_spec_cisco_ios

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
