from ipaddress import IPv4Network

from src.flowspec import Action, Between, Eq, FlowSpec
from src.routers.juniper_junos import parse_flow_spec_juniper_junos

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
        ),
        FlowSpec(
            dst_addr=IPv4Network("134.34.2.128/25", strict=False),
            proto=[Eq(17)],
            dst_port=[Between(1026, 65499)],
            src_port=[Between(1026, 65499)],
            matched_bytes=213018385651,
            matched_packets=204410643,
        ),
        FlowSpec(
            dst_addr=IPv4Network("11.194.71.7"),
            dst_port=[Eq(40), Eq(50), Eq(60), Between(70, 80)],
            matched_bytes=100568357,
            matched_packets=94618,
            action=Action.RATE_LIMIT,
            rate_limit_bps=6291000,
        ),
    ]
