from ipaddress import IPv4Network

from src.flowspec import Action, Eq, FlowSpec, Fragment
from src.routers.arista_eos import parse_flow_spec_arista_eos

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
            action=Action.DISCARD,
        )
    ]
