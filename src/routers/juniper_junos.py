import itertools
from contextlib import suppress
from ipaddress import ip_network

from netaddr import IPNetwork
from ntc_templates.parse import parse_output  # type: ignore

from ..consts import COMMANDS
from ..flowspec import Action, FlowSpec, Fragment, parse_value


def parse_flow_spec_juniper_junos(
    data: str, command: str = COMMANDS["juniper_junos"]
) -> list[FlowSpec]:
    entries = parse_output(
        platform="juniper_junos",
        command=command,
        data=data,
    )

    flow_specs = []

    for entry in entries:
        flow_spec = FlowSpec()

        if entry["dst"] and entry["dst"] != "*":
            with suppress(ValueError):
                flow_spec.dst_addr = ip_network(str(IPNetwork(entry["dst"], expand_partial=True)))
        if entry["src"] and entry["src"] != "*":
            with suppress(ValueError):
                flow_spec.src_addr = ip_network(str(IPNetwork(entry["src"], expand_partial=True)))
        if entry["proto"]:
            flow_spec.proto = parse_value(entry["proto"])
        if entry["dstport"]:
            flow_spec.dst_port = parse_value(entry["dstport"])
        if entry["srcport"]:
            flow_spec.src_port = parse_value(entry["srcport"])
        if entry["len"]:
            flow_spec.length = parse_value(entry["len"])
        if entry["tcp_flag"]:
            flow_spec.tcp_flags = int(entry["tcp_flag"], 16)

        if entry["frag"]:
            match entry["frag"]:
                case "01":
                    flow_spec.fragment = Fragment.DONT_FRAGMENT
                case "02":
                    flow_spec.fragment = Fragment.IS_FRAGMENT
                case "04":
                    flow_spec.fragment = Fragment.FIRST_FRAGMENT
                case "08":
                    flow_spec.fragment = Fragment.LAST_FRAGMENT
                case "10":
                    flow_spec.fragment = Fragment.NOT_A_FRAGMENT

        if entry["rate_limit"]:
            flow_spec.action = Action.RATE_LIMIT

            factor = entry["rate_limit"][-1].lower()

            match factor:
                case "k":
                    factor = 1_000
                case "m":
                    factor = 1_000_000
                case "g":
                    factor = 1_000_000_000
                case _:
                    raise ValueError(f"Invalid rate limit factor: {factor}")

            flow_spec.rate_limit_bps = int(entry["rate_limit"][:-1]) * factor

        flow_spec.matched_packets = int(entry["packets"])
        flow_spec.matched_bytes = int(entry["bytes"])

        flow_specs.append(flow_spec)

    return flow_specs
