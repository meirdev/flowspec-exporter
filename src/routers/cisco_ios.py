from ipaddress import ip_network

from ntc_templates.parse import parse_output  # type: ignore

from ..consts import COMMANDS
from ..flowspec import Action, FlowSpec, Fragment, parse_value


def parse_flow_spec_cisco_ios(
    data: str, command: str = COMMANDS["cisco_ios"]
) -> list[FlowSpec]:
    entries = parse_output(platform="cisco_ios", command=command, data=data)

    flow_specs = []

    for entry in entries:
        flow_spec = FlowSpec()

        if entry["dest"]:
            flow_spec.dst_addr = ip_network(entry["dest"], strict=False)
        if entry["source"]:
            flow_spec.src_addr = ip_network(entry["source"], strict=False)
        if entry["proto"]:
            flow_spec.proto = parse_value(entry["proto"])
        if entry["dport"]:
            flow_spec.dst_port = parse_value(entry["dport"])
        if entry["sport"]:
            flow_spec.src_port = parse_value(entry["sport"])
        if entry["length"]:
            flow_spec.length = parse_value(entry["length"])
        if entry["tcp_flags"]:
            flow_spec.tcp_flags = int(entry["tcp_flags"][1:], 16)

        if entry["frag"]:
            match entry["frag"]:
                case "~DF":
                    flow_spec.fragment = Fragment.DONT_FRAGMENT
                case "~FF":
                    flow_spec.fragment = Fragment.FIRST_FRAGMENT
                case "~LF":
                    flow_spec.fragment = Fragment.LAST_FRAGMENT
                case "~IsF":
                    flow_spec.fragment = Fragment.IS_FRAGMENT

        match entry["action"]:
            case "transmit":
                flow_spec.action = Action.ACCEPT
            case "Traffic-rate":
                if entry["traffic_rate_bps"] == "0":
                    flow_spec.action = Action.DISCARD
                else:
                    flow_spec.action = Action.RATE_LIMIT
                    flow_spec.rate_limit_bps = int(entry["traffic_rate_bps"])
            case _:
                pass

        if entry["matched_packets"] != "":
            flow_spec.matched_packets = int(entry["matched_packets"])
        if entry["matched_bytes"] != "":
            flow_spec.matched_bytes = int(entry["matched_bytes"])

        if entry["transmitted_packets"] != "":
            flow_spec.transmitted_packets = int(entry["transmitted_packets"])
        if entry["transmitted_bytes"] != "":
            flow_spec.transmitted_bytes = int(entry["transmitted_bytes"])

        if entry["dropped_packets"] != "":
            flow_spec.dropped_packets = int(entry["dropped_packets"])
        if entry["dropped_bytes"] != "":
            flow_spec.dropped_bytes = int(entry["dropped_bytes"])

        flow_specs.append(flow_spec)

    return flow_specs
