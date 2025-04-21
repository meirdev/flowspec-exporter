from contextlib import suppress
from ipaddress import ip_network

from ntc_templates.parse import parse_output  # type: ignore

from ..consts import COMMANDS
from ..flowspec import Action, FlowSpec, Fragment, parse_value


def parse_flow_spec_arista_eos(
    data: str, command: str = COMMANDS["arista_eos"]
) -> list[FlowSpec]:
    entries = parse_output(
        platform="arista_eos",
        command=command,
        data=data,
    )

    flow_specs = []

    for entry in entries:
        flow_spec = FlowSpec()

        if entry["dest"] and entry["dest"] != "*":
            with suppress(ValueError):
                flow_spec.dst_addr = ip_network(entry["dest"], strict=False)
        if entry["source"] and entry["source"] != "*":
            with suppress(ValueError):
                flow_spec.src_addr = ip_network(entry["source"], strict=False)
        if entry["ip"]:
            flow_spec.proto = parse_value(entry["ip"])
        if entry["dp"]:
            flow_spec.dst_port = parse_value(entry["dp"])
        if entry["sp"]:
            flow_spec.src_port = parse_value(entry["sp"])
        if entry["len"]:
            flow_spec.length = parse_value(entry["len"])
        if entry["tcp"]:
            flow_spec.tcp_flags = int(entry["tcp"])

        if entry["frag"]:
            match entry["frag"]:
                case "0":
                    flow_spec.fragment = Fragment.NOT_A_FRAGMENT
                case "1":
                    flow_spec.fragment = Fragment.DONT_FRAGMENT
                case "2":
                    flow_spec.fragment = Fragment.IS_FRAGMENT
                case "4":
                    flow_spec.fragment = Fragment.FIRST_FRAGMENT
                case "8":
                    flow_spec.fragment = Fragment.LAST_FRAGMENT

        if entry["rate_limit"]:
            flow_spec.action = Action.RATE_LIMIT

            number, size = entry["rate_limit"].split(" ")

            match size:
                case "bps":
                    size = 1
                case "Kbps":
                    size = 1_000
                case "Mbps":
                    size = 1_000_000
                case "Gbps":
                    size = 1_000_000_000
                case _:
                    raise ValueError(f"Invalid rate limit size: {size}")

            flow_spec.rate_limit_bps = int(round(float(number) * size))
        else:
            flow_spec.action = Action.DISCARD

        if entry["packets"] != "":
            flow_spec.matched_packets = int(entry["packets"])

        if entry["bytes"] != "":
            flow_spec.matched_bytes = int(entry["bytes"])

        flow_specs.append(flow_spec)

    return flow_specs
