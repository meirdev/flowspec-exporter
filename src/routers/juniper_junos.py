import re

from src.flowspec import (
    Action,
    BitmaskValues,
    FlowSpec,
)
from src.routers.common import parse_bitmask, parse_numeric_values, parse_prefix


def _parse_bitmask_values(value: str) -> BitmaskValues:
    if value.startswith("!"):
        not_ = True
        value = value[1:]
    else:
        not_ = False

    return parse_bitmask(value[1:], not_)


def _juniper_pattern() -> re.Pattern:
    prefix = r"(?P<{key}>[^\s,]+)"
    number = r"(?P<{key}>(,?(((=|>=|<=)\d+)&?))+)"
    bitmask = r"(?P<{key}>!?:\d+)"

    dst = prefix.format(key="dst")
    src = prefix.format(key="src")
    proto = number.format(key="proto")
    port = number.format(key="port")
    dstport = number.format(key="dstport")
    srcport = number.format(key="srcport")
    icmp_type = number.format(key="icmp_type")
    icmp_code = number.format(key="icmp_code")
    len = number.format(key="len")
    dscp = number.format(key="dscp")

    tcp_flag = bitmask.format(key="tcp_flag")
    frag = bitmask.format(key="frag")

    bytes = r"(?P<bytes>\d+)"
    packets = r"(?P<packets>\d+)"

    rate_limit = r"(?P<rate_limit>\d+(k|m|g))"

    return re.compile(
        rf"(?P<raw>({rate_limit}_)?{dst},{src}(,?(proto{proto}|port{port}|dstport{dstport}|srcport{srcport}|icmp-type{icmp_type}|icmp-code{icmp_code}|tcp-flag{tcp_flag}|len{len}|dscp{dscp}|frag{frag}))*.*?)\s+{bytes}\s+{packets}",
        re.MULTILINE | re.IGNORECASE,
    )


JUNIPER_PATTERN = _juniper_pattern()


def parse_flow_spec_juniper_junos(data: str) -> list[FlowSpec]:
    entries = JUNIPER_PATTERN.finditer(data)

    flow_specs: list[FlowSpec] = []

    for entry in entries:
        flow_spec = FlowSpec(raw=entry.group("raw"))

        if dst := entry.group("dst"):
            flow_spec.destination_prefix = parse_prefix(dst)
        if src := entry.group("src"):
            flow_spec.source_prefix = parse_prefix(src)
        if proto := entry.group("proto"):
            flow_spec.ip_protocol = parse_numeric_values(proto)
        if port := entry.group("port"):
            flow_spec.port = parse_numeric_values(port)
        if dstport := entry.group("dstport"):
            flow_spec.destination_port = parse_numeric_values(dstport)
        if srcport := entry.group("srcport"):
            flow_spec.source_port = parse_numeric_values(srcport)
        if icmp_type := entry["icmp_type"]:
            flow_spec.icmp_type = parse_numeric_values(icmp_type)
        if icmp_code := entry["icmp_code"]:
            flow_spec.icmp_code = parse_numeric_values(icmp_code)
        if tcp_flag := entry["tcp_flag"]:
            flow_spec.tcp_flags = _parse_bitmask_values(tcp_flag)
        if len := entry["len"]:
            flow_spec.packet_length = parse_numeric_values(len)
        if dscp := entry["dscp"]:
            flow_spec.dscp = parse_numeric_values(dscp)
        if frag := entry["frag"]:
            flow_spec.fragment = _parse_bitmask_values(frag)

        if rate_limit := entry.group("rate_limit"):
            flow_spec.action = Action.RATE_LIMIT

            factor = rate_limit[-1].lower()

            match factor:
                case "k":
                    factor = 1_000
                case "m":
                    factor = 1_000_000
                case "g":
                    factor = 1_000_000_000
                case _:
                    raise ValueError(f"Invalid rate limit factor: {factor}")

            flow_spec.rate_limit_bps = int(rate_limit[:-1]) * factor

            flow_spec.dropped_packets = int(entry.group("packets"))
            flow_spec.dropped_bytes = int(entry.group("bytes"))

            flow_spec.matched_packets = int(entry.group("packets"))
            flow_spec.matched_bytes = int(entry.group("bytes"))
        else:
            # There is no indication whether counters are dropped or transmitted,

            flow_spec.matched_packets = int(entry.group("packets"))
            flow_spec.matched_bytes = int(entry.group("bytes"))

        flow_specs.append(flow_spec)

    # Juniper returns counters and policers, the rate limit is the policer.
    # If the policer is present, the corresponding counter is the transmitted one (accept traffic)

    flow_specs_dict: dict[str, FlowSpec] = {}

    for flow_spec in flow_specs:
        flow_spec_key = flow_spec.str_filter()

        if flow_spec_item := flow_specs_dict.get(flow_spec_key):
            if flow_spec.action is Action.RATE_LIMIT:
                flow_spec.transmitted_bytes = flow_spec_item.matched_bytes
                flow_spec.transmitted_packets = flow_spec_item.matched_packets

                flow_spec.matched_bytes += flow_spec.transmitted_bytes  # type: ignore
                flow_spec.matched_packets += flow_spec.transmitted_packets  # type: ignore

        flow_specs_dict[flow_spec_key] = flow_spec

    return list(flow_specs_dict.values())
