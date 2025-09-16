import re

from src.flowspec import (
    Action,
    BitmaskValues,
    FlowSpec,
)
from src.routers.common import parse_bitmask, parse_numeric_values, parse_prefix


def _parse_frag(value: str) -> BitmaskValues:
    match value:
        case "~DF":
            v = 0x01
        case "~IsF":
            v = 0x02
        case "~FF":
            v = 0x04
        case "~LF":
            v = 0x08
        case _:
            raise ValueError(f"Invalid fragment value: {value}")

    return parse_bitmask(str(v))


def _cisco_pattern() -> re.Pattern:
    prefix = r"(?P<{key}>[^\s,]+)"
    number = r"(?P<{key}>(,?(((=|>=|<=)\d+)&?))+)"

    dest = prefix.format(key="dest")
    source = prefix.format(key="source")
    proto = number.format(key="proto")
    dport = number.format(key="dport")
    sport = number.format(key="sport")
    length = number.format(key="length")
    tcp_flags = r"(?P<tcp_flags>~0x[0-9a-f]+)"
    frag = r"(?P<frag>~[a-zA-Z]+)"

    action = r"(?P<action>Traffic-rate|Redirect|transmit)"
    traffic_rate_bps = r"(?P<traffic_rate_bps>\d+)"

    matched_packets = r"(?P<matched_packets>\d+)"
    matched_bytes = r"(?P<matched_bytes>\d+)"
    transmitted_packets = r"(?P<transmitted_packets>\d+)"
    transmitted_bytes = r"(?P<transmitted_bytes>\d+)"
    dropped_packets = r"(?P<dropped_packets>\d+)"
    dropped_bytes = r"(?P<dropped_bytes>\d+)"

    return re.compile(
        rf"Flow\s*:(?P<raw>((Dest:{dest}|Source:{source}|Proto:{proto}|DPort:{dport}|SPort:{sport}|Length:{length}|TCPFlags:{tcp_flags}|Frag:{frag}),?)+).*?"
        + rf"Actions\s*:{action}(:\s*{traffic_rate_bps} bps)?.*?"
        + rf"Matched\s*:\s*{matched_packets}/{matched_bytes}[^\w]*"
        + rf"(Transmitted\s*:\s*{transmitted_packets}/{transmitted_bytes}[^\w]*)?"
        + rf"(Dropped\s*:\s*{dropped_packets}/{dropped_bytes})?",
        re.DOTALL | re.MULTILINE | re.IGNORECASE,
    )


CISCO_PATTERN = _cisco_pattern()


def parse_flow_spec_cisco_ios(data: str) -> list[FlowSpec]:
    entries = CISCO_PATTERN.finditer(data)

    flow_specs: list[FlowSpec] = []

    for entry in entries:
        flow_spec = FlowSpec(raw=entry.group("raw"))

        if dest := entry.group("dest"):
            flow_spec.destination_prefix = parse_prefix(dest)
        if source := entry.group("source"):
            flow_spec.source_prefix = parse_prefix(source)
        if proto := entry.group("proto"):
            flow_spec.ip_protocol = parse_numeric_values(proto)
        if dport := entry.group("dport"):
            flow_spec.destination_port = parse_numeric_values(dport)
        if sport := entry.group("sport"):
            flow_spec.source_port = parse_numeric_values(sport)
        if length := entry.group("length"):
            flow_spec.packet_length = parse_numeric_values(length)
        if tcp_flags := entry.group("tcp_flags"):
            flow_spec.tcp_flags = parse_bitmask(tcp_flags[1:])
        if frag := entry.group("frag"):
            flow_spec.fragment = _parse_frag(frag)

        match entry.group("action"):
            case "transmit":
                flow_spec.action = Action.ACCEPT
            case "Traffic-rate":
                if entry["traffic_rate_bps"] == "0":
                    flow_spec.action = Action.DISCARD
                else:
                    flow_spec.action = Action.RATE_LIMIT
                    flow_spec.rate_limit_bps = int(entry.group("traffic_rate_bps"))
            case _:
                pass

        if matched_packets := entry.group("matched_packets"):
            flow_spec.matched_packets = int(matched_packets)
        if matched_bytes := entry.group("matched_bytes"):
            flow_spec.matched_bytes = int(matched_bytes)

        if (transmitted_packets := entry.group("transmitted_packets")) is not None:
            flow_spec.transmitted_packets = int(transmitted_packets)
        if (transmitted_bytes := entry.group("transmitted_bytes")) is not None:
            flow_spec.transmitted_bytes = int(transmitted_bytes)

        if (dropped_packets := entry.group("dropped_packets")) is not None:
            flow_spec.dropped_packets = int(dropped_packets)
        if (dropped_bytes := entry.group("dropped_bytes")) is not None:
            flow_spec.dropped_bytes = int(dropped_bytes)

        flow_specs.append(flow_spec)

    return flow_specs
