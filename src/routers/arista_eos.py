import re

from src.flowspec import (
    Action,
    FlowSpec,
)
from src.routers.common import parse_bitmask, parse_numeric_values, parse_prefix


def _arista_pattern() -> re.Pattern:
    prefix = r"(?P<{key}>[^;]+)"
    number = r"(?P<{key}>((,?(((=|>|<)\d+)&?))+))"

    dest = prefix.format(key="dest")
    source = prefix.format(key="source")

    ip = number.format(key="ip")
    dp = number.format(key="dp")
    sp = number.format(key="sp")
    len = number.format(key="len")

    tcp = r"(?P<tcp>\d+)"
    frag = r"(?P<frag>\d+)"

    action = r"(?P<action>Drop)"
    rate_limit = r"(?P<rate_limit>\d+(\.\d+) (K|M|G)?bps)"

    packets = r"(?P<packets>\d+)"
    bytes = r"(?P<bytes>\d+)"

    return re.compile(
        rf"Flow-spec rule:\s*(?P<raw>{dest};{source};((IP:{ip}|DP:{dp}|SP:{sp}|LEN:{len}|TCP:{tcp}|FRAG:{frag});)+).*?"
        + rf"({action}|(Police:\s*({rate_limit}))).*?"
        + rf"Counter:\s*{packets}\s+packets,\s*{bytes}\s+bytes",
        re.DOTALL | re.MULTILINE | re.IGNORECASE,
    )


ARISTA_PATTERN = _arista_pattern()


def parse_flow_spec_arista_eos(data: str) -> list[FlowSpec]:
    entries = ARISTA_PATTERN.finditer(data)

    flow_specs: list[FlowSpec] = []

    for entry in entries:
        flow_spec = FlowSpec(raw=entry.group("raw"))

        if dest := entry.group("dest"):
            flow_spec.destination_prefix = parse_prefix(dest)
        if source := entry.group("source"):
            flow_spec.source_prefix = parse_prefix(source)
        if ip := entry.group("ip"):
            flow_spec.ip_protocol = parse_numeric_values(ip)
        if dp := entry.group("dp"):
            flow_spec.destination_port = parse_numeric_values(dp)
        if sp := entry.group("sp"):
            flow_spec.source_port = parse_numeric_values(sp)
        if len := entry.group("len"):
            flow_spec.packet_length = parse_numeric_values(len)
        if tcp := entry.group("tcp"):
            flow_spec.tcp_flags = parse_bitmask(tcp)
        if frag := entry.group("frag"):
            flow_spec.fragment = parse_bitmask(frag)

        if rate_limit := entry.group("rate_limit"):
            flow_spec.action = Action.RATE_LIMIT

            number, size = rate_limit.split(" ")

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

        if (packets := entry.group("packets")) is not None:
            flow_spec.matched_packets = int(packets)

        if (bytes := entry.group("bytes")) is not None:
            flow_spec.matched_bytes = int(bytes)

        flow_specs.append(flow_spec)

    return flow_specs
