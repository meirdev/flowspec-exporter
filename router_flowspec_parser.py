import itertools
import os
import re
from abc import ABC
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
from typing import Any, Literal

from ntc_templates.parse import parse_output  # type: ignore

DIR = Path(__file__).absolute().parent

os.environ["NTC_TEMPLATES_DIR"] = str(DIR / "templates")

COMMANDS = {
    "cisco_ios": "show flowspec vrf all ipv4 detail",
    "juniper_junos": "show firewall filter detail __flowspec_default_inet__",
    "arista_eos": "show flow-spec ipv4",
}


@dataclass
class Value(ABC):
    pass


@dataclass
class Eq(Value):
    value: int

    def __str__(self) -> str:
        return f"={self.value}"


@dataclass
class Between(Value):
    start: int
    end: int

    def __str__(self) -> str:
        return f">={self.start}&<={self.end}"


type Platform = Literal["cisco_ios", "juniper_junos", "arista_eos"]


class Action(StrEnum):
    ACCEPT = "accept"
    DISCARD = "discard"
    RATE_LIMIT = "rate-limit"


class Fragment(StrEnum):
    NOT_A_FRAGMENT = "not-a-fragment"
    DONT_FRAGMENT = "dont-fragment"
    IS_FRAGMENT = "is-fragment"
    FIRST_FRAGMENT = "first-fragment"
    LAST_FRAGMENT = "last-fragment"


@dataclass
class FlowSpec:
    dst_addr: IPv4Network | IPv6Network | None = None
    dst_port: list[Value] | None = None
    src_addr: IPv4Network | IPv6Network | None = None
    src_port: list[Value] | None = None
    proto: list[Value] | None = None
    tcp_flags: int | None = None
    fragment: Fragment | None = None
    length: list[Value] | None = None
    action: Action | None = None
    rate_limit_bps: int | None = None
    matched_packets: int | None = None
    matched_bytes: int | None = None
    transmitted_packets: int | None = None
    transmitted_bytes: int | None = None
    dropped_packets: int | None = None
    dropped_bytes: int | None = None

    def str_filter(self) -> str:
        return ",".join(
            f"{key}:{_stringify(getattr(self, attr))}"
            for (key, attr) in (
                ("dst", "dst_addr"),
                ("src", "src_addr"),
                ("dstport", "dst_port"),
                ("srcport", "src_port"),
                ("proto", "proto"),
                ("tcp-flags", "tcp_flags"),
                ("frag", "fragment"),
                ("len", "length"),
                ("action", "action"),
                ("rate-limit-bps", "rate_limit_bps"),
            )
            if getattr(self, attr) is not None
        )


def _parse_value(value: str) -> list[Value]:
    values: list[Value] = []

    for val in value.split(","):
        op: Value

        if match := re.match(r">=(\d+)&<=(\d+)", val):
            op = Between(int(match.group(1)), int(match.group(2)))
        elif match := re.match(r">(\d+)&<(\d+)", val):
            op = Between(int(match.group(1)) + 1, int(match.group(2)) - 1)
        elif match := re.match(r"=(\d+)", val):
            op = Eq(int(match.group(1)))
        else:
            raise ValueError(f"Invalid value: {val}")

        values.append(op)

    return values


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
            flow_spec.proto = _parse_value(entry["proto"])
        if entry["dport"]:
            flow_spec.dst_port = _parse_value(entry["dport"])
        if entry["sport"]:
            flow_spec.src_port = _parse_value(entry["sport"])
        if entry["length"]:
            flow_spec.length = _parse_value(entry["length"])
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

        flow_spec.matched_packets = int(entry["matched_packets"])
        flow_spec.matched_bytes = int(entry["matched_bytes"])
        flow_spec.transmitted_packets = int(entry["transmitted_packets"] or 0)
        flow_spec.transmitted_bytes = int(entry["transmitted_bytes"] or 0)
        flow_spec.dropped_packets = int(entry["dropped_packets"])
        flow_spec.dropped_bytes = int(entry["dropped_bytes"])

        flow_specs.append(flow_spec)

    return flow_specs


def _fix_ip_network(value: str) -> str:
    # Fixes the IP address format to ensure it has 4 octets
    if "/" in value:
        ip_addr, mask = value.split("/")
        ip_addr = ".".join(
            i
            for i, _ in itertools.zip_longest(
                ip_addr.split("."), ["0", "0", "0", "0"], fillvalue="0"
            )
        )
        return f"{ip_addr}/{mask}"
    return value


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
                flow_spec.dst_addr = ip_network(
                    _fix_ip_network(entry["dst"]), strict=False
                )
        if entry["src"] and entry["src"] != "*":
            with suppress(ValueError):
                flow_spec.src_addr = ip_network(
                    _fix_ip_network(entry["src"]), strict=False
                )
        if entry["proto"]:
            flow_spec.proto = _parse_value(entry["proto"])
        if entry["dstport"]:
            flow_spec.dst_port = _parse_value(entry["dstport"])
        if entry["srcport"]:
            flow_spec.src_port = _parse_value(entry["srcport"])
        if entry["len"]:
            flow_spec.length = _parse_value(entry["len"])
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
            flow_spec.proto = _parse_value(entry["ip"])
        if entry["dp"]:
            flow_spec.dst_port = _parse_value(entry["dp"])
        if entry["sp"]:
            flow_spec.src_port = _parse_value(entry["sp"])
        if entry["len"]:
            flow_spec.length = _parse_value(entry["len"])
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

        flow_spec.matched_packets = int(entry["packets"] or 0)
        flow_spec.matched_bytes = int(entry["bytes"] or 0)

        flow_specs.append(flow_spec)

    return flow_specs


def parse_flow_spec(platform: Platform, data: str, command: str) -> list[FlowSpec]:
    match platform:
        case "cisco_ios":
            return parse_flow_spec_cisco_ios(data, command)
        case "juniper_junos":
            return parse_flow_spec_juniper_junos(data, command)
        case "arista_eos":
            return parse_flow_spec_arista_eos(data, command)


def _stringify(value: Any) -> str:
    if isinstance(value, list):
        return "|".join(map(_stringify, value))
    return str(value)
