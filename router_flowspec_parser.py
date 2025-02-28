import os
import re
from abc import ABC
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
from typing import Literal, TypeAlias, Any

from ntc_templates.parse import parse_output  # type: ignore

DIR = Path(__file__).absolute().parent

os.environ["NTC_TEMPLATES_DIR"] = str(DIR / "templates")


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


Platform: TypeAlias = Literal["cisco_ios", "juniper_junos"]


class Action(StrEnum):
    ACCEPT = "accept"
    DISCARD = "discard"
    RATE_LIMIT = "rate-limit"


@dataclass
class FlowSpec:
    dst_addr: IPv4Network | IPv6Network | None = None
    dst_port: list[Value] | None = None
    src_addr: IPv4Network | IPv6Network | None = None
    src_port: list[Value] | None = None
    proto: list[Value] | None = None
    tcp_flags: int | None = None
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
            f"{attr}:{_stringify(getattr(self, attr))}"
            for attr in (
                "dst_addr",
                "src_addr",
                "dst_port",
                "src_port",
                "proto",
                "tcp_flags",
                "length",
                "action",
                "rate_limit_bps",
            )
            if getattr(self, attr) is not None
        )


def _parse_value(value: str) -> list[Value]:
    values = []

    for val in value.split(","):
        op: type[Value]

        if match := re.match(r">=(\d+)&<=(\d+)", val):
            op = Between
        elif match := re.match(r"=(\d+)", val):
            op = Eq
        else:
            raise ValueError(f"Invalid value: {val}")

        values.append(op(*map(int, match.groups())))

    return values


def parse_flow_spec_cisco_ios(data: str, command: str) -> list[FlowSpec]:
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
        flow_spec.transmitted_packets = int(entry["transmitted_packets"])
        flow_spec.transmitted_bytes = int(entry["transmitted_bytes"])
        flow_spec.dropped_packets = int(entry["dropped_packets"])
        flow_spec.dropped_bytes = int(entry["dropped_bytes"])

        flow_specs.append(flow_spec)

    return flow_specs


def parse_flow_spec_juniper_junos(data: str, command: str) -> list[FlowSpec]:
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
                flow_spec.dst_addr = ip_network(entry["dst"], strict=False)
        if entry["src"] and entry["src"] != "*":
            with suppress(ValueError):
                flow_spec.src_addr = ip_network(entry["src"], strict=False)
        if entry["proto"]:
            flow_spec.proto = _parse_value(entry["proto"])
        if entry["dstport"]:
            flow_spec.dst_port = _parse_value(entry["dstport"])
        if entry["srcport"]:
            flow_spec.src_port = _parse_value(entry["srcport"])
        if entry["len"]:
            flow_spec.length = _parse_value(entry["len"])
        if entry["tcp_flags"]:
            flow_spec.tcp_flags = int(entry["tcp_flags"], 16)

        if entry["rate_limit"]:
            flow_spec.action = Action.RATE_LIMIT
            flow_spec.rate_limit_bps = int(entry["rate_limit"][:-1]) * 1000
        else:
            flow_spec.action = Action.DISCARD

        flow_spec.matched_packets = int(entry["packets"])
        flow_spec.matched_bytes = int(entry["bytes"])
        flow_spec.dropped_packets = int(entry["packets"])
        flow_spec.dropped_bytes = int(entry["bytes"])

        flow_specs.append(flow_spec)

    return flow_specs


def parse_flow_spec(platform: Platform, data: str, command: str) -> list[FlowSpec]:
    match platform:
        case "cisco_ios":
            return parse_flow_spec_cisco_ios(data, command)
        case "juniper_junos":
            return parse_flow_spec_juniper_junos(data, command)
        case _:
            raise ValueError(f"Unsupported platform: {platform}")


def _stringify(value: Any) -> str:
    if isinstance(value, list):
        return "|".join(map(_stringify, value))
    return str(value)
