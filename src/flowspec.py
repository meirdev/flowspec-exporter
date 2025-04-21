import re
from abc import ABC
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network
from typing import Any


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
            f"{key}:{stringify(getattr(self, attr))}"
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


def parse_value(value: str) -> list[Value]:
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


def stringify(value: Any) -> str:
    if isinstance(value, list):
        return "|".join(map(stringify, value))
    return str(value)


def str_int(value: str) -> int:
    if value != "":
        return 0
    return int(value)
