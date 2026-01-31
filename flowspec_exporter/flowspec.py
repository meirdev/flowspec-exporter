import itertools
import math
from collections import UserList
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import NamedTuple, Self

from dataclasses_json import config, dataclass_json
from netaddr import IPNetwork

COMPONENTS = (
    "destination_prefix",
    "source_prefix",
    "ip_protocol",
    "port",
    "destination_port",
    "source_port",
    "icmp_type",
    "icmp_code",
    "tcp_flags",
    "packet_length",
    "dscp",
    "fragment",
)


class Action(StrEnum):
    ACCEPT = "accept"
    DISCARD = "discard"
    RATE_LIMIT = "rate-limit"
    REDIRECT = "redirect"


class ComponentType(IntEnum):
    DESTINATION_PREFIX = 1
    SOURCE_PREFIX = 2
    IP_PROTOCOL = 3
    PORT = 4
    DESTINATION_PORT = 5
    SOURCE_PORT = 6
    ICMP_TYPE = 7
    ICMP_CODE = 8
    TCP_FLAGS = 9
    PACKET_LENGTH = 10
    DSCP = 11
    FRAGMENT = 12

    @classmethod
    def from_str(cls, value: str) -> "ComponentType":
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"Invalid command type: {value}")

    def __str__(self) -> str:
        match self:
            case ComponentType.DESTINATION_PREFIX:
                return "destination-prefix"
            case ComponentType.SOURCE_PREFIX:
                return "source-prefix"
            case ComponentType.IP_PROTOCOL:
                return "ip-protocol"
            case ComponentType.PORT:
                return "port"
            case ComponentType.DESTINATION_PORT:
                return "destination-port"
            case ComponentType.SOURCE_PORT:
                return "source-port"
            case ComponentType.ICMP_TYPE:
                return "icmp-type"
            case ComponentType.ICMP_CODE:
                return "icmp-code"
            case ComponentType.TCP_FLAGS:
                return "tcp-flags"
            case ComponentType.PACKET_LENGTH:
                return "packet-length"
            case ComponentType.DSCP:
                return "dscp"
            case ComponentType.FRAGMENT:
                return "fragment"


@dataclass_json
@dataclass(eq=True)
class NumericOp:
    and_: bool = False
    lt: bool = False
    gt: bool = False
    eq: bool = False

    def set_and(self, value: bool) -> Self:
        self.and_ = value

        return self

    def __str__(self) -> str:
        s = ""

        match (self.lt, self.gt, self.eq):
            case (False, False, False):
                s = "false"
            case (False, False, True):
                s = "="
            case (False, True, False):
                s = ">"
            case (False, True, True):
                s = ">="
            case (True, False, False):
                s = "<"
            case (True, False, True):
                s = "<="
            case (True, True, False):
                s = "!="
            case (True, True, True):
                s = "true"

        return s


NumericOpFalse = NumericOp()

NumericOpEq = NumericOp(eq=True)

NumericOpGt = NumericOp(gt=True)

NumericOpGte = NumericOp(gt=True, eq=True)

NumericOpLt = NumericOp(lt=True)

NumericOpLte = NumericOp(lt=True, eq=True)

NumericOpNe = NumericOp(gt=True, lt=True)

NumericOpTrue = NumericOp(lt=True, gt=True, eq=True)


@dataclass_json
@dataclass(eq=True)
class BitmaskOp:
    and_: bool = False
    not_: bool = False
    match: bool = False

    def set_and(self, value: bool) -> Self:
        self.and_ = value

        return self

    def __str__(self) -> str:
        s = ""

        if self.not_:
            s += "!"

        if self.match:
            s += "="

        return s


class NumericValues(UserList[tuple[NumericOp, int]]):
    def __init__(self, *args: tuple[NumericOp, int]):
        super().__init__(args)

    def __str__(self) -> str:
        s = []

        for op, value in self.data:
            if op.and_:
                s += ["&", f"{op}{value}"]
            else:
                s += [" ", f"{op}{value}"]

        return "".join(s).strip()

    def __bytes__(self) -> bytes:
        result = bytearray()

        for i, (op, value) in enumerate(self.data):
            is_last = i == len(self.data) - 1
            size = _get_bytes_size(value)

            op_byte = 0

            if is_last:
                op_byte |= 0b10000000
            if op.and_:
                op_byte |= 0b01000000

            if size == 1:
                op_byte |= 0b00000000
            elif size == 2:
                op_byte |= 0b00010000
            elif size == 4:
                op_byte |= 0b00100000
            elif size == 8:
                op_byte |= 0b00110000

            if op.lt:
                op_byte |= 0b00000100
            if op.gt:
                op_byte |= 0b00000010
            if op.eq:
                op_byte |= 0b00000001

            result.extend(op_byte.to_bytes(1))
            result.extend(value.to_bytes(size))

        return bytes(result)


class BitmaskValues(UserList[tuple[BitmaskOp, int]]):
    def __init__(self, *args: tuple[BitmaskOp, int]):
        super().__init__(args)

    def __str__(self) -> str:
        s = []

        for op, value in self.data:
            if op.and_:
                s += ["&", f"{op}0x{value:02x}"]
            else:
                s += [" ", f"{op}0x{value:02x}"]

        return "".join(s).strip()

    def __bytes__(self) -> bytes:
        result = bytearray()

        for i, (op, value) in enumerate(self.data):
            is_last = i == len(self.data) - 1
            size = _get_bytes_size(value)

            op_byte = 0

            if is_last:
                op_byte |= 0b10000000
            if op.and_:
                op_byte |= 0b01000000

            if size == 1:
                op_byte |= 0b00000000
            elif size == 2:
                op_byte |= 0b00010000
            elif size == 4:
                op_byte |= 0b00100000
            elif size == 8:
                op_byte |= 0b00110000

            if op.not_:
                op_byte |= 0b00000010
            if op.match:
                op_byte |= 0b00000001

            result.extend(op_byte.to_bytes(1))
            result.extend(value.to_bytes(size))

        return bytes(result)


def _str_encode(obj: object) -> str | None:
    if obj is None:
        return None
    return str(obj)


def _get_bytes_size(n: int) -> int:
    bits = n.bit_length()
    if bits <= 8:
        return 1
    if bits <= 16:
        return 2
    if bits <= 32:
        return 4
    return 8


def ipnetwork_to_bytes(net: IPNetwork) -> bytes:
    result = bytearray()

    result.extend(net.prefixlen.to_bytes())
    result.extend(net.ip.packed[: math.ceil(net.prefixlen / 8)])

    return bytes(result)


class NLRIComponent(NamedTuple):
    component_type: ComponentType
    op_value: bytes | IPNetwork


class NLRI(UserList[NLRIComponent]):
    def __lt__(self, other):
        for comp_a, comp_b in itertools.zip_longest(self, other):
            if not comp_a:
                return True
            if not comp_b:
                return False

            comp_a: NLRIComponent
            comp_b: NLRIComponent

            if comp_a.component_type < comp_b.component_type:
                return False
            if comp_a.component_type > comp_b.component_type:
                return True

            if comp_a.component_type in (
                ComponentType.DESTINATION_PREFIX,
                ComponentType.SOURCE_PREFIX,
            ):
                assert isinstance(comp_a.op_value, IPNetwork)

                if (
                    comp_a.op_value in comp_b.op_value
                    or comp_b.op_value in comp_a.op_value
                ):
                    if comp_a.op_value.prefixlen > comp_b.op_value.prefixlen:
                        return False
                    if comp_a.op_value.prefixlen < comp_b.op_value.prefixlen:
                        return True
                elif comp_a.op_value > comp_b.op_value:
                    return True
                elif comp_a.op_value < comp_b.op_value:
                    return False
            else:
                if len(comp_a.op_value) == len(comp_b.op_value):
                    if comp_a.op_value > comp_b.op_value:
                        return True
                    if comp_a.op_value < comp_b.op_value:
                        return False
                else:
                    common = min(len(comp_a.op_value), len(comp_b.op_value))
                    if comp_a.op_value[:common] > comp_b.op_value[:common]:
                        return True
                    elif comp_a.op_value[:common] < comp_b.op_value[:common]:
                        return False
                    elif len(comp_a.op_value) > len(comp_b.op_value):
                        return False
                    else:
                        return True
        return False


@dataclass_json
@dataclass
class FlowSpec:
    raw: str = ""
    destination_prefix: IPNetwork | None = field(
        default=None, metadata=config(encoder=_str_encode)
    )
    source_prefix: IPNetwork | None = field(
        default=None, metadata=config(encoder=_str_encode)
    )
    ip_protocol: NumericValues | None = None
    port: NumericValues | None = None
    destination_port: NumericValues | None = None
    source_port: NumericValues | None = None
    icmp_type: NumericValues | None = None
    icmp_code: NumericValues | None = None
    tcp_flags: BitmaskValues | None = None
    packet_length: NumericValues | None = None
    dscp: NumericValues | None = None
    fragment: BitmaskValues | None = None
    action: Action | None = None
    rate_limit_bps: int | None = None
    matched_packets: int | None = None
    matched_bytes: int | None = None
    transmitted_packets: int | None = None
    transmitted_bytes: int | None = None
    dropped_packets: int | None = None
    dropped_bytes: int | None = None

    metadata: dict[str, str] = field(default_factory=dict)

    filter: str | None = None

    def str_filter(self) -> str:
        s = []

        for key in COMPONENTS:
            value = getattr(self, key)

            if value is not None:
                s.append(f"{ComponentType.from_str(key)}: {value}")

        return ", ".join(s)

    def to_nlri(self) -> NLRI:
        nlri = NLRI()

        for key in COMPONENTS:
            value = getattr(self, key)

            if value is not None:
                component_type = ComponentType.from_str(key)

                if isinstance(value, IPNetwork):
                    data = value.cidr
                elif isinstance(value, (BitmaskValues, NumericValues)):
                    data = bytes(value)

                nlri.append(NLRIComponent(component_type, data))

        return nlri


@dataclass_json
@dataclass
class FlowSpecs:
    flows: list[FlowSpec]


__all__ = [
    "Action",
    "ComponentType",
    "NumericOp",
    "NumericOpFalse",
    "NumericOpEq",
    "NumericOpGt",
    "NumericOpGte",
    "NumericOpLt",
    "NumericOpLte",
    "NumericOpNe",
    "NumericOpTrue",
    "BitmaskOp",
    "NumericValues",
    "BitmaskValues",
    "FlowSpec",
]
