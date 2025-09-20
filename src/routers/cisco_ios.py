import logging
import re
from typing import NotRequired, TypedDict, Unpack

from asyncssh import SSHClientConnection
from netaddr import IPNetwork

from src.flowspec import (
    Action,
    BitmaskOp,
    BitmaskValues,
    FlowSpec,
    NumericOp,
    NumericOpEq,
    NumericOpGt,
    NumericOpGte,
    NumericOpLt,
    NumericOpLte,
    NumericOpNe,
    NumericValues,
)

logger = logging.getLogger(__name__)


DEFAULT_VRF = "all"

COMMAND_SHOW_FLOWSPEC = "show flowspec vrf {vrf} ipv4 detail"

RE_FIND_FLOWS = re.compile(
    r"Flow\s*:\s*(?P<raw>[^\n\r]+)\s*"
    r"Actions\s*:\s*(?P<actions>[^\n\r]+)\s*"
    r"Statistics\s*\(packets/bytes\)\s*"
    r"Matched\s*:\s*(?P<matched_packets>\d+)/(?P<matched_bytes>\d+)\s*"
    r"(?:Transmitted\s*:\s*(?P<transmitted_packets>\d+)/(?P<transmitted_bytes>\d+)\s*)?"
    r"(?:Dropped\s*:\s*(?P<dropped_packets>\d+)/(?P<dropped_bytes>\d+)\s*)?"
)

RE_FIND_COMPONENTS = re.compile(
    r"(?P<key>Dest|Source|Proto|Port|DPort|SPort|Length|ICMPCode|ICMPType|TCPFlags|Frag):(?P<value>[^,\s]+)"
)

RE_FIND_NUMERIC_VALUES = re.compile(r"(?P<op>[><=!]+)(?P<val>\d+)(?P<and_or>[|&])?")

RE_FIND_BITMASK_VALUES = re.compile(
    r"(?P<not>!)?(?P<match>[=~])(?P<val>[^|&]+)(?P<and_or>[|&])?"
)

RE_MATCH_ACTION = re.compile(
    r"(?P<action>(?:Traffic-rate:\s*(?P<bps>\d+)\s*bps)|Redirect|transmit)"
)


def _parse_prefix(value: str) -> IPNetwork | None:
    return IPNetwork(value, expand_partial=True)


def _parse_numeric_values(value: str) -> NumericValues:
    values, set_and = NumericValues(), False

    for i in RE_FIND_NUMERIC_VALUES.finditer(value):
        numeric_op: NumericOp

        match i.group("op"):
            case ">=":
                numeric_op = NumericOpGte
            case "<=":
                numeric_op = NumericOpLte
            case "=":
                numeric_op = NumericOpEq
            case "!=":
                numeric_op = NumericOpNe
            case ">":
                numeric_op = NumericOpGt
            case "<":
                numeric_op = NumericOpLt
            case _:
                logger.error("Invalid operator: %s", i.group("op"))
                continue

        values.append((numeric_op.set_and(set_and), int(i.group("val"))))

        set_and = i.group("and_or") == "&"

    return values


def _parse_bitmask_values(value: str) -> BitmaskValues:
    values, set_and = BitmaskValues(), False

    for i in RE_FIND_BITMASK_VALUES.finditer(value):
        not_ = i.group("not") is not None
        match_ = i.group("match") == "="

        val: str = i.group("val")

        if val.startswith("0x"):
            value_int = int(val, 16)
        else:
            value_int = 0

            for v in val.split(":"):
                match v:
                    case "DF":
                        value_int |= 0x01
                    case "IsF":
                        value_int |= 0x02
                    case "FF":
                        value_int |= 0x04
                    case "LF":
                        value_int |= 0x08
                    case _:
                        logger.error("Unknown fragment type: %s", v)
                        continue

        values.append((BitmaskOp(not_=not_, match=match_).set_and(set_and), value_int))

        set_and = i.group("and_or") == "&"

    return values


def parse_output(data: str) -> list[FlowSpec]:
    flowspecs: list[FlowSpec] = []

    for match in RE_FIND_FLOWS.finditer(data):
        flowspec = FlowSpec()

        raw = match.group("raw").strip()

        flowspec.raw = raw

        logger.debug("Parsing flowspec: %s", raw)

        for key, value in RE_FIND_COMPONENTS.findall(raw):
            key: str
            value: str

            key, value = key.strip(), value.strip()

            match key:
                case "Dest":
                    flowspec.destination_prefix = _parse_prefix(value)
                case "Source":
                    flowspec.source_prefix = _parse_prefix(value)
                case "Proto":
                    flowspec.ip_protocol = _parse_numeric_values(value)
                case "Port":
                    flowspec.port = _parse_numeric_values(value)
                case "DPort":
                    flowspec.destination_port = _parse_numeric_values(value)
                case "SPort":
                    flowspec.source_port = _parse_numeric_values(value)
                case "Length":
                    flowspec.packet_length = _parse_numeric_values(value)
                case "ICMPCode":
                    flowspec.icmp_code = _parse_numeric_values(value)
                case "ICMPType":
                    flowspec.icmp_type = _parse_numeric_values(value)
                case "TCPFlags":
                    flowspec.tcp_flags = _parse_bitmask_values(value)
                case "Frag":
                    flowspec.fragment = _parse_bitmask_values(value)
                case _:
                    logger.error("Unknown key: %s", key)
                    continue

        flowspec.matched_bytes = int(match.group("matched_bytes"))
        flowspec.matched_packets = int(match.group("matched_packets"))

        if (transmitted_packets := match.group("transmitted_packets")) is not None:
            flowspec.transmitted_packets = int(transmitted_packets)
        if (transmitted_bytes := match.group("transmitted_bytes")) is not None:
            flowspec.transmitted_bytes = int(transmitted_bytes)

        if (dropped_packets := match.group("dropped_packets")) is not None:
            flowspec.dropped_packets = int(dropped_packets)
        if (dropped_bytes := match.group("dropped_bytes")) is not None:
            flowspec.dropped_bytes = int(dropped_bytes)

        actions = match.group("actions")

        if (actions_match := RE_MATCH_ACTION.search(actions)) is not None:
            action = actions_match.group("action").lower()

            if action.startswith("traffic-rate"):
                bps = int(actions_match.group("bps"))

                if bps == 0:
                    flowspec.action = Action.DISCARD
                else:
                    flowspec.action = Action.RATE_LIMIT
                    flowspec.rate_limit_bps = bps
            elif action == "redirect":
                flowspec.action = Action.REDIRECT
            elif action == "transmit":
                flowspec.action = Action.ACCEPT
            else:
                logger.error("Unknown action: %s", action)
                continue
        else:
            logger.error("Failed to parse action from: %s", actions)
            continue

        flowspecs.append(flowspec)

    return flowspecs


class FlowSpecCiscoIosKwargs(TypedDict):
    vrf: NotRequired[str]


async def parse_flow_spec_cisco_ios(
    connection: SSHClientConnection,
    **kwargs: Unpack[FlowSpecCiscoIosKwargs],
) -> list[FlowSpec]:
    vrf = kwargs.get("vrf", DEFAULT_VRF)

    command = COMMAND_SHOW_FLOWSPEC.format(vrf=vrf)

    logger.info("Sending command", extra={"command": command})
    result = await connection.run(command, check=True)

    output = str(result.stdout)
    logger.info("Command output", extra={"output": output})

    return parse_output(output)
