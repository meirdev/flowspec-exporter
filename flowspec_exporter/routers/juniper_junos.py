import logging
import re
from typing import NotRequired, TypedDict, Unpack

from asyncssh import SSHClientConnection
from netaddr import IPNetwork

from flowspec_exporter.flowspec import (
    Action,
    BitmaskOp,
    BitmaskValues,
    FlowSpec,
    NumericOp,
    NumericOpEq,
    NumericOpGte,
    NumericOpLte,
    NumericValues,
)

logger = logging.getLogger(__name__)


DEFAULT_FILTER_NAME = "__flowspec_default_inet__"

COMMAND_SHOW_FIREWALL_FILTER = "show firewall filter detail {filter_name}"

RE_FIND_COUNTERS_AND_POLICERS = re.compile(
    r"^(?P<raw>[^\s]+)\s+(?P<bytes>\d+)\s+(?P<packets>\d+)$", re.MULTILINE
)

# Juniper has overflow issues with rate limit: -589934592K !
RE_FIND_RATE_LIMIT_DST_SRC = re.compile(
    r"(?:(?P<rate_limit>-?\d+)(?P<rate_limit_factor>K|M|G)_)?(?P<dst>[^,]+),(?P<src>[^,]+)"
)

RE_FIND_COMPONENTS = re.compile(
    r"(?P<key>proto|port|dstport|srcport|icmp-type|icmp-code|tcp-flag|len|dscp|frag)(?P<value>[^a-z]+)"
)

RE_FIND_NUMERIC_VALUES = re.compile(r"(?P<op>[><=]+)(?P<val>\d+)(?P<and_or>[,&])?")

RE_FIND_BITMASK_VALUES = re.compile(
    r"(?P<not>!)?(?P<match>[:=])(?P<val>\d+)(?P<and_or>[,&])?"
)


def _parse_prefix(value: str) -> IPNetwork | None:
    if value == "*":
        return None

    return IPNetwork(value, expand_partial=True)


def _parse_numeric_values(value: str) -> NumericValues:
    values, set_and = NumericValues(), False

    for i in RE_FIND_NUMERIC_VALUES.finditer(value):
        numeric_op: NumericOp

        # Juniper doesn't use '>', '<' and '!=' in the output! it converts them to '>=' and '<='.
        # Example: 'port>100' becomes 'port>=101&<=65535', 'port!=100' becomes 'port>=0&<=99'.

        match i.group("op"):
            case ">=":
                numeric_op = NumericOpGte
            case "<=":
                numeric_op = NumericOpLte
            case "=":
                numeric_op = NumericOpEq
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
        value_int = int(val, 16)

        values.append((BitmaskOp(not_=not_, match=match_).set_and(set_and), value_int))

        set_and = i.group("and_or") == "&"

    return values


def parse_flows(output: str) -> list[FlowSpec]:
    flowspecs: list[FlowSpec] = []

    for raw, bytes, packets in RE_FIND_COUNTERS_AND_POLICERS.findall(output):
        logger.debug(
            "Parsing flowspec: %s, bytes: %s, packets: %s", raw, bytes, packets
        )

        flowspec = FlowSpec()

        flowspec.raw = raw

        flowspec.matched_bytes = int(bytes)
        flowspec.matched_packets = int(packets)

        match = RE_FIND_RATE_LIMIT_DST_SRC.match(raw)
        if not match:
            logger.error("Failed to parse rate limit, dst, src from: %s", raw)
            continue

        flowspec.destination_prefix = _parse_prefix(match.group("dst"))
        flowspec.source_prefix = _parse_prefix(match.group("src"))

        rate_limit, rate_limit_factor = (
            match.group("rate_limit"),
            match.group("rate_limit_factor"),
        )
        if rate_limit and rate_limit_factor:
            rate_limit: str
            rate_limit_factor: str

            flowspec.action = Action.RATE_LIMIT

            match rate_limit_factor:
                case "K":
                    factor = 1_000
                case "M":
                    factor = 1_000_000
                case "G":
                    factor = 1_000_000_000
                case _:
                    logger.error("Invalid rate limit factor: %s", rate_limit_factor)
                    continue

            flowspec.rate_limit_bps = int(rate_limit) * factor

            flowspec.dropped_bytes = flowspec.matched_bytes
            flowspec.dropped_packets = flowspec.matched_packets

        for key, value in RE_FIND_COMPONENTS.findall(raw):
            key: str
            value: str

            key, value = key, value.strip(",")  # Remove trailing comma from value

            match key:
                case "proto":
                    flowspec.ip_protocol = _parse_numeric_values(value)
                case "port":
                    flowspec.port = _parse_numeric_values(value)
                case "dstport":
                    flowspec.destination_port = _parse_numeric_values(value)
                case "srcport":
                    flowspec.source_port = _parse_numeric_values(value)
                case "icmp-type":
                    flowspec.icmp_type = _parse_numeric_values(value)
                case "icmp-code":
                    flowspec.icmp_code = _parse_numeric_values(value)
                case "tcp-flag":
                    flowspec.tcp_flags = _parse_bitmask_values(value)
                case "len":
                    flowspec.packet_length = _parse_numeric_values(value)
                case "dscp":
                    flowspec.dscp = _parse_numeric_values(value)
                case "frag":
                    flowspec.fragment = _parse_bitmask_values(value)

        flowspecs.append(flowspec)

    # Juniper returns counters and policers, the rate limit is the policer.
    # If the policer is present, the corresponding counter is the transmitted one (accept traffic)

    flowspecs_dict: dict[str, FlowSpec] = {}

    for flow_spec in flowspecs:
        flow_spec_key = flow_spec.str_filter()

        if flow_spec_item := flowspecs_dict.get(flow_spec_key):
            if flow_spec.action == Action.RATE_LIMIT:
                flow_spec.transmitted_bytes = flow_spec_item.matched_bytes
                flow_spec.transmitted_packets = flow_spec_item.matched_packets

                flow_spec.matched_bytes += flow_spec.transmitted_bytes  # type: ignore
                flow_spec.matched_packets += flow_spec.transmitted_packets  # type: ignore

        flowspecs_dict[flow_spec_key] = flow_spec

    return list(flowspecs_dict.values())


class FlowSpecJuniperJunosKwargs(TypedDict):
    filter_name: NotRequired[str]


async def parse_flow_spec_juniper_junos(
    connection: SSHClientConnection,
    **kwargs: Unpack[FlowSpecJuniperJunosKwargs],
) -> list[FlowSpec]:
    filter_name = kwargs.get("filter_name", DEFAULT_FILTER_NAME)

    command = COMMAND_SHOW_FIREWALL_FILTER.format(filter_name=filter_name)

    logger.info("Sending command", extra={"command": command})
    result = await connection.run(command, check=True)

    output = str(result.stdout)
    logger.info("Command output", extra={"output": output})

    return parse_flows(output)
