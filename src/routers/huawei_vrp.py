import logging
import re
from typing import TypedDict, Unpack

from asyncssh import SSHClientConnection, SSHReader
from netaddr import IPNetwork

from src.flowspec import (
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


RE_SHELL_PROMPT = re.compile(r"<.*?>")


COMMAND_DISPLAY_ROUTING_TABLE = (
    "display bgp flow vpnv4 vpn-instance {vpn_instance} routing-table | no-more"
)

RE_FIND_FLOWS = re.compile(
    r"ReIndex\s*:\s*(?P<re_index>\d+)\s+Dissemination Rules:\s+(?P<dissemination_rules>.+?)(?=ReIndex|\Z)",
    re.DOTALL | re.MULTILINE,
)
RE_FIND_RULES = re.compile(
    r"(?P<key>Destination IP|Source IP|Protocol|Port|Src\. Port|Dest\. Port|ICMP Type|ICMP Code|TCP-flags|FragmentType|Packet-Length)\s*:\s*(?P<value>[^\n\r]+)"
)


COMMAND_DISPLAY_STATISTICS = (
    "display flowspec vpnv4 vpn-instance {vpn_instance} statistics {re_index} | no-more"
)

RE_FIND_STATISTICS = re.compile(
    r"(?P<key>Matched|Passed|Dropped)\s+(?P<packets_pps>\d+)\s+(?P<bytes_bps>\d+)"
)


RE_FIND_NUMERIC_VALUES = re.compile(
    r"((?P<op>eq|gt|lt|greater or equal|less or equal|less or greater)\s+(?P<val>\d+)(\s+(?P<and_or>and|or))?)+"
)

RE_FIND_BITMASK_VALUES = re.compile(
    r"((?P<not>not)?(?P<match>match|any-match)\s+(?P<val>\d+|\([^)]+\))(\s+(?P<and_or>and|or))?)+"
)


class FlowSpecHuaweiVrpKwargs(TypedDict):
    vpn_instance: str


class FlowStatistic(TypedDict):
    matched_packets: int
    matched_bytes: int
    passed_packets: int
    passed_bytes: int
    dropped_packets: int
    dropped_bytes: int


def _parse_prefix(value: str) -> IPNetwork:
    return IPNetwork(value, expand_partial=True)


def _parse_numeric_values(value: str) -> NumericValues:
    values, set_and = NumericValues(), False

    for i in RE_FIND_NUMERIC_VALUES.finditer(value):
        numeric_op: NumericOp

        match i.group("op"):
            case "greater or equal":
                numeric_op = NumericOpGte
            case "less or equal":
                numeric_op = NumericOpLte
            case "eq":
                numeric_op = NumericOpEq
            case "less or greater":
                numeric_op = NumericOpNe
            case "gt":
                numeric_op = NumericOpGt
            case "lt":
                numeric_op = NumericOpLt
            case _:
                logger.error("Invalid operator: %s", i.group("op"))
                continue

        values.append((numeric_op.set_and(set_and), int(i.group("val"))))

        set_and = i.group("and_or") == "and"

    return values


def _parse_bitmask_values(value: str) -> BitmaskValues:
    values, set_and = BitmaskValues(), False

    for i in RE_FIND_BITMASK_VALUES.finditer(value):
        not_ = i.group("not") is not None
        match_ = i.group("match") == "any-match"

        val: str = i.group("val")

        if val.isnumeric():
            value_int = int(val)
        else:
            match val[1:-1]:  # Remove parentheses
                case "Don't fragment":
                    value_int = 0x01
                case "Is a fragment":
                    value_int = 0x02
                case "First fragment":
                    value_int = 0x04
                case "Last fragment":
                    value_int = 0x08
                case _:
                    logger.error("Unknown fragment type: %s", val)
                    continue

        values.append((BitmaskOp(not_=not_, match=match_).set_and(set_and), value_int))

        set_and = i.group("and_or") == "and"

    return values


async def _read_until_shell_prompt(stdout: SSHReader) -> str:
    return re.sub(r"<.*?>$", "", await stdout.readuntil(RE_SHELL_PROMPT)).strip()


def parse_flows(output: str) -> list[FlowSpec]:
    flowspecs: list[FlowSpec] = []

    for re_index, dissemination_rules in RE_FIND_FLOWS.findall(output):
        logger.debug("ReIndex: %s", re_index)
        logger.debug("Dissemination Rules: %s", dissemination_rules)

        flowspec = FlowSpec(raw=dissemination_rules)

        for key, value in RE_FIND_RULES.findall(dissemination_rules):
            key: str
            value: str

            key, value = key.strip(), value.strip()

            match key:
                case "Destination IP":
                    flowspec.destination_prefix = _parse_prefix(value)
                case "Source IP":
                    flowspec.source_prefix = _parse_prefix(value)
                case "Protocol":
                    flowspec.ip_protocol = _parse_numeric_values(value)
                case "Port":
                    flowspec.port = _parse_numeric_values(value)
                case "Src. Port":
                    flowspec.port = _parse_numeric_values(value)
                case "Dest. Port":
                    flowspec.destination_port = _parse_numeric_values(value)
                case "ICMP Type":
                    flowspec.icmp_type = _parse_numeric_values(value)
                case "ICMP Code":
                    flowspec.icmp_code = _parse_numeric_values(value)
                case "TCP-flags":
                    flowspec.tcp_flags = _parse_bitmask_values(value)
                case "FragmentType":
                    flowspec.fragment = _parse_bitmask_values(value)
                case "Packet-Length":
                    flowspec.packet_length = _parse_numeric_values(value)
                case _:
                    logger.error("Unknown key: %s", key)
                    continue

        flowspec.metadata["re_index"] = re_index

        flowspecs.append(flowspec)

    return flowspecs


def parse_flow_statistics(output: str) -> FlowStatistic:
    statistics: dict[str, dict[str, int]] = {}

    for key, packets_pps, bytes_bps in RE_FIND_STATISTICS.findall(output):
        # skip on bps and pps
        key: str = key.lower()

        if key not in statistics:
            statistics[key] = {
                "packets": int(packets_pps),
                "bytes": int(bytes_bps),
            }

    return {
        "matched_packets": statistics.get("matched", {}).get("packets", 0),
        "matched_bytes": statistics.get("matched", {}).get("bytes", 0),
        "passed_packets": statistics.get("passed", {}).get("packets", 0),
        "passed_bytes": statistics.get("passed", {}).get("bytes", 0),
        "dropped_packets": statistics.get("dropped", {}).get("packets", 0),
        "dropped_bytes": statistics.get("dropped", {}).get("bytes", 0),
    }


async def parse_flow_spec_huawei_vrp(
    connection: SSHClientConnection,
    **kwargs: Unpack[FlowSpecHuaweiVrpKwargs],
) -> list[FlowSpec]:
    writer, stdout, _ = await connection.open_session()

    logger.debug("Waiting for shell prompt")
    _ = await _read_until_shell_prompt(stdout)

    command = COMMAND_DISPLAY_ROUTING_TABLE.format(vpn_instance=kwargs["vpn_instance"])

    logger.info("Sending command", extra={"command": command})
    writer.write(f"{command}\n")

    output = await _read_until_shell_prompt(stdout)
    logger.info("Command output", extra={"output": output})

    flowspecs: list[FlowSpec] = parse_flows(output)

    for flowspec in flowspecs:
        re_index = flowspec.metadata.get("re_index")

        command = COMMAND_DISPLAY_STATISTICS.format(
            vpn_instance=kwargs["vpn_instance"], re_index=re_index
        )

        logger.info("Sending command", extra={"command": command})
        writer.write(f"{command}\n")

        output = await _read_until_shell_prompt(stdout)
        logger.info("Command output", extra={"output": output})

        statistics = parse_flow_statistics(output)
        logger.debug("Statistics: %s", statistics)

        flowspec.matched_packets = statistics["matched_packets"]
        flowspec.matched_bytes = statistics["matched_bytes"]
        flowspec.transmitted_packets = statistics["passed_packets"]
        flowspec.transmitted_bytes = statistics["passed_bytes"]
        flowspec.dropped_packets = statistics["dropped_packets"]
        flowspec.dropped_bytes = statistics["dropped_bytes"]

        logger.debug("Parsed FlowSpec: %s", flowspec)

        flowspecs.append(flowspec)

    return flowspecs
