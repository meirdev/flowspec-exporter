import logging
import re
from typing import Literal, NotRequired, TypedDict, Unpack

from asyncssh import SSHClientConnection
from netaddr import IPNetwork

from flowspec_exporter.flowspec import (
    Action,
    BitmaskOp,
    BitmaskValues,
    FlowSpec,
    NumericOpEq,
    NumericValues,
)

logger = logging.getLogger(__name__)


DEFAULT_INET_FAMILY = "ipv4"

COMMAND_SHOW_FLOWSPEC = "show flow-spec {inet_family}"

RE_FIND_FLOW_SPEC = re.compile(
    r"(?P<flowspec_rule>Flow-spec rule:.+?)(?=Flow-spec rule|\Z)",
    re.DOTALL | re.MULTILINE,
)

RE_FIND_RULES = re.compile(
    r"(?P<key>Flow-spec rule|Rule identifier|Destination prefix|Source prefix|Next protocol|Destination port|Source port|TCP flags)\s*:\s*(?P<value>[^\n\r]+)"
)

RE_FIND_TCP_FLAGS = re.compile(r"TCP:(?P<tcp_flags>\d+)")

RE_FIND_COUNTER = re.compile(
    r"Counter: (?P<packets>\d+) packets, (?P<bytes>\d+) bytes"
)

RE_FIND_ACTIONS = re.compile(
    r"Actions:\s+(?P<action>Drop|(?:Police:\s+(?P<rate_limit>.+)))"
)


def parse_flows(data: str) -> list[FlowSpec]:
    flowspecs: list[FlowSpec] = []

    for match in RE_FIND_FLOW_SPEC.findall(data):
        flowspec = FlowSpec(raw=match)

        try:
            action_match = RE_FIND_ACTIONS.search(match)

            if action_match:
                if action_match.group("action") == "Drop":
                    flowspec.action = Action.DISCARD
                elif action_match.group("action").startswith("Policy"):
                    flowspec.action = Action.RATE_LIMIT
                    flowspec.rate_limit_bps = 0

                    rate_limit = action_match.group("rate_limit")
                    if rate_limit:
                        if "Gbps" in rate_limit:
                            pass
                        elif "Mbps" in rate_limit:
                            pass
                        elif "Kbps" in rate_limit:
                            pass

            counter_match = RE_FIND_COUNTER.search(match)

            if counter_match:
                counter_bytes = counter_match.group("bytes")
                if counter_bytes:
                    flowspec.matched_bytes = flowspec.transmitted_bytes = int(
                        counter_bytes
                    )

                    if flowspec.action == Action.DISCARD:
                        flowspec.dropped_bytes = flowspec.matched_bytes
                    elif flowspec.action == Action.RATE_LIMIT:
                        pass

                counter_packets = counter_match.group("packets")
                if counter_packets:
                    flowspec.matched_packets = flowspec.transmitted_packets = int(
                        counter_packets
                    )

                    if flowspec.action == Action.DISCARD:
                        flowspec.dropped_packets = flowspec.matched_packets
                    elif flowspec.action == Action.RATE_LIMIT:
                        pass

            rules = RE_FIND_RULES.findall(match)

            for key, value in rules:
                match key:
                    case "Flow-spec rule":
                        tcp_flags_match = RE_FIND_TCP_FLAGS.search(value)
                        if tcp_flags_match:
                            tcp_flags = tcp_flags_match.group("tcp_flags")
                            flowspec.tcp_flags = BitmaskValues(
                                (BitmaskOp(), int(tcp_flags))
                            )
                    case "Rule identifier":
                        flowspec.metadata["rule_identifier"] = value
                    case "Destination prefix":
                        flowspec.destination_prefix = IPNetwork(value)
                    case "Source prefix":
                        flowspec.source_prefix = IPNetwork(value)
                    case "Next protocol":
                        flowspec.ip_protocol = NumericValues(
                            (NumericOpEq, int(value))
                        )
                    case "Destination port":
                        flowspec.destination_port = NumericValues(
                            (NumericOpEq, int(value))
                        )
                    case "Source port":
                        flowspec.source_port = NumericValues(
                            (NumericOpEq, int(value))
                        )

            flowspecs.append(flowspec)
        except Exception:
            pass

    return flowspecs


class FlowSpecAristaEosKwargs(TypedDict):
    inet_family: NotRequired[Literal["ipv4", "ipv6"]]


async def parse_flow_spec_arista_eos(
    connection: SSHClientConnection,
    **kwargs: Unpack[FlowSpecAristaEosKwargs],
) -> list[FlowSpec]:
    inet_family = kwargs.get("inet_family", DEFAULT_INET_FAMILY)

    command = COMMAND_SHOW_FLOWSPEC.format(inet_family=inet_family)

    logger.info("Sending command", extra={"command": command})
    result = await connection.run(command, check=True)

    output = str(result.stdout)
    logger.info("Command output", extra={"output": output})

    return parse_flows(output)
