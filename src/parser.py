from typing import Literal

from src.flowspec import FlowSpec
from src.routers.arista_eos import parse_flow_spec_arista_eos
from src.routers.cisco_ios import parse_flow_spec_cisco_ios
from src.routers.juniper_junos import parse_flow_spec_juniper_junos

type Platform = Literal["cisco_ios", "juniper_junos", "arista_eos"]


def parse_flow_spec(platform: Platform, data: str) -> list[FlowSpec]:
    match platform:
        case "cisco_ios":
            return parse_flow_spec_cisco_ios(data)
        case "juniper_junos":
            return parse_flow_spec_juniper_junos(data)
        case "arista_eos":
            return parse_flow_spec_arista_eos(data)
