from typing import Literal

from asyncssh import SSHClientConnection

from src.flowspec import FlowSpec
from src.routers.cisco_ios import parse_flow_spec_cisco_ios
from src.routers.huawei_vrp import parse_flow_spec_huawei_vrp
from src.routers.juniper_junos import parse_flow_spec_juniper_junos

type Platform = Literal["cisco_ios", "juniper_junos", "huawei_vrp"]

PLATFORMS = ["cisco_ios", "juniper_junos", "huawei_vrp"]


async def parse_flow_spec(
    platform: Platform,
    connection: SSHClientConnection,
    **kwargs,
) -> list[FlowSpec]:
    match platform:
        case "cisco_ios":
            return await parse_flow_spec_cisco_ios(connection, **kwargs)
        case "juniper_junos":
            return await parse_flow_spec_juniper_junos(connection, **kwargs)
        case "huawei_vrp":
            return await parse_flow_spec_huawei_vrp(connection, **kwargs)
        case _:
            raise ValueError(f"Unsupported platform: {platform}")
