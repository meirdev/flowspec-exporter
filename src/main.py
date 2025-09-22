import argparse
import sys
from typing import Callable

from src.flowspec import FlowSpec, FlowSpecs
from src.routers.cisco_ios import parse_flows as cisco_ios_parse_flows
from src.routers.huawei_vrp import parse_flows as huawei_vrp_parse_flows
from src.routers.juniper_junos import parse_flows as juniper_junos_parse_flows

PARSERS: dict[str, Callable[[str], list[FlowSpec]]] = {
    "cisco_ios_parse_flows": cisco_ios_parse_flows,
    "huawei_vrp_parse_flows": huawei_vrp_parse_flows,
    "juniper_junos_parse_flows": juniper_junos_parse_flows,
}


def main() -> None:
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "file", nargs="?", type=argparse.FileType("r"), default=sys.stdin
    )
    arg_parser.add_argument("parser", choices=PARSERS.keys())

    args = arg_parser.parse_args()

    data = args.file.read()

    parser = PARSERS[args.parser]

    flows = parser(data)

    for flow in flows:
        flow.filter = flow.str_filter()

    flowspecs = FlowSpecs(flows=flows)

    print(flowspecs.to_json(indent=2, default=str))  # type: ignore


if __name__ == "__main__":
    main()
