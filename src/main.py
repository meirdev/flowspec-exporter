import argparse
import dataclasses
import json
import sys

from src.flowspec import FlowSpec
from src.routers.cisco_ios import parse_flows as cisco_ios_parse_flows
from src.routers.huawei_vrp import parse_flows as huawei_vrp_parse_flows
from src.routers.juniper_junos import parse_flows as juniper_junos_parse_flows

PARSERS = {
    "cisco_ios_parse_flows": cisco_ios_parse_flows,
    "huawei_vrp_parse_flows": huawei_vrp_parse_flows,
    "juniper_junos_parse_flows": juniper_junos_parse_flows,
}


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            data = dataclasses.asdict(o)  # type: ignore

            if isinstance(o, FlowSpec):
                data["flowspec"] = o.str_filter()

            return data
        else:
            return str(o)


def main() -> None:
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "file", nargs="?", type=argparse.FileType("r"), default=sys.stdin
    )
    arg_parser.add_argument("parser", choices=PARSERS.keys())

    args = arg_parser.parse_args()

    data = args.file.read()

    parser = PARSERS[args.parser]

    entries = parser(data)

    print(json.dumps(entries, cls=EnhancedJSONEncoder, indent=2))


if __name__ == "__main__":
    main()
