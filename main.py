import argparse
import dataclasses
import json
import sys

from router_flowspec_parser import (
    COMMANDS,
    parse_flow_spec_arista_eos,
    parse_flow_spec_cisco_ios,
    parse_flow_spec_juniper_junos,
)


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)  # type: ignore
        else:
            return str(o)


def main() -> None:
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "file", nargs="?", type=argparse.FileType("r"), default=sys.stdin
    )
    arg_parser.add_argument(
        "-p", "--platform", required=True, choices=COMMANDS.keys(), type=str
    )
    arg_parser.add_argument(
        "-c", "--command", type=str, help="Command used to fetch the flow spec data"
    )

    args = arg_parser.parse_args()

    data = args.file.read()

    if args.platform == "juniper_junos":
        command = args.command or COMMANDS["juniper_junos"]
        entries = parse_flow_spec_juniper_junos(data, command)
    elif args.platform == "cisco_ios":
        command = args.command or COMMANDS["cisco_ios"]
        entries = parse_flow_spec_cisco_ios(data, command)
    elif args.platform == "arista_eos":
        command = args.command or COMMANDS["arista_eos"]
        entries = parse_flow_spec_arista_eos(data, command)
    else:
        raise ValueError(f"Unsupported platform: {args.platform}")

    print(json.dumps(entries, cls=EnhancedJSONEncoder, indent=2))


if __name__ == "__main__":
    main()
