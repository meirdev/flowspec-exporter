import argparse
import dataclasses
import json
import sys

from .consts import COMMANDS
from .parser import parse_flow_spec


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

    command = args.command or COMMANDS[args.platform]
    entries = parse_flow_spec(args.platform, data, command)

    print(json.dumps(entries, cls=EnhancedJSONEncoder, indent=2))


if __name__ == "__main__":
    main()
