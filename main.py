import argparse
import dataclasses
import json
import sys

import router_flowspec_parser


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        else:
            return str(o)


def main() -> None:
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "file", nargs="?", type=argparse.FileType("r"), default=sys.stdin
    )
    arg_parser.add_argument(
        "-p", "--platform", required=True, choices=["juniper_junos", "cisco_ios"]
    )

    args = arg_parser.parse_args()

    data = args.file.read()

    if args.platform == "juniper_junos":
        entries = router_flowspec_parser.parse_flow_spec_juniper_junos(data)
    elif args.platform == "cisco_ios":
        entries = router_flowspec_parser.parse_flow_spec_cisco_ios(data)
    else:
        raise ValueError(f"Unsupported platform: {args.platform}")

    print(json.dumps(entries, cls=EnhancedJSONEncoder, indent=2))


if __name__ == "__main__":
    main()
