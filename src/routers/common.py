import re

from netaddr import IPNetwork

from src.flowspec import (
    BitmaskOp,
    BitmaskValues,
    NumericOp,
    NumericOpEq,
    NumericOpGt,
    NumericOpGte,
    NumericOpLt,
    NumericOpLte,
    NumericOpNe,
    NumericValues,
)


def parse_prefix(value: str) -> IPNetwork | None:
    if value == "*":
        return None

    return IPNetwork(value, expand_partial=True)


def parse_numeric_values(value: str) -> NumericValues:
    values_or = NumericValues()

    for s1 in value.split(","):
        values_and = NumericValues()

        set_and = False

        for s2 in s1.split("&"):
            if match := re.match(r"(?P<op>[><=!]+)(?P<val>\d+)", s2):
                numeric_op: NumericOp

                match match.group("op"):
                    case ">=":
                        numeric_op = NumericOpGte
                    case "<=":
                        numeric_op = NumericOpLte
                    case "=":
                        numeric_op = NumericOpEq
                    case "!=":
                        numeric_op = NumericOpNe
                    case ">":
                        numeric_op = NumericOpGt
                    case "<":
                        numeric_op = NumericOpLt
                    case _:
                        raise ValueError(f"Invalid operator: {match.group('op')}")

                values_and.append(
                    (numeric_op.set_and(set_and), int(match.group("val")))
                )

                set_and = True

        values_or += values_and

    return values_or


def parse_bitmask(value: str, not_: bool = False) -> BitmaskValues:
    return BitmaskValues((BitmaskOp(not_=not_), int(value, 16)))
