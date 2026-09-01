"""Tests for NLRI component encoding and RFC 8955 §5.1 flow ordering."""

from netaddr import IPNetwork

from flowspec_exporter.flowspec import (
    NLRI,
    BitmaskOp,
    BitmaskValues,
    ComponentType,
    FlowSpec,
    FlowSpecs,
    NLRIComponent,
    NumericOpEq,
    NumericOpGte,
    NumericOpLte,
    NumericValues,
)


def _flow(**components) -> FlowSpec:
    flow = FlowSpec()
    for key, value in components.items():
        setattr(flow, key, value)
    return flow


def _nlri(**components) -> NLRI:
    return _flow(**components).to_nlri()


def _precedes(higher: NLRI, lower: NLRI) -> bool:
    """True if ``higher`` has strictly higher precedence than ``lower``.

    NLRI.__lt__ puts the *lower* precedence NLRI first, so the check is
    ``lower < higher`` and not the other way round.
    """
    return lower < higher and not higher < lower


def test_to_nlri_empty_flow_has_no_components():
    assert list(_nlri()) == []


def test_to_nlri_components_follow_component_type_order():
    nlri = _nlri(
        fragment=BitmaskValues((BitmaskOp(match=True), 0x02)),
        source_port=NumericValues((NumericOpEq, 53)),
        destination_prefix=IPNetwork("10.0.0.0/8"),
        ip_protocol=NumericValues((NumericOpEq, 17)),
    )

    assert [c.component_type for c in nlri] == [
        ComponentType.DESTINATION_PREFIX,
        ComponentType.IP_PROTOCOL,
        ComponentType.SOURCE_PORT,
        ComponentType.FRAGMENT,
    ]


def test_to_nlri_prefix_component_is_normalised_cidr():
    nlri = _nlri(destination_prefix=IPNetwork("10.1.2.3/8"))

    assert nlri[0] == NLRIComponent(
        ComponentType.DESTINATION_PREFIX, IPNetwork("10.0.0.0/8")
    )


def test_to_nlri_numeric_component_is_encoded_bytes():
    # eq 80: end-of-list | 1-byte length | eq  ->  0x80 | 0x00 | 0x01 = 0x81
    nlri = _nlri(destination_port=NumericValues((NumericOpEq, 80)))

    assert nlri[0].component_type == ComponentType.DESTINATION_PORT
    assert nlri[0].op_value == bytes.fromhex("81 50")


def test_to_nlri_numeric_component_with_and_flag():
    # >=1024 & <=2048 -> first op 0x12 (2-byte, gt|eq), last op 0xd5 (end, and, 2-byte, lt|eq)
    nlri = _nlri(
        port=NumericValues(
            (NumericOpGte, 1024),
            (NumericOpLte.set_and(True), 2048),
        )
    )

    assert nlri[0].op_value == bytes.fromhex("13 0400 d5 0800")


def test_to_nlri_bitmask_component_is_encoded_bytes():
    # match 0x02 (SYN): end-of-list | 1-byte | match -> 0x81
    nlri = _nlri(tcp_flags=BitmaskValues((BitmaskOp(match=True), 0x02)))

    assert nlri[0].component_type == ComponentType.TCP_FLAGS
    assert nlri[0].op_value == bytes.fromhex("81 02")


def test_to_nlri_bitmask_not_flag():
    nlri = _nlri(fragment=BitmaskValues((BitmaskOp(not_=True, match=True), 0x01)))

    assert nlri[0].op_value == bytes.fromhex("83 01")


def test_identical_nlris_are_not_ordered():
    a = _nlri(destination_prefix=IPNetwork("10.0.0.0/8"))
    b = _nlri(destination_prefix=IPNetwork("10.0.0.0/8"))

    assert not a < b
    assert not b < a


def test_lower_component_type_has_precedence():
    dst = _nlri(destination_prefix=IPNetwork("10.0.0.0/8"))
    src = _nlri(source_prefix=IPNetwork("1.0.0.0/8"))

    assert _precedes(dst, src)


def test_more_specific_prefix_has_precedence():
    broad = _nlri(destination_prefix=IPNetwork("10.0.0.0/8"))
    specific = _nlri(destination_prefix=IPNetwork("10.1.0.0/16"))

    assert _precedes(specific, broad)


def test_lowest_ip_has_precedence_for_disjoint_prefixes():
    low = _nlri(destination_prefix=IPNetwork("10.0.0.0/8"))
    high = _nlri(destination_prefix=IPNetwork("11.0.0.0/8"))

    assert _precedes(low, high)


def test_disjoint_prefix_beats_prefix_length():
    # 10.0.0.0/24 is more specific but 9.0.0.0/8 is lower and disjoint.
    low = _nlri(destination_prefix=IPNetwork("9.0.0.0/8"))
    specific = _nlri(destination_prefix=IPNetwork("10.0.0.0/24"))

    assert _precedes(low, specific)


def test_more_components_has_precedence():
    short = _nlri(destination_prefix=IPNetwork("10.0.0.0/8"))
    long = _nlri(
        destination_prefix=IPNetwork("10.0.0.0/8"),
        ip_protocol=NumericValues((NumericOpEq, 6)),
    )

    assert _precedes(long, short)


def test_empty_nlri_has_lowest_precedence():
    empty = _nlri()
    anything = _nlri(source_port=NumericValues((NumericOpEq, 1)))

    assert _precedes(anything, empty)


def test_lowest_bytes_have_precedence_for_equal_length():
    tcp = _nlri(ip_protocol=NumericValues((NumericOpEq, 6)))
    udp = _nlri(ip_protocol=NumericValues((NumericOpEq, 17)))

    assert _precedes(tcp, udp)


def test_lowest_common_prefix_has_precedence_for_different_lengths():
    # Common first byte differs: 0x81 (end-of-list) vs 0x01 -> 0x01 is lower.
    single = _nlri(ip_protocol=NumericValues((NumericOpEq, 6)))
    double = _nlri(
        ip_protocol=NumericValues((NumericOpEq, 6), (NumericOpEq, 17)),
    )

    assert _precedes(double, single)


def test_longest_bytes_have_precedence_for_equal_common_prefix():
    short = NLRI([NLRIComponent(ComponentType.IP_PROTOCOL, b"\x01\x06")])
    long = NLRI([NLRIComponent(ComponentType.IP_PROTOCOL, b"\x01\x06\x81\x11")])

    assert _precedes(long, short)


def test_first_differing_component_decides():
    # Same first component; second component decides (lower port wins).
    a = _nlri(
        destination_prefix=IPNetwork("10.0.0.0/8"),
        destination_port=NumericValues((NumericOpEq, 80)),
    )
    b = _nlri(
        destination_prefix=IPNetwork("10.0.0.0/8"),
        destination_port=NumericValues((NumericOpEq, 443)),
    )

    assert _precedes(a, b)


def test_sorted_returns_highest_precedence_first():
    flows = [
        _flow(source_prefix=IPNetwork("1.0.0.0/8")),
        _flow(destination_prefix=IPNetwork("10.0.0.0/8")),
        _flow(destination_prefix=IPNetwork("11.0.0.0/8")),
        _flow(
            destination_prefix=IPNetwork("10.0.0.0/8"),
            ip_protocol=NumericValues((NumericOpEq, 6)),
        ),
        _flow(destination_prefix=IPNetwork("10.1.0.0/16")),
        _flow(),
    ]

    result = FlowSpecs(flows=flows).sorted()

    assert [f.str_filter() for f in result.flows] == [
        "destination-prefix: 10.1.0.0/16",
        "destination-prefix: 10.0.0.0/8, ip-protocol: =6",
        "destination-prefix: 10.0.0.0/8",
        "destination-prefix: 11.0.0.0/8",
        "source-prefix: 1.0.0.0/8",
        "",
    ]


def test_sorted_is_stable_for_equal_flows():
    first = _flow(destination_prefix=IPNetwork("10.0.0.0/8"))
    second = _flow(destination_prefix=IPNetwork("10.0.0.0/8"))
    first.raw, second.raw = "first", "second"

    result = FlowSpecs(flows=[first, second]).sorted()

    assert [f.raw for f in result.flows] == ["first", "second"]
