from __future__ import annotations

import json

from dissect.cstruct import (
    PartialBytes,
    PartialResult,
    cstruct,
    read_partial,
)


def test_partial_enum_range_and_excluded_branch(cs: cstruct) -> None:
    cs.load(
        """
        enum State : uint16 {
            IDLE = 0x0000,
            RUN = 0x0100,
            FAULT = 0x0200,
        };

        struct record {
            uint8 version;
            State state;
            uint16 flags;
        };
        """
    )

    data = bytes([1, 0, 0x02, 0x34, 0x12])
    result = cs.record.read_partial(data, unknown_bytes=[1])

    assert isinstance(result, PartialResult)
    assert not result.exact

    state = result.fields["state"]
    assert state.range == (0x0200, 0x02FF)
    assert state.min == 0x0200
    assert state.max == 0x02FF
    assert "FAULT" in state.possible_branches
    assert "RUN" in state.excluded_branches
    assert "IDLE" in state.excluded_branches

    run = next(branch for branch in state.branches if branch.name == "RUN")
    assert "requires 1" in run.reason
    assert "byte 2, bit 0" in run.reason
    assert state.unknown_bits == tuple(range(8, 16))
    assert result.suggestions


def test_partial_full_input_matches_regular_parse(cs: cstruct) -> None:
    cs.load(
        """
        enum State : uint16 {
            IDLE = 0,
            RUN = 1,
            FAULT = 2,
        };

        struct record {
            uint8 version;
            State state;
            uint16 flags;
        };
        """
    )

    data = bytes([3, 1, 0x00, 0x34, 0x12])
    regular = cs.record(data)
    result = cs.record.read_partial(data)

    assert result.exact
    assert result == regular
    assert result.value == regular
    assert result.fields["version"].value == regular.version
    assert result.fields["state"].value == regular.state
    assert result.fields["flags"].value == regular.flags


def test_partial_unknown_specifications_are_equivalent(cs: cstruct) -> None:
    cs.load("struct record { uint16 value; };")
    data = bytes([0x12, 0x34])

    results = [
        cs.record.read_partial(data, unknown=0b1111111100000000),
        cs.record.read_partial(data, unknown_bits=range(8, 16)),
        cs.record.read_partial(data, unknown_bytes=[1]),
        cs.record.read_partial(data, unknown={1: 0xFF}),
        cs.record.read_partial(PartialBytes(data, unknown_bytes=[1])),
    ]

    for result in results:
        assert result.fields["value"].range == (0x0012, 0xFF12)


def test_partial_signed_ranges(cs: cstruct) -> None:
    cs.load("struct record { int16 value; };")

    positive = cs.record.read_partial(bytes([0x00, 0x7F]), unknown_bytes=[0])
    assert positive.fields["value"].range == (0x7F00, 0x7FFF)

    negative = cs.record.read_partial(bytes([0x00, 0x80]), unknown_bytes=[0])
    assert negative.fields["value"].range == (-0x8000, -0x7F01)


def test_partial_bitfields(cs: cstruct) -> None:
    cs.load(
        """
        struct record {
            uint16 a : 4;
            uint16 b : 4;
            uint16 c : 8;
        };
        """
    )

    data = bytes([0x12, 0x34])
    regular = cs.record(data)
    result = cs.record.read_partial(data)

    assert result.exact
    assert result.fields["a"].value == regular.a == 2
    assert result.fields["b"].value == regular.b == 1
    assert result.fields["c"].value == regular.c == 0x34

    partial = cs.record.read_partial(data, unknown_bytes=[1])
    assert partial.fields["a"].exact
    assert partial.fields["b"].exact
    assert partial.fields["c"].range == (0x00, 0xFF)


def test_partial_bitfields_big_endian(cs: cstruct) -> None:
    cs.endian = ">"
    cs.load(
        """
        struct record {
            uint16 a : 4;
            uint16 b : 4;
            uint16 c : 8;
        };
        """
    )

    data = bytes([0x12, 0x34])
    regular = cs.record(data)
    result = cs.record.read_partial(data, endian=">")

    assert result.exact
    assert result.fields["a"].value == regular.a == 1
    assert result.fields["b"].value == regular.b == 2
    assert result.fields["c"].value == regular.c == 0x34


def test_partial_flags(cs: cstruct) -> None:
    cs.load(
        """
        flag Flags : uint8 {
            A = 1,
            B = 2,
            C = 4,
        };
        struct record { Flags flags; };
        """
    )

    result = cs.record.read_partial(bytes([0x05]))
    flags = result.fields["flags"]
    assert "A" in flags.possible_branches
    assert "C" in flags.possible_branches
    assert "B" in flags.excluded_branches

    partial = cs.record.read_partial(bytes([0x00]), unknown_bits=[1])
    assert "B" in partial.fields["flags"].possible_branches


def test_partial_unknown_field(cs: cstruct) -> None:
    cs.load("struct record { uint8 version; uint16 value; };")
    result = cs.record.read_partial(bytes([1, 0x12, 0x34]), unknown_fields=["value"])
    assert result.fields["value"].range == (0, 0xFFFF)
    assert result.fields["version"].value == 1


def test_partial_conditional_array(cs: cstruct) -> None:
    cs.load("struct record { uint8 count; uint16 values[count]; uint8 tail; };")

    result = cs.record.read_partial(bytes([2, 0x11, 0x22, 0x33, 0x44, 0xAA]))
    assert result.exact
    assert result.fields["values"].value == [0x2211, 0x4433]
    assert result.fields["tail"].value == 0xAA

    partial = cs.record.read_partial(bytes([2, 0x11, 0x22, 0x33, 0x44, 0xAA]), unknown_bits=[16])
    assert partial.fields["values"].elements[0].range == (0x2211, 0x2311)
    assert partial.fields["values"].elements[1].exact


def test_partial_to_dict_and_json(cs: cstruct) -> None:
    cs.load("struct record { uint16 value; };")
    result = cs.record.read_partial(bytes([0x12, 0x34]), unknown_bytes=[1])
    data = result.to_dict()

    assert data["fields"]["value"]["min"] == 0x0012
    assert data["fields"]["value"]["max"] == 0xFF12
    assert json.loads(result.to_json())["exact"] is False


def test_partial_convenience_apis(cs: cstruct) -> None:
    cs.load("struct record { uint16 value; };")
    data = bytes([0x12, 0x34])

    assert cs.read_partial("record", data, unknown_bytes=[1]).fields["value"].range == (0x0012, 0xFF12)
    assert cs.partial_read("record", data, unknown_bytes=[1]).fields["value"].range == (0x0012, 0xFF12)
    assert cs.record.partial_read(data, unknown_bytes=[1]).fields["value"].range == (0x0012, 0xFF12)
    assert read_partial(cs.record, data, unknown_bytes=[1]).fields["value"].range == (0x0012, 0xFF12)
