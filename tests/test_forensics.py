import io
from fractions import Fraction

import pcapng.blocks as blocks
from pcapng import FileWriter
from pcapng.forensics import (
    ClockCalibration,
    Ordering,
    read_captures,
)
from pcapng.utils import pack_timestamp_resolution


def _write_section(stream, endianness, ticks, resolution_exponent=9, spb=False):
    shb = blocks.SectionHeader(endianness=endianness)
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=0,
        options={
            "if_tsresol": pack_timestamp_resolution(10, resolution_exponent),
        },
    )
    writer = FileWriter(stream, shb)
    for tick in ticks:
        if spb:
            block = shb.new_member(
                blocks.SimplePacket,
                packet_data=b"simple packet",
            )
        else:
            block = shb.new_member(
                blocks.EnhancedPacket,
                interface_id=0,
                timestamp_high=tick >> 32,
                timestamp_low=tick & 0xFFFFFFFF,
                packet_data=b"enhanced packet",
            )
        writer.write_block(block)
    return shb


def _capture(endianness, ticks, resolution_exponent=9, spb=False):
    stream = io.BytesIO()
    _write_section(stream, endianness, ticks, resolution_exponent, spb)
    return stream.getvalue()


def test_adjacent_ticks_survive_float_precision_loss_and_need_calibration():
    tick = 1 << 60
    big = _capture(">", [tick])
    little = _capture("<", [tick + 1])

    capture = read_captures(
        [big, little],
        names=["big", "little"],
        calibrations=[
            ClockCalibration((0, 0, 0), 0, 0, anchor_group="gps-a"),
            ClockCalibration((1, 0, 0), 0, 0, anchor_group="gps-b"),
        ],
    )
    first, second = capture.records

    assert first.section_ref.endianness == ">"
    assert second.section_ref.endianness == "<"
    assert first.tick == tick
    assert second.tick == tick + 1
    assert first.tick != second.tick
    assert first.timestamp != second.timestamp
    assert first.timestamp_resolution == Fraction(1, 10**9)
    assert second.timestamp_resolution == Fraction(1, 10**9)

    # This is the lossy value users would get from a plain float sort.
    assert first.timestamp_float == second.timestamp_float
    assert first.timestamp - second.timestamp == Fraction(-1, 10**9)

    assert capture.compare(first, second) == Ordering.BEFORE

    # Without calibration these are two unrelated clock domains, even though
    # their numeric ticks are adjacent and their endianness is known.
    without = read_captures([big, little], names=["big", "little"])
    assert without.compare(
        without.records[0], without.records[1]
    ) == Ordering.INCOMPARABLE

    # Calibration can also be withdrawn from an existing capture.
    assert capture.compare(
        first, second, calibrations=None
    ) == Ordering.INCOMPARABLE


def test_calibration_interval_that_overlaps_is_not_a_definite_order():
    tick = 1 << 60
    capture = read_captures(
        [_capture(">", [tick]), _capture("<", [tick + 1])],
        calibrations=[
            ClockCalibration((0, 0, 0), 0, 0, anchor_group="a"),
            ClockCalibration(
                (1, 0, 0),
                Fraction(-1, 10**9),
                0,
                anchor_group="b",
            ),
        ],
    )

    result = capture.compare(*capture.records)
    assert result == Ordering.OVERLAP
    assert result.overlap
    assert result.left_interval.intersects(result.right_interval)


def test_stream_order_conflict_is_reported_without_reordering():
    stream = io.BytesIO()
    # Two sections in one file: the first record has tick 100 with a zero
    # offset, the second has tick 0 with a -200 second offset.  Calibration
    # therefore says the second record happened first.
    _write_section(stream, ">", [100], resolution_exponent=0)
    _write_section(stream, "<", [0], resolution_exponent=0)

    capture = read_captures(
        stream.getvalue(),
        calibrations=[
            ClockCalibration((0, 0, 0), 0, 0, anchor_group="section-0-anchors"),
            ClockCalibration(
                (0, 1, 0), -200, -200, anchor_group="section-1-anchors"
            ),
        ],
    )
    first, second = capture.records

    assert [record.record_index for record in capture.records] == [0, 1]
    assert capture.compare(first, second) == Ordering.AFTER
    assert capture.compare(first, second).stream_conflict is not None

    assert len(capture.conflicts) == 1
    conflict = capture.conflicts[0]
    assert conflict.first is first
    assert conflict.second is second
    assert set(conflict.anchor_groups) == {
        "section-0-anchors",
        "section-1-anchors",
    }

    # An explicit sort is allowed, but it does not mutate the capture order.
    sorted_records = capture.sorted_by_calibrated_time()
    assert sorted_records == [second, first]
    assert capture.records == [first, second]


def test_simple_packet_has_explicit_absent_time_provenance():
    capture = read_captures(_capture(">", [1], spb=True))
    record = capture.records[0]

    assert record.is_simple_packet
    assert record.tick is None
    assert record.timestamp is None
    assert record.has_timestamp is False
    assert record.provenance.kind == "absent"
    assert record.provenance.block_type == "simple_packet"
    assert record.provenance.interface_ref == record.interface_ref
    assert record.provenance.section_ref == record.section_ref
    assert record.provenance.stream_order == 0
    assert "no timestamp" in record.provenance.detail

    raw_block = record.block
    assert raw_block.has_timestamp is False
    assert raw_block.timestamp is None
    assert raw_block.timestamp_provenance == "simple-packet:no-timestamp-field"

    # An SPB cannot establish a cross-source time relation.
    other = read_captures(_capture("<", [2])).records[0]
    assert capture.compare(record, other) == Ordering.INCOMPARABLE


def test_raw_block_exposes_exact_tick_and_resolution():
    tick = (1 << 60) + 1
    capture = read_captures(_capture(">", [tick]))
    record = capture.records[0]

    assert record.block.raw_tick == tick
    assert record.block.raw_timestamp == tick
    assert record.block.timestamp_exact == record.timestamp
    assert record.block.timestamp_exact == Fraction(tick, 10**9)
    # The legacy property is intentionally kept as the display float.
    assert record.block.timestamp == float(Fraction(tick, 10**9))


def test_with_calibrations_returns_a_new_view():
    tick = 1 << 60
    capture = read_captures([_capture(">", [tick]), _capture("<", [tick + 1])])
    calibrated = capture.with_calibrations(
        [
            ClockCalibration((0, 0, 0), 0, 0, anchor_group="a"),
            ClockCalibration((1, 0, 0), 0, 0, anchor_group="b"),
        ]
    )

    assert capture.compare(*capture.records) == Ordering.INCOMPARABLE
    assert calibrated.compare(*calibrated.records) == Ordering.BEFORE
    assert capture.records[0]._clock is capture.calibrations
    assert calibrated.records[0]._clock is calibrated.calibrations
