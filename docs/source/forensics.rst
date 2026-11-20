Forensic capture correlation
############################

The pcapng.forensics module provides a read-only view over one or more
pcap-ng sources. It keeps the section/interface identity, the original 64-bit
integer tick, and the exact rational timestamp resolution for every record.

Example
=======

.. code-block:: python

    from pcapng.forensics import ClockCalibration, Ordering, read_captures

    captures = read_captures(
        [("collector-a", bytes_a), ("collector-b", bytes_b)],
        calibrations=[
            ClockCalibration("collector-a", 0, 0, anchor_group="gps-a"),
            ClockCalibration("collector-b", 0, 0, anchor_group="gps-b"),
        ],
    )

    result = captures.compare(captures.records[0], captures.records[1])
    assert result in (Ordering.BEFORE, Ordering.AFTER, Ordering.OVERLAP,
                      Ordering.INCOMPARABLE)

Calibration values are closed intervals of offsets in seconds. A comparison
returns BEFORE or AFTER only when the calibrated intervals are disjoint;
overlapping intervals return OVERLAP. Records whose clocks have no calibration
relation return INCOMPARABLE.

Records are always exposed in input/block order. If calibration reverses the
order of two records from the same capture stream, the contradiction is
available through captures.conflicts; the affected anchor_groups are reported
and the records are not silently re-sorted. An explicit
sorted_by_calibrated_time() call returns a new list and never changes
captures.records.

Simple Packet Blocks have no timestamp field. They are represented with a None
tick/timestamp and a provenance whose kind is absent; their section, interface
and stream position are still retained.
