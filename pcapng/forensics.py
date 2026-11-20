"""
Read-only forensic correlation helpers for pcap-ng captures.

The normal :class:`pcapng.scanner.FileScanner` API is deliberately close to
the pcap-ng block layout.  That is useful for editing, but it loses two pieces
of information that matter when several capture machines are compared:

* a 64 bit tick is converted to a Python ``float`` by
  :attr:`pcapng.blocks.BlockWithTimestampMixin.timestamp`; adjacent ticks
  above ``2**53`` can therefore collapse into the same value;
* the identity of the section and interface that produced a timestamp is not
  carried by the timestamp itself.

This module builds a read-only view which keeps the original integer tick,
the exact (rational) timestamp resolution, the section/interface identity and
the position of every record in its capture stream.  Cross-capture ordering is
only attempted when the caller supplies calibration intervals for the clocks
involved.

No block from the input is modified.  The public objects below are immutable
apart from the private calibration hook attached to records by their owning
:class:`CaptureSet`.

Example
-------

.. code-block:: python

    from fractions import Fraction
    from pcapng.forensics import ClockCalibration, read_captures

    capture = read_captures(
        ["capture-a.pcapng", "capture-b.pcapng"],
        calibrations=[
            ClockCalibration((0, 0, 0), 0, 0, anchor_group="gps-a"),
            ClockCalibration((1, 0, 0), 0, 0, anchor_group="gps-b"),
        ],
    )

    result = capture.compare(capture.records[0], capture.records[1])
    print(result.ordering)       # before / after / overlap / incomparable
    print(result.anchor_groups)  # groups used by the calibrated relation

Calibration offsets are intervals in seconds.  An interval means "the true
offset is somewhere in this closed interval"; it is not a point estimate.
Keeping the interval, rather than collapsing it to a float midpoint, is what
lets the API say *overlap* when the available clocks cannot resolve an order.
"""

import copy
import io
import math
import os
from collections import OrderedDict, defaultdict
from enum import Enum
from fractions import Fraction

from pcapng.blocks import (
    EnhancedPacket,
    InterfaceDescription,
    InterfaceStatistics,
    ObsoletePacket,
    SectionHeader,
    SimplePacket,
)
from pcapng.exceptions import PcapngException
from pcapng.scanner import FileScanner
from pcapng.utils import unpack_timestamp_resolution_exact


_DEFAULT = object()

_PATH_TYPES = (str,) + ((os.PathLike,) if hasattr(os, "PathLike") else ())


class ForensicError(PcapngException):
    """Base class for errors raised by the forensic correlation API."""


class CalibrationError(ForensicError):
    """A calibration interval or anchor group cannot be interpreted."""


class Ordering(str, Enum):
    """
    The result of comparing two records on a common reference clock.

    Only the first four members are distinct values.  The remaining names are
    aliases, kept because they read naturally in reports and make the API
    forgiving to callers using slightly different terminology.
    """

    BEFORE = "before"
    AFTER = "after"
    OVERLAP = "overlap"
    INCOMPARABLE = "incomparable"

    DEFINITE_BEFORE = "before"
    DEFINITELY_BEFORE = "before"
    DEFINITE_AFTER = "after"
    DEFINITELY_AFTER = "after"
    TIME_OVERLAP = "overlap"
    TIMES_OVERLAP = "overlap"
    OVERLAPPING = "overlap"
    EARLIER = "before"
    LATER = "after"
    NOT_COMPARABLE = "incomparable"
    UNCOMPARABLE = "incomparable"
    UNORDERED = "incomparable"

    @property
    def definite(self):
        return self in (Ordering.BEFORE, Ordering.AFTER)


# ``Order`` is a convenient short spelling used by some callers.
Order = Ordering


class TimeInterval(object):
    """
    A closed interval of exact rational seconds.

    ``low == high`` represents a point in time.  The class deliberately uses
    :class:`fractions.Fraction`; converting a 64 bit tick to ``float`` before
    subtracting two nearby ticks loses the distinction this API is meant to
    preserve.
    """

    __slots__ = ("low", "high")

    def __init__(self, low, high=None):
        low = _as_fraction(low, "interval start")
        high = low if high is None else _as_fraction(high, "interval end")
        if high < low:
            raise ValueError("interval end {0!r} precedes start {1!r}".format(
                high, low
            ))
        self.low = low
        self.high = high

    @classmethod
    def point(cls, value):
        return cls(value)

    @property
    def start(self):
        return self.low

    @property
    def end(self):
        return self.high

    @property
    def is_point(self):
        return self.low == self.high

    @property
    def width(self):
        return self.high - self.low

    def contains(self, value):
        value = _as_fraction(value, "value")
        return self.low <= value <= self.high

    def intersects(self, other):
        other = _as_interval(other)
        return self.low <= other.high and other.low <= self.high

    def intersection(self, other):
        other = _as_interval(other)
        low = max(self.low, other.low)
        high = min(self.high, other.high)
        if high < low:
            return None
        return TimeInterval(low, high)

    def relation(self, other):
        """Return the :class:`Ordering` of ``self`` relative to ``other``."""
        other = _as_interval(other)
        if self.high < other.low:
            return Ordering.BEFORE
        if other.high < self.low:
            return Ordering.AFTER
        return Ordering.OVERLAP

    def __eq__(self, other):
        if isinstance(other, TimeInterval):
            return self.low == other.low and self.high == other.high
        try:
            other_interval = _as_interval(other)
        except (TypeError, ValueError):
            return False
        return self == other_interval

    def __hash__(self):
        return hash((self.low, self.high))

    def __repr__(self):
        if self.is_point:
            return "TimeInterval({0!r}, {0!r})".format(self.low)
        return "TimeInterval({0!r}, {1!r})".format(self.low, self.high)


class TimestampProvenance(object):
    """
    Where a record's time (or lack of time) came from.

    Simple Packet Blocks (SPBs) have no timestamp field in the pcap-ng format.
    They are still represented as records, with ``has_timestamp`` false and a
    provenance whose ``kind`` is ``"absent"``.  This makes the absence explicit
    and keeps the section, interface and stream position available for a
    reader; it never invents a timestamp from a neighbouring block.
    """

    __slots__ = (
        "kind",
        "block_type",
        "field",
        "detail",
        "section_ref",
        "interface_ref",
        "stream_order",
    )

    def __init__(
        self,
        kind,
        block_type,
        field=None,
        detail=None,
        section_ref=None,
        interface_ref=None,
        stream_order=None,
    ):
        self.kind = kind
        self.block_type = block_type
        self.field = field
        self.detail = detail
        self.section_ref = section_ref
        self.interface_ref = interface_ref
        self.stream_order = stream_order

    @property
    def has_timestamp(self):
        return self.kind == "block"

    @property
    def source(self):
        """Short machine-readable source name (the block kind)."""
        return self.block_type

    @property
    def reason(self):
        return self.detail

    def as_dict(self):
        return {
            "kind": self.kind,
            "block_type": self.block_type,
            "field": self.field,
            "detail": self.detail,
            "section": None if self.section_ref is None else self.section_ref.key,
            "interface": (
                None if self.interface_ref is None else self.interface_ref.key
            ),
            "stream_order": self.stream_order,
        }

    def __eq__(self, other):
        if isinstance(other, TimestampProvenance):
            return self.as_dict() == other.as_dict()
        if isinstance(other, str):
            return other in {
                self.kind,
                self.block_type,
                self.source,
                self.kind + ":" + self.block_type,
            }
        return NotImplemented

    def __hash__(self):
        return hash((self.kind, self.block_type, self.field))

    def __str__(self):
        return "{0}:{1}".format(self.kind, self.block_type)

    def __repr__(self):
        return (
            "<TimestampProvenance kind={0!r} block_type={1!r} field={2!r}>"
        ).format(self.kind, self.block_type, self.field)


class SectionRef(object):
    """Identity of one section within one input source."""

    __slots__ = (
        "source",
        "source_index",
        "section_index",
        "endianness",
        "interfaces",
        "records",
    )

    def __init__(self, source, source_index, section_index, endianness):
        self.source = source
        self.source_index = source_index
        self.section_index = section_index
        self.endianness = endianness
        self.interfaces = []
        self.records = []

    @property
    def key(self):
        return (self.source_index, self.section_index)

    @property
    def id(self):
        return self.key

    def __eq__(self, other):
        return isinstance(other, SectionRef) and self.key == other.key

    def __hash__(self):
        return hash(self.key)

    def __repr__(self):
        return "<SectionRef source={0!r} section={1} endianness={2!r}>".format(
            self.source, self.section_index, self.endianness
        )


class InterfaceRef(object):
    """
    Identity of a pcap-ng interface, scoped to its section.

    Interface ids are only unique within a section.  Carrying the source and
    section index avoids treating interface 0 of one capture as interface 0 of
    another (which is exactly the mistake that produces two different stories
    from the same two files).
    """

    __slots__ = (
        "source",
        "source_index",
        "section_index",
        "interface_id",
        "section_ref",
        "name",
        "records",
    )

    def __init__(
        self,
        source,
        source_index,
        section_index,
        interface_id,
        section_ref=None,
        name=None,
    ):
        self.source = source
        self.source_index = source_index
        self.section_index = section_index
        self.interface_id = interface_id
        self.section_ref = section_ref
        self.name = name
        self.records = []

    @property
    def key(self):
        return (self.source_index, self.section_index, self.interface_id)

    @property
    def id(self):
        return self.interface_id

    @property
    def section_key(self):
        return (self.source_index, self.section_index)

    @property
    def if_name(self):
        return self.name

    def __eq__(self, other):
        return isinstance(other, InterfaceRef) and self.key == other.key

    def __hash__(self):
        return hash(self.key)

    def __repr__(self):
        return (
            "<InterfaceRef source={0!r} section={1} interface={2}>"
        ).format(self.source, self.section_index, self.interface_id)


class SourceRef(object):
    """Identity of one input capture file/stream."""

    __slots__ = ("index", "name", "size")

    def __init__(self, index, name, size=None):
        self.index = index
        self.name = name
        self.size = size

    @property
    def key(self):
        return self.index

    def __repr__(self):
        return "<SourceRef index={0} name={1!r}>".format(self.index, self.name)


class CaptureRecord(object):
    """
    One packet-bearing block, in the order it occurred in its input stream.

    The integer ``tick`` is retained verbatim.  ``timestamp`` is the exact
    local timestamp (tick times resolution, plus ``if_tsoffset``) as a
    :class:`fractions.Fraction`, or ``None`` for a Simple Packet Block.
    Cross-source comparison uses :meth:`CaptureSet.compare`, which applies the
    caller's calibration intervals and returns an interval-aware relation.
    """

    __slots__ = (
        "record_index",
        "source_index",
        "source_name",
        "section_ref",
        "interface_ref",
        "interface_id",
        "block_index",
        "section_order",
        "interface_order",
        "stream_order",
        "tick",
        "timestamp_high",
        "timestamp_low",
        "resolution",
        "tsoffset",
        "block",
        "block_type",
        "packet_data",
        "captured_len",
        "packet_len",
        "provenance",
        "_clock",
    )

    def __init__(
        self,
        record_index,
        source_index,
        source_name,
        section_ref,
        interface_ref,
        interface_id,
        block_index,
        section_order,
        interface_order,
        stream_order,
        tick,
        timestamp_high,
        timestamp_low,
        resolution,
        tsoffset,
        block,
        block_type,
        packet_data,
        captured_len,
        packet_len,
        provenance,
    ):
        self.record_index = record_index
        self.source_index = source_index
        self.source_name = source_name
        self.section_ref = section_ref
        self.interface_ref = interface_ref
        self.interface_id = interface_id
        self.block_index = block_index
        self.section_order = section_order
        self.interface_order = interface_order
        self.stream_order = stream_order
        self.tick = tick
        self.timestamp_high = timestamp_high
        self.timestamp_low = timestamp_low
        self.resolution = _as_fraction(resolution, "timestamp resolution")
        self.tsoffset = _as_fraction(tsoffset, "interface timestamp offset")
        self.block = block
        self.block_type = block_type
        self.packet_data = packet_data
        self.captured_len = captured_len
        self.packet_len = packet_len
        self.provenance = provenance
        self._clock = None

    # -- timestamp/access aliases -------------------------------------

    @property
    def raw_tick(self):
        return self.tick

    @property
    def timestamp(self):
        """Exact local timestamp, or ``None`` if the block has no time."""
        if self.tick is None:
            return None
        return self.tick * self.resolution + self.tsoffset

    @property
    def timestamp_exact(self):
        return self.timestamp

    @property
    def timestamp_fraction(self):
        return self.timestamp

    @property
    def raw_timestamp(self):
        return self.tick

    @property
    def ticks(self):
        return self.tick

    @property
    def local_time(self):
        return self.timestamp

    @property
    def timestamp_float(self):
        """The lossy value for display only; ordering never uses this."""
        value = self.timestamp
        return None if value is None else float(value)

    @property
    def timestamp_resolution(self):
        """Exact resolution (a :class:`fractions.Fraction`)."""
        return self.resolution

    @property
    def resolution_exact(self):
        return self.resolution

    @property
    def timestamp_resolution_exact(self):
        return self.resolution

    @property
    def timestamp_resolution_float(self):
        return float(self.resolution)

    @property
    def has_timestamp(self):
        return self.tick is not None

    @property
    def timestamp_provenance(self):
        return self.provenance

    @property
    def time_provenance(self):
        return self.provenance

    @property
    def timestamp_source(self):
        return self.provenance.source

    @property
    def timestamp_origin(self):
        return self.provenance.source

    @property
    def is_simple_packet(self):
        return self.block_type == "simple_packet"

    @property
    def interface(self):
        return self.block.interface

    @property
    def section(self):
        return self.block.section

    @property
    def source(self):
        return self.source_name

    @property
    def file_index(self):
        return self.source_index

    @property
    def section_index(self):
        return self.section_ref.section_index

    @property
    def interface_key(self):
        return self.interface_ref.key

    @property
    def interface_name(self):
        return self.interface_ref.name

    @property
    def source_file(self):
        return self.source_name

    @property
    def file_name(self):
        return self.source_name

    @property
    def block_type_name(self):
        return self.block_type

    @property
    def section_key(self):
        return self.section_ref.key

    @property
    def stream_key(self):
        # A file is one capture stream.  Sections in the same file are kept in
        # file order; section identity is retained separately on the record.
        return self.source_index

    @property
    def interface_identity(self):
        return self.interface_ref

    @property
    def section_identity(self):
        return self.section_ref

    @property
    def time_interval(self):
        """Calibrated interval on the reference clock, if available."""
        if self._clock is None:
            return None
        return self._clock.record_interval(self)

    calibrated_interval = time_interval

    def compare(self, other, calibrations=_DEFAULT):
        """Compare this record with another one (see :class:`CaptureSet`)."""
        if self._clock is None:
            raise ForensicError("record is not attached to a CaptureSet")
        return self._clock.owner.compare(self, other, calibrations=calibrations)

    def __repr__(self):
        return (
            "<CaptureRecord #{0} interface={1!r} tick={2!r} "
            "resolution={3!r} block={4}>"
        ).format(
            self.record_index,
            self.interface_ref,
            self.tick,
            self.resolution,
            self.block_type,
        )


class ClockCalibration(object):
    """
    A calibration interval for one interface's clock.

    :param interface:
        interface selector.  Accepted forms are an :class:`InterfaceRef`, a
        section-scoped tuple ``(source_index, section_index, interface_id)``,
        ``(source_index, interface_id)`` for single-section sources, a source
        name, the interface's ``if_name``, an interface id integer, or the
        :class:`pcapng.blocks.InterfaceDescription` object.
    :param low/high:
        closed interval, in seconds, added to the local timestamp to obtain
        the common reference clock.  They are absolute offsets, not a
        width/uncertainty pair.
    :param anchor_group:
        optional caller supplied identifier for the anchor group that produced
        the interval.  Stream-order conflicts report these identifiers.
    :param anchors:
        optional iterable of anchors.  Each anchor can be ``(tick, ref)`` or
        ``(tick, ref_low, ref_high)``, where ``ref`` values are reference-clock
        seconds.  Alternatively a mapping with ``tick`` and ``ref`` (or
        ``reference``) keys is accepted.  Anchors are intersected to produce
        the offset interval.
    :param resolution:
        optional exact local resolution used to interpret anchor ticks.  If
        omitted, the resolution of the selected interface is used.
    :param uncertainty:
        convenience for a point midpoint plus/minus this many seconds.
    """

    __slots__ = (
        "interface",
        "low",
        "high",
        "anchor_group",
        "anchors",
        "resolution",
        "uncertainty",
    )

    def __init__(
        self,
        interface=None,
        low=None,
        high=None,
        anchor_group=None,
        anchors=None,
        resolution=None,
        uncertainty=None,
        id=None,
        group=None,
        offset_low=None,
        offset_high=None,
        **kwargs
    ):
        if isinstance(low, (tuple, list)) and len(low) == 2:
            if high is None:
                low, high = low
            elif not _is_number(high) and anchor_group is None:
                anchor_group = high
                low, high = low
        # Accept ClockCalibration({...}) and common keyword spellings.
        if isinstance(interface, dict):
            data = dict(interface)
            interface = data.pop("interface", None)
            if interface is None and any(
                key in data for key in ("source", "section", "interface_id")
            ):
                source = data.pop("source", None)
                section = data.pop("section", None)
                interface_id = data.pop("interface_id", None)
                if interface_id is not None:
                    if section is not None:
                        interface = (source, section, interface_id)
                    elif source is not None:
                        interface = (source, interface_id)
                    else:
                        interface = interface_id
            low = data.pop("low", data.pop("offset_low", low))
            high = data.pop("high", data.pop("offset_high", high))
            offset = data.pop(
                "offset",
                data.pop("interval", data.pop("bounds", None)),
            )
            if offset is not None:
                if not isinstance(offset, (tuple, list)) or len(offset) != 2:
                    raise CalibrationError(
                        "offset/interval/bounds must be a (low, high) pair"
                    )
                if low is not None or high is not None:
                    raise CalibrationError(
                        "offset interval conflicts with low/high fields"
                    )
                low, high = offset
            anchor_group = data.pop(
                "anchor_group",
                data.pop("group", data.pop("id", anchor_group)),
            )
            anchors = data.pop("anchors", anchors)
            resolution = data.pop("resolution", resolution)
            uncertainty = data.pop("uncertainty", uncertainty)
            data.update(kwargs)
            if data:
                leftovers = ", ".join(sorted(data))
                raise CalibrationError(
                    "unknown calibration field(s): {0}".format(leftovers)
                )

        if interface is None and any(
            key in kwargs for key in ("source", "section", "interface_id")
        ):
            source = kwargs.pop("source", None)
            section = kwargs.pop("section", None)
            interface_id = kwargs.pop("interface_id", None)
            if interface_id is not None:
                if section is not None:
                    interface = (source, section, interface_id)
                elif source is not None:
                    interface = (source, interface_id)
                else:
                    interface = interface_id
        if "offset" in kwargs or "interval" in kwargs or "bounds" in kwargs:
            offset = kwargs.pop(
                "offset", kwargs.pop("interval", kwargs.pop("bounds", None))
            )
            if not isinstance(offset, (tuple, list)) or len(offset) != 2:
                raise CalibrationError("offset must be a (low, high) pair")
            if low is not None or high is not None:
                raise CalibrationError(
                    "offset interval conflicts with low/high fields"
                )
            low, high = offset
        if anchors is None:
            for anchor_key in ("anchor_groups", "anchor_points", "points"):
                if anchor_key in kwargs:
                    anchors = kwargs.pop(anchor_key)
                    break
        if "group_id" in kwargs and anchor_group is None:
            anchor_group = kwargs.pop("group_id")

        if offset_low is not None:
            if low is not None and low != offset_low:
                raise CalibrationError("low and offset_low disagree")
            low = offset_low
        if offset_high is not None:
            if high is not None and high != offset_high:
                raise CalibrationError("high and offset_high disagree")
            high = offset_high

        if anchor_group is None:
            anchor_group = group if group is not None else id

        if low is None and high is None and anchors is None:
            raise CalibrationError(
                "calibration needs an offset interval or anchor points"
            )
        if (low is None) != (high is None):
            raise CalibrationError("both low and high must be supplied")

        if uncertainty is not None:
            if low is None:
                raise CalibrationError("uncertainty requires a midpoint interval")
            unc = _as_fraction(uncertainty, "uncertainty")
            if unc < 0:
                raise CalibrationError("uncertainty cannot be negative")
            low = _as_fraction(low, "offset") - unc
            high = _as_fraction(high, "offset") + unc
        else:
            if low is not None:
                low = _as_fraction(low, "offset")
            if high is not None:
                high = _as_fraction(high, "offset")

        if low is not None and high < low:
            raise CalibrationError(
                "calibration interval end {0!r} precedes start {1!r}".format(
                    high, low
                )
            )

        self.interface = interface
        self.low = low
        self.high = high
        self.anchor_group = anchor_group
        self.anchors = list(anchors) if anchors is not None else None
        self.resolution = (
            None if resolution is None else _as_fraction(resolution, "resolution")
        )
        self.uncertainty = uncertainty

    @classmethod
    def from_interval(cls, interface, low, high, anchor_group=None):
        """Build a calibration from a closed offset interval."""
        return cls(interface, low, high, anchor_group=anchor_group)

    from_bounds = from_interval
    from_offsets = from_interval

    @classmethod
    def at_offset(cls, interface, offset, anchor_group=None):
        """Build a point calibration (zero-width offset interval)."""
        return cls(interface, offset, offset, anchor_group=anchor_group)

    @classmethod
    def from_anchors(
        cls, interface, anchors, anchor_group=None, resolution=None
    ):
        """Build a calibration by intersecting (tick, reference) anchors."""
        return cls(
            interface=interface,
            anchors=anchors,
            anchor_group=anchor_group,
            resolution=resolution,
        )

    @property
    def offset_low(self):
        return self.low

    @property
    def offset_high(self):
        return self.high

    @property
    def interval(self):
        if self.low is None:
            return None
        return TimeInterval(self.low, self.high)

    @property
    def lower(self):
        return self.low

    @property
    def upper(self):
        return self.high

    @property
    def width(self):
        if self.low is None:
            return None
        return self.high - self.low

    @property
    def source(self):
        if isinstance(self.interface, (tuple, list)) and self.interface:
            return self.interface[0]
        return self.interface

    @property
    def section(self):
        if isinstance(self.interface, (tuple, list)) and len(self.interface) >= 3:
            return self.interface[1]
        return None

    @property
    def interface_id(self):
        if isinstance(self.interface, (tuple, list)):
            return self.interface[-1]
        if isinstance(self.interface, int):
            return self.interface
        return getattr(self.interface, "interface_id", None)

    @property
    def group(self):
        return self.anchor_group

    @property
    def group_id(self):
        return self.anchor_group

    @property
    def id(self):
        return self.anchor_group

    def with_interface(self, interface):
        return ClockCalibration(
            interface=interface,
            low=self.low,
            high=self.high,
            anchor_group=self.anchor_group,
            anchors=self.anchors,
            resolution=self.resolution,
        )

    def __repr__(self):
        return (
            "<ClockCalibration interface={0!r} offset=[{1!r}, {2!r}] "
            "anchor_group={3!r}>"
        ).format(self.interface, self.low, self.high, self.anchor_group)


class AnchorGroup(ClockCalibration):
    """
    Named collection of anchors for one interface clock.

    This is a small convenience wrapper around :class:`ClockCalibration`.
    """

    def __init__(
        self,
        anchors,
        id=None,
        interface=None,
        anchor_group=None,
        resolution=None,
        low=None,
        high=None,
        **kwargs
    ):
        super(AnchorGroup, self).__init__(
            interface=interface,
            low=low,
            high=high,
            anchor_group=anchor_group if anchor_group is not None else id,
            anchors=anchors,
            resolution=resolution,
            **kwargs
        )


# Friendly aliases.
Calibration = ClockCalibration


class CalibrationEstimate(object):
    """Combined calibration interval for one interface."""

    __slots__ = ("interface_ref", "interval", "groups", "entries", "problems")

    def __init__(
        self, interface_ref, interval=None, groups=(), entries=(), problems=()
    ):
        self.interface_ref = interface_ref
        self.interval = interval
        self.groups = tuple(groups)
        self.entries = tuple(entries)
        self.problems = tuple(problems)

    @property
    def valid(self):
        return self.interval is not None

    @property
    def has_calibration(self):
        return bool(self.entries)

    @property
    def low(self):
        return None if self.interval is None else self.interval.low

    @property
    def high(self):
        return None if self.interval is None else self.interval.high

    def __repr__(self):
        return (
            "<CalibrationEstimate interface={0!r} interval={1!r} groups={2!r}>"
        ).format(self.interface_ref, self.interval, self.groups)


class CalibrationConflict(object):
    """Anchor groups which cannot all be true at the same time."""

    __slots__ = ("interface_ref", "groups", "reason", "entries")

    def __init__(self, interface_ref, groups, reason, entries=()):
        self.interface_ref = interface_ref
        self.groups = tuple(groups)
        self.reason = reason
        self.entries = tuple(entries)

    @property
    def anchor_groups(self):
        return self.groups

    def __repr__(self):
        return (
            "<CalibrationConflict interface={0!r} groups={1!r} reason={2!r}>"
        ).format(self.interface_ref, self.groups, self.reason)


class StreamConflict(object):
    """
    A calibration result that contradicts the order in one capture stream.

    ``first`` and ``second`` are in their original stream order.  The
    calibration says ``second`` definitely happened before ``first``.  The
    records are *not* reordered; ``anchor_groups`` identifies the calibration
    anchors responsible for the contradiction.
    """

    __slots__ = (
        "stream_key",
        "source",
        "first",
        "second",
        "ordering",
        "anchor_groups",
        "reason",
    )

    def __init__(
        self,
        stream_key,
        source,
        first,
        second,
        ordering,
        anchor_groups,
        reason=None,
    ):
        self.stream_key = stream_key
        self.source = source
        self.first = first
        self.second = second
        self.ordering = ordering
        self.anchor_groups = tuple(anchor_groups)
        self.reason = reason or (
            "calibration says record #{0} happened before record #{1}, "
            "but record #{0} occurs later in the capture stream".format(
                second.record_index, first.record_index
            )
        )

    @property
    def groups(self):
        return self.anchor_groups

    @property
    def group_ids(self):
        return self.anchor_groups

    @property
    def first_anchor_groups(self):
        clock = self.first._clock
        if clock is None:
            return ()
        return clock.estimate_for(self.first.interface_ref).groups

    @property
    def second_anchor_groups(self):
        clock = self.second._clock
        if clock is None:
            return ()
        return clock.estimate_for(self.second.interface_ref).groups

    @property
    def earlier(self):
        return self.first

    @property
    def later(self):
        return self.second

    @property
    def anchor_group(self):
        if len(self.anchor_groups) == 1:
            return self.anchor_groups[0]
        return self.anchor_groups

    def as_dict(self):
        return {
            "stream_key": self.stream_key,
            "source": self.source,
            "first": self.first.record_index,
            "second": self.second.record_index,
            "ordering": self.ordering.value,
            "anchor_groups": list(self.anchor_groups),
            "reason": self.reason,
        }

    def __repr__(self):
        return (
            "<StreamConflict source={0!r} first=#{1} second=#{2} "
            "anchor_groups={3!r}>"
        ).format(
            self.source,
            self.first.record_index,
            self.second.record_index,
            self.anchor_groups,
        )


class Comparison(object):
    """
    Interval-aware comparison of two capture records.

    The object compares equal to its :class:`Ordering` (and to its string
    value), so ``capture.compare(a, b) == Ordering.BEFORE`` is valid while the
    extra information remains available as attributes.
    """

    __slots__ = (
        "left",
        "right",
        "ordering",
        "left_interval",
        "right_interval",
        "anchor_groups",
        "reason",
        "stream_conflict",
    )

    def __init__(
        self,
        left,
        right,
        ordering,
        left_interval=None,
        right_interval=None,
        anchor_groups=(),
        reason=None,
        stream_conflict=None,
    ):
        self.left = left
        self.right = right
        self.ordering = Ordering(ordering)
        self.left_interval = left_interval
        self.right_interval = right_interval
        self.anchor_groups = tuple(anchor_groups)
        self.reason = reason
        self.stream_conflict = stream_conflict

    @property
    def relation(self):
        return self.ordering

    @property
    def groups(self):
        return self.anchor_groups

    @property
    def definite(self):
        return self.ordering.definite

    @property
    def is_definite(self):
        return self.ordering.definite

    @property
    def overlap(self):
        return self.ordering is Ordering.OVERLAP

    @property
    def incomparable(self):
        return self.ordering is Ordering.INCOMPARABLE

    @property
    def stream_relation(self):
        """Relation established solely by position in one capture stream."""
        if self.left is self.right:
            return Ordering.OVERLAP
        if self.left.stream_key != self.right.stream_key:
            return Ordering.INCOMPARABLE
        if self.left.stream_order < self.right.stream_order:
            return Ordering.BEFORE
        return Ordering.AFTER

    @property
    def in_stream_order(self):
        return self.stream_relation is Ordering.BEFORE

    @property
    def has_conflict(self):
        return self.stream_conflict is not None

    @property
    def conflict(self):
        return self.stream_conflict

    @property
    def value(self):
        return self.ordering.value

    def reversed(self):
        flipped = {
            Ordering.BEFORE: Ordering.AFTER,
            Ordering.AFTER: Ordering.BEFORE,
            Ordering.OVERLAP: Ordering.OVERLAP,
            Ordering.INCOMPARABLE: Ordering.INCOMPARABLE,
        }[self.ordering]
        return Comparison(
            self.right,
            self.left,
            flipped,
            self.right_interval,
            self.left_interval,
            self.anchor_groups,
            self.reason,
            self.stream_conflict,
        )

    def as_dict(self):
        return {
            "left": self.left.record_index,
            "right": self.right.record_index,
            "ordering": self.ordering.value,
            "stream_relation": self.stream_relation.value,
            "left_interval": _interval_dict(self.left_interval),
            "right_interval": _interval_dict(self.right_interval),
            "anchor_groups": list(self.anchor_groups),
            "reason": self.reason,
        }

    def __eq__(self, other):
        if isinstance(other, Comparison):
            return (
                self.left.record_index == other.left.record_index
                and self.right.record_index == other.right.record_index
                and self.ordering == other.ordering
            )
        if isinstance(other, Ordering):
            return self.ordering == other
        if isinstance(other, str):
            return self.ordering.value == other
        return NotImplemented

    def __hash__(self):
        return hash((self.left.record_index, self.right.record_index, self.ordering))

    def __bool__(self):
        return self.ordering.definite

    __nonzero__ = __bool__

    def __str__(self):
        return self.ordering.value

    def __repr__(self):
        return "<Comparison #{0} {1} #{2}>".format(
            self.left.record_index, self.ordering.value, self.right.record_index
        )


class CalibrationSet(object):
    """Normalised calibration entries and their per-interface intersection."""

    __slots__ = ("owner", "entries", "_cache", "_conflicts")

    def __init__(self, calibrations=None, owner=None):
        self.owner = owner
        calibrations = _calibrations_by_source_order(calibrations, owner)
        self.entries = _normalise_calibrations(calibrations)
        self._cache = {}
        self._conflicts = None

    def _matching(self, interface_ref):
        return [
            entry
            for entry in self.entries
            if _calibration_matches(entry.interface, interface_ref, self.owner)
        ]

    def estimate_for(self, interface_ref):
        cached = self._cache.get(interface_ref)
        if cached is not None:
            return cached

        entries = self._matching(interface_ref)
        groups = _unique_groups(
            entry.anchor_group
            if entry.anchor_group is not None
            else "calibration[{0}]".format(self.entries.index(entry))
            for entry in entries
        )
        if not entries:
            estimate = CalibrationEstimate(interface_ref)
            self._cache[interface_ref] = estimate
            return estimate

        interval = None
        problems = []
        for entry in entries:
            try:
                entry_interval = _calibration_interval(entry, interface_ref, self.owner)
            except CalibrationError as exc:
                problems.append(str(exc))
                continue
            if interval is None:
                interval = entry_interval
            else:
                interval = interval.intersection(entry_interval)
                if interval is None:
                    problems.append(
                        "calibration intervals do not intersect"
                    )
                    break

        if interval is None or problems:
            estimate = CalibrationEstimate(
                interface_ref,
                interval=None,
                groups=groups,
                entries=entries,
                problems=problems,
            )
        else:
            estimate = CalibrationEstimate(
                interface_ref,
                interval=interval,
                groups=groups,
                entries=entries,
            )
        self._cache[interface_ref] = estimate
        return estimate

    @property
    def conflicts(self):
        if self._conflicts is None:
            conflicts = []
            refs = OrderedDict()
            for entry in self.entries:
                for ref in self._refs_matching(entry.interface):
                    refs[ref] = None
            for ref in refs:
                estimate = self.estimate_for(ref)
                if estimate.entries and not estimate.valid:
                    conflicts.append(
                        CalibrationConflict(
                            ref,
                            estimate.groups,
                            "; ".join(estimate.problems)
                            or "calibration interval unavailable",
                            estimate.entries,
                        )
                    )
            self._conflicts = conflicts
        return self._conflicts

    def _refs_matching(self, selector):
        if self.owner is None:
            return []
        return [
            ref
            for ref in self.owner.interfaces
            if _calibration_matches(selector, ref, self.owner)
        ]

    def record_interval(self, record):
        return self._record_interval(record, record.interface_ref)

    def _record_interval(self, record, interface_ref):
        if record.tick is None:
            return None
        estimate = self.estimate_for(interface_ref)
        if not estimate.valid:
            return None
        local = record.tick * record.resolution + record.tsoffset
        return TimeInterval(
            local + estimate.interval.low, local + estimate.interval.high
        )

    def __bool__(self):
        return bool(self.entries)

    __nonzero__ = __bool__

    def __repr__(self):
        return "<CalibrationSet entries={0}>".format(len(self.entries))


class CaptureSet(object):
    """
    Read-only collection of capture records and their calibration context.

    Iteration and :attr:`records` always follow input order (file order, then
    section order, then block order).  There is deliberately no implicit
    timestamp sort: calibration may contradict stream order, and that
    contradiction is reported through :attr:`conflicts`.
    """

    def __init__(
        self,
        sources,
        calibrations=None,
        names=None,
        include_statistics=False,
        calibration_intervals=None,
    ):
        if calibrations is None:
            calibrations = calibration_intervals
        self.sources = []
        self.sections = []
        self.interfaces = []
        self.records = []
        self.include_statistics = include_statistics
        self._interface_by_block_id = {}
        self._resolution_by_interface = {}
        self._sections_by_source = defaultdict(list)
        self._source_streams = []
        self._parse(sources, names=names)
        self.calibrations = CalibrationSet(calibrations, owner=self)
        for record in self.records:
            record._clock = self.calibrations
        self._conflicts = None

    # -- parsing ------------------------------------------------------

    def _parse(self, sources, names=None):
        source_specs = _normalise_sources(sources, names)
        for source_index, (source_name, stream, close_stream) in enumerate(
            source_specs
        ):
            try:
                self._parse_one_source(source_index, source_name, stream)
            finally:
                if close_stream:
                    stream.close()

    def _parse_one_source(self, source_index, source_name, stream):
        source_ref = SourceRef(source_index, source_name)
        self.sources.append(source_ref)
        self._source_streams.append(source_name)

        section_ref = None
        section_index = -1
        section_order = 0
        stream_order = 0
        interface_order = defaultdict(int)
        block_index = -1

        scanner = FileScanner(stream)
        for block_index, block in enumerate(scanner):
            if isinstance(block, SectionHeader):
                section_index += 1
                section_order = 0
                section_ref = SectionRef(
                    source_name, source_index, section_index, block.endianness
                )
                self.sections.append(section_ref)
                self._sections_by_source[source_index].append(section_ref)
                continue

            if isinstance(block, InterfaceDescription):
                if section_ref is None:
                    raise ForensicError(
                        "interface block outside a section in {0!r}".format(
                            source_name
                        )
                    )
                name = block.options.get("if_name") if block.options else None
                ref = InterfaceRef(
                    source_name,
                    source_index,
                    section_index,
                    block.interface_id,
                    section_ref=section_ref,
                    name=name,
                )
                self.interfaces.append(ref)
                if section_ref is not None:
                    section_ref.interfaces.append(ref)
                self._interface_by_block_id[id(block)] = ref
                self._resolution_by_interface[ref] = (
                    block.timestamp_resolution_exact
                )
                continue

            if not _is_packet_block(block, self.include_statistics):
                continue
            if section_ref is None:
                continue

            interface_block = block.interface
            interface_ref = self._interface_by_block_id.get(id(interface_block))
            if interface_ref is None:
                # Be defensive about unusual streams where an interface
                # description was not observed: retain identity anyway.
                interface_ref = InterfaceRef(
                    source_name,
                    source_index,
                    section_index,
                    block.interface_id,
                    section_ref=section_ref,
                )
                self.interfaces.append(interface_ref)
                if section_ref is not None:
                    section_ref.interfaces.append(interface_ref)
                self._resolution_by_interface[interface_ref] = (
                    interface_block.timestamp_resolution_exact
                )

            resolution = self._resolution_by_interface.get(
                interface_ref, interface_block.timestamp_resolution_exact
            )
            record = self._make_record(
                source_index=source_index,
                source_name=source_name,
                section_ref=section_ref,
                interface_ref=interface_ref,
                interface_block=interface_block,
                block=block,
                block_index=block_index,
                section_order=section_order,
                interface_order=interface_order[interface_ref],
                stream_order=stream_order,
                resolution=resolution,
            )
            self.records.append(record)
            if section_ref is not None:
                section_ref.records.append(record)
            interface_ref.records.append(record)
            section_order += 1
            interface_order[interface_ref] += 1
            stream_order += 1

    def _make_record(
        self,
        source_index,
        source_name,
        section_ref,
        interface_ref,
        interface_block,
        block,
        block_index,
        section_order,
        interface_order,
        stream_order,
        resolution,
    ):
        record_index = len(self.records)
        tsoffset = interface_block.timestamp_offset
        packet_data = getattr(block, "packet_data", b"")
        captured_len = _safe_len(block, "captured_len", packet_data)
        packet_len = _safe_len(block, "packet_len", captured_len)

        if isinstance(block, SimplePacket):
            provenance = TimestampProvenance(
                kind="absent",
                block_type="simple_packet",
                field=None,
                detail=(
                    "Simple Packet Block has no timestamp field; only its "
                    "capture-stream position and interface identity are "
                    "available"
                ),
                section_ref=section_ref,
                interface_ref=interface_ref,
                stream_order=stream_order,
            )
            return CaptureRecord(
                record_index=record_index,
                source_index=source_index,
                source_name=source_name,
                section_ref=section_ref,
                interface_ref=interface_ref,
                interface_id=block.interface_id,
                block_index=block_index,
                section_order=section_order,
                interface_order=interface_order,
                stream_order=stream_order,
                tick=None,
                timestamp_high=None,
                timestamp_low=None,
                resolution=resolution,
                tsoffset=tsoffset,
                block=block,
                block_type="simple_packet",
                packet_data=packet_data,
                captured_len=captured_len,
                packet_len=packet_len,
                provenance=provenance,
            )

        high = block.timestamp_high
        low = block.timestamp_low
        tick = (high << 32) | low
        block_type = _block_type_name(block)
        provenance = TimestampProvenance(
            kind="block",
            block_type=block_type,
            field="timestamp_high/timestamp_low",
            detail="timestamp supplied by the {0} block".format(
                block.__class__.__name__
            ),
            section_ref=section_ref,
            interface_ref=interface_ref,
            stream_order=stream_order,
        )
        return CaptureRecord(
            record_index=record_index,
            source_index=source_index,
            source_name=source_name,
            section_ref=section_ref,
            interface_ref=interface_ref,
            interface_id=block.interface_id,
            block_index=block_index,
            section_order=section_order,
            interface_order=interface_order,
            stream_order=stream_order,
            tick=tick,
            timestamp_high=high,
            timestamp_low=low,
            resolution=resolution,
            tsoffset=tsoffset,
            block=block,
            block_type=block_type,
            packet_data=packet_data,
            captured_len=captured_len,
            packet_len=packet_len,
            provenance=provenance,
        )

    # -- collection behaviour ----------------------------------------

    def __iter__(self):
        return iter(self.records)

    def __len__(self):
        return len(self.records)

    def __getitem__(self, index):
        return self.records[index]

    @property
    def timeline(self):
        """Records in original stream order (never silently re-sorted)."""
        return list(self.records)

    @property
    def ordered_records(self):
        return list(self.records)

    def records_in_stream_order(self):
        return list(self.records)

    def record(self, value):
        if isinstance(value, CaptureRecord):
            return value
        return self.records[value]

    def records_for_interface(self, interface_ref):
        return [
            record
            for record in self.records
            if record.interface_ref == interface_ref
        ]

    def resolution_for(self, interface_ref):
        return self._resolution_by_interface.get(interface_ref)

    def with_calibrations(self, calibrations):
        """
        Return a new read-only view of the same records with a new
        calibration context.

        The original capture and its records are not modified.  Passing
        None removes calibration (useful for demonstrating that a
        cross-source order conclusion depends on the anchors).
        """
        clone = object.__new__(CaptureSet)
        clone.sources = list(self.sources)
        clone.sections = list(self.sections)
        clone.interfaces = list(self.interfaces)
        clone.include_statistics = self.include_statistics
        clone._interface_by_block_id = dict(self._interface_by_block_id)
        clone._resolution_by_interface = dict(self._resolution_by_interface)
        clone._sections_by_source = dict(self._sections_by_source)
        clone._source_streams = list(self._source_streams)
        clone.records = [copy.copy(record) for record in self.records]
        clone.calibrations = CalibrationSet(calibrations, owner=clone)
        for record in clone.records:
            record._clock = clone.calibrations
        clone._conflicts = None
        return clone

    def without_calibrations(self):
        return self.with_calibrations(None)

    replace_calibrations = with_calibrations
    recalibrate = with_calibrations

    def sorted_by_calibrated_time(self, calibrations=_DEFAULT):
        """
        Return a newly sorted list, explicitly requested by the caller.

        The original :attr:`records` list is never mutated.  Records with no
        comparable calibrated interval are kept at the end in stream order.
        """
        clock = self._clock_for(calibrations)
        comparable = []
        incomparable = []
        for record in self.records:
            interval = clock.record_interval(record)
            if interval is None:
                incomparable.append(record)
            else:
                comparable.append((interval.low, interval.high, record))
        comparable.sort(key=lambda item: (item[0], item[1], item[2].record_index))
        return [item[2] for item in comparable] + incomparable

    # -- comparison ---------------------------------------------------

    def _clock_for(self, calibrations):
        if calibrations is _DEFAULT:
            return self.calibrations
        return CalibrationSet(calibrations, owner=self)

    def compare(self, left, right, calibrations=_DEFAULT):
        left = self.record(left)
        right = self.record(right)
        if left is right:
            return Comparison(
                left,
                right,
                Ordering.OVERLAP,
                reason="a record compared with itself overlaps itself",
                anchor_groups=self._groups_for(
                    left, right, self._clock_for(calibrations)
                ),
            )

        clock = self._clock_for(calibrations)
        result = self._compare_with_clock(left, right, clock)
        if (
            result.ordering is Ordering.AFTER
            and left.stream_key == right.stream_key
            and left.stream_order < right.stream_order
            and (
                clock.estimate_for(left.interface_ref).has_calibration
                or clock.estimate_for(right.interface_ref).has_calibration
            )
        ):
            result.stream_conflict = self._make_conflict(
                left, right, result.ordering, clock
            )
        return result

    compare_records = compare

    def _compare_with_clock(self, left, right, clock):
        left_estimate = clock.estimate_for(left.interface_ref)
        right_estimate = clock.estimate_for(right.interface_ref)

        if left.tick is None or right.tick is None:
            return Comparison(
                left,
                right,
                Ordering.INCOMPARABLE,
                anchor_groups=_merge_groups(
                    left_estimate.groups, right_estimate.groups
                ),
                reason="at least one record has no timestamp",
            )

        if left_estimate.valid and right_estimate.valid:
            left_interval = clock.record_interval(left)
            right_interval = clock.record_interval(right)
            ordering = left_interval.relation(right_interval)
            groups = _merge_groups(
                left_estimate.groups, right_estimate.groups
            )
            reason = {
                Ordering.BEFORE: "calibrated time intervals are disjoint",
                Ordering.AFTER: "calibrated time intervals are disjoint",
                Ordering.OVERLAP: "calibrated time intervals overlap",
            }[ordering]
            return Comparison(
                left,
                right,
                ordering,
                left_interval,
                right_interval,
                groups,
                reason,
            )

        # No calibration was supplied for one or both clocks.  Ticks from
        # different interface identities are not assumed to share an epoch,
        # even if their numeric values happen to be close.
        if (
            left.interface_ref == right.interface_ref
            and not left_estimate.has_calibration
            and not right_estimate.has_calibration
        ):
            left_interval = TimeInterval(left.timestamp)
            right_interval = TimeInterval(right.timestamp)
            ordering = left_interval.relation(right_interval)
            return Comparison(
                left,
                right,
                ordering,
                left_interval,
                right_interval,
                (),
                "same interface clock; exact local ticks compared",
            )

        problems = []
        for estimate in (left_estimate, right_estimate):
            problems.extend(estimate.problems)
        if problems:
            reason = "calibration is unusable: " + "; ".join(problems)
        else:
            reason = (
                "clocks are unrelated: no calibration interval for at least "
                "one interface"
            )
        return Comparison(
            left,
            right,
            Ordering.INCOMPARABLE,
            anchor_groups=_merge_groups(
                left_estimate.groups, right_estimate.groups
            ),
            reason=reason,
        )

    def _groups_for(self, left, right, clock):
        return _merge_groups(
            clock.estimate_for(left.interface_ref).groups,
            clock.estimate_for(right.interface_ref).groups,
        )

    def _make_conflict(self, first, second, ordering, clock=None):
        if clock is None:
            clock = self.calibrations
        groups = _merge_groups(
            clock.estimate_for(first.interface_ref).groups,
            clock.estimate_for(second.interface_ref).groups,
        )
        return StreamConflict(
            first.stream_key,
            first.source_name,
            first,
            second,
            ordering,
            groups,
        )

    @property
    def conflicts(self):
        """Calibration conclusions that contradict stream order."""
        if self._conflicts is None:
            self._conflicts = self.find_conflicts()
        return self._conflicts

    def find_conflicts(self, calibrations=_DEFAULT):
        """
        Return stream-order conflicts without changing record order.

        Detection is linear in the number of records per source.  It keeps the
        earlier record whose calibrated lower bound is greatest; if a later
        record's interval lies strictly before that boundary, the two records
        are definitely reversed by the calibration.
        """
        clock = self._clock_for(calibrations)
        conflicts = []
        by_stream = OrderedDict()
        for record in self.records:
            by_stream.setdefault(record.stream_key, []).append(record)

        for stream_key, records in by_stream.items():
            best = None
            best_interval = None
            for record in records:
                interval = clock.record_interval(record)
                if interval is None:
                    continue
                if best is not None and interval.high < best_interval.low:
                    groups = _merge_groups(
                        clock.estimate_for(best.interface_ref).groups,
                        clock.estimate_for(record.interface_ref).groups,
                    )
                    conflicts.append(
                        StreamConflict(
                            stream_key,
                            record.source_name,
                            best,
                            record,
                            Ordering.AFTER,
                            groups,
                        )
                    )
                if best is None or interval.low > best_interval.low:
                    best = record
                    best_interval = interval
        return conflicts

    @property
    def calibration_intervals(self):
        return self.calibrations

    @property
    def calibration_conflicts(self):
        return self.calibrations.conflicts

    @property
    def anchor_conflicts(self):
        return self.calibrations.conflicts

    @property
    def calibration_problems(self):
        return self.calibrations.conflicts

    def __repr__(self):
        return (
            "<CaptureSet sources={0} sections={1} interfaces={2} records={3}>"
        ).format(
            len(self.sources),
            len(self.sections),
            len(self.interfaces),
            len(self.records),
        )


# ``Timeline`` is a descriptive alias for the same read-only collection.
Timeline = CaptureSet


class ForensicReader(object):
    """
    Small read-only facade for callers that prefer an explicit reader object.

    ``ForensicReader(sources, calibrations=...).read()`` returns a
    :class:`CaptureSet`; iterating the reader yields its records.
    """

    def __init__(self, sources, calibrations=None, names=None, **kwargs):
        self.sources = sources
        self.calibrations = calibrations
        self.names = names
        self.kwargs = kwargs
        self._capture = None

    def read(self):
        if self._capture is None:
            self._capture = read_captures(
                self.sources,
                calibrations=self.calibrations,
                names=self.names,
                **self.kwargs
            )
        return self._capture

    def __iter__(self):
        return iter(self.read())

    def __len__(self):
        return len(self.read())

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.read(), name)


def read_captures(
    sources=None,
    calibrations=None,
    names=None,
    include_statistics=False,
    files=None,
    calibration_intervals=None,
):
    """
    Read one or more pcap-ng sources into a read-only :class:`CaptureSet`.

    :param sources:
        a path, binary file-like object, ``bytes``/``bytearray``/``memoryview``
        containing a whole capture, or an iterable of those.  In-memory sources
        are never written to and are kept open only for the duration of the
        read.
    :param calibrations:
        calibration intervals/anchor groups.  See :class:`ClockCalibration`.
    :param names:
        optional source label or iterable of labels.  Labels are useful for
        in-memory captures and for selecting calibrations by name.
    :param include_statistics:
        also include Interface Statistics Blocks (they carry timestamps but
        are not packets; default false).
    """
    if calibrations is None:
        calibrations = calibration_intervals
    if sources is None:
        sources = files
    elif files is not None:
        raise TypeError("pass either sources or files, not both")
    if sources is None:
        raise TypeError("read_captures needs at least one source")
    if (
        calibrations is not None
        and _looks_like_single_source(sources)
        and _looks_like_single_source(calibrations)
    ):
        # Convenience for read_captures(first, second) as well as
        # read_captures([first, second], calibrations=...).
        sources = [sources, calibrations]
        calibrations = None
    return CaptureSet(
        sources,
        calibrations=calibrations,
        names=names,
        include_statistics=include_statistics,
    )


def load_captures(*args, **kwargs):
    """Alias of :func:`read_captures`."""
    return read_captures(*args, **kwargs)


build_timeline = read_captures
read_timeline = read_captures
read_forensic = read_captures
load_forensic = read_captures
correlate = read_captures
read_files = read_captures
load_files = read_captures
scan_captures = read_captures


def compare_records(left, right, calibrations=_DEFAULT):
    """
    Compare two :class:`CaptureRecord` objects.

    If they came from a :class:`CaptureSet`, its calibration context is used
    unless ``calibrations`` is supplied.  An explicit ``None`` removes all
    calibration for this comparison.
    """
    if not isinstance(left, CaptureRecord) or not isinstance(right, CaptureRecord):
        raise TypeError("compare_records expects CaptureRecord objects")
    if left._clock is None or right._clock is None:
        raise ForensicError("records are not attached to a CaptureSet")
    # Records from two independently-read sets are still comparable: the
    # interface references carry enough identity and the caller can supply
    # calibration intervals explicitly.
    return left._clock.owner.compare(left, right, calibrations=calibrations)


def compare(left, right, calibrations=_DEFAULT):
    """Alias of :func:`compare_records`."""
    return compare_records(left, right, calibrations=calibrations)


def compare_ticks(
    tick_a,
    resolution_a,
    tick_b,
    resolution_b,
    offset_a=(0, 0),
    offset_b=(0, 0),
):
    """
    Compare two raw ticks with exact arithmetic.

    Offsets are calibration intervals ``(low, high)`` in seconds.  The return
    value is an :class:`Ordering`.  This helper is useful for independently
    checking the core precision guarantee without building a capture set.
    """
    interval_a = TimeInterval(
        Fraction(tick_a) * _as_fraction(resolution_a, "resolution")
        + _as_fraction(offset_a[0], "offset"),
        Fraction(tick_a) * _as_fraction(resolution_a, "resolution")
        + _as_fraction(offset_a[1], "offset"),
    )
    interval_b = TimeInterval(
        Fraction(tick_b) * _as_fraction(resolution_b, "resolution")
        + _as_fraction(offset_b[0], "offset"),
        Fraction(tick_b) * _as_fraction(resolution_b, "resolution")
        + _as_fraction(offset_b[1], "offset"),
    )
    return interval_a.relation(interval_b)


def _is_packet_block(block, include_statistics):
    if isinstance(block, (EnhancedPacket, SimplePacket, ObsoletePacket)):
        return True
    return include_statistics and isinstance(block, InterfaceStatistics)


def _block_type_name(block):
    if isinstance(block, EnhancedPacket):
        return "enhanced_packet"
    if isinstance(block, SimplePacket):
        return "simple_packet"
    if isinstance(block, ObsoletePacket):
        return "obsolete_packet"
    if isinstance(block, InterfaceStatistics):
        return "interface_statistics"
    return block.__class__.__name__.lower()


def _safe_len(block, attribute, fallback):
    try:
        value = getattr(block, attribute)
    except Exception:
        return fallback
    return fallback if value is None else value


def _as_fraction(value, what="value"):
    if isinstance(value, Fraction):
        return value
    if isinstance(value, bool):
        return Fraction(int(value))
    if isinstance(value, int):
        return Fraction(value)
    try:
        from decimal import Decimal

        if isinstance(value, Decimal):
            return Fraction(value)
    except ImportError:  # pragma: no cover - decimal is always available
        pass
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("{0} must be finite".format(what))
        # A caller writing 1e-9 means the decimal value, not its binary
        # approximation.  Fraction(str(value)) preserves that intent.
        return Fraction(str(value))
    if isinstance(value, str):
        return Fraction(value)
    if hasattr(value, "numerator") and hasattr(value, "denominator"):
        return Fraction(value.numerator, value.denominator)
    raise TypeError("cannot convert {0!r} to an exact {1}".format(value, what))


def _as_interval(value):
    if isinstance(value, TimeInterval):
        return value
    if isinstance(value, (tuple, list)):
        if len(value) == 1:
            return TimeInterval(value[0])
        if len(value) == 2:
            return TimeInterval(value[0], value[1])
    raise TypeError("expected a TimeInterval or (low, high) pair")


def _interval_dict(interval):
    if interval is None:
        return None
    return {
        "low": str(interval.low),
        "high": str(interval.high),
        "low_numerator": interval.low.numerator,
        "low_denominator": interval.low.denominator,
        "high_numerator": interval.high.numerator,
        "high_denominator": interval.high.denominator,
    }


def _normalise_sources(sources, names):
    if _looks_like_single_source(sources):
        source_list = [sources]
    else:
        try:
            source_list = list(sources)
        except TypeError:
            source_list = [sources]

    if names is None:
        name_list = [None] * len(source_list)
    elif isinstance(names, str):
        name_list = [names] + [None] * (len(source_list) - 1)
    else:
        name_list = list(names)
        if len(name_list) < len(source_list):
            name_list.extend([None] * (len(source_list) - len(name_list)))

    result = []
    for index, source in enumerate(source_list):
        name = name_list[index]
        if isinstance(source, tuple) and len(source) == 2 and isinstance(
            source[0], str
        ):
            if name is None:
                name = source[0]
            source = source[1]

        if isinstance(source, (bytes, bytearray, memoryview)):
            data = bytes(source)
            stream = io.BytesIO(data)
            stream_name = name or "<memory:{0}>".format(index)
            result.append((stream_name, stream, True))
            continue

        if isinstance(source, _PATH_TYPES):
            path = os.fspath(source)
            stream = open(path, "rb")
            stream_name = name or path
            result.append((stream_name, stream, True))
            continue

        if hasattr(source, "read"):
            stream_name = (
                name
                or getattr(source, "name", None)
                or "<memory:{0}>".format(index)
            )
            result.append((stream_name, source, False))
            continue

        raise TypeError(
            "unsupported capture source {0!r}; expected bytes, a path or a "
            "file-like object".format(source)
        )
    return result


def _looks_like_single_source(value):
    if isinstance(value, (bytes, bytearray, memoryview) + _PATH_TYPES):
        return True
    if hasattr(value, "read"):
        return True
    if (
        isinstance(value, tuple)
        and len(value) == 2
        and isinstance(value[0], str)
    ):
        return True
    return False


def _calibrations_by_source_order(calibrations, owner):
    """
    Accept [(low, high), (low, high), ...] as a shorthand for calibrating
    the single interface of each input source, in input order.
    """
    if owner is None or calibrations is None:
        return calibrations
    if isinstance(calibrations, ClockCalibration):
        return calibrations
    if isinstance(calibrations, dict):
        if not calibrations:
            return calibrations
        if not all(
            isinstance(key, int)
            and not isinstance(key, bool)
            and 0 <= key < len(owner.sources)
            for key in calibrations
        ):
            return calibrations
        converted = []
        for source_index, value in calibrations.items():
            refs = [
                ref
                for ref in owner.interfaces
                if ref.source_index == source_index
            ]
            if len(refs) != 1:
                return calibrations
            converted.extend(_calibrations_from_mapping(refs[0], value))
        return converted
    if not isinstance(calibrations, (list, tuple)):
        return calibrations
    if len(calibrations) != len(owner.sources) or not calibrations:
        return calibrations
    keys = []
    for item in calibrations:
        if not (
            isinstance(item, (tuple, list))
            and len(item) == 2
            and _is_number(item[0])
            and _is_number(item[1])
        ):
            return calibrations
    for source_index, source in enumerate(owner.sources):
        refs = [
            ref
            for ref in owner.interfaces
            if ref.source_index == source_index
        ]
        if len(refs) != 1:
            return calibrations
        keys.append(ClockCalibration(refs[0], *calibrations[source_index]))
    return keys


def _normalise_calibrations(calibrations):
    if calibrations is None:
        return []
    if isinstance(calibrations, ClockCalibration):
        return [calibrations]
    if isinstance(calibrations, dict):
        entries = []
        for selector, value in calibrations.items():
            entries.extend(_calibrations_from_mapping(selector, value))
        return entries
    try:
        items = list(calibrations)
    except TypeError:
        raise CalibrationError(
            "calibrations must be a ClockCalibration, mapping or iterable"
        )
    entries = []
    for item in items:
        if isinstance(item, ClockCalibration):
            entries.append(item)
        elif isinstance(item, dict):
            entries.append(ClockCalibration(item))
        else:
            raise CalibrationError(
                "unsupported calibration entry {0!r}".format(item)
            )
    return entries


def _calibrations_from_mapping(selector, value):
    if isinstance(value, ClockCalibration):
        if value.interface is None:
            return [value.with_interface(selector)]
        return [value]
    if isinstance(value, dict):
        # A mapping may describe one calibration or a set of named groups.
        calibration_fields = {
            "interface",
            "low",
            "high",
            "offset_low",
            "offset_high",
            "anchors",
            "anchor_group",
            "group",
            "id",
            "resolution",
            "uncertainty",
        }
        if calibration_fields.intersection(value):
            data = dict(value)
            data.setdefault("interface", selector)
            return [ClockCalibration(data)]
        entries = []
        for group_id, group_value in value.items():
            entries.extend(
                _calibrations_from_mapping(
                    selector,
                    _with_group_id(group_value, group_id),
                )
            )
        return entries
    if isinstance(value, (tuple, list)):
        if len(value) == 2 and _is_number(value[0]) and _is_number(value[1]):
            return [ClockCalibration(selector, value[0], value[1])]
        if (
            len(value) == 2
            and isinstance(value[0], str)
            and isinstance(value[1], (tuple, list, dict, ClockCalibration))
        ):
            return _calibrations_from_mapping(
                selector, _with_group_id(value[1], value[0])
            )
        if len(value) == 0:
            return []
        entries = []
        for item in value:
            entries.extend(_calibrations_from_mapping(selector, item))
        return entries
    if _is_number(value):
        return [ClockCalibration(selector, value, value)]
    raise CalibrationError(
        "unsupported calibration value {0!r} for {1!r}".format(value, selector)
    )


def _with_group_id(value, group_id):
    if isinstance(value, ClockCalibration):
        if value.anchor_group is None:
            return ClockCalibration(
                value.interface,
                value.low,
                value.high,
                anchor_group=group_id,
                anchors=value.anchors,
                resolution=value.resolution,
            )
        return value
    if isinstance(value, dict):
        data = dict(value)
        data.setdefault("anchor_group", group_id)
        return data
    if isinstance(value, (tuple, list)) and len(value) == 2 and all(
        _is_number(item) for item in value
    ):
        return {"low": value[0], "high": value[1], "anchor_group": group_id}
    return value


def _is_number(value):
    return isinstance(value, (int, float, Fraction)) or hasattr(
        value, "numerator"
    )


def _unique_groups(groups):
    result = []
    for group in groups:
        if group is None:
            continue
        if group not in result:
            result.append(group)
    return tuple(result)


def _merge_groups(*group_lists):
    result = []
    for groups in group_lists:
        for group in groups:
            if group is None:
                continue
            if group not in result:
                result.append(group)
    return tuple(result)


def _calibration_matches(selector, interface_ref, owner):
    if selector is None:
        return False
    if isinstance(selector, InterfaceRef):
        return selector == interface_ref

    if isinstance(selector, SourceRef):
        return selector.index == interface_ref.source_index

    if isinstance(selector, SectionRef):
        return (
            selector.source_index == interface_ref.source_index
            and selector.section_index == interface_ref.section_index
        )

    if isinstance(selector, InterfaceDescription):
        if owner is None:
            return False
        ref = owner._interface_by_block_id.get(id(selector))
        return ref == interface_ref

    if isinstance(selector, int) and not isinstance(selector, bool):
        return interface_ref.interface_id == selector

    if isinstance(selector, str):
        return (
            selector == interface_ref.source
            or selector == interface_ref.name
        )

    if isinstance(selector, (tuple, list)):
        parts = list(selector)
        if len(parts) == 1:
            return interface_ref.interface_id == parts[0]
        if len(parts) == 2:
            first, second = parts
            # (source, interface) or (section, interface)
            if first == interface_ref.source or first == interface_ref.source_index:
                if second == interface_ref.interface_id:
                    return True
            if (
                first == interface_ref.section_index
                and second == interface_ref.interface_id
            ):
                return True
            return False
        if len(parts) >= 3:
            source, section, interface_id = parts[:3]
            return (
                (source == interface_ref.source or source == interface_ref.source_index)
                and section == interface_ref.section_index
                and interface_id == interface_ref.interface_id
            )
    return False


def _calibration_interval(entry, interface_ref, owner):
    if entry.low is not None:
        return TimeInterval(entry.low, entry.high)
    if not entry.anchors:
        raise CalibrationError("calibration has neither interval nor anchors")

    resolution = entry.resolution
    if resolution is None:
        if owner is not None:
            resolution = owner.resolution_for(interface_ref)
        if resolution is None:
            resolution = Fraction(1, 1000000)
    resolution = _as_fraction(resolution, "anchor resolution")

    interval = None
    for index, anchor in enumerate(entry.anchors):
        tick, ref_low, ref_high = _unpack_anchor(anchor, index)
        local = Fraction(tick) * resolution
        if isinstance(ref_low, tuple) and ref_low and ref_low[0] == "offset":
            anchor_interval = TimeInterval(ref_low[1], ref_low[2])
        else:
            anchor_interval = TimeInterval(
                _as_fraction(ref_low, "anchor reference") - local,
                _as_fraction(ref_high, "anchor reference") - local,
            )
        if interval is None:
            interval = anchor_interval
        else:
            interval = interval.intersection(anchor_interval)
            if interval is None:
                raise CalibrationError(
                    "anchor points in group {0!r} imply disjoint offsets".format(
                        entry.anchor_group
                    )
                )
    return interval


def _unpack_anchor(anchor, index):
    if not isinstance(anchor, (dict, tuple, list)) and hasattr(anchor, "tick"):
        tick = anchor.tick
        low = getattr(
            anchor,
            "ref_low",
            getattr(
                anchor,
                "reference_low",
                getattr(anchor, "ref", getattr(anchor, "reference", None)),
            ),
        )
        high = getattr(anchor, "ref_high", getattr(anchor, "reference_high", low))
        if low is None:
            raise CalibrationError("anchor #{0} has no reference".format(index))
        return tick, low, high
    if isinstance(anchor, dict):
        tick = anchor.get("tick", anchor.get("raw_tick"))
        if tick is None:
            raise CalibrationError("anchor #{0} has no tick".format(index))
        if "offset" in anchor or "offset_low" in anchor:
            offset = anchor.get(
                "offset",
                (anchor.get("offset_low"), anchor.get("offset_high")),
            )
            if isinstance(offset, (tuple, list)) and len(offset) == 2:
                return tick, ("offset", offset[0], offset[1]), None
            raise CalibrationError(
                "anchor #{0} offset must be a (low, high) pair".format(index)
            )
        low = anchor.get(
            "ref_low",
            anchor.get(
                "reference_low",
                anchor.get(
                    "ref",
                    anchor.get(
                        "reference",
                        anchor.get("timestamp", anchor.get("time")),
                    ),
                ),
            ),
        )
        high = anchor.get(
            "ref_high",
            anchor.get(
                "reference_high", anchor.get("timestamp_high", low)
            ),
        )
        if isinstance(low, (tuple, list)) and len(low) == 2:
            high = low[1]
            low = low[0]
        if low is None:
            raise CalibrationError("anchor #{0} has no reference".format(index))
        return tick, low, high
    if isinstance(anchor, (tuple, list)):
        if len(anchor) == 2:
            return anchor[0], anchor[1], anchor[1]
        if len(anchor) == 3:
            return anchor[0], anchor[1], anchor[2]
    raise CalibrationError(
        "anchor #{0} must be (tick, ref) or (tick, ref_low, ref_high)".format(
            index
        )
    )


# Read-only convenience for users who only want the exact resolution decode.
def timestamp_resolution(value):
    """Decode an ``if_tsresol`` byte to an exact :class:`fractions.Fraction`."""
    return unpack_timestamp_resolution_exact(value)


ForensicScanner = ForensicReader
TimelineRecord = CaptureRecord
TimeRelation = Ordering
OrderingResult = Comparison


def read_forensic_captures(*args, **kwargs):
    """Alias of :func:`read_captures`."""
    return read_captures(*args, **kwargs)


def correlate_captures(*args, **kwargs):
    """Alias of :func:`read_captures`."""
    return read_captures(*args, **kwargs)


__all__ = [
    "AnchorGroup",
    "Calibration",
    "CalibrationConflict",
    "CalibrationError",
    "CalibrationEstimate",
    "CalibrationSet",
    "CaptureRecord",
    "CaptureSet",
    "ClockCalibration",
    "Comparison",
    "ForensicError",
    "ForensicReader",
    "ForensicScanner",
    "InterfaceRef",
    "Order",
    "Ordering",
    "OrderingResult",
    "SectionRef",
    "SourceRef",
    "StreamConflict",
    "TimeInterval",
    "TimeRelation",
    "TimelineRecord",
    "TimestampProvenance",
    "build_timeline",
    "compare",
    "compare_records",
    "compare_ticks",
    "correlate",
    "correlate_captures",
    "load_captures",
    "load_forensic",
    "read_captures",
    "read_files",
    "load_files",
    "scan_captures",
    "read_forensic",
    "read_forensic_captures",
    "read_timeline",
    "timestamp_resolution",
]
