#-------------------------------------------------------------------------------
# elftools: dwarf/locatability.py
#
# Read-only semantic analysis of the address ranges over which a variable's
# location is known. Unlike a debugger, this module never reads process memory
# and never computes a runtime value: it only combines the compile unit base
# address, the lexical scope ranges and the location list entries recorded in
# the DWARF sections.
#
# Locations that cannot be proven to cover a concrete range (a single
# expression, a default location entry, or entries whose indices cannot be
# resolved) are retained instead of being dropped, and location entries that
# cover the same addresses are all surfaced as overlapping candidates.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from ..common.exceptions import DWARFError
from .descriptions import describe_form_class
from .locationlists import (
    BaseAddressEntry as LocBaseAddressEntry,
    LocationEntry,
    LocationExpr,
    LocationParser,
)
from .ranges import BaseAddressEntry as RangeBaseAddressEntry
from .ranges import RangeEntry

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from .compileunit import CompileUnit
    from .dwarfinfo import DWARFInfo
    from .die import DIE
    from .locationlists import LocationLists, LocationListsPair
    from .typeunit import TypeUnit


# Sentinel used for ranges that are not tied to a concrete pair of addresses:
# the location is valid "everywhere it applies" rather than on [begin, end).
UNPROVABLE_RANGE: tuple[int, int] = (-1, -1)


class LocatableRange(NamedTuple):
    """ One address interval over which a variable has a known location.

        begin_address/end_address delimit a half-open [begin, end) interval of
        code addresses, fully resolved against the unit base address. When the
        location cannot be pinned to concrete addresses (a bare expression, a
        default entry or an unresolvable index), both fields are -1 and
        ``provable`` is False.

        loc_expr holds the raw DWARF expression bytes for the location.

        provable is False when the entry makes no concrete address claim.

        overlapping is True when another retained entry covers at least part of
        the same interval, so the entries are competing candidates rather than
        a single authoritative location.

        default_location marks DW_LLE_default_location entries (v5) and bare
        LocationExpr attributes, both of which apply outside any concrete list
        range.

        source_offset is the offset of the entry inside the location section;
        the same underlying offset may be decoded from several unit contexts.
    """
    begin_address: int
    end_address: int
    loc_expr: bytes | list[int]
    provable: bool
    overlapping: bool
    default_location: bool
    source_offset: int | None


class VariableLocator:
    """ Read-only facade for the ranges in which a DIE's location is defined.

        All work is pure section decoding. The loclists/rnglists sections are
        re-read for every query and every result is derived from the CU passed
        in, so a location list shared between two compile units produces an
        independent set of ranges in each unit context.
    """
    def __init__(
        self,
        dwarfinfo: DWARFInfo,
        location_lists: LocationLists | LocationListsPair | None = None,
    ) -> None:
        self.dwarfinfo = dwarfinfo
        self._loc_parser = LocationParser(location_lists)

    def iter_variable_ranges(self, die: DIE) -> Iterator[LocatableRange]:
        """ Yield the locatable ranges of a single variable DIE.

            The result does not depend on the order in which DIEs or compile
            units are visited: each query only reads the DIE's own unit.
        """
        cu = die.cu
        scope = self._scope_ranges(die)
        parsed = self._parse_location(die)
        yield from self._build_ranges(parsed, scope, cu)

    def get_variable_ranges(self, die: DIE) -> list[LocatableRange]:
        """ Eager counterpart of iter_variable_ranges.
        """
        return list(self.iter_variable_ranges(die))

    def iter_all_variable_ranges(
        self,
        cus: Sequence[CompileUnit | TypeUnit] | None = None,
    ) -> Iterator[tuple[DIE, list[LocatableRange]]]:
        """ For every DIE carrying DW_AT_location in the given units (or every
            unit in the section), yield the DIE and its locatable ranges.

            The units are always processed in ascending section offset order,
            regardless of the order the caller supplied, so the emitted
            results are stable.
        """
        if cus is None:
            units: list[CompileUnit | TypeUnit] = list(self.dwarfinfo.iter_CUs())
        else:
            units = sorted(cus, key=lambda unit: unit.cu_offset)
        for cu in units:
            for die in cu.iter_DIEs():
                if 'DW_AT_location' in die.attributes:
                    yield die, self.get_variable_ranges(die)

    #------ PRIVATE ------#

    def _parse_location(
        self,
        die: DIE,
    ) -> tuple[LocatableRange, ...]:
        attr = die.attributes.get('DW_AT_location')
        if attr is None:
            return ()
        cu = die.cu
        version = cu.header.version
        if not self._loc_parser.attribute_has_location(attr, version):
            return ()
        try:
            location = self._loc_parser.parse_from_attribute(
                attr, version, die=die)
        except (DWARFError, NotImplementedError):
            # Typically a DW_FORM_loclistx/DW_LLE_*x entry referencing an
            # address or offset index table that the object does not carry.
            # The location cannot be resolved, but it must not disappear.
            return (LocatableRange(
                begin_address=UNPROVABLE_RANGE[0],
                end_address=UNPROVABLE_RANGE[1],
                loc_expr=bytes(attr.value) if isinstance(attr.value, (bytes, bytearray)) else b'',
                provable=False,
                overlapping=False,
                default_location=True,
                source_offset=attr.value
                    if isinstance(attr.value, int) else None),)

        if isinstance(location, LocationExpr):
            # A self-contained expression makes no address claim by itself;
            # keep it as an unprovable/default candidate rather than stamping
            # it across the whole stack frame or scope.
            return (LocatableRange(
                begin_address=UNPROVABLE_RANGE[0],
                end_address=UNPROVABLE_RANGE[1],
                loc_expr=location.loc_expr,
                provable=False,
                overlapping=False,
                default_location=True,
                source_offset=None),)
        return self._entries_to_raw_ranges(location, cu)

    def _entries_to_raw_ranges(
        self,
        entries: list[object],
        cu: CompileUnit | TypeUnit,
    ) -> tuple[LocatableRange, ...]:
        raw: list[LocatableRange] = []
        # Until a base address selection entry overrides it, relative entries
        # are offsets from the unit base address (DWARF <=4 default base).
        base_address = self._unit_base_address(cu)
        for entry in entries:
            if isinstance(entry, LocBaseAddressEntry):
                base_address = entry.base_address
                continue
            if not isinstance(entry, LocationEntry):
                # LocationViewPair and friends carry no expression; the actual
                # locations come from the paired LocationEntry objects.
                continue
            is_default = entry.begin_offset == -1 and entry.end_offset == -1
            if is_default:
                raw.append(LocatableRange(
                    begin_address=UNPROVABLE_RANGE[0],
                    end_address=UNPROVABLE_RANGE[1],
                    loc_expr=entry.loc_expr,
                    provable=False,
                    overlapping=False,
                    default_location=True,
                    source_offset=entry.entry_offset))
            elif entry.is_absolute:
                raw.append(LocatableRange(
                    begin_address=entry.begin_offset,
                    end_address=entry.end_offset,
                    loc_expr=entry.loc_expr,
                    provable=True,
                    overlapping=False,
                    default_location=False,
                    source_offset=entry.entry_offset))
            else:
                # Relative entries are offsets from the most recent base
                # address selection entry (defaulting to the unit base).
                raw.append(LocatableRange(
                    begin_address=base_address + entry.begin_offset,
                    end_address=base_address + entry.end_offset,
                    loc_expr=entry.loc_expr,
                    provable=True,
                    overlapping=False,
                    default_location=False,
                    source_offset=entry.entry_offset))
        return tuple(raw)

    def _build_ranges(
        self,
        raw: Sequence[LocatableRange],
        scope: Sequence[tuple[int, int]] | None,
        cu: CompileUnit | TypeUnit,
    ) -> Iterator[LocatableRange]:
        provable = [r for r in raw if r.provable]
        unprovable = [r for r in raw if not r.provable]

        # Mark provable entries whose concrete intervals overlap. Candidates
        # that cover identical addresses (a common compiler trick for the same
        # variable at the same PC) are flagged on both sides.
        overlaps = [False] * len(provable)
        for i in range(len(provable)):
            for j in range(i + 1, len(provable)):
                left = provable[i]
                right = provable[j]
                if (left.begin_address < right.end_address and
                        right.begin_address < left.end_address):
                    overlaps[i] = True
                    overlaps[j] = True

        emitted: list[LocatableRange] = []
        for entry, is_overlap in zip(provable, overlaps, strict=True):
            clipped = self._clip_to_scope(entry, scope)
            if clipped is None:
                # The list claims addresses outside any proven scope; keep the
                # raw claim flagged as unprovable rather than silently losing
                # the location.
                emitted.append(entry._replace(
                    provable=False,
                    overlapping=is_overlap,
                    default_location=False))
                continue
            for begin, end in clipped:
                emitted.append(entry._replace(
                    begin_address=begin,
                    end_address=end,
                    overlapping=is_overlap))

        # Unprovable/default entries have no concrete interval, so they can
        # neither be tested for overlap nor dropped; they are retained as-is.
        emitted.extend(unprovable)

        # Deterministic ordering independent of query/iteration order.
        emitted.sort(key=lambda r: (
            r.default_location,
            r.begin_address,
            r.end_address,
            r.source_offset if r.source_offset is not None else -1))
        yield from emitted

    @staticmethod
    def _clip_to_scope(
        entry: LocatableRange,
        scope: Sequence[tuple[int, int]] | None,
    ) -> list[tuple[int, int]] | None:
        if scope is None:
            return [(entry.begin_address, entry.end_address)]
        pieces: list[tuple[int, int]] = []
        for begin, end in scope:
            lo = max(entry.begin_address, begin)
            hi = min(entry.end_address, end)
            if lo < hi:
                pieces.append((lo, hi))
        return pieces or None

    def _scope_ranges(
        self,
        die: DIE,
    ) -> list[tuple[int, int]] | None:
        """ Resolve the lexical scope that bounds the variable: the DIE itself
            when it carries PC ranges, otherwise the nearest enclosing DIE
            (lexical block / subprogram / compile unit) that does.
        """
        owner: DIE | None = die
        while owner is not None:
            ranges = self._die_pc_ranges(owner)
            if ranges:
                return ranges
            owner = owner.get_parent()
        top = die.cu.get_top_DIE()
        if top is not die:
            top_ranges = self._die_pc_ranges(top)
            return top_ranges or None
        return None

    def _die_pc_ranges(self, die: DIE) -> list[tuple[int, int]]:
        attrs = die.attributes
        if 'DW_AT_low_pc' in attrs:
            low = attrs['DW_AT_low_pc'].value
            if 'DW_AT_high_pc' in attrs:
                high_attr = attrs['DW_AT_high_pc']
                if describe_form_class(high_attr.form) == 'address':
                    high = high_attr.value
                else:
                    high = low + high_attr.value
            else:
                high = low
            return [(low, high)] if low < high else []
        if 'DW_AT_ranges' in attrs:
            return self._resolve_ranges(die)
        return []

    def _resolve_ranges(self, die: DIE) -> list[tuple[int, int]]:
        cu = die.cu
        range_lists = self.dwarfinfo.range_lists()
        if range_lists is None:
            return []
        offset = die.attributes['DW_AT_ranges'].value
        try:
            entries = range_lists.get_range_list_at_offset(offset, cu)
        except (DWARFError, NotImplementedError):
            # A missing rnglists offset/address index table: the scope cannot
            # be proven, so do not constrain (or fabricate) any range.
            return []

        ranges: list[tuple[int, int]] = []
        base_address = self._unit_base_address(cu)
        for entry in entries:
            if isinstance(entry, RangeBaseAddressEntry):
                base_address = entry.base_address
            elif isinstance(entry, RangeEntry):
                if entry.is_absolute:
                    ranges.append((entry.begin_offset, entry.end_offset))
                else:
                    ranges.append((
                        base_address + entry.begin_offset,
                        base_address + entry.end_offset))
        return ranges

    @staticmethod
    def _unit_base_address(cu: CompileUnit | TypeUnit) -> int:
        """ The unit's base address: its DW_AT_low_pc when present (the DWARF
            default base for relative list entries), otherwise zero.
        """
        top = cu.get_top_DIE()
        attr = top.attributes.get('DW_AT_low_pc')
        return int(attr.value) if attr is not None else 0


def get_variable_locatable_ranges(die: DIE) -> list[LocatableRange]:
    """ Convenience wrapper building a VariableLocator from the DIE's own
        DWARFInfo and returning its locatable ranges.
    """
    locator = VariableLocator(
        die.cu.dwarfinfo,
        die.cu.dwarfinfo.location_lists())
    return locator.get_variable_ranges(die)
