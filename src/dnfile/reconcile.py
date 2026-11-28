# -*- coding: utf-8 -*-
"""
Reconcile external metadata-table row ranges against the tables parsed by dnfile.

External tooling sometimes reports metadata members (MethodDef, Field, ...) using
row numbers from a different snapshot of the assembly than the one dnfile parsed.
Caller-approved renumbering maps describe how external rows relate to the rows
of the parsed tables.  This module keeps the provenance of every conclusion:

* which external segment and row produced the request,
* which approved mapping translated it, if any,
* which owning TypeDef row structurally contains the member via its
  ``MethodList`` / ``FieldList`` runs.

A member is only attributed to an owning type when the parsed tables provide
structural evidence.  Two types that merely share a name never merge evidence.
Renumbering maps are scoped to individual segments, so a segment without an
approved mapping can still be queried on its own.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple


class ReconcileError(Exception):
    """Base class for reconciliation failures."""


class MappingError(ReconcileError):
    """A renumbering map is invalid or cannot represent a given row."""


class SegmentError(ReconcileError):
    """A requested external segment was never registered."""


@dataclass(frozen=True)
class RowRange:
    """A 1-based, inclusive range of rows of a single metadata table.

    External tooling reports row ranges such as ``MethodDef rows 1-4``.  Both
    bounds are inclusive, matching the row identifiers encoded in a .NET file.
    """

    table_name: str
    first_row: int
    last_row: int

    def __post_init__(self):
        if self.first_row < 1 or self.last_row < self.first_row:
            raise MappingError(
                "invalid row range for table %s: %d-%d"
                % (self.table_name, self.first_row, self.last_row)
            )

    def __contains__(self, row_index: int) -> bool:
        return self.first_row <= row_index <= self.last_row

    def rows(self) -> range:
        return range(self.first_row, self.last_row + 1)


class RenumberingMap:
    """An approved translation from external row numbers to parsed-table rows.

    The mapping is intentionally explicit: only external rows registered here
    are translated.  It does not assume identity mapping, contiguous output,
    or any relationship between rows that were not approved.  A map belongs to
    one segment, so partial coverage never leaks into another segment.
    """

    def __init__(self, table_name: str, mapping: Optional[Dict[int, int]] = None):
        self.table_name = table_name
        self._mapping: Dict[int, int] = {}
        if mapping:
            for external_row, parsed_row in mapping.items():
                self.add(external_row, parsed_row)

    def add(self, external_row: int, parsed_row: int) -> None:
        if external_row < 1 or parsed_row < 1:
            raise MappingError(
                "row numbers must be positive: external=%d parsed=%d" % (external_row, parsed_row)
            )
        if external_row in self._mapping and self._mapping[external_row] != parsed_row:
            raise MappingError(
                "external %s row %d maps to two parsed rows: %d and %d"
                % (self.table_name, external_row, self._mapping[external_row], parsed_row)
            )
        self._mapping[external_row] = parsed_row

    def covers(self, external_row: int) -> bool:
        return external_row in self._mapping

    def translate(self, external_row: int) -> int:
        try:
            return self._mapping[external_row]
        except KeyError:
            raise MappingError(
                "no approved mapping for external %s row %d" % (self.table_name, external_row)
            )

    def __len__(self) -> int:
        return len(self._mapping)

    def __contains__(self, external_row: int) -> bool:
        return self.covers(external_row)


@dataclass(frozen=True)
class Segment:
    """One externally reported row range plus its caller-approved mapping.

    ``mapping`` is optional: a segment without a mapping is still queryable,
    and its rows are treated as parsed-table row numbers unchanged.
    """

    segment_id: str
    range: RowRange
    mapping: Optional[RenumberingMap] = None

    def __post_init__(self):
        if self.mapping is not None and self.mapping.table_name != self.range.table_name:
            raise MappingError(
                "mapping table %s does not match segment %s table %s"
                % (self.mapping.table_name, self.segment_id, self.range.table_name)
            )

    @property
    def table_name(self) -> str:
        return self.range.table_name

    def resolve_row(self, external_row: int) -> "ResolvedRow":
        if external_row not in self.range:
            raise SegmentError(
                "external %s row %d is outside segment %s range %d-%d"
                % (
                    self.table_name,
                    external_row,
                    self.segment_id,
                    self.range.first_row,
                    self.range.last_row,
                )
            )
        if self.mapping is None:
            return ResolvedRow(
                table_name=self.table_name,
                external_row=external_row,
                parsed_row=external_row,
                segment_id=self.segment_id,
                mapped=False,
            )
        if not self.mapping.covers(external_row):
            raise MappingError(
                "segment %s mapping does not cover external %s row %d"
                % (self.segment_id, self.table_name, external_row)
            )
        return ResolvedRow(
            table_name=self.table_name,
            external_row=external_row,
            parsed_row=self.mapping.translate(external_row),
            segment_id=self.segment_id,
            mapped=True,
        )


@dataclass(frozen=True)
class ResolvedRow:
    """The result of locating an external row inside the parsed tables."""

    table_name: str
    external_row: int
    parsed_row: int
    segment_id: str
    mapped: bool


@dataclass(frozen=True)
class OwnershipEvidence:
    """Structural evidence that one TypeDef row owns a member row.

    ``run_start`` and ``run_end`` are the 1-based bounds of the owning type's
    member list run in the parsed member table, mirroring TypeDef's
    FieldList/MethodList encoding in ECMA-335.
    """

    owner_row: int
    owner_type_name: str
    owner_type_namespace: Optional[str]
    member_table: str
    member_row: int
    run_start: int
    run_end: int


@dataclass(frozen=True)
class RejectedCandidate:
    """A candidate owner that was considered but not structurally confirmed."""

    type_row: int
    type_name: str
    type_namespace: Optional[str]
    reason: str


@dataclass(frozen=True)
class ReconciledMember:
    """The disclosure for one externally reported member.

    When the parsed tables do not provide enough evidence, ``confirmed`` is
    ``False`` and no owning type is disclosed.  The rejected candidates and the
    reason explain why the evidence was insufficient.
    """

    table_name: str
    external_row: int
    parsed_row: int
    segment_id: str
    member_name: Optional[str]
    is_public: bool
    confirmed: bool
    evidence: Optional[OwnershipEvidence]
    rejected: Tuple[RejectedCandidate, ...] = field(default_factory=tuple)
    reason: Optional[str] = None


def _table(mdtables, table_name: str):
    table = getattr(mdtables, table_name, None)
    if table is None and isinstance(getattr(mdtables, "tables", None), dict):
        table = mdtables.tables.get(table_name)
    return table


def _row_name(row) -> Optional[str]:
    return getattr(row, "Name", None)


def _type_name(row) -> Optional[str]:
    return getattr(row, "TypeName", _row_name(row))


def _is_public(member_table: str, row) -> bool:
    flags = getattr(row, "Flags", None)
    if flags is None:
        return False
    if member_table == "MethodDef":
        return bool(getattr(flags, "mdPublic", False))
    if member_table == "Field":
        return bool(getattr(flags, "fdPublic", False))
    return False


def _member_list_attr(member_table: str) -> Optional[str]:
    if member_table == "MethodDef":
        return "MethodList"
    if member_table == "Field":
        return "FieldList"
    return None


def _index_rows(indexes: Sequence) -> List[int]:
    return [int(index.row_index) for index in indexes]


class Reconciler:
    """Reconcile externally reported members against parsed metadata tables.

    Construct one from a ``dnfile`` ``MetaDataTables`` object (``dn.net.mdtables``)
    and the segments reported by the external tool.
    """

    def __init__(self, mdtables, segments: Sequence[Segment]):
        self._mdtables = mdtables
        self._segments: Dict[str, Segment] = {}
        for segment in segments:
            if segment.segment_id in self._segments:
                raise SegmentError("duplicate segment id: %s" % segment.segment_id)
            self._segments[segment.segment_id] = segment

    def segment(self, segment_id: str) -> Segment:
        try:
            return self._segments[segment_id]
        except KeyError:
            raise SegmentError("unknown segment: %s" % segment_id)

    def reconcile_member(self, segment_id: str, external_row: int) -> ReconciledMember:
        """Resolve one externally reported member and its owning type.

        Only structural ownership (the TypeDef member-list runs) confirms an
        owner.  A matching type name alone is never treated as evidence.
        """
        segment = self.segment(segment_id)
        resolved = segment.resolve_row(external_row)

        table = _table(self._mdtables, resolved.table_name)
        if table is None:
            return self._unresolved(
                resolved, None, False, "table %s is not present" % resolved.table_name, ()
            )
        if resolved.parsed_row > table.num_rows:
            return self._unresolved(
                resolved,
                None,
                False,
                "parsed %s row %d does not exist (table has %d rows)"
                % (resolved.table_name, resolved.parsed_row, table.num_rows),
                (),
            )

        row = table.get_with_row_index(resolved.parsed_row)
        if row is None:
            return self._unresolved(
                resolved,
                None,
                False,
                "parsed %s row %d could not be parsed" % (resolved.table_name, resolved.parsed_row),
                (),
            )

        member_name = _row_name(row)
        is_public = _is_public(resolved.table_name, row)
        evidence, rejected = self._establish_ownership(resolved.table_name, resolved.parsed_row)
        if evidence is None:
            return self._unresolved(
                resolved, member_name, is_public, "no TypeDef run contains the member", rejected
            )
        return ReconciledMember(
            table_name=resolved.table_name,
            external_row=resolved.external_row,
            parsed_row=resolved.parsed_row,
            segment_id=resolved.segment_id,
            member_name=member_name,
            is_public=is_public,
            confirmed=True,
            evidence=evidence,
            rejected=tuple(rejected),
        )

    def reconcile_range(self, segment_id: str, only_public: bool = False) -> List[ReconciledMember]:
        """Reconcile every row of one segment independently of other segments."""
        segment = self.segment(segment_id)
        results = []
        for external_row in segment.range.rows():
            result = self.reconcile_member(segment_id, external_row)
            if only_public and not result.is_public:
                continue
            results.append(result)
        return results

    def _establish_ownership(
        self, member_table: str, member_row: int
    ) -> Tuple[Optional[OwnershipEvidence], List[RejectedCandidate]]:
        list_attr = _member_list_attr(member_table)
        typedefs = _table(self._mdtables, "TypeDef")
        if list_attr is None or typedefs is None:
            return None, []

        matches: List[OwnershipEvidence] = []
        rejected: List[RejectedCandidate] = []
        for offset, type_row in enumerate(typedefs.rows, start=1):
            if type_row is None:
                continue
            indexes = _index_rows(getattr(type_row, list_attr, []))
            type_name = _type_name(type_row)
            namespace = getattr(type_row, "TypeNamespace", None)
            if not indexes:
                rejected.append(
                    RejectedCandidate(offset, type_name, namespace, "member list run is empty")
                )
                continue
            run_start, run_end = indexes[0], indexes[-1]
            if member_row in indexes:
                matches.append(
                    OwnershipEvidence(
                        owner_row=offset,
                        owner_type_name=type_name,
                        owner_type_namespace=namespace,
                        member_table=member_table,
                        member_row=member_row,
                        run_start=run_start,
                        run_end=run_end,
                    )
                )
            else:
                rejected.append(
                    RejectedCandidate(
                        offset,
                        type_name,
                        namespace,
                        "%s run %d-%d does not contain row %d"
                        % (member_table, run_start, run_end, member_row),
                    )
                )

        if len(matches) == 1:
            return matches[0], rejected
        if len(matches) > 1:
            # Well-formed tables give disjoint runs, but never guess if not.
            rejected.extend(
                RejectedCandidate(
                    match.owner_row,
                    match.owner_type_name,
                    match.owner_type_namespace,
                    "member is claimed by multiple TypeDef runs",
                )
                for match in matches
            )
        return None, rejected

    @staticmethod
    def _unresolved(
        resolved: ResolvedRow,
        member_name: Optional[str],
        is_public: bool,
        reason: str,
        rejected: Sequence[RejectedCandidate],
    ) -> ReconciledMember:
        return ReconciledMember(
            table_name=resolved.table_name,
            external_row=resolved.external_row,
            parsed_row=resolved.parsed_row,
            segment_id=resolved.segment_id,
            member_name=member_name,
            is_public=is_public,
            confirmed=False,
            evidence=None,
            rejected=tuple(rejected),
            reason=reason,
        )


def reconcile(
    mdtables,
    segments: Sequence[Segment],
    segment_id: str,
    external_row: int,
) -> ReconciledMember:
    """Convenience wrapper for a single member lookup."""
    return Reconciler(mdtables, segments).reconcile_member(segment_id, external_row)


__all__ = [
    "MappingError",
    "OwnershipEvidence",
    "ReconcileError",
    "ReconciledMember",
    "Reconciler",
    "RejectedCandidate",
    "RenumberingMap",
    "ResolvedRow",
    "RowRange",
    "Segment",
    "SegmentError",
    "reconcile",
]
