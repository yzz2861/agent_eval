# -*- coding: utf-8 -*-
"""Tests for external row-range reconciliation against dnfile metadata tables."""
import pytest

from dnfile import enums
from dnfile.reconcile import (
    MappingError,
    Reconciler,
    RenumberingMap,
    RowRange,
    Segment,
    SegmentError,
    reconcile,
)


class _FakeIndex:
    """Stand-in for dnfile.base.MDTableIndex: only row_index is needed."""

    def __init__(self, row_index):
        self.row_index = row_index


class _FakeFlags:
    """Stand-in for dnfile ClrFlags objects, exposing the public access bits."""

    def __init__(self, method_public=False, field_public=False):
        self.mdPublic = method_public
        self.fdPublic = field_public


class _FakeMember:
    def __init__(self, name, flags):
        self.Name = name
        self.Flags = flags


class _FakeType:
    def __init__(self, name, namespace, method_runs=(), field_runs=()):
        self.TypeName = name
        self.TypeNamespace = namespace
        self.MethodList = [_FakeIndex(row) for row in method_runs]
        self.FieldList = [_FakeIndex(row) for row in field_runs]


class _FakeTable:
    """Tiny stand-in matching the dnfile table surface used by the reconciler."""

    def __init__(self, name, rows):
        self.name = name
        self.rows = list(rows)
        self.num_rows = len(self.rows)

    def get_with_row_index(self, row_index):
        # dnfile row identifiers are 1-based.
        return self.rows[row_index - 1]


class _FakeMdTables:
    def __init__(self, **tables):
        for name, table in tables.items():
            setattr(self, name, table)
        self.tables = {name: table for name, table in tables.items()}


def _two_types_sharing_a_name():
    # A very small MethodDef sample: two methods, one of them declared public.
    methods = [
        _FakeMember("OpenApi", _FakeFlags(method_public=True)),
        _FakeMember("OpenApi", _FakeFlags(method_public=False)),
    ]
    method_table = _FakeTable("MethodDef", methods)

    # Two distinct owning types happen to share the same simple name.  Only the
    # second type's MethodList run structurally contains MethodDef row 1.
    first = _FakeType("Widget", "Vendor.A", method_runs=[2])
    second = _FakeType("Widget", "Vendor.B", method_runs=[1])
    typedef_table = _FakeTable("TypeDef", [first, second])
    return _FakeMdTables(TypeDef=typedef_table, MethodDef=method_table)


def test_public_member_is_attributed_only_to_structurally_confirmed_owner():
    mdtables = _two_types_sharing_a_name()
    segment = Segment("s1", RowRange("MethodDef", 1, 2))
    reconciler = Reconciler(mdtables, [segment])

    result = reconciler.reconcile_member("s1", 1)

    assert result.is_public is True
    assert result.confirmed is True
    assert result.member_name == "OpenApi"
    # Only the owning type whose MethodList run contains the row is disclosed.
    assert result.evidence.owner_row == 2
    assert result.evidence.owner_type_name == "Widget"
    assert result.evidence.owner_type_namespace == "Vendor.B"
    assert result.evidence.run_start == 1
    assert result.evidence.run_end == 1

    # The same-named candidate is retained as rejected evidence, never merged in.
    rejected_rows = {candidate.type_row for candidate in result.rejected}
    assert rejected_rows == {1}
    rejected = result.rejected[0]
    assert rejected.type_name == "Widget"
    assert rejected.type_namespace == "Vendor.A"
    assert "does not contain row 1" in rejected.reason


def test_same_name_alone_never_confirms_an_owner():
    mdtables = _two_types_sharing_a_name()
    segment = Segment("s1", RowRange("MethodDef", 1, 2))

    result = reconcile(mdtables, [segment], "s1", 1)

    assert result.confirmed is True
    assert result.evidence.owner_type_namespace == "Vendor.B"
    # Every disclosure carries its external and parsed provenance.
    assert result.segment_id == "s1"
    assert result.external_row == 1
    assert result.parsed_row == 1


def test_renumbering_map_translates_external_row_and_records_provenance():
    mdtables = _two_types_sharing_a_name()
    # The external snapshot numbered the public member as row 4; the approved
    # map says external row 4 is parsed row 1.
    mapping = RenumberingMap("MethodDef", {4: 1})
    segment = Segment("mapped", RowRange("MethodDef", 3, 4), mapping=mapping)
    reconciler = Reconciler(mdtables, [segment])

    result = reconciler.reconcile_member("mapped", 4)

    assert result.confirmed is True
    assert result.external_row == 4
    assert result.parsed_row == 1
    assert result.evidence.member_row == 1
    assert result.evidence.owner_row == 2


def test_partial_mapping_leaves_other_segments_independently_queryable():
    mdtables = _two_types_sharing_a_name()
    mapped_segment = Segment(
        "mapped",
        RowRange("MethodDef", 3, 4),
        mapping=RenumberingMap("MethodDef", {4: 1}),
    )
    # A second segment has no mapping at all; its rows are used unchanged.
    unmapped_segment = Segment("plain", RowRange("MethodDef", 1, 2))
    reconciler = Reconciler(mdtables, [mapped_segment, unmapped_segment])

    # The map deliberately covers only one row of its own segment.
    with pytest.raises(MappingError):
        reconciler.reconcile_member("mapped", 3)

    # The other segment still resolves on its own.
    plain = reconciler.reconcile_member("plain", 1)
    assert plain.confirmed is True
    assert plain.external_row == 1
    assert plain.parsed_row == 1
    assert plain.segment_id == "plain"


def test_mapping_does_not_leak_across_segments():
    mdtables = _two_types_sharing_a_name()
    mapped_segment = Segment(
        "mapped",
        RowRange("MethodDef", 3, 4),
        mapping=RenumberingMap("MethodDef", {4: 1}),
    )
    plain_segment = Segment("plain", RowRange("MethodDef", 1, 2))
    reconciler = Reconciler(mdtables, [mapped_segment, plain_segment])

    # External row 4 exists in the mapped segment but means nothing to "plain".
    with pytest.raises(SegmentError):
        reconciler.reconcile_member("plain", 4)
    with pytest.raises(SegmentError):
        reconciler.reconcile_member("unknown", 1)


def test_range_query_reports_each_row_and_can_filter_to_public():
    mdtables = _two_types_sharing_a_name()
    segment = Segment("s1", RowRange("MethodDef", 1, 2))
    reconciler = Reconciler(mdtables, [segment])

    all_results = reconciler.reconcile_range("s1")
    assert [result.external_row for result in all_results] == [1, 2]

    public_only = reconciler.reconcile_range("s1", only_public=True)
    assert len(public_only) == 1
    assert public_only[0].external_row == 1
    assert public_only[0].is_public is True


def test_member_outside_every_owner_run_is_not_disclosed():
    # TypeDef runs cover rows 2-3 only, so MethodDef row 1 has no structural owner.
    methods = [_FakeMember("Orphan", _FakeFlags(method_public=True))]
    method_table = _FakeTable("MethodDef", methods)
    owner = _FakeType("Solo", "Vendor", method_runs=[2, 3])
    typedef_table = _FakeTable("TypeDef", [owner])
    mdtables = _FakeMdTables(TypeDef=typedef_table, MethodDef=method_table)

    result = Reconciler(mdtables, [Segment("s1", RowRange("MethodDef", 1, 1))]).reconcile_member("s1", 1)

    assert result.confirmed is False
    assert result.evidence is None
    assert result.is_public is True
    assert result.reason == "no TypeDef run contains the member"
    assert result.rejected[0].type_row == 1
    assert "does not contain row 1" in result.rejected[0].reason


def test_field_ownership_uses_field_runs():
    fields = [_FakeMember("state", _FakeFlags(field_public=True))]
    field_table = _FakeTable("Field", fields)
    owner = _FakeType("Holder", "Vendor", field_runs=[1])
    typedef_table = _FakeTable("TypeDef", [owner])
    mdtables = _FakeMdTables(TypeDef=typedef_table, Field=field_table)

    result = reconcile(mdtables, [Segment("f", RowRange("Field", 1, 1))], "f", 1)

    assert result.confirmed is True
    assert result.is_public is True
    assert result.table_name == "Field"
    assert result.evidence.owner_type_name == "Holder"
    assert result.evidence.member_table == "Field"


def test_mapping_rejects_conflicts_and_invalid_ranges():
    renumbering = RenumberingMap("MethodDef")
    renumbering.add(4, 1)
    with pytest.raises(MappingError):
        renumbering.add(4, 2)

    with pytest.raises(MappingError):
        RowRange("MethodDef", 0, 2)
    with pytest.raises(MappingError):
        RowRange("MethodDef", 3, 2)

    with pytest.raises(MappingError):
        Segment(
            "bad",
            RowRange("MethodDef", 1, 1),
            mapping=RenumberingMap("Field", {1: 1}),
        )


def test_missing_and_oversized_rows_stay_unresolved():
    mdtables = _two_types_sharing_a_name()
    segment = Segment(
        "mapped",
        RowRange("MethodDef", 9, 9),
        mapping=RenumberingMap("MethodDef", {9: 7}),
    )
    result = Reconciler(mdtables, [segment]).reconcile_member("mapped", 9)

    assert result.confirmed is False
    assert result.evidence is None
    assert result.parsed_row == 7
    assert "does not exist" in result.reason



def test_segment_without_mapping_uses_identity_and_stays_independent():
    mdtables = _two_types_sharing_a_name()
    mapped_segment = Segment(
        "mapped",
        RowRange("MethodDef", 3, 4),
        mapping=RenumberingMap("MethodDef", {3: 2, 4: 1}),
    )
    identity_segment = Segment("identity", RowRange("MethodDef", 1, 2))
    reconciler = Reconciler(mdtables, [mapped_segment, identity_segment])

    # Rows inside the mapped segment use the approved translation.
    assert reconciler.reconcile_member("mapped", 4).parsed_row == 1
    # The identity segment ignores the other segment's map entirely.
    identity_result = reconciler.reconcile_member("identity", 2)
    assert identity_result.parsed_row == 2
    assert identity_result.segment_id == "identity"
    # External row 2 stays private in the sample, but its owner is still proven.
    assert identity_result.is_public is False
    assert identity_result.confirmed is True
    assert identity_result.evidence.owner_row == 1


def test_reconciler_accepts_real_dnfile_flag_enums():
    # Guards the public-bit contract against the actual dnfile enum wrappers.
    public_flags = enums.ClrMethodAttr(0x0006)
    private_flags = enums.ClrMethodAttr(0x0001)
    assert public_flags.mdPublic is True
    assert private_flags.mdPublic is False
    field_flags = enums.ClrFieldAttr(0x0006)
    assert field_flags.fdPublic is True
