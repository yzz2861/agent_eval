#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Forensic name identity auditing tests.

These tests build synthetic hives in memory (no system registry access) and
exercise case, invisible characters, compressed vs UTF-16 storage and normal
non-ASCII names.  The legacy browsing API is separately asserted unchanged.
"""
from __future__ import unicode_literals

import pytest

from Registry import Registry
from Registry import NameAudit
from Registry import NameQuery
from Registry import SyntheticHive


def build(keys=None, values=None):
    root = SyntheticHive.SyntheticKey(
        "AuditRoot", subkeys=keys or [], values=values or [])
    return SyntheticHive.open_synthetic(root)


def make_ambiguous_hive():
    return build(keys=[
        SyntheticHive.SyntheticKey("Persistence"),
        SyntheticHive.SyntheticKey("PERSISTENCE", compressed=False),
    ])


def test_raw_bytes_distinguish_equal_display_names():
    reg = make_ambiguous_hive()
    identities = reg.root().subkey_name_view().identities()
    assert len(identities) == 2
    assert identities[0].text() != identities[1].text()
    assert identities[0].raw_bytes() == b"Persistence"
    assert identities[1].raw_bytes() == "PERSISTENCE".encode("utf-16le")
    assert identities[0].encoding() == NameAudit.NameEncoding.COMPRESSED
    assert identities[1].encoding() == NameAudit.NameEncoding.UTF16
    # distinct raw identities must never compare equal
    assert identities[0] != identities[1]
    assert hash(identities[0]) != hash(identities[1])


def test_case_insensitive_ascii_lookup_is_ambiguous():
    reg = make_ambiguous_hive()
    result = reg.root().subkey_name_view().lookup("persistence")
    assert result.outcome() == NameAudit.LookupOutcome.AMBIGUOUS
    assert result.collation_rule() ==         NameAudit.CollationRule.CASE_INSENSITIVE_ASCII
    offsets = result.offsets()
    assert len(offsets) == 2
    assert len(set(offsets)) == 2
    with pytest.raises(NameQuery.AmbiguousNameException):
        reg.root().subkey_name_view().require("persistence")


def test_legacy_subkey_still_returns_a_single_key():
    reg = make_ambiguous_hive()
    # the old API contract is intentionally preserved
    key = reg.root().subkey("PeRsIsTeNcE")
    assert key.name().lower() == "persistence"


def test_invisible_code_points_are_audited_not_hidden():
    reg = build(keys=[
        SyntheticHive.SyntheticKey("Visible"),
        SyntheticHive.SyntheticKey("Visible\x00"),
        SyntheticHive.SyntheticKey("Tab\tName"),
    ])
    view = reg.root().subkey_name_view()
    texts = [identity.text() for identity in view.identities()]
    assert "Visible" in texts
    assert "Visible\x00" in texts
    nul = view.lookup("Visible\x00")
    assert nul.is_match()
    candidate = nul.single_candidate().identity()
    assert candidate.codepoints()[-1] == 0
    assert candidate.codepoint_sequence()[-1] == "U+0000"
    assert candidate.display_name().endswith("\\u0000")
    # the plain visible name must not collide with the NUL suffixed one
    plain = view.lookup("Visible")
    assert plain.is_match()
    assert plain.offsets() != nul.offsets()


def test_display_escaping_does_not_change_query_identity():
    reg = build(keys=[SyntheticHive.SyntheticKey("A\nB")])
    key = reg.root().subkeys()[0]
    identity = key.name_identity()
    assert identity.display_name() == "A\\u000aB"
    # escaping is a view only; lookup still uses the real code points
    result = reg.root().subkey_name_view().lookup("A\nB")
    assert result.is_match()
    missing = reg.root().subkey_name_view().lookup(identity.display_name())
    assert missing.outcome() == NameAudit.LookupOutcome.NOT_FOUND


def test_compressed_and_utf16_same_text_are_both_retained():
    reg = build(keys=[
        SyntheticHive.SyntheticKey("Dual", compressed=True),
        SyntheticHive.SyntheticKey("Dual", compressed=False),
    ])
    identities = reg.root().subkey_name_view().identities()
    assert [identity.text() for identity in identities] == ["Dual", "Dual"]
    assert identities[0].raw_bytes() == b"Dual"
    assert identities[1].raw_bytes() == "Dual".encode("utf-16le")
    result = reg.root().subkey_name_view().lookup("dual")
    assert result.is_ambiguous()
    assert len(result.offsets()) == 2


def test_non_ascii_names_keep_identity_and_unknown_rule():
    reg = build(keys=[
        SyntheticHive.SyntheticKey("caf\u00e9", compressed=False),
        SyntheticHive.SyntheticKey("CAF\u00c9", compressed=False),
        SyntheticHive.SyntheticKey("\u4e2d\u6587", compressed=False),
    ])
    view = reg.root().subkey_name_view()
    for identity in view.identities():
        assert identity.collation_rule() == NameAudit.CollationRule.UNKNOWN
        assert identity.lookup_key() is None

    exact = view.lookup("caf\u00e9")
    assert exact.is_match()
    assert exact.collation_rule() == NameAudit.CollationRule.UNKNOWN

    # casefold would merge these; the audited view must not
    folded = view.lookup("CAF\u00c9")
    assert folded.is_match()
    assert exact.offsets() != folded.offsets()

    with pytest.raises(NameQuery.UnknownCollationException):
        view.require("caf\u00c9")


def test_normal_nonascii_round_trips_through_legacy_api():
    reg = build(keys=[
        SyntheticHive.SyntheticKey("\u4e2d\u6587", compressed=False)])
    key = reg.root().subkey("\u4e2d\u6587")
    assert key.name() == "\u4e2d\u6587"
    assert key.name_identity().raw_bytes() ==         "\u4e2d\u6587".encode("utf-16le")


def test_value_name_audit_and_ambiguity():
    reg = build(values=[
        SyntheticHive.SyntheticValue("Flag", b"a\x00"),
        SyntheticHive.SyntheticValue("FLAG", b"b\x00", compressed=False),
        SyntheticHive.SyntheticValue("", b"default\x00"),
    ])
    view = reg.root().value_name_view()
    result = view.lookup("flag")
    assert result.is_ambiguous()
    assert len(result.offsets()) == 2
    default = view.lookup("(default)")
    assert default.is_match()
    assert default.single_candidate().identity().raw_bytes() == b""
    with pytest.raises(Registry.RegistryValueNotFoundException):
        view.require("does-not-exist")


def test_query_input_is_not_mutated():
    reg = make_ambiguous_hive()
    query = "MiXeD"
    snapshot = query
    reg.root().subkey_name_view().lookup(query)
    assert query == snapshot


def test_synthetic_hive_is_self_consistent():
    reg = make_ambiguous_hive()
    assert reg._regf.validate_checksum()
    assert reg._regf.file_type().value == 0
    names = [key.name() for key in reg.root().subkeys()]
    assert len(names) == 2
