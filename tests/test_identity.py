"""Regression tests for the read-only Registry identity layer."""
from __future__ import print_function

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from Registry.Identity import (
    Confidence,
    ResolutionStatus,
    TrustedSidTable,
    TrustedSidTableError,
    correlate_identities,
    load_trusted_sid_table,
    parse_mount_note,
    MountNote,
    parse_sid,
    sid_from_binary,
)
from reg_identity.hive_builder import (
    REG_BINARY,
    REG_DWORD,
    REG_SZ,
    HiveBuilder,
    dword,
    sam_f,
    sam_v,
    sid_bytes,
    utf16,
)


SID_A = "S-1-5-21-111111111-222222222-333333333-1001"
SID_B = "S-1-5-21-111111111-222222222-333333333-1002"
MACHINE_SID = "S-1-5-21-111111111-222222222-333333333"


def _values(**items):
    result = {}
    for key, value in items.items():
        if isinstance(value, tuple):
            result[key] = value
        else:
            result[key] = (REG_SZ, utf16(value))
    return result


def build_ntuser(username="alice", sid=SID_A, domain=None,
                 profile_path=None, include_environment=True):
    hive = HiveBuilder("NTUSER.DAT")
    if include_environment:
        values = {"USERNAME": (REG_SZ, utf16(username))}
        if domain:
            values["USERDOMAIN"] = (REG_SZ, utf16(domain))
        if profile_path:
            values["USERPROFILE"] = (REG_SZ, utf16(profile_path))
        hive.add_key(hive.root, "Volatile Environment", values)

    software = None
    microsoft = None
    if profile_path or sid:
        software = hive.add_key(hive.root, "Software")
        microsoft = hive.add_key(software, "Microsoft")

    if profile_path:
        windows = hive.add_key(microsoft, "Windows")
        current = hive.add_key(windows, "CurrentVersion")
        explorer = hive.add_key(current, "Explorer")
        hive.add_key(explorer, "Shell Folders", {
            "Desktop": (REG_SZ, utf16(profile_path + "\\Desktop")),
            "Personal": (REG_SZ, utf16(profile_path + "\\Documents")),
        })

    if sid:
        protected = hive.add_key(microsoft,
                                 "Protected Storage System Provider")
        hive.add_key(protected, sid)
    return hive.build()


def build_software_profiles(profiles):
    hive = HiveBuilder("SOFTWARE")
    microsoft = hive.add_key(hive.root, "Microsoft")
    windows_nt = hive.add_key(microsoft, "Windows NT")
    current = hive.add_key(windows_nt, "CurrentVersion")
    profile_list = hive.add_key(current, "ProfileList")
    for sid, path in profiles:
        values = {
            "ProfileImagePath": (REG_SZ, utf16(path)),
            "Sid": (REG_BINARY, sid_bytes(sid)),
        }
        hive.add_key(profile_list, sid, values)
    return hive.build()


def build_sam(accounts, machine_sid=MACHINE_SID):
    hive = HiveBuilder("SAM")
    sam = hive.add_key(hive.root, "SAM")
    domains = hive.add_key(sam, "Domains")
    account = hive.add_key(domains, "Account")
    hive.add_value(account, "V", REG_BINARY, sid_bytes(machine_sid))
    users = hive.add_key(account, "Users")
    names = hive.add_key(users, "Names")
    for name, rid, profile in accounts:
        hive.add_key(names, name, {"": (rid, b"")})
        hive.add_key(users, "%08X" % rid, {
            "V": (REG_BINARY, sam_v(name, profile_path=profile)),
            "F": (REG_BINARY, sam_f(rid)),
        })
    return hive.build()


def test_sid_text_and_binary_round_trip():
    assert parse_sid("s-1-5-21-1-2-3-1001") == "S-1-5-21-1-2-3-1001"
    assert parse_sid(sid_bytes(SID_A)) == SID_A
    assert sid_from_binary(sid_bytes(SID_A)) == SID_A
    with pytest.raises(ValueError):
        parse_sid("alice")


def test_mount_notes_are_conservative_and_keep_path_provenance():
    assert [clue.value for clue in
            parse_mount_note("C__Users_alice_NTUSER.DAT").usernames] == [
                "alice"]
    assert parse_mount_note("NTUSER.DAT").usernames == []
    assert parse_mount_note("SAM.xz").usernames == []

    default = parse_mount_note("C__Users_Default_NTUSER.DAT")
    assert [(clue.value, clue.tags) for clue in default.usernames] == [
        ("Default", ("machine_default",))]

    direct = MountNote("C__Users_alice_NTUSER.DAT", "E1")
    assert [clue.value for clue in direct.usernames] == ["alice"]

    explicit = parse_mount_note(
        "export=lab; user=alice; domain=ACME; sid=" + SID_A)
    assert explicit.sids[0].value == SID_A
    assert explicit.usernames[0].value == "alice"
    assert explicit.usernames[0].domain == "ACME"


def test_trusted_table_accepts_csv_json_and_text():
    csv_table = load_trusted_sid_table(
        "username,sid,domain\nalice,%s,ACME\n" % SID_A,
        format="csv")
    assert csv_table.records()[0].display_name == "ACME\\alice"

    json_table = load_trusted_sid_table(
        {"users": [{"username": "alice", "sid": SID_A}]})
    assert json_table.records()[0].sid == SID_A

    mapping_table = TrustedSidTable.from_json({SID_A: "alice"})
    assert mapping_table.records()[0].username == "alice"

    text_table = load_trusted_sid_table(
        "S-1-5-21-1-2-3-1001 alice", format="text")
    assert text_table.records()[0].sid == "S-1-5-21-1-2-3-1001"

    with pytest.raises(TrustedSidTableError):
        load_trusted_sid_table("alice,S-1-5-21-1-2-3-NOPE", format="csv")


def test_no_trusted_table_never_produces_unique_attribution():
    hive = build_ntuser(profile_path="C:\\Users\\alice")
    report = correlate_identities([
        {"data": hive, "evidence_id": "SITE", "mount_note":
         "C__Users_alice_NTUSER.DAT"},
    ])

    assert report.is_unique is False
    assert report.unique is False
    assert report.attribution is None
    assert report.trusted_sid_table_present is False
    assert len(report.identities) == 1
    identity = report.identities[0]
    assert identity.sid == SID_A
    assert identity.username == "alice"
    assert identity.status == ResolutionStatus.UNRESOLVED
    assert identity.unique is False
    assert report.attribution_for("SITE").unique is False
    assert report.attribution_for("SITE").sid is None


def test_same_hive_exported_two_ways_is_one_person_with_table():
    hive = build_ntuser(profile_path="C:\\Users\\alice")
    report = correlate_identities([
        {"data": hive, "evidence_id": "SITE", "mount_note": "alice"},
        {"data": hive, "evidence_id": "LAB", "mount_note":
         "C__Users_alice_NTUSER.DAT"},
    ], trusted_sid_table=[("alice", SID_A)])

    assert report.is_unique is True
    assert report.attribution["sid"] == SID_A
    assert report.attribution["username"] == "alice"
    assert set(report.attribution["evidence_ids"]) == {"SITE", "LAB"}
    assert len(report.identities) == 1
    assert report.identities[0].evidence_ids == ["SITE", "LAB"]
    assert len(report.mirror_groups) == 1
    assert report.mirror_groups[0]["kind"] == "byte_identical"
    assert report.attribution_for("SITE").unique is True
    assert report.attribution_for("LAB").unique is True


def test_mirror_copy_keeps_both_mount_notes_and_adds_conflict():
    hive = build_ntuser(profile_path="C:\\Users\\alice")
    report = correlate_identities([
        {"data": hive, "evidence_id": "SITE", "mount_note": "alice"},
        {"data": hive, "evidence_id": "LAB", "mount_note": "bob"},
    ], trusted_sid_table=[("alice", SID_A)])

    assert report.is_unique is True
    assert len(report.identities) == 1
    assert set(report.identities[0].evidence_ids) == {"SITE", "LAB"}
    assert any(conflict.kind == "mirror_copy_provenance_conflict"
               for conflict in report.conflicts)
    assert all(len(evidence.mount_notes) == 1 for evidence in report.evidence)


def test_same_name_with_conflicting_sids_is_preserved():
    hive_a = build_ntuser(username="alice", sid=SID_A,
                          profile_path="C:\\Users\\alice")
    hive_b = build_ntuser(username="alice", sid=SID_B,
                          profile_path="C:\\Users\\alice")
    report = correlate_identities([
        {"data": hive_a, "evidence_id": "A"},
        {"data": hive_b, "evidence_id": "B"},
    ])

    assert report.is_unique is False
    assert len(report.identities) == 2
    assert set(identity.sid for identity in report.identities) == {SID_A, SID_B}
    assert any(conflict.kind == "same_name_sid_conflict"
               for conflict in report.conflicts)

    resolved = correlate_identities([
        {"data": hive_a, "evidence_id": "A"},
        {"data": hive_b, "evidence_id": "B"},
    ], trusted_sid_table=[("alice", SID_A)])
    statuses = {identity.sid: identity.status for identity in resolved.identities}
    assert statuses[SID_A] == ResolutionStatus.RESOLVED
    assert statuses[SID_B] == ResolutionStatus.CONFLICT
    assert resolved.is_unique is False
    assert resolved.attribution is None


def test_missing_sid_is_resolved_by_unique_trusted_name_only():
    hive = build_ntuser(username="alice", sid=None,
                        profile_path="C:\\Users\\alice")
    report = correlate_identities([
        {"data": hive, "evidence_id": "E1"},
    ], trusted_sid_table=[("alice", SID_A)])

    assert report.is_unique is True
    identity = report.identities[0]
    assert identity.sid == SID_A
    assert identity.username == "alice"
    assert identity.status == ResolutionStatus.RESOLVED
    assert identity.trusted_match == "name"
    assert identity.sid_missing_evidence_ids == ["E1"]
    assert any("did not contain a SID" in warning
               for warning in identity.warnings)


def test_missing_sid_with_ambiguous_trusted_name_stays_ambiguous():
    hive = build_ntuser(username="alice", sid=None,
                        profile_path="C:\\Users\\alice")
    table = [
        ("DOMAIN1\\alice", SID_A),
        ("DOMAIN2\\alice", SID_B),
    ]
    report = correlate_identities([
        {"data": hive, "evidence_id": "E1"},
    ], trusted_sid_table=table)

    assert report.is_unique is False
    assert report.attribution is None
    identity = report.identities[0]
    assert identity.status == ResolutionStatus.AMBIGUOUS
    assert identity.reason == "trusted_name_ambiguous"
    assert report.attribution_for("E1").unique is False


def test_software_profilelist_and_machine_defaults_are_separate():
    hive = build_software_profiles([
        ("S-1-5-18", "%systemroot%\\system32\\config\\systemprofile"),
        (SID_A, "C:\\Users\\alice"),
    ])
    report = correlate_identities([
        {"data": hive, "evidence_id": "SOFTWARE"},
    ], trusted_sid_table=[("alice", SID_A)])

    by_sid = {identity.sid: identity for identity in report.identities}
    assert by_sid["S-1-5-18"].kind == "machine_default"
    assert by_sid["S-1-5-18"].unique is False
    assert by_sid[SID_A].status == ResolutionStatus.RESOLVED
    assert by_sid[SID_A].unique is True
    # A machine-wide SOFTWARE hive is not itself one user.
    assert report.is_unique is False
    assert report.attribution_for("SOFTWARE").status == (
        ResolutionStatus.MACHINE_SCOPE)


def test_sam_hive_exposes_machine_sid_and_accounts():
    hive = build_sam([
        ("alice", 1001, "C:\\Users\\alice"),
        ("Guest", 501, "C:\\Users\\Guest"),
    ])
    report = correlate_identities([
        {"data": hive, "evidence_id": "SAM"},
    ])
    evidence = report.evidence[0]
    assert evidence.hive_type == "sam"
    assert evidence.metadata["machine_sid"] == MACHINE_SID
    identities = {identity.sid: identity for identity in report.identities}
    assert identities[MACHINE_SID + "-1001"].username == "alice"
    assert identities[MACHINE_SID + "-501"].kind == "machine_default"
    assert all(identity.unique is False for identity in report.identities)


def test_domain_qualification_uses_hive_userdomain():
    hive = build_ntuser(domain="ACME", profile_path="C:\\Users\\alice")
    report = correlate_identities(
        [{"data": hive, "evidence_id": "E1"}],
        trusted_sid_table=[("ACME\\alice", SID_A)])
    assert report.is_unique is True
    assert report.attribution["domain"] == "ACME"
    assert report.identities[0].display_name == "ACME\\alice"


def test_default_profile_path_with_a_user_sid_is_still_machine_default():
    hive = build_software_profiles([(SID_A, "C:\\Users\\Default")])
    report = correlate_identities(
        [{"data": hive, "evidence_id": "SOFTWARE"}],
        trusted_sid_table=[("alice", SID_A)])
    identity = report.identity_by_id("sid:" + SID_A)
    assert identity.kind == "machine_default"
    assert identity.unique is False
    assert report.is_unique is False


def test_sid_less_copy_is_attached_to_the_sid_cluster():
    with_sid = build_ntuser(profile_path="C:\\Users\\alice")
    without_sid = build_ntuser(sid=None, profile_path="C:\\Users\\alice")
    report = correlate_identities(
        [
            {"data": with_sid, "evidence_id": "WITH"},
            {"data": without_sid, "evidence_id": "WITHOUT"},
        ],
        trusted_sid_table=[("alice", SID_A)])
    assert report.is_unique is True
    assert len(report.identities) == 1
    identity = report.identities[0]
    assert identity.sid == SID_A
    assert set(identity.evidence_ids) == {"WITH", "WITHOUT"}
    assert identity.sid_missing_evidence_ids == ["WITHOUT"]


def test_read_only_and_json_serializable(tmp_path):
    hive = build_ntuser(profile_path="C:\\Users\\alice")
    path = tmp_path / "NTUSER.DAT"
    path.write_bytes(hive)
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    report = correlate_identities(
        [path], trusted_sid_table=[("alice", SID_A)])
    after = hashlib.sha256(path.read_bytes()).hexdigest()

    assert before == after
    assert report.is_unique is True
    decoded = json.loads(report.to_json())
    assert decoded["read_only"] is True
    assert decoded["attribution"]["sid"] == SID_A


def test_trusted_table_is_never_auto_discovered(tmp_path):
    hive = build_ntuser(profile_path="C:\\Users\\alice")
    (tmp_path / "NTUSER.DAT").write_bytes(hive)
    (tmp_path / "sid_table.csv").write_text(
        "username,sid\nalice,%s\n" % SID_A)

    report = correlate_identities([str(tmp_path / "NTUSER.DAT")])
    assert report.trusted_sid_table_present is False
    assert report.is_unique is False
