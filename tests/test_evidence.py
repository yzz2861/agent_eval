import hashlib
import json
import os

import pytest

from Evtx.Evidence import (
    ACCESS_OMIT,
    STATUS_NOT_COLLECTED,
    STATUS_PARSE_FAILURE,
    STATUS_PRESENT,
    STATUS_REDACTED,
    EvidencePolicy,
    FieldRule,
    actor_and_org_unit_policy,
    actor_only_policy,
    create_evidence_bundle,
    load_bundle,
    locate_field,
    package_digest,
    recompute_digests,
    record_digest,
    relationship_digest,
    verify_bundle,
)
from evtx_scripts.evtx_evidence import main as evidence_main


def data_path(name):
    return os.path.join(os.path.dirname(__file__), "data", name)


def field(entry, name):
    for item in entry["fields"]:
        if item["name"] == name:
            return item
    raise AssertionError("missing field {!r}".format(name))


def test_actor_only_and_actor_plus_org_unit_scopes(tmp_path):
    source = data_path("security.evtx")
    records = "4-5,16-17,130-132"
    narrow = create_evidence_bundle(
        source, str(tmp_path / "narrow"), actor_only_policy(), record_numbers=records
    )
    broad = create_evidence_bundle(
        source, str(tmp_path / "broad"), actor_and_org_unit_policy(), record_numbers=records
    )

    assert narrow.manifest["policy"]["name"] == "actor-only"
    for entry in narrow.records:
        assert field(entry, "actor")["status"] == STATUS_PRESENT
        assert field(entry, "org_unit")["status"] == STATUS_REDACTED
        assert field(entry, "org_unit")["reason"] == "approval_withheld"
        assert "value" not in field(entry, "org_unit") or field(entry, "org_unit")["value"] is None

    for entry in broad.records:
        assert field(entry, "actor")["status"] == STATUS_PRESENT
        assert field(entry, "org_unit")["status"] == STATUS_PRESENT
        assert field(entry, "org_unit")["value"]

    narrow_bytes = (tmp_path / "narrow" / "records.jsonl").read_text(encoding="utf-8")
    assert "WORKGROUP" not in narrow_bytes
    assert "SubjectDomainName" not in narrow_bytes
    assert "WORKGROUP" in (tmp_path / "broad" / "records.jsonl").read_text(encoding="utf-8")

    assert narrow.relationships["scope"] == ["actor"]
    assert broad.relationships["scope"] == ["actor", "org_unit"]
    assert all(obj["kind"] == "actor" for obj in narrow.relationships["objects"])
    workgroup = [
        obj
        for obj in broad.relationships["objects"]
        if obj["kind"] == "org_unit" and obj["value"] == "WORKGROUP"
    ]
    assert workgroup and workgroup[0]["records"] == [4, 5, 16]
    assert any(
        link["kind"] == "same_actor" and link["records"] == [4, 5, 16]
        for link in narrow.relationships["relationships"]
    )

    assert verify_bundle(narrow) == {
        "ok": True,
        "errors": [],
        "warnings": [],
        "digest_ok": True,
        "relationships_ok": True,
        "source_ok": None,
        "records_checked": 7,
        "field_refs_checked": 0,
        "policy": "actor-only",
    }
    report = verify_bundle(broad, source=source)
    assert report["ok"]
    assert report["field_refs_checked"] == 7 * 6


def test_missing_values_are_explained(tmp_path):
    source = data_path("system.evtx")
    bundle = create_evidence_bundle(
        source,
        str(tmp_path / "system"),
        actor_and_org_unit_policy(),
        record_numbers="12049-12050",
    )
    for entry in bundle.records:
        actor = field(entry, "actor")
        assert actor["status"] == STATUS_NOT_COLLECTED
        assert actor["reason"] == "source_field_absent"

    redacted = create_evidence_bundle(
        data_path("security.evtx"),
        str(tmp_path / "redacted"),
        actor_only_policy(),
        record_numbers="4",
    )
    assert field(redacted.records[0], "org_unit")["status"] == STATUS_REDACTED

    malformed = create_evidence_bundle(
        data_path("dns_log_malformed.evtx"),
        str(tmp_path / "malformed"),
        actor_and_org_unit_policy(),
        record_numbers="1-2",
    )
    broken = malformed.record(2)
    assert broken["status"] == STATUS_PARSE_FAILURE
    assert broken["error"].startswith("UnicodeDecodeError:")
    assert all(item["status"] == STATUS_PARSE_FAILURE for item in broken["fields"])
    assert all(item["reason"] == "parser_error" for item in broken["fields"])

    omitted = create_evidence_bundle(
        data_path("security.evtx"),
        str(tmp_path / "omitted"),
        EvidencePolicy(
            name="omit-test",
            fields=(FieldRule("raw_xml", (), access=ACCESS_OMIT),),
            metadata=(),
        ),
        record_numbers="4",
    )
    assert field(omitted.records[0], "raw_xml")["status"] == STATUS_NOT_COLLECTED
    assert field(omitted.records[0], "raw_xml")["reason"] == "policy_excluded"


@pytest.mark.parametrize(
    "selection, expected_records, expected_refs",
    [
        ("4-5", 2, 10),
        ("4-5,16-17,130", 5, 25),
    ],
)
def test_two_extract_sizes_resolve_every_original_reference(tmp_path, selection, expected_records, expected_refs):
    source = data_path("security.evtx")
    bundle = create_evidence_bundle(
        source,
        str(tmp_path / "bundle"),
        actor_only_policy(),
        record_numbers=selection,
    )
    report = verify_bundle(bundle, source=source)
    assert report["ok"], report["errors"]
    assert report["records_checked"] == expected_records
    assert report["field_refs_checked"] == expected_refs

    with open(source, "rb") as stream:
        for entry in bundle.records:
            ref = entry["record"]
            stream.seek(ref["offset"])
            raw_record = stream.read(ref["length"])
            assert raw_record[0:4] == b"\x2a\x2a\x00\x00"
            assert int.from_bytes(raw_record[4:8], "little") == ref["length"]
            assert hashlib.sha256(raw_record).hexdigest() == ref["raw_sha256"]

            for item in entry["fields"] + entry["metadata"]:
                if item["status"] != STATUS_PRESENT:
                    continue
                for segment in item["source"]["segments"]:
                    stream.seek(segment["offset"])
                    raw = stream.read(segment["length"])
                    assert hashlib.sha256(raw).hexdigest() == segment["raw_sha256"]
                    if segment["encoding"] == "utf-16le":
                        assert raw.decode("utf-16le").rstrip("\x00") == item["value"]

            located = locate_field(source, ref, "EventData/Data[@Name='SubjectUserName']")
            assert located["status"] == STATUS_PRESENT
            assert located["value"] == field(entry, "actor")["value"]


def test_digests_are_recomputable_and_tampering_is_detected(tmp_path):
    source = data_path("security.evtx")
    created = create_evidence_bundle(
        source, str(tmp_path / "bundle"), actor_and_org_unit_policy(), record_numbers="4-5"
    )
    loaded = load_bundle(str(tmp_path / "bundle"))

    assert record_digest(loaded.records[0]) == loaded.records[0]["digest"]
    assert relationship_digest(loaded.relationships) == loaded.relationships["digest"]
    assert package_digest(loaded.manifest, loaded.records, loaded.relationships) == loaded.manifest["forensic_digest"]
    assert (
        recompute_digests(loaded.manifest, loaded.records, loaded.relationships)
        == created.manifest["forensic_digest"]
    )

    loaded.records[0]["fields"][0]["value"] = "tampered"
    report = verify_bundle(loaded)
    assert not report["ok"]
    assert any("digest mismatch" in error for error in report["errors"])

    loaded = load_bundle(str(tmp_path / "bundle"))
    loaded.records[0]["fields"][0]["value"] = "tampered"
    loaded.records[0]["fields"][0]["value_sha256"] = hashlib.sha256(b"tampered").hexdigest()
    loaded.records[0]["digest"] = record_digest(loaded.records[0])
    report = verify_bundle(loaded)
    assert not report["ok"]
    assert any(error.startswith("relationships:") for error in report["errors"])


def test_verify_reports_source_mismatch(tmp_path):
    source = data_path("security.evtx")
    bundle = create_evidence_bundle(
        source, str(tmp_path / "bundle"), actor_only_policy(), record_numbers="4"
    )
    changed = tmp_path / "changed.evtx"
    with open(source, "rb") as stream:
        data = bytearray(stream.read())
    data[-1] ^= 0xFF
    changed.write_bytes(data)

    report = verify_bundle(bundle, source=str(changed))
    assert not report["ok"]
    assert report["source_ok"] is False
    assert "source: sha256 mismatch" in report["errors"]
    assert json.dumps(report, sort_keys=True)


def test_cli_creates_and_verifies_bundle(tmp_path, capsys):
    source = data_path("security.evtx")
    target = str(tmp_path / "cli-bundle")
    assert evidence_main(["create", source, target, "--policy", "narrow", "--records", "4-5"]) == 0
    capsys.readouterr()
    assert evidence_main(["verify", target, "--evtx", source]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is True
    assert output["records_checked"] == 2
