"""Tests for the opt-in execution evidence adjudication API.

The fixtures are synthetic plugin-output snapshots (no registry hive parsing
required) so the adjudication rules can be tested deterministically:

* file_present_only: AmCache alone must never prove execution.
* execution_evidence_compatible: aligned UserAssist + AmCache evidence.
* same_name_different_users: per-SID facts are never spliced into one process.
* collection_gap: disjoint/unknown acquisition windows block cross-hive
  splicing, and unobserved subjects stay "insufficient" rather than negative.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from regipy.evidence import (
    CollectionWindow,
    CounterEvidenceReason,
    EvidenceAdjudicator,
    FactStrength,
    Proposition,
    SourceContext,
    UserIdentity,
    Verdict,
    VERDICT_LABELS_ZH,
    normalize_amcache,
    normalize_bam,
    normalize_path,
    normalize_shimcache,
    normalize_user_assist,
)

FIXTURE_DIR = Path(__file__).parent.joinpath("data", "evidence")
UTC = dt.timezone.utc


def _load_fixture(name: str) -> dict:
    with open(FIXTURE_DIR.joinpath(name), encoding="utf-8") as handle:
        return json.load(handle)


def _build_windows(raw: dict) -> dict[str, CollectionWindow]:
    return {
        source: CollectionWindow(
            start=dt.datetime.fromisoformat(value["start"]) if value.get("start") else None,
            end=dt.datetime.fromisoformat(value["end"]) if value.get("end") else None,
            source_name=value.get("source_name"),
        )
        for source, value in raw.items()
    }


def _build_identities(raw: dict) -> dict[str, UserIdentity]:
    return {
        source: UserIdentity(
            sid=value.get("sid"),
            username=value.get("username"),
            hive_origin=value.get("hive_origin"),
        )
        for source, value in raw.items()
    }


def _run_fixture(fixture: dict) -> list:
    adjudicator = EvidenceAdjudicator(volume_mappings=fixture.get("volume_mappings"))
    windows = _build_windows(fixture.get("windows", {}))
    identities = _build_identities(fixture.get("identities", {}))
    for source, entries in fixture["plugin_outputs"].items():
        adjudicator.add_plugin_output(
            source,
            entries,
            window=windows.get(source),
            identity=identities.get(source),
        )
    return adjudicator.adjudicate_all()


def test_fixture_file_present_only_never_proves_execution():
    fixture = _load_fixture("file_present_only.json")
    conclusions = _run_fixture(fixture)

    assert len(conclusions) == 1
    conclusion = conclusions[0]
    assert conclusion.verdict is Verdict.PRESENT
    assert conclusion.verdict_label_zh == VERDICT_LABELS_ZH[Verdict.PRESENT]
    assert conclusion.minimal_support == ["amcache:0"]
    assert conclusion.counter_evidence == []
    # The AmCache fact is explicitly a file_present proposition, not execution.
    adjudicator = EvidenceAdjudicator()
    facts = adjudicator.add_plugin_output(
        "amcache",
        fixture["plugin_outputs"]["amcache"],
        window=_build_windows(fixture["windows"])["amcache"],
    )
    assert all(fact.proposition is Proposition.FILE_PRESENT for fact in facts)


def test_fixture_execution_evidence_compatible_splices_aligned_facts():
    fixture = _load_fixture("execution_evidence_compatible.json")
    conclusions = _run_fixture(fixture)
    by_identity = {conclusion.identity_key: conclusion for conclusion in conclusions}

    user_conclusion = by_identity["sid:S-1-5-21-1-1001"]
    assert user_conclusion.verdict is Verdict.EXECUTION_EVIDENCED
    assert user_conclusion.minimal_support == ["user_assist:0"]
    # The machine-wide AmCache fact is spliced in as supporting evidence.
    assert "amcache:0" in user_conclusion.supporting_fact_ids
    assert user_conclusion.counter_evidence == []
    assert user_conclusion.conflicts == []

    # The host-level anonymous view still only proves presence.
    host_conclusion = by_identity[None]
    assert host_conclusion.verdict is Verdict.PRESENT
    assert host_conclusion.minimal_support == ["amcache:0"]


def test_fixture_same_name_different_users_are_separate_conclusions():
    fixture = _load_fixture("same_name_different_users.json")
    conclusions = _run_fixture(fixture)

    assert len(conclusions) == 2
    identity_keys = {conclusion.identity_key for conclusion in conclusions}
    assert identity_keys == {"sid:S-1-5-21-1-1001", "sid:S-1-5-21-1-1002"}

    for conclusion in conclusions:
        assert conclusion.verdict is Verdict.EXECUTION_EVIDENCED
        assert len(conclusion.minimal_support) == 1
        reasons = {item.reason for item in conclusion.counter_evidence}
        assert reasons == {CounterEvidenceReason.IDENTITY_MISMATCH}
        # The other user fact must never appear as supporting evidence.
        own_sid = conclusion.identity_key
        for fact_id in conclusion.supporting_fact_ids:
            index = int(fact_id.rsplit(":", 1)[1])
            expected_index = 0 if own_sid.endswith("1001") else 1
            assert index == expected_index


def test_fixture_collection_gap_blocks_splicing_and_keeps_unknown_open():
    fixture = _load_fixture("collection_gap.json")
    conclusions = _run_fixture(fixture)

    observed = {(conclusion.path, conclusion.identity_key, conclusion.verdict) for conclusion in conclusions}
    for expected in fixture["expected_conclusions"]:
        key = (expected["path"], expected["identity_key"], Verdict(expected["verdict"]))
        assert key in observed

    all_reasons = {item.reason for conclusion in conclusions for item in conclusion.counter_evidence}
    for reason_name in fixture["expected_counter_reasons"]:
        assert CounterEvidenceReason(reason_name) in all_reasons

    # No conclusion may splice the disjoint-window BAM fact with AmCache.
    for conclusion in conclusions:
        if conclusion.identity_key == "sid:S-1-5-21-1-1001" and conclusion.verdict is Verdict.EXECUTION_EVIDENCED:
            assert "amcache:0" not in conclusion.supporting_fact_ids
            assert "shimcache:0" not in conclusion.supporting_fact_ids

    # An unobserved subject is insufficient, never a negative execution verdict.
    adjudicator = EvidenceAdjudicator(volume_mappings=fixture.get("volume_mappings"))
    for source, entries in fixture["plugin_outputs"].items():
        adjudicator.add_plugin_output(
            source,
            entries,
            window=_build_windows(fixture["windows"]).get(source),
        )
    unknown = adjudicator.adjudicate_path(fixture["unobserved_query"]["path"])
    assert unknown.verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert unknown.minimal_support == []
    assert unknown.supporting_fact_ids == []


def test_conflicting_observations_are_retained_not_merged():
    window = CollectionWindow(dt.datetime(2020, 1, 1, tzinfo=UTC), dt.datetime(2020, 3, 1, tzinfo=UTC), "shared")
    alice = UserIdentity(sid="S-1-5-21-1-1001", username="alice")
    adjudicator = EvidenceAdjudicator()
    adjudicator.add_plugin_output(
        "user_assist",
        [{"name": r"C:\Tools\conflict.exe", "run_counter": 0, "timestamp": "2020-02-01T00:00:00+00:00"}],
        window=window,
        identity=alice,
    )
    adjudicator.add_plugin_output(
        "background_activity_moderator",
        [{"executable": r"C:\Tools\conflict.exe", "sid": "S-1-5-21-1-1001", "timestamp": "2020-02-02T00:00:00+00:00"}],
        window=window,
    )
    conclusions = adjudicator.adjudicate_all()
    relevant = [item for item in conclusions if item.identity_key == "sid:S-1-5-21-1-1001"]
    assert len(relevant) == 1
    conclusion = relevant[0]
    assert conclusion.verdict is Verdict.EXECUTION_EVIDENCED
    assert conclusion.minimal_support == ["background_activity_moderator:0"]
    assert len(conclusion.conflicts) == 1
    assert "run_counter=0" in conclusion.conflicts[0]
    assert "without time-based merge" in conclusion.conflicts[0]
    # Both facts remain represented even though they contradict each other.
    assert set(conclusion.supporting_fact_ids) == {"background_activity_moderator:0", "user_assist:0"}


def test_path_normalization_equivalence_rules():
    drive = normalize_path(r"C:\Windows\System32\cmd.exe")
    mapped_device = normalize_path(
        r"\Device\HarddiskVolume2\Windows\System32\cmd.exe",
        {r"\Device\HarddiskVolume2": "C:"},
    )
    assert drive.equivalent_to(mapped_device)

    unmapped = normalize_path(r"\Device\HarddiskVolume9\a.exe")
    assert unmapped.device_form is True
    assert not unmapped.equivalent_to(normalize_path(r"C:\a.exe"))

    per_user = normalize_path(r"%APPDATA%\a.exe")
    assert per_user.unresolved == ("%APPDATA%",)
    assert not per_user.equivalent_to(normalize_path(r"C:\Users\u\AppData\Roaming\a.exe"))

    with pytest.raises(ValueError):
        normalize_path("")


def test_normalizers_emit_conservative_propositions():
    window = CollectionWindow(dt.datetime(2020, 1, 1, tzinfo=UTC), dt.datetime(2020, 2, 1, tzinfo=UTC), "w")
    context = SourceContext(source="user_assist", window=window)

    strong, weak = normalize_user_assist(
        [
            {"name": r"C:\x\run.exe", "run_counter": 3, "timestamp": "2020-01-01T00:00:00+00:00"},
            {"name": r"C:\x\idle.exe", "run_counter": 0, "timestamp": "2020-01-01T00:00:00+00:00"},
        ],
        context,
    )
    assert strong.proposition is Proposition.EXECUTION_OCCURRED
    assert strong.strength is FactStrength.STRONG
    assert weak.proposition is Proposition.EXECUTION_POSSIBLE
    assert weak.strength is FactStrength.WEAK

    amcache_facts = normalize_amcache([{"full_path": r"C:\x\run.exe"}], SourceContext(source="amcache", window=window))
    assert amcache_facts[0].proposition is Proposition.FILE_PRESENT
    assert amcache_facts[0].machine_wide is True

    bam_facts = normalize_bam(
        [{"executable": r"C:\x\run.exe", "sid": "S-1-5-21-1-9", "timestamp": "2020-01-01T00:00:00+00:00"}],
        SourceContext(source="background_activity_moderator", window=window),
    )
    assert bam_facts[0].identity.sid == "S-1-5-21-1-9"
    assert bam_facts[0].proposition is Proposition.EXECUTION_OCCURRED

    shim_facts = normalize_shimcache(
        [{"path": r"\??\C:\x\run.exe", "last_mod_date": "2020-01-01T00:00:00+00:00"}],
        SourceContext(source="shimcache", window=window),
    )
    assert shim_facts[0].proposition is Proposition.EXECUTION_POSSIBLE
    assert shim_facts[0].machine_wide is True


def test_unknown_source_raises_and_conclusions_are_json_serializable():
    adjudicator = EvidenceAdjudicator()
    with pytest.raises(ValueError):
        adjudicator.add_plugin_output("not_a_real_plugin", [])

    fixture = _load_fixture("file_present_only.json")
    conclusions = _run_fixture(fixture)
    serialized = json.dumps([conclusion.to_dict() for conclusion in conclusions])
    decoded = json.loads(serialized)
    assert decoded[0]["verdict"] == "present"
    assert "minimal_support" in decoded[0]
    assert "counter_evidence" in decoded[0]


def test_fact_ids_are_stable_and_minimal_support_is_subset():
    fixture = _load_fixture("execution_evidence_compatible.json")
    first = _run_fixture(fixture)
    second = _run_fixture(fixture)
    first_ids = [item.supporting_fact_ids for item in first]
    second_ids = [item.supporting_fact_ids for item in second]
    assert first_ids == second_ids
    for conclusion in first:
        assert conclusion.minimal_support
        assert set(conclusion.minimal_support).issubset(set(conclusion.supporting_fact_ids))


def test_adjudicate_path_includes_machine_wide_facts_for_a_user():
    window = CollectionWindow(dt.datetime(2020, 1, 1, tzinfo=UTC), dt.datetime(2020, 2, 1, tzinfo=UTC), "shared")
    alice = UserIdentity(sid="S-1-5-21-1-1001", username="alice")
    adjudicator = EvidenceAdjudicator()
    adjudicator.add_plugin_output(
        "amcache",
        [{"full_path": r"C:\Tools\x.exe", "timestamp": "2020-01-10T00:00:00+00:00"}],
        window=window,
    )
    adjudicator.add_plugin_output(
        "user_assist",
        [{"name": r"C:\Tools\x.exe", "run_counter": 2, "timestamp": "2020-01-20T00:00:00+00:00"}],
        window=window,
        identity=alice,
    )
    conclusion = adjudicator.adjudicate_path(r"C:\Tools\x.exe", alice)
    assert conclusion.verdict is Verdict.EXECUTION_EVIDENCED
    assert "amcache:0" in conclusion.supporting_fact_ids
    assert conclusion.minimal_support == ["user_assist:0"]


def test_adjudicate_path_keeps_window_gap_as_counter_evidence():
    early = CollectionWindow(dt.datetime(2020, 1, 1, tzinfo=UTC), dt.datetime(2020, 2, 1, tzinfo=UTC), "early")
    late = CollectionWindow(dt.datetime(2021, 6, 1, tzinfo=UTC), dt.datetime(2021, 7, 1, tzinfo=UTC), "late")
    alice = UserIdentity(sid="S-1-5-21-1-1001")
    adjudicator = EvidenceAdjudicator()
    adjudicator.add_plugin_output(
        "amcache",
        [{"full_path": r"C:\Tools\gap2.exe", "timestamp": "2020-01-10T00:00:00+00:00"}],
        window=early,
    )
    adjudicator.add_plugin_output(
        "background_activity_moderator",
        [{"executable": r"C:\Tools\gap2.exe", "sid": "S-1-5-21-1-1001", "timestamp": "2021-06-10T00:00:00+00:00"}],
        window=late,
    )
    conclusion = adjudicator.adjudicate_path(r"C:\Tools\gap2.exe", alice)
    assert conclusion.verdict is Verdict.EXECUTION_EVIDENCED
    reasons = {item.reason for item in conclusion.counter_evidence}
    assert CounterEvidenceReason.WINDOW_DISJOINT in reasons
    assert "amcache:0" not in conclusion.supporting_fact_ids
