import json
import os

import pytest

from Evtx.Index import (
    EVENT_TYPE_POLICY,
    FULL_POLICY,
    AccessPolicy,
    EvidenceLocation,
    OfflineIndex,
    QueryCondition,
    RecordView,
    STATUS_AVAILABLE,
    STATUS_NOT_INDEXED,
    STATUS_NOT_PERMITTED,
    STATUS_UNSUPPORTED_OPERATOR,
    build_evtx_index,
    build_index_from_views,
)


DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
SYSTEM_EVTX = os.path.join(DATA_DIR, "system.evtx")


def _record_xml(event_id, target_user, secret, record_id=1):
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System>"
        '<Provider Name="Microsoft-Windows-Security-Auditing"/>'
        "<EventID>{event_id}</EventID>"
        "<Channel>Security</Channel>"
        "<Computer>WORKSTATION</Computer>"
        "<EventRecordID>{record_id}</EventRecordID>"
        "</System>"
        "<EventData>"
        '<Data Name="TargetUserName">{target_user}</Data>'
        '<Data Name="Secret">{secret}</Data>'
        "</EventData>"
        "</Event>"
    ).format(event_id=event_id, record_id=record_id, target_user=target_user, secret=secret)


def _views(secret):
    return [
        RecordView(
            _record_xml(4624, "alice", secret, record_id=1),
            EvidenceLocation("evidence.evtx", 0, 4096, 1, 4608),
        ),
        RecordView(
            _record_xml(4625, "bob", secret, record_id=2),
            EvidenceLocation("evidence.evtx", 0, 4096, 2, 6000),
        ),
    ]


@pytest.fixture(scope="module")
def event_index():
    return build_evtx_index(SYSTEM_EVTX, EVENT_TYPE_POLICY)


@pytest.fixture(scope="module")
def field_index():
    policy = AccessPolicy.limited_fields(
        ("System.EventID", "EventData.param1", "EventData.param2"),
        name="field-content",
    )
    return build_evtx_index(SYSTEM_EVTX, policy)


def test_event_type_index_keeps_locations_and_counts(event_index):
    assert event_index.coverage.records_indexed == 1601
    assert event_index.coverage.is_partial() is False

    result = event_index.query([QueryCondition("EventID", "7036")])
    assert result.available is True
    assert result.hit_count == 1288
    assert result.condition_counts == [1288]
    assert len(result.hits) == result.hit_count
    assert len({hit.location.record_num for hit in result.hits}) == result.hit_count
    assert all(hit.location.source == SYSTEM_EVTX for hit in result.hits)
    assert all(hit.location.chunk_offset >= 0x1000 for hit in result.hits)
    assert all(hit.location.record_offset > hit.location.chunk_offset for hit in result.hits)


def test_same_conjunction_under_two_policies(event_index, field_index):
    conditions = ["System.EventID=7036", "EventData.param1?"]

    restricted = event_index.query(conditions, viewer_policy=EVENT_TYPE_POLICY)
    assert restricted.available is False
    assert restricted.hit_count is None
    assert restricted.condition_counts is None
    assert restricted.hits == []
    statuses = {assessment.field: assessment.status for assessment in restricted.assessments}
    assert statuses["System.EventID"] == STATUS_AVAILABLE
    assert statuses["EventData.param1"] == STATUS_NOT_INDEXED

    permitted = field_index.query(conditions, viewer_policy=field_index.policy)
    assert permitted.available is True
    assert permitted.hit_count == 1288
    assert permitted.condition_counts is not None
    assert permitted.condition_counts[0] == 1288
    assert 0 < permitted.condition_counts[1] <= 1601

    event_only = event_index.query(["System.EventID=7036"])
    assert event_only.available is True
    assert event_only.hit_count == 1288


def test_viewer_policy_is_a_narrowing_filter(event_index):
    broad = build_index_from_views(_views("classified"), FULL_POLICY)
    assessment = broad.assess(["Secret=classified"], viewer_policy=EVENT_TYPE_POLICY)[0]
    assert assessment.field == "EventData.Secret"
    assert assessment.status == STATUS_NOT_PERMITTED

    result = broad.query(["System.EventID=4624", "Secret=classified"], viewer_policy=EVENT_TYPE_POLICY)
    assert result.available is False
    assert result.hit_count is None
    assert result.hits == []

    only_event = broad.query(["System.EventID=4624"], viewer_policy=EVENT_TYPE_POLICY)
    assert only_event.available is True
    assert only_event.hit_count == 1

    field_policy = AccessPolicy.limited_fields(
        ("System.EventID", "EventData.Secret"),
        name="field-content",
    )
    conditions = ["System.EventID=4624", "Secret=classified"]
    assert broad.query(conditions, viewer_policy=EVENT_TYPE_POLICY).available is False
    same_index_result = broad.query(conditions, viewer_policy=field_policy)
    assert same_index_result.available is True
    assert same_index_result.hit_count == 1


def test_unauthorized_field_changes_do_not_change_restricted_presentation():
    restricted_policy = AccessPolicy.limited_fields(
        ("System.EventID", "EventData.TargetUserName"),
        name="restricted",
    )
    first = build_index_from_views(_views("first-secret"), restricted_policy)
    second = build_index_from_views(_views("second-secret"), restricted_policy)

    assert first.to_dict() == second.to_dict()
    assert first.fingerprint() == second.fingerprint()
    rendered = json.dumps(first.to_dict())
    assert "first-secret" not in rendered
    assert "second-secret" not in rendered
    assert "EventData.Secret" not in rendered

    first_result = first.query(["System.EventID=4624", "TargetUserName=alice"])
    second_result = second.query(["System.EventID=4624", "TargetUserName=alice"])
    assert first_result.to_dict() == second_result.to_dict()
    assert first_result.hit_count == 1

    broad_first = build_index_from_views(_views("first-secret"), FULL_POLICY)
    broad_second = build_index_from_views(_views("second-secret"), FULL_POLICY)
    restricted_first = broad_first.to_dict(viewer_policy=restricted_policy)
    restricted_second = broad_second.to_dict(viewer_policy=restricted_policy)
    assert restricted_first == restricted_second
    assert broad_first.fingerprint(restricted_policy) == broad_second.fingerprint(restricted_policy)
    assert "first-secret" not in json.dumps(restricted_first)
    assert "second-secret" not in json.dumps(restricted_second)

    mixed_policy = AccessPolicy(
        "mixed",
        ("System.EventID", "EventData.Secret"),
        "Event type plus one restricted field.",
    )
    mixed = build_index_from_views(_views("hidden-secret"), mixed_policy)
    mixed_view = mixed.to_dict(viewer_policy=EVENT_TYPE_POLICY)
    assert "hidden-secret" not in json.dumps(mixed_view)
    assert "EventData.Secret" not in json.dumps(mixed_view)
    assert mixed_view["build_policy"]["redacted"] is True


def test_refused_conjunction_does_not_depend_on_unauthorized_value(event_index):
    presentations = []
    for value in ("alpha", "a completely different value"):
        result = event_index.query(["System.EventID=7036", "EventData.param1=%s" % value])
        assert result.available is False
        assert result.hit_count is None
        assert result.hits == []
        presentations.append(
            (
                [assessment.to_dict() for assessment in result.assessments],
                result.hit_count,
                result.hits,
                event_index.fingerprint(),
            )
        )
    assert presentations[0][1:] == presentations[1][1:]


def test_tampered_unauthorized_value_in_saved_index_is_not_presented(tmp_path):
    restricted_policy = AccessPolicy.limited_fields(
        ("System.EventID", "EventData.TargetUserName"),
        name="restricted",
    )
    full = build_index_from_views(_views("original-secret"), FULL_POLICY)
    path = tmp_path / "full.json"
    full.save(path)

    data = json.loads(path.read_text())
    for record in data["records"]:
        record["fields"]["EventData.Secret"] = ["tampered-secret"]
    path.write_text(json.dumps(data))

    loaded = OfflineIndex.load(path)
    assert loaded.to_dict(viewer_policy=restricted_policy) == full.to_dict(viewer_policy=restricted_policy)
    assert loaded.fingerprint(restricted_policy) == full.fingerprint(restricted_policy)
    assert "tampered-secret" not in json.dumps(loaded.to_dict(viewer_policy=restricted_policy))


def test_partial_views_only_query_verified_fragments():
    good_location = EvidenceLocation("fragment.evtx", 3, 0x4000, 77, 0x4800)
    bad_location = EvidenceLocation("fragment.evtx", 4, 0x14000, 78, 0x14800)
    index = build_index_from_views(
        [
            RecordView(_record_xml(42, "alice", "s", record_id=77), good_location),
            RecordView("<Event><System>", bad_location),
        ],
        EVENT_TYPE_POLICY,
    )

    assert index.coverage.records_seen == 2
    assert index.coverage.records_indexed == 1
    assert index.coverage.records_failed == 1
    assert index.coverage.is_partial() is True
    assert index.coverage.failed_locations[0]["record_num"] == 78
    assert index.coverage.failed_locations[0]["reason"] == "record view could not be parsed"

    result = index.query(["System.EventID=42"])
    assert result.available is True
    assert result.hit_count == 1
    assert result.hits[0].location == good_location
    assert bad_location not in [hit.location for hit in result.hits]


def test_truncated_evtx_indexes_the_verified_prefix(tmp_path):
    with open(SYSTEM_EVTX, "rb") as source:
        raw = source.read()
    truncated = raw[: 0x1000 + (2 * 0x10000) + 0x100]
    path = tmp_path / "truncated.evtx"
    path.write_bytes(truncated)

    index = build_evtx_index(path, EVENT_TYPE_POLICY)
    assert index.coverage.chunks_declared == 9
    assert index.coverage.chunks_seen == 2
    assert index.coverage.chunks_missing == 7
    assert index.coverage.is_partial() is True
    assert index.coverage.records_indexed > 0

    result = index.query(["System.EventID=7036"])
    assert result.available is True
    assert result.hit_count > 0
    assert all(hit.location.chunk_index in (0, 1) for hit in result.hits)


def test_save_and_load_round_trip(event_index, tmp_path):
    path = tmp_path / "index.json"
    event_index.save(path)
    loaded = OfflineIndex.load(path)
    assert loaded.fingerprint() == event_index.fingerprint()
    assert loaded.query(["EventID=7036"]).to_dict() == event_index.query(["EventID=7036"]).to_dict()


def test_condition_availability_is_explicit(event_index):
    missing = build_index_from_views(_views("s"), FULL_POLICY).assess(["EventData.NotThere?"])[0]
    assert missing.status == STATUS_AVAILABLE
    assert missing.observed is False

    missing_result = build_index_from_views(_views("s"), FULL_POLICY).query(["EventData.NotThere?"])
    assert missing_result.available is True
    assert missing_result.hit_count == 0

    unsupported = event_index.assess([QueryCondition("System.EventID", "1", "regex")])[0]
    assert unsupported.status == STATUS_UNSUPPORTED_OPERATOR

    restricted = event_index.assess(["EventData.param1?"])[0]
    assert restricted.status == STATUS_NOT_INDEXED


def test_condition_text_parsing():
    assert QueryCondition.from_text("EventID=4624") == QueryCondition("EventID", "4624", "eq")
    assert QueryCondition.from_text("EventData.TargetUserName~=adm") == QueryCondition(
        "EventData.TargetUserName", "adm", "contains"
    )
    assert QueryCondition.from_text("EventData.TargetUserName?") == QueryCondition(
        "EventData.TargetUserName", None, "exists"
    )


def test_cli_build_query_and_refusal(tmp_path):
    from evtx_scripts.evtx_index import main

    output = tmp_path / "cli-index.json"
    source = os.path.join(DATA_DIR, "issue_38.evtx")
    assert main(["build", source, "-o", str(output), "--policy", "event-type"]) == 0
    assert output.exists()
    assert main(["query", str(output), "--where", "EventID=4672", "--policy", "event-type", "--json"]) == 0
    assert (
        main(
            [
                "query",
                str(output),
                "--where",
                "EventID=4672",
                "--where",
                "EventData.TargetUserName?",
                "--policy",
                "event-type",
                "--json",
            ]
        )
        == 2
    )
