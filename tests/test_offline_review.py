"""Tests for the offline evidence review entry point."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigma.collection import SigmaCollection
from sigma.matching import (
    EventExport,
    FieldRetention,
    MissingFieldReason,
    OfflineReviewer,
    RetentionPolicy,
    ReviewStatus,
    TimeWindow,
    review_offline,
)
from sigma.processing.pipeline import ProcessingPipeline

UTC = timezone.utc
FILES = Path(__file__).parent / "files" / "review"


@pytest.fixture
def collection():
    return SigmaCollection.from_yaml((FILES / "multi_condition_rule.yml").read_text())


@pytest.fixture
def pipeline():
    return ProcessingPipeline.from_yaml((FILES / "ecs_pipeline.yml").read_text())


@pytest.fixture
def retained_export():
    return EventExport.from_file(FILES / "export_retained.json")


@pytest.fixture
def reduced_export():
    return EventExport.from_file(FILES / "export_reduced.json")


def test_retained_export_recomputes_multi_condition_alert(
    collection, pipeline, retained_export
):
    report = OfflineReviewer(collection, RetentionPolicy(), pipeline=pipeline).review(
        retained_export
    )

    assert report.summary()["reviewable"] == 1
    review = report[0]
    assert review.status is ReviewStatus.REVIEWABLE
    assert review.reviewable
    assert review.reproduced
    assert len(review.matches) == 1
    assert review.matches[0].rule.name == "office_powershell_download"
    assert review.matches[0].events[0].data["user.name"] == "analyst"

    # Only fields referenced by the condition are required; the unused
    # "unused_context" detection must not inflate the backfill request.
    assert review.required_fields == ("CommandLine", "Image", "ParentImage")
    assert "User" not in review.required_fields

    # Before/after conversion mapping is exposed to the investigator.
    assert review.field_mappings["CommandLine"] == ("process.command_line",)
    assert review.field_mappings["Image"] == ("process.executable",)
    assert review.field_mappings["ParentImage"] == ("process.parent.name",)
    assert review.fields_to_backfill == ()
    assert review.missing_fields == ()


def test_reduced_export_reports_minimum_backfill_and_unrecoverable_fields(
    collection, pipeline, reduced_export
):
    policy = RetentionPolicy(
        never_captured_fields={"process.parent.name"},
        purged_fields={
            "process.executable": TimeWindow(
                datetime(2026, 11, 1, tzinfo=UTC),
                datetime(2026, 11, 20, tzinfo=UTC),
            )
        },
    )
    report = OfflineReviewer(collection, policy, pipeline=pipeline).review(reduced_export)
    review = report[0]

    assert review.status is ReviewStatus.NEEDS_BACKFILL
    assert not review.reviewable
    assert not review.reproduced
    assert review.fields_to_backfill == ("Image",)
    assert {finding.field for finding in review.unrecoverable_fields} == {"ParentImage"}

    missing = {finding.field: finding for finding in review.missing_fields}
    image = missing["Image"]
    assert image.mapped_fields == ("process.executable",)
    assert image.reason is MissingFieldReason.RETENTION_PURGED
    assert image.recoverable
    assert image.blocking
    assert image.applicable_from == datetime(2026, 11, 19, 3, 5, tzinfo=UTC)
    assert image.applicable_to == datetime(2026, 11, 19, 3, 5, tzinfo=UTC)

    parent = missing["ParentImage"]
    assert parent.mapped_fields == ("process.parent.name",)
    assert parent.reason is MissingFieldReason.NEVER_CAPTURED
    assert not parent.recoverable
    assert parent.blocking


def test_source_absent_is_not_confused_with_retention_loss(collection, pipeline):
    export = EventExport.from_dict(
        {
            "retained_fields": [
                "process.parent.name",
                "process.command_line",
                "process.executable",
            ],
            "events": [
                {
                    "timestamp": "2026-11-18T10:15:00Z",
                    "logsource": {
                        "category": "process_creation",
                        "product": "windows",
                    },
                    "data": {
                        "process.parent.name": "C:\\Office16\\WINWORD.EXE",
                        "process.command_line": "powershell -Command IEX(...)",
                    },
                }
            ],
        }
    )
    report = OfflineReviewer(collection, RetentionPolicy(), pipeline=pipeline).review(
        export
    )
    review = report[0]
    assert review.status is ReviewStatus.REVIEWABLE
    assert review.reproduced
    absent = review.source_absent_fields
    assert len(absent) == 1
    assert absent[0].field == "Image"
    assert absent[0].reason is MissingFieldReason.SOURCE_ABSENT
    assert not absent[0].blocking
    assert not absent[0].recoverable
    assert review.fields_to_backfill == ()


def test_review_offline_accepts_export_path_and_serializes_report(collection, pipeline):
    report = review_offline(
        collection,
        FILES / "export_retained.json",
        RetentionPolicy(),
        pipeline=pipeline,
    )
    assert report.reviewable_rules
    payload = json.loads(report.to_json())
    assert payload["summary"]["reviewable"] == 1
    assert payload["summary"]["reproduced"] == 1
    assert payload["rules"][0]["status"] == "reviewable"
    assert payload["rules"][0]["field_mappings"]["Image"] == ["process.executable"]


def test_not_applicable_when_logsource_absent(collection, pipeline):
    export = EventExport.from_dict(
        {
            "retained_fields": ["process.command_line"],
            "events": [
                {
                    "timestamp": "2026-11-18T10:15:00Z",
                    "logsource": {"category": "network_connection"},
                    "data": {"process.command_line": "IEX(...)"},
                }
            ],
        }
    )
    review = OfflineReviewer(collection, RetentionPolicy(), pipeline=pipeline).review(
        export
    )[0]
    assert review.status is ReviewStatus.NOT_APPLICABLE
    assert not review.reviewable


def test_explicit_field_policy_can_mark_purged_as_unrecoverable(collection, pipeline):
    policy = RetentionPolicy(
        field_policies={
            "process.executable": FieldRetention(
                field="process.executable",
                reason=MissingFieldReason.RETENTION_PURGED,
                recoverable=False,
            )
        },
        never_captured_fields={"process.parent.name"},
    )
    export = EventExport.from_file(FILES / "export_reduced.json")
    review = OfflineReviewer(collection, policy, pipeline=pipeline).review(export)[0]
    assert review.status is ReviewStatus.UNRECOVERABLE
    assert review.fields_to_backfill == ()
    assert {finding.field for finding in review.unrecoverable_fields} == {
        "Image",
        "ParentImage",
    }


def test_keyword_rule_requires_raw_log_text():
    collection = SigmaCollection.from_yaml(
        """
title: Keyword Alert
name: keyword_alert
status: test
logsource:
    category: process_creation
    product: windows
detection:
    keywords:
        - "IEX"
        - "Invoke-WebRequest"
    condition: keywords
"""
    )
    export = EventExport.from_dict(
        {
            "retained_fields": ["process.command_line"],
            "events": [
                {
                    "timestamp": "2026-11-18T10:15:00Z",
                    "logsource": {
                        "category": "process_creation",
                        "product": "windows",
                    },
                    "data": {"process.command_line": "IEX(...)"},
                }
            ],
        }
    )
    review = OfflineReviewer(collection, RetentionPolicy()).review(export)[0]
    assert review.status is ReviewStatus.NEEDS_BACKFILL
    assert review.fields_to_backfill == ("<raw>",)


def test_or_branch_minimizes_backfill_to_available_evidence(pipeline):
    collection = SigmaCollection.from_yaml(
        """
title: Alternative Process Evidence
name: alternative_process_evidence
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains: "IEX"
        - ParentImage|endswith: "\\\\WINWORD.EXE"
    condition: selection
"""
    )
    export = EventExport.from_dict(
        {
            "retained_fields": ["process.command_line"],
            "events": [
                {
                    "timestamp": "2026-11-18T10:15:00Z",
                    "logsource": {
                        "category": "process_creation",
                        "product": "windows",
                    },
                    "data": {"process.command_line": "powershell -Command IEX(...)"},
                }
            ],
        }
    )
    review = OfflineReviewer(collection, RetentionPolicy(), pipeline=pipeline).review(
        export
    )[0]
    assert review.status is ReviewStatus.REVIEWABLE
    assert review.required_fields == ("CommandLine",)
    assert review.mapped_fields == ("process.command_line",)
    assert review.fields_to_backfill == ()
    assert review.reproduced


def test_policy_normalizes_simple_inputs(reduced_export):
    policy = RetentionPolicy(
        retained_fields="process.command_line",
        never_captured_fields="process.parent.name",
        purged_fields={"process.executable": datetime(2026, 11, 20, tzinfo=UTC)},
    )
    assert policy.retained_fields == frozenset({"process.command_line"})
    assert policy.never_captured_fields == frozenset({"process.parent.name"})
    assert policy.purged_fields["process.executable"] == TimeWindow(
        end=datetime(2026, 11, 20, tzinfo=UTC)
    )
