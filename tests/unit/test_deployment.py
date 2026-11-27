from datetime import datetime

from cpe.deployment import (
    AFFECTED,
    NOT_AFFECTED,
    UNKNOWN,
    DeploymentRecord,
    evaluate_deployments,
)


LEGACY_CPE = "cpe:2.3:a:acme:legacy:1.*:*:*:*:*:*:*:*"
LEGACY_1_CPE = "cpe:2.3:a:acme:legacy:1.0:*:*:*:*:*:*:*"
LEGACY_2_CPE = "cpe:2.3:a:acme:legacy:2.0:*:*:*:*:*:*:*"
RUNTIME_CPE = "cpe:2.3:o:acme:runtime:1.0:*:*:*:*:*:*:*"


def expression(*facts):
    fact_xml = "".join(
        '<cpe:fact-ref name="{0}" />'.format(fact) for fact in facts)
    return (
        '<?xml version="1.0"?>'
        '<cpe:platform-specification '
        'xmlns:cpe="http://cpe.mitre.org/language/2.0">'
        '<cpe:platform><cpe:logical-test operator="AND" negate="FALSE">'
        + fact_xml +
        '</cpe:logical-test></cpe:platform>'
        '</cpe:platform-specification>'
    )


def record(deployment_id, cpe, effective, retired=None,
           environment_known=True, complete_environment=False):
    return DeploymentRecord(
        deployment_id, cpe, datetime.strptime(effective, "%Y-%m-%d"),
        datetime.strptime(retired, "%Y-%m-%d") if retired else None,
        environment_known, complete_environment)


def test_one_day_component_switch_pins_exposure_segment():
    records = [
        record("machine-a", LEGACY_1_CPE, "2026-01-01", "2026-01-03"),
        record("machine-a", LEGACY_2_CPE, "2026-01-03"),
        record("machine-a", RUNTIME_CPE, "2026-01-01"),
        record("machine-b", LEGACY_1_CPE, "2026-01-01", "2026-01-04"),
        record("machine-b", RUNTIME_CPE, "2026-01-01", "2026-01-04"),
    ]

    segments = evaluate_deployments(
        expression(LEGACY_CPE, RUNTIME_CPE),
        records,
        datetime(2026, 1, 1),
        datetime(2026, 1, 6))

    assert [segment.as_dict() for segment in segments] == [
        {
            "start": datetime(2026, 1, 1),
            "end": datetime(2026, 1, 3),
            "status": AFFECTED,
            "deployments": ["machine-a", "machine-b"],
            "missing_facts": [],
            "unresolved_facts": [],
        },
        {
            "start": datetime(2026, 1, 3),
            "end": datetime(2026, 1, 4),
            "status": UNKNOWN,
            "deployments": ["machine-a", "machine-b"],
            "missing_facts": [],
            "unresolved_facts": [LEGACY_CPE],
        },
        {
            "start": datetime(2026, 1, 4),
            "end": datetime(2026, 1, 6),
            "status": UNKNOWN,
            "deployments": ["machine-a"],
            "missing_facts": [],
            "unresolved_facts": [LEGACY_CPE],
        },
    ]


def test_unknown_environment_interval_is_preserved_with_missing_record():
    records = [
        record("machine-a", LEGACY_1_CPE, "2026-01-01", "2026-01-03"),
        record("machine-a", LEGACY_2_CPE, "2026-01-03"),
        record("machine-a", RUNTIME_CPE, "2026-01-01", "2026-01-02",
               environment_known=False),
        record("machine-a", RUNTIME_CPE, "2026-01-02"),
        record("machine-b", LEGACY_1_CPE, "2026-01-01", "2026-01-04"),
        record("machine-b", RUNTIME_CPE, "2026-01-01", "2026-01-04"),
    ]

    segments = evaluate_deployments(
        expression(LEGACY_CPE, RUNTIME_CPE),
        records,
        datetime(2026, 1, 1),
        datetime(2026, 1, 6))

    assert [segment.status for segment in segments] == [
        UNKNOWN, AFFECTED, UNKNOWN, UNKNOWN]
    assert segments[0].start == datetime(2026, 1, 1)
    assert segments[0].end == datetime(2026, 1, 2)
    assert segments[0].deployments == ["machine-a", "machine-b"]
    assert segments[0].missing_facts == [RUNTIME_CPE]
    assert segments[0].unresolved_facts == []
    assert segments[1].start == datetime(2026, 1, 2)
    assert segments[1].end == datetime(2026, 1, 3)
    assert segments[1].deployments == ["machine-a", "machine-b"]
    assert segments[1].missing_facts == []
    assert segments[1].unresolved_facts == []
    assert segments[2].start == datetime(2026, 1, 3)
    assert segments[2].end == datetime(2026, 1, 4)
    assert segments[2].deployments == ["machine-a", "machine-b"]
    assert segments[2].missing_facts == []
    assert segments[2].unresolved_facts == [LEGACY_CPE]
    assert segments[3].start == datetime(2026, 1, 4)
    assert segments[3].end == datetime(2026, 1, 6)
    assert segments[3].status == UNKNOWN
    assert segments[3].deployments == ["machine-a"]
    assert segments[3].missing_facts == []
    assert segments[3].unresolved_facts == [LEGACY_CPE]


def test_cpe_facts_are_evaluated_within_the_same_deployment():
    records = [
        record("legacy-only", LEGACY_1_CPE, "2026-01-01"),
        record("runtime-only", RUNTIME_CPE, "2026-01-01"),
    ]

    segments = evaluate_deployments(
        expression(LEGACY_CPE, RUNTIME_CPE),
        records,
        datetime(2026, 1, 1),
        datetime(2026, 1, 2))

    assert len(segments) == 1
    assert segments[0].status == UNKNOWN
    assert segments[0].deployments == ["legacy-only", "runtime-only"]
    assert segments[0].unresolved_facts == [LEGACY_CPE, RUNTIME_CPE]


def test_known_conflicting_environment_is_not_affected():
    records = [
        record("machine-a", LEGACY_2_CPE, "2026-01-01",
               complete_environment=True),
        record("machine-a", RUNTIME_CPE, "2026-01-01",
               complete_environment=True),
    ]

    segments = evaluate_deployments(
        expression(LEGACY_CPE, RUNTIME_CPE),
        records,
        datetime(2026, 1, 1),
        datetime(2026, 1, 2))

    assert len(segments) == 1
    assert segments[0].status == NOT_AFFECTED
    assert segments[0].deployments == []
    assert segments[0].missing_facts == []
    assert segments[0].unresolved_facts == []


def test_adjacent_segments_with_same_conclusion_are_merged():
    records = [
        record("machine-a", LEGACY_1_CPE, "2026-01-01", "2026-01-02"),
        record("machine-a", LEGACY_1_CPE, "2026-01-02", "2026-01-03"),
        record("machine-a", RUNTIME_CPE, "2026-01-01", "2026-01-03"),
    ]

    segments = evaluate_deployments(
        expression(LEGACY_CPE, RUNTIME_CPE),
        records,
        datetime(2026, 1, 1),
        datetime(2026, 1, 3))

    assert len(segments) == 1
    assert segments[0].start == datetime(2026, 1, 1)
    assert segments[0].end == datetime(2026, 1, 3)
    assert segments[0].status == AFFECTED


def test_or_expression_does_not_report_satisfied_alternatives_as_missing():
    alternative_runtime = (
        "cpe:2.3:o:acme:runtime:2.0:*:*:*:*:*:*:*")
    or_expression = (
        '<?xml version="1.0"?>'
        '<cpe:platform-specification '
        'xmlns:cpe="http://cpe.mitre.org/language/2.0">'
        '<cpe:platform><cpe:logical-test operator="AND" negate="FALSE">'
        '<cpe:fact-ref name="' + LEGACY_CPE + '" />'
        '<cpe:logical-test operator="OR" negate="FALSE">'
        '<cpe:fact-ref name="' + RUNTIME_CPE + '" />'
        '<cpe:fact-ref name="' + alternative_runtime + '" />'
        '</cpe:logical-test>'
        '</cpe:logical-test></cpe:platform>'
        '</cpe:platform-specification>'
    )
    records = [
        record("machine-a", LEGACY_1_CPE, "2026-01-01"),
        record("machine-a", RUNTIME_CPE, "2026-01-01"),
    ]

    segments = evaluate_deployments(
        or_expression,
        records,
        datetime(2026, 1, 1),
        datetime(2026, 1, 2))

    assert len(segments) == 1
    assert segments[0].status == AFFECTED
    assert segments[0].missing_facts == []
    assert segments[0].unresolved_facts == []
