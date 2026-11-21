"""Tests for evidence-bound policy explanations."""

import json
import os

from click.testing import CliRunner

from regipy.policy import (
    MACHINE_PRECEDENCE,
    Evidence,
    PolicyContext,
    PolicyRecord,
    PolicyRule,
    RoleContext,
    build_policy_report,
    extract_policy_records,
    render_report,
)
from regipy.policy.cli import policy_explain
from regipy.registry import RegistryHive


def _machine_user_evidence():
    return [
        Evidence("machine-hive", hive_path="SOFTWARE", hive_type="software", scope="machine"),
        Evidence("user-hive", hive_path="NTUSER.DAT", hive_type="ntuser", scope="user"),
    ]


def _cmd_records(machine_value=1, user_value=1):
    return [
        PolicyRecord(
            "machine-hive",
            r"\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "DisableCMD",
            machine_value,
            policy_id="cmd",
            scope="machine",
            value_type="REG_DWORD",
        ),
        PolicyRecord(
            "user-hive",
            r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "DisableCMD",
            user_value,
            policy_id="cmd",
            scope="user",
            value_type="REG_DWORD",
        ),
    ]


def _cmd_rule(combination="per_scope"):
    return PolicyRule(
        rule_id="cmd",
        policy_id="cmd",
        value_name="DisableCMD",
        conclusion_by_value={1: "Command Prompt is disabled", 0: "Command Prompt is allowed"},
        scope_qualifiers={"machine": "host-wide", "user": "only this user logon context"},
        combination=combination,
    )


def test_same_value_in_two_roles_has_role_specific_conclusions():
    context = PolicyContext(
        evidence=_machine_user_evidence(),
        roles=[
            RoleContext("host", "machine", evidence_ids=["machine-hive"]),
            RoleContext("alice", "user", evidence_ids=["user-hive"], login_context="interactive"),
        ],
        records=_cmd_records(1, 1),
        rules=[_cmd_rule()],
    )

    report = build_policy_report(context)
    assert len(report.explanations) == 2
    by_role = {item.role_id: item for item in report.explanations}
    host = by_role["host"]
    alice = by_role["alice"]

    # The raw value is identical, but the role changes the meaning.
    assert host.conclusion != alice.conclusion
    assert "host-wide" in host.conclusion
    assert "only this user logon context" in alice.conclusion
    assert host.evidence[0]["evidence_id"] == "machine-hive"
    assert alice.evidence[0]["evidence_id"] == "user-hive"
    assert all(condition["satisfied"] for condition in host.conditions)
    assert all(condition["satisfied"] for condition in alice.conditions)
    assert {item["kind"] for item in host.conditions} >= {"role", "evidence_binding", "scope", "value"}


def test_same_value_requires_both_scopes_for_always_install_elevated():
    records = [
        PolicyRecord(
            "machine-hive",
            r"\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "AlwaysInstallElevated",
            1,
            policy_id="always-install",
            scope="machine",
            value_type="REG_DWORD",
        ),
        PolicyRecord(
            "user-hive",
            r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            "AlwaysInstallElevated",
            1,
            policy_id="always-install",
            scope="user",
            value_type="REG_DWORD",
        ),
    ]
    context = PolicyContext(
        evidence=_machine_user_evidence(),
        roles=[
            RoleContext("host", "machine", evidence_ids=["machine-hive"]),
            RoleContext("alice", "user", evidence_ids=["machine-hive", "user-hive"], login_context="interactive"),
        ],
        records=records,
    )

    report = build_policy_report(context)
    assert len(report.explanations) == 1
    explanation = report.explanations[0]
    assert explanation.role_id == "alice"
    assert explanation.conclusion_code == "in_effect"
    assert explanation.combination == "all_scopes_required"
    assert "machine" in explanation.combination_expression
    assert "user" in explanation.combination_expression
    assert {item["evidence_id"] for item in explanation.evidence} == {"machine-hive", "user-hive"}

    # The machine role saw the same value 1, but one scope is not enough.
    incomplete = [item for item in report.unbound_contexts if item.reason == "incomplete_combination"]
    assert len(incomplete) == 1
    assert incomplete[0].role_id == "host"
    assert incomplete[0].related["missing_scopes"] == ["user"]
    assert incomplete[0].related["present_scopes"] == ["machine"]


def test_machine_precedence_keeps_user_record_as_overridden_evidence():
    context = PolicyContext(
        evidence=_machine_user_evidence(),
        roles=[RoleContext("alice", "user", evidence_ids=["machine-hive", "user-hive"], login_context="interactive")],
        records=_cmd_records(1, 0),
        rules=[_cmd_rule(MACHINE_PRECEDENCE)],
    )

    report = build_policy_report(context)
    assert len(report.explanations) == 1
    explanation = report.explanations[0]
    assert explanation.rule_id == "cmd"
    assert explanation.status == "applied"
    assert "Command Prompt is disabled" in explanation.conclusion
    assert explanation.overridden_by
    by_evidence = {item["evidence_id"]: item for item in explanation.evidence}
    assert by_evidence["machine-hive"]["selection"] == "selected"
    assert by_evidence["user-hive"]["selection"] == "overridden"
    assert any("takes precedence" in item["expression"] for item in explanation.conditions)


def test_login_context_decides_whether_a_policy_can_be_explained():
    record = PolicyRecord(
        "machine-hive",
        r"\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "DontDisplayLastUserName",
        1,
        policy_id="hide-last-user",
        scope="machine",
        value_type="REG_DWORD",
    )
    context = PolicyContext(
        evidence=[Evidence("machine-hive", hive_path="SOFTWARE", hive_type="software", scope="machine")],
        roles=[
            RoleContext("interactive-role", "machine", evidence_ids=["machine-hive"], login_context="interactive"),
            RoleContext("service-role", "machine", evidence_ids=["machine-hive"], login_context="service"),
        ],
        records=[record],
    )

    report = build_policy_report(context)
    assert [item.role_id for item in report.explanations] == ["interactive-role"]
    assert report.explanations[0].conclusion_code.startswith("The last logged-on user name is hidden")
    unbound = [item for item in report.unbound_contexts if item.reason == "login_context_not_applicable"]
    assert len(unbound) == 1
    assert unbound[0].role_id == "service-role"


def test_unbound_contexts_list_missing_and_orphan_evidence():
    context = PolicyContext(
        evidence=[
            Evidence("machine-hive", scope="machine"),
            Evidence("orphan-hive", scope="machine"),
        ],
        roles=[
            RoleContext("empty-role", "machine", evidence_ids=[]),
            RoleContext("bad-role", "machine", evidence_ids=["does-not-exist"]),
            RoleContext("good-role", "machine", evidence_ids=["machine-hive"]),
        ],
        records=[
            PolicyRecord("orphan-hive", r"\\Policies\\Test", "SomeValue", 1, scope="machine"),
        ],
    )

    report = build_policy_report(context)
    reasons = {item.reason for item in report.unbound_contexts}
    assert "role_without_evidence" in reasons
    assert "unknown_evidence" in reasons
    assert "orphan_record" in reasons
    assert report.summary["unbound_by_reason"]["orphan_record"] == 1


def test_strict_rules_emits_unbound_instead_of_raw_observation():
    context = PolicyContext(
        evidence=[Evidence("machine-hive", scope="machine")],
        roles=[RoleContext("host", "machine", evidence_ids=["machine-hive"])],
        records=[
            PolicyRecord("machine-hive", r"\\Policies\\Vendor", "UnmappedPolicy", 1, scope="machine"),
        ],
    )

    observed = build_policy_report(context)
    assert observed.explanations[0].status == "observed"
    assert observed.explanations[0].interpretation == "raw_observation"
    assert not observed.unbound_contexts

    strict = build_policy_report(context, strict_rules=True)
    assert not strict.explanations
    assert [item.reason for item in strict.unbound_contexts] == ["no_matching_rule"]


def test_policy_context_from_mapping_accepts_singular_evidence_id():
    context = PolicyContext.from_mapping(
        {
            "evidence": {
                "user-hive": {"path": "NTUSER.DAT", "type": "ntuser", "scope": "user"},
            },
            "roles": [{"role_id": "alice", "kind": "user", "evidence_id": "user-hive", "logon_context": "interactive"}],
            "records": [
                {"evidence_id": "user-hive", "key": r"\\Software\\Policies\\Test", "name": "Foo", "value": 1, "scope": "user"},
            ],
        }
    )
    assert context.roles[0].evidence_ids == ["user-hive"]
    assert context.roles[0].login_context == "interactive"
    assert context.evidence[0].evidence_id == "user-hive"
    assert context.records[0].policy_id


def test_report_json_and_markdown_keep_provenance_and_unbound_sections():
    context = PolicyContext(
        evidence=_machine_user_evidence(),
        roles=[RoleContext("host", "machine", evidence_ids=["machine-hive"])],
        records=[_cmd_records(1, 1)[0]],
        rules=[_cmd_rule()],
    )
    report = build_policy_report(context)
    payload = json.loads(report.to_json())
    assert payload["records"][0]["evidence_id"] == "machine-hive"
    assert payload["explanations"][0]["evidence"][0]["key_path"]
    assert payload["explanations"][0]["conditions"]
    assert "unbound_contexts" in payload

    markdown = report.to_markdown()
    assert "# Policy context report" in markdown
    assert "machine-hive" in markdown
    assert "## Unbound contexts" in markdown
    assert render_report(report, "json") == report.to_json()

    try:
        render_report(report, "xml")
    except ValueError:
        pass
    else:
        raise AssertionError("unsupported format should fail")


def test_extract_policy_records_from_real_software_hive(software_hive):
    hive = RegistryHive(software_hive)
    records = extract_policy_records(hive, "machine-test", scope="machine")
    assert records
    by_name = {record.value_name: record for record in records}
    assert by_name["EnableLUA"].value == 1
    assert by_name["EnableLUA"].policy_id == r"policies\system::enablelua"
    assert by_name["EnableLUA"].value_type == "REG_DWORD"
    assert by_name["ConsentPromptBehaviorAdmin"].policy_id == r"policies\system::consentpromptbehavioradmin"


def test_cli_writes_reviewable_context_report():
    context_path = os.path.abspath(".policy_context_cli_test.json")
    output_path = os.path.abspath(".policy_context_cli_test.out.json")
    context = {
        "evidence": [
            {"evidence_id": "machine-hive", "hive_path": "SOFTWARE", "hive_type": "software", "scope": "machine"},
            {"evidence_id": "user-hive", "hive_path": "NTUSER.DAT", "hive_type": "ntuser", "scope": "user"},
        ],
        "roles": [
            {"role_id": "host", "kind": "machine", "evidence_ids": ["machine-hive"]},
            {"role_id": "alice", "kind": "user", "evidence_ids": ["user-hive"], "login_context": "interactive"},
        ],
        "records": [
            {
                "policy_id": "cmd",
                "evidence_id": "machine-hive",
                "scope": "machine",
                "key_path": r"\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value_name": "DisableCMD",
                "value": 1,
            },
            {
                "policy_id": "cmd",
                "evidence_id": "user-hive",
                "scope": "user",
                "key_path": r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "value_name": "DisableCMD",
                "value": 1,
            },
        ],
        "rules": [
            {
                "rule_id": "cmd",
                "policy_id": "cmd",
                "value_name": "DisableCMD",
                "conclusion_by_value": {"1": "Command Prompt is disabled"},
                "scope_qualifiers": {"machine": "host-wide", "user": "only this user logon context"},
            }
        ],
    }
    try:
        with open(context_path, "w", encoding="utf-8") as handle:
            json.dump(context, handle)
        result = CliRunner().invoke(
            policy_explain,
            ["--context", context_path, "--output", output_path, "--format", "json"],
        )
        assert result.exit_code == 0, result.output
        with open(output_path, encoding="utf-8") as handle:
            payload = json.load(handle)
        assert len(payload["explanations"]) == 2
        assert payload["unbound_contexts"] == []
        assert {item["role_id"] for item in payload["explanations"]} == {"host", "alice"}
    finally:
        for path in (context_path, output_path):
            if os.path.exists(path):
                os.remove(path)


def test_role_attributes_are_part_of_the_evaluated_conditions():
    rule = PolicyRule(
        rule_id="admin-only",
        value_name="DisableCMD",
        scope="machine",
        conclusion_by_value={1: "Command Prompt is disabled"},
        required_role_attributes={"elevated": True},
    )
    context = PolicyContext(
        evidence=[Evidence("machine-hive", scope="machine")],
        roles=[
            RoleContext(
                "admin-role",
                "machine",
                evidence_ids=["machine-hive"],
                login_context="interactive",
                attributes={"elevated": True},
            ),
            RoleContext(
                "standard-role",
                "machine",
                evidence_ids=["machine-hive"],
                login_context="interactive",
                attributes={"elevated": False},
            ),
        ],
        records=[PolicyRecord("machine-hive", r"\\Policies\\System", "DisableCMD", 1, scope="machine")],
        rules=[rule],
    )

    report = build_policy_report(context)
    assert [item.role_id for item in report.explanations] == ["admin-role"]
    assert any(condition["kind"] == "role_attribute" for condition in report.explanations[0].conditions)
    mismatched = [item for item in report.unbound_contexts if item.reason == "role_attribute_mismatch"]
    assert len(mismatched) == 1
    assert mismatched[0].role_id == "standard-role"


def test_separate_per_scope_rules_are_evaluated_per_record():
    machine_rule = PolicyRule(
        rule_id="machine-rule",
        policy_id="cmd",
        value_name="DisableCMD",
        scope="machine",
        conclusion_by_value={1: "Command Prompt is disabled by machine policy"},
    )
    user_rule = PolicyRule(
        rule_id="user-rule",
        policy_id="cmd",
        value_name="DisableCMD",
        scope="user",
        conclusion_by_value={1: "Command Prompt is disabled by user policy"},
    )
    context = PolicyContext(
        evidence=_machine_user_evidence(),
        roles=[RoleContext("alice", "user", evidence_ids=["machine-hive", "user-hive"], login_context="interactive")],
        records=_cmd_records(1, 1),
        rules=[machine_rule, user_rule],
    )

    report = build_policy_report(context)
    assert len(report.explanations) == 2
    assert {item.rule_id for item in report.explanations} == {"machine-rule", "user-rule"}
    assert {item.evidence[0]["evidence_id"] for item in report.explanations} == {"machine-hive", "user-hive"}
    assert not report.unbound_contexts
