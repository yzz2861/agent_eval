import pathlib


import yaml


FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "policy_roundtrip"


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def contract():
    return yaml.PolicyContract({
        "team_alpha.audit": {yaml.ALLOW, yaml.DENY, yaml.INHERIT},
        "team_alpha.guest": yaml.INHERIT,
        "team_beta.audit": yaml.DENY,
    })


def test_three_states_are_kept_per_path():
    document = yaml.load_policy(fixture("policy.yaml"))

    assert document.decision("defaults.admin").state == yaml.DENY
    assert document.decision("defaults.audit").state == yaml.DENY
    assert document.decision("defaults.guest").state == yaml.INHERIT
    assert document.decision("team_alpha.audit").state == yaml.DENY
    assert document.decision("team_alpha.guest").state == yaml.INHERIT
    assert document.decision("team_beta.audit").state == yaml.DENY


def test_shared_consumers_are_reported_before_and_after_change():
    source = fixture("policy.yaml")
    before = yaml.load_policy(source)
    before_shared = before.shared_items(
        ["team_alpha.audit", "team_beta.audit"])
    before_paths = {tuple(item.paths) for item in before_shared.values()}

    result = yaml.roundtrip_policy(
        source,
        contract(),
        changes={"team_alpha.audit": yaml.INHERIT},
    )
    after_shared = result.report.shared
    after_paths = {tuple(item.paths) for item in after_shared.values()}

    assert (("defaults", "audit"), ("team_alpha", "audit"),
            ("team_beta", "audit")) in before_paths
    assert (("defaults", "audit"), ("team_alpha", "audit"),
            ("team_beta", "audit")) not in after_paths
    assert (("defaults", "audit"), ("team_beta", "audit")) in after_paths


def test_keep_inherit_then_change_deny_to_default():
    result = yaml.roundtrip_policy(
        fixture("policy.yaml"),
        contract(),
        changes={"team_alpha.audit": yaml.INHERIT},
    )

    assert result.ok, [issue.to_dict() for issue in result.issues]
    assert result.report.before_decisions["team_alpha.audit"].state == yaml.DENY
    assert result.decisions["team_alpha.audit"].state == yaml.INHERIT
    assert result.decisions["team_alpha.audit"].present is True
    assert result.decisions["team_alpha.guest"].state == yaml.INHERIT
    assert result.decisions["team_beta.audit"].state == yaml.DENY
    assert result.text.count("inherit") >= 2


def test_saved_document_is_verified_through_another_loader():
    result = yaml.roundtrip_policy(
        fixture("policy.yaml"),
        contract(),
        changes={"team_alpha.audit": yaml.INHERIT},
    )

    first, second = result.report.loaders
    assert first is not second
    assert result.after.loader is second
    reloaded = yaml.load_policy(result.text, Loader=second)
    assert reloaded.decision("team_alpha.audit").state == yaml.INHERIT
    assert reloaded.decision("team_alpha.guest").state == yaml.INHERIT
    assert reloaded.decision("team_beta.audit").state == yaml.DENY


def test_explicit_deny_is_not_downgraded_by_an_intermediate_tool():
    source = "rules:\n  alpha: deny\n  beta: inherit\n"

    def lossy_tool(data):
        data["rules"].pop("alpha")
        return data

    result = yaml.roundtrip_policy(
        source,
        {"rules.alpha": yaml.DENY, "rules.beta": yaml.INHERIT},
        through=lossy_tool,
    )

    assert result.ok is False
    issue = next(item for item in result.issues
                 if item.kind == "decision_lost")
    assert issue.path == ("rules", "alpha")
    assert issue.before == yaml.DENY
    assert issue.after is None


def test_contract_rejects_missing_required_path():
    report = yaml.verify_policy_roundtrip(
        "rules:\n  beta: inherit\n",
        "rules:\n  beta: inherit\n",
        {"rules.alpha": yaml.DENY},
    )

    assert report.ok is False
    assert report.findings("missing")[0].path == ("rules", "alpha")


def test_alias_override_isolated_to_one_consumer():
    source = "base: &base\n  x: deny\n  y: allow\nt1: *base\nt2: *base\n"
    document = yaml.load_policy(source)

    document.set("t1.x", yaml.INHERIT)
    text = document.dump()
    reloaded = yaml.load_policy(text, Loader=yaml.FullLoader)

    assert reloaded.decision("t1.x").state == yaml.INHERIT
    assert reloaded.decision("t2.x").state == yaml.DENY
    assert reloaded.decision("base.x").state == yaml.DENY
    assert reloaded.decision("t2.y").state == yaml.ALLOW


def test_legacy_migration_reports_manual_review_fields():
    legacy_contract = yaml.PolicyContract({
        "rules.api.read": yaml.ALLOW,
        "rules.api.write": yaml.DENY,
        "rules.api.delete": yaml.INHERIT,
        "rules.api.audit": yaml.INHERIT,
    })
    result = yaml.migrate_legacy_policy(
        fixture("legacy.yaml"), legacy_contract)

    assert "version: 1" in result.text
    assert "read: allow" in result.text
    assert "write: deny" in result.text
    assert "delete: inherit" in result.text
    assert result.decisions["rules.api.write"].state == yaml.DENY
    assert result.decisions["rules.api.delete"].state == yaml.INHERIT

    reviews = {item.path_str: item for item in result.manual_review}
    assert "rules.api.delete" in reviews
    assert reviews["rules.api.delete"].reason == "legacy_empty_value"
    assert "rules.api.audit" in reviews
    assert reviews["rules.api.audit"].reason == "unknown_legacy_value"
    assert "version" not in reviews


def test_report_is_safe_dumpable_and_paths_accept_both_forms():
    result = yaml.roundtrip_policy(
        fixture("policy.yaml"),
        contract(),
        changes={"team_alpha.audit": yaml.INHERIT},
    )

    data = result.report.to_dict()
    assert yaml.safe_load(yaml.safe_dump(data))["ok"] is True
    assert result.decisions["team_alpha.audit"].state == yaml.INHERIT
    assert result.decisions[("team_alpha", "audit")].state == yaml.INHERIT


def test_constraints_alias_and_report_yaml():
    result = yaml.roundtrip_policy(
        fixture("policy.yaml"),
        constraints={"team_alpha.audit": yaml.INHERIT,
                     "team_alpha.guest": yaml.INHERIT,
                     "team_beta.audit": yaml.DENY},
        changes={"team_alpha.audit": yaml.INHERIT},
    )

    assert result.ok
    loaded = yaml.safe_load(result.to_yaml())
    assert loaded["ok"] is True
    assert loaded["decisions"]["team_alpha.audit"] == yaml.INHERIT
    assert loaded["decisions"]["team_beta.audit"] == yaml.DENY


def test_shared_definition_change_reports_consumers():
    source = "base: &base\n  x: deny\nt1: *base\nt2: *base\n"
    result = yaml.roundtrip_policy(
        source,
        constraints={"base.x": yaml.INHERIT,
                     "t1.x": yaml.INHERIT,
                     "t2.x": yaml.INHERIT},
        changes={"base.x": yaml.INHERIT},
    )

    # A definition edit reaches every consumer; the report makes that
    # impact explicit instead of hiding it behind identical values.
    assert result.ok is False
    assert {issue.path for issue in result.issues} >= {
        ("t1", "x"), ("t2", "x")
    }
    assert result.report.consumption["base.x"] == [
        "base.x", "t1.x", "t2.x"
    ]
