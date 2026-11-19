from policy_audit import (
    analyze_policy,
    compare_policies,
    load_policy,
    render_comparison,
    render_report,
)
from policy_audit.analyze import Context, rule_matches

FIXTURES = "fixtures/policy"


def fixture_path(name):
    return "%s/%s" % (FIXTURES, name)


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def audit(paths):
    policy = load_policy(paths)
    verdicts, issues, domain = analyze_policy(policy)
    return policy, verdicts, issues, domain


def verdict_by_id(verdicts, rule_id):
    for verdict in verdicts:
        if verdict.rule_id == rule_id:
            return verdict
    raise AssertionError("no verdict for %r" % rule_id)


# --- loading: real merge and real scalar resolution -------------------------


def test_merge_concatenates_rules_and_keeps_provenance():
    policy, verdicts, issues, _ = audit(
        [fixture_path("base.yaml"), fixture_path("overlay.yaml")]
    )
    assert issues == []
    assert [v.rule_id for v in verdicts] == [
        "allow-internal",
        "deny-prod-debug",
        "allow-health",
        "deny-crypto-export",
        "allow-all-external",
    ]
    deny = verdict_by_id(verdicts, "deny-prod-debug")
    assert deny.entry.provenance.path.endswith("base.yaml")
    assert deny.entry.provenance.line > 1
    overlay_rule = verdict_by_id(verdicts, "allow-all-external")
    assert overlay_rule.entry.provenance.path.endswith("overlay.yaml")


def test_scalar_resolution_is_real_yaml_11(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
rules:
  - id: r1
    action: deny
    priority: 010
    environments: [prod]
""",
    )
    policy = load_policy([path])
    # YAML 1.1 octal: the effective priority is 8, not 10.
    assert policy.rules[0].data["priority"] == 8


def test_merge_key_and_deep_merge(tmp_path):
    base = write(
        tmp_path,
        "base.yaml",
        """
policy: {name: p, retries: 1}
common: &common
  action: deny
  priority: 5
rules:
  - id: r1
    <<: *common
    environments: [dev]
""",
    )
    overlay = write(tmp_path, "overlay.yaml", "policy: {retries: 3}\n")
    policy = load_policy([base, overlay])
    assert policy.data["policy"] == {"name": "p", "retries": 3}
    assert policy.rules[0].data["action"] == "deny"


# --- shadowing verdicts on the shipped fixtures -----------------------------


def test_prod_deny_rule_is_fully_shadowed():
    _, verdicts, _, _ = audit(
        [fixture_path("base.yaml"), fixture_path("overlay.yaml")]
    )
    deny = verdict_by_id(verdicts, "deny-prod-debug")
    assert deny.verdict == "fully_shadowed"
    assert deny.winning_points == 0
    assert deny.matched_points > 0
    assert "allow-all-external" in deny.shadowed_by
    # The witness is verifiable: it matches the deny rule, and the
    # shadowing rule outranks it there.
    example = deny.shadowed_example
    assert example.environment == "prod"
    assert rule_matches(deny.entry.data, example)


def test_partial_and_effective_verdicts():
    _, verdicts, _, _ = audit(
        [fixture_path("base.yaml"), fixture_path("overlay.yaml")]
    )
    internal = verdict_by_id(verdicts, "allow-internal")
    assert internal.verdict == "partially_shadowed"
    assert 0 < internal.winning_points < internal.matched_points
    assert internal.winning_example.environment in ("dev", "staging")
    # Shadowed in prod by allow-all-external, and anywhere the
    # higher-priority deny-crypto-export also matches.
    assert internal.shadowed_by == ["allow-all-external", "deny-crypto-export"]
    assert rule_matches(internal.entry.data, internal.shadowed_example)

    crypto = verdict_by_id(verdicts, "deny-crypto-export")
    assert crypto.verdict == "effective"
    assert crypto.winning_points == crypto.matched_points
    assert crypto.shadowed_by == []


def test_report_mentions_provenance_and_examples():
    policy, verdicts, issues, domain = audit(
        [fixture_path("base.yaml"), fixture_path("overlay.yaml")]
    )
    text = render_report(policy, verdicts, issues, domain)
    assert "fully_shadowed" in text
    assert "base.yaml" in text and "overlay.yaml" in text
    assert "shadowed example" in text


# --- distinct results for the three failure modes ---------------------------


def test_circular_reference_is_a_separate_result(tmp_path):
    path = write(
        tmp_path,
        "loop.yaml",
        """
a: &x
  self: *x
rules:
  - id: r1
    action: deny
    priority: 1
""",
    )
    policy = load_policy([path])
    assert [i.kind for i in policy.issues] == ["circular_reference"]
    assert policy.issues[0].provenance.path == path
    assert policy.rules == []


def test_unsupported_condition_is_a_separate_result(tmp_path):
    path = write(
        tmp_path,
        "u.yaml",
        """
rules:
  - id: r1
    action: deny
    priority: 1
    cidr: 10.0.0.0/8
  - id: r2
    action: allow
    priority: 2
""",
    )
    _, verdicts, issues, _ = audit([path])
    kinds = [i.kind for i in issues]
    assert kinds == ["unsupported_condition"]
    assert issues[0].rule_id == "r1"
    assert issues[0].provenance.line > 1
    # The analyzable rule still gets a verdict.
    assert [v.rule_id for v in verdicts] == ["r2"]


def test_conflicting_definitions_are_a_separate_result(tmp_path):
    one = write(
        tmp_path,
        "one.yaml",
        """
rules:
  - id: dup
    action: deny
    priority: 1
""",
    )
    two = write(
        tmp_path,
        "two.yaml",
        """
rules:
  - id: dup
    action: allow
    priority: 2
  - id: other
    action: allow
    priority: 3
""",
    )
    _, verdicts, issues, _ = audit([one, two])
    kinds = [i.kind for i in issues]
    assert kinds == ["conflicting_definitions"]
    assert issues[0].rule_id == "dup"
    assert "one.yaml" in issues[0].message and "two.yaml" in issues[0].message
    assert [v.rule_id for v in verdicts] == ["other"]


def test_identical_redefinition_is_not_a_conflict(tmp_path):
    body = "rules:\n  - id: same\n    action: deny\n    priority: 1\n"
    one = write(tmp_path, "a.yaml", body)
    two = write(tmp_path, "b.yaml", body)
    _, verdicts, issues, _ = audit([one, two])
    assert issues == []
    assert [v.rule_id for v in verdicts] == ["same"]


# --- priority swap: which deployment scope changes hands --------------------


def test_priority_swap_moves_prod_scope():
    old = [fixture_path("base.yaml"), fixture_path("overlay.yaml")]
    new = [fixture_path("base_swapped.yaml"), fixture_path("overlay_swapped.yaml")]
    changes, _, _ = compare_policies(old, new)

    by_pair = {(c.old_winner, c.new_winner): c for c in changes}
    assert all(c.environment == "prod" for c in changes)
    # The debugger scope flips from the broad allow to the explicit deny...
    handover = by_pair[("allow-all-external", "deny-prod-debug")]
    assert handover.points > 0
    # ...and the internal-network scope falls back to allow-internal.
    assert ("allow-all-external", "allow-internal") in by_pair

    # The witness is verifiable against both policy states.
    example = handover.example
    assert example.environment == "prod"
    assert rule_matches(
        {"environments": ["prod"], "tags": {"component": "debugger"}}, example
    )
    _, new_verdicts, _, _ = audit(new)
    deny = verdict_by_id(new_verdicts, "deny-prod-debug")
    assert rule_matches(deny.entry.data, example)
    assert deny.verdict == "effective"


def test_priority_swap_report_is_explainable():
    old = [fixture_path("base.yaml"), fixture_path("overlay.yaml")]
    new = [fixture_path("base_swapped.yaml"), fixture_path("overlay_swapped.yaml")]
    changes, _, _ = compare_policies(old, new)
    text = render_comparison(changes, old, new)
    assert "'prod'" in text
    assert "allow-all-external -> deny-prod-debug" in text
    assert "example:" in text


def test_compare_with_self_reports_no_changes():
    old = [fixture_path("base.yaml"), fixture_path("overlay.yaml")]
    changes, _, _ = compare_policies(old, old)
    assert changes == []
