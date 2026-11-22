"""Offline property tests for the three-state approval YAML contract.

These tests need nothing beyond the standard library and the in-tree PyYAML:
generation, shrinking and reporting all live in :mod:`tests.tri_state`.

There are two complementary suites:

* hand-written, hand-checkable cases pin the concrete YAML shapes (key order,
  anchor naming, ambiguous scalars) the contract cares about;
* the self-contained property campaign fuzzes many legal representations and
  proves the strict loader always agrees with the contract while a lenient
  "unknown means pass" stand-in is caught and shrunk to a tiny repro.
"""

from __future__ import annotations

import pytest

from .contract import (
    AmbiguousDecisionError,
    Decision,
    MissingFieldError,
    permissive_load,
    strict_load,
)
from .properties import check_document, run_property, shrink
from .strategy import (
    ANCHOR_NAMES,
    KEY_ORDERS,
    DocumentSpec,
    PolicySpec,
    Scalar,
    canonical_scalar,
)

# Fixed seed keeps the whole suite deterministic and offline-friendly.
SEED = 20261123
ITERATIONS = 400


# --------------------------------------------------------------------------- #
# Hand-checkable cases
# --------------------------------------------------------------------------- #


def _canonical_spec(decision: Decision, key_order: tuple[str, ...]) -> PolicySpec:
    return PolicySpec(
        policy_id="pol-000",
        reviewer="alice",
        scalar=Scalar(token=decision.value, style="plain",
                      ambiguous=False, expected=decision),
        key_order=key_order,
    )


@pytest.mark.parametrize("key_order", KEY_ORDERS)
def test_every_key_order_round_trips(key_order):
    spec = DocumentSpec(policies=[_canonical_spec(Decision.DENIED, key_order)])
    outcome = check_document(strict_load, spec)
    assert outcome.ok, outcome.message


@pytest.mark.parametrize("anchor_name", ANCHOR_NAMES)
def test_anchor_and_alias_share_one_decision(anchor_name):
    spec = DocumentSpec(
        policies=[_canonical_spec(Decision.PENDING, ("id", "reviewer", "decision"))],
        anchor_name=anchor_name,
        alias_count=1,
    )
    outcome = check_document(strict_load, spec)
    assert outcome.ok, outcome.message
    imported = strict_load(spec.render())
    assert all(policy.decision is Decision.PENDING for policy in imported)


@pytest.mark.parametrize("style", ("plain", "single", "double"))
def test_canonical_token_survives_every_scalar_style(style):
    token = {"plain": "approved", "single": "'approved'",
             "double": '"approved"'}[style]
    spec = DocumentSpec(
        policies=[
            PolicySpec(
                policy_id="pol-000",
                reviewer="alice",
                scalar=Scalar(token=token, style=style, ambiguous=False,
                              expected=Decision.APPROVED),
                key_order=("id", "reviewer", "decision"),
            )
        ]
    )
    assert check_document(strict_load, spec).ok


@pytest.mark.parametrize("token", ["yes", "no", "on", "off", "null", "~",
                                   "approve", "aprove", "ENABLED"])
def test_strict_loader_rejects_every_ambiguous_scalar(token):
    spec = DocumentSpec(
        policies=[
            PolicySpec(
                policy_id="pol-000",
                reviewer="alice",
                scalar=Scalar(token=token, style="plain", ambiguous=True,
                              expected=None),
                key_order=("id", "reviewer", "decision"),
            )
        ]
    )
    with pytest.raises((AmbiguousDecisionError, MissingFieldError)):
        strict_load(spec.render())


def test_quoted_ambiguity_is_still_rejected():
    # A quoted "no" decodes to the string "no", not False, but it is still not
    # one of the three canonical tokens.
    spec = DocumentSpec(
        policies=[
            PolicySpec(
                policy_id="pol-000",
                reviewer="alice",
                scalar=Scalar(token='"no"', style="double", ambiguous=True,
                              expected=None),
                key_order=("id", "reviewer", "decision"),
            )
        ]
    )
    with pytest.raises(AmbiguousDecisionError):
        strict_load(spec.render())


def test_three_states_remain_distinct_in_one_document():
    spec = DocumentSpec(
        policies=[
            _canonical_spec(Decision.DENIED, ("id", "reviewer", "decision")),
            _canonical_spec(Decision.PENDING, ("decision", "id", "reviewer")),
            _canonical_spec(Decision.APPROVED, ("reviewer", "decision", "id")),
        ]
    )
    imported = strict_load(spec.render())
    assert [p.decision for p in imported] == [
        Decision.DENIED,
        Decision.PENDING,
        Decision.APPROVED,
    ]


# --------------------------------------------------------------------------- #
# Property campaign
# --------------------------------------------------------------------------- #


def test_strict_loader_satisfies_contract_across_campaign():
    failure = run_property(strict_load, seed=SEED, iterations=ITERATIONS)
    assert failure is None, failure.render_report() if failure else ""


def test_lenient_standin_is_caught_and_reported():
    failure = run_property(permissive_load, seed=SEED, iterations=ITERATIONS)
    assert failure is not None, "the lenient loader must trigger a failure"
    assert failure.kind == "swallowed-decision"
    report = failure.render_report()
    # The report must make the swallowed decision hand-checkable.
    assert "ambiguous decision was imported instead of rejected" in report
    assert any("rendered token" in line for line in report.splitlines())


def test_shrunk_failure_is_minimal_and_still_fails():
    failure = run_property(permissive_load, seed=SEED, iterations=ITERATIONS)
    assert failure is not None
    reduced = failure.document
    # A shrunk repro has no aliases, a single policy and the canonical key
    # order, so a human can read it at a glance.
    assert reduced.alias_count == 0
    assert len(reduced.policies) == 1
    assert reduced.policies[0].key_order == ("id", "reviewer", "decision")
    assert reduced.policies[0].scalar.ambiguous is True
    # And it still genuinely violates the contract.
    assert check_document(permissive_load, reduced).ok is False


def test_shrink_is_a_fixed_point():
    failure = run_property(permissive_load, seed=SEED, iterations=ITERATIONS)
    assert failure is not None
    again = shrink(permissive_load, failure.document)
    assert again.render() == failure.document.render()


def test_replay_uses_same_seed():
    first = run_property(permissive_load, seed=SEED, iterations=ITERATIONS)
    second = run_property(permissive_load, seed=SEED, iterations=ITERATIONS)
    assert first is not None and second is not None
    assert first.yaml_text == second.yaml_text


def test_lenient_loader_still_parses_canonical_states():
    # The stand-in is only dangerous on ambiguity; an explicit deny must not be
    # mistaken for an approval. This pins where the boundary of the bug is.
    spec = DocumentSpec(
        policies=[
            PolicySpec(
                policy_id="pol-000",
                reviewer="alice",
                scalar=Scalar(token="denied", style="plain", ambiguous=False,
                              expected=Decision.DENIED),
                key_order=("id", "reviewer", "decision"),
            )
        ]
    )
    assert check_document(permissive_load, spec).ok


def test_report_names_decoded_value_and_swallowed_state():
    failure = run_property(permissive_load, seed=SEED, iterations=ITERATIONS)
    assert failure is not None
    report = failure.render_report()
    # The trace must show both what YAML decoded the token to and the state the
    # loader fell back to, so an on-call reviewer can verify the swallowed call.
    assert "yaml decodes it to" in report
    assert "Decision.APPROVED" in report
