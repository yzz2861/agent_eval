import json
import os

import pytest

from acceptance_validator import ReleaseGate, render_text_report

BUNDLE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "sample_bundle.json")


@pytest.fixture(scope="module")
def verdicts():
    gate = ReleaseGate(BUNDLE_PATH)
    return gate.run()


@pytest.fixture(scope="module")
def by_name(verdicts):
    return {verdict.name: verdict for verdict in verdicts}


def test_six_conclusions_loaded(verdicts):
    assert len(verdicts) == 6


def test_independent_corroboration_is_releasable(by_name):
    verdict = by_name["C1 entity attributes corroborated by two units"]
    assert verdict.releasable is True
    assert len(verdict.independent_sources) == 2
    assert len(verdict.independent_material) == 2


def test_long_evidence_list_single_source_is_blocked(by_name):
    verdict = by_name["C2 six references all quoting one authorized source"]
    assert verdict.releasable is False
    assert len(verdict.evidence_refs) == 6
    assert verdict.material_reference_counts == {"MAT-SHARED": 6}
    assert len(verdict.independent_sources) == 1
    assert len(verdict.independent_material) == 1
    assert any("distinct observing source" in reason for reason in verdict.reasons)
    assert any("distinct raw material" in reason for reason in verdict.reasons)


def test_unapproved_authorization_blocks_release(by_name):
    verdict = by_name["C3 relationship inference under an unapproved warrant"]
    assert verdict.releasable is False
    assert any("no approved investigation authorization" in reason for reason in verdict.reasons)
    assert verdict.independent_sources == set()


def test_scope_mismatch_blocks_relationship_conclusion(by_name):
    verdict = by_name["C4 derived link released beyond the authorization scope"]
    assert verdict.releasable is False
    finding = next(f for f in verdict.authorization_findings if not f["usable"])
    assert "scope" in finding["detail"]


def test_shared_material_preserved_but_counts_once_per_report(by_name):
    alpha = by_name["C5 report alpha reusing shared material"]
    beta = by_name["C5 report beta reusing the same shared material"]
    assert alpha.releasable is True and beta.releasable is True
    assert "MAT-SHARED-5" in alpha.material_reference_counts
    assert "MAT-SHARED-5" in beta.material_reference_counts
    assert len(alpha.independent_material) == 2
    assert len(beta.independent_material) == 2


def test_text_report_explains_hold(verdicts):
    text = render_text_report(verdicts)
    assert "[HOLD] C2 six references all quoting one authorized source" in text
    assert "MAT-SHARED x6" in text
    assert "references preserved, counted once" in text


def test_json_report_structure(verdicts):
    from acceptance_validator import build_report
    report = build_report(verdicts)
    assert report["summary"] == {
        "total_conclusions": 6, "releasable": 3, "blocked": 3,
        "required_independent_observations": 2,
    }
    for verdict in report["verdicts"]:
        assert set(verdict) >= {"conclusion_id", "releasable", "reasons",
                                "independent_source_count", "material_reference_counts"}
