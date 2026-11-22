# -*- coding: utf-8 -*-
import json
import os

import pytest

from cpe.cpe2_3_wfn import CPE2_3_WFN
from cpe.cpeset2_3 import CPESet2_3
from cpe.cpelang2_3 import CPELanguage2_3
from cpe.cpediff2_3 import (
    CPEDiffError,
    diff_expressions,
    format_text_report,
    normalize_review,
)


BASE_OS = "cpe:2.3:o:acme:edge_os:*:*:*:*:*:*:*:*"
BASE_APP = "cpe:2.3:a:acme:edge_agent:*:*:*:*:*:*:*:*"
OS_10 = "cpe:2.3:o:acme:edge_os:1.0:*:*:*:*:*:*:*"
OS_11 = "cpe:2.3:o:acme:edge_os:1.1:*:*:*:*:*:*:*"
OS_12 = "cpe:2.3:o:acme:edge_os:1.2:*:*:*:*:*:*:*"
OS_20 = "cpe:2.3:o:acme:edge_os:2.0:*:*:*:*:*:*:*"


def fact(name):
    return '<cpe:fact-ref name="{0}"/>'.format(name)


def platform(inner):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<cpe:platform-specification '
        'xmlns:cpe="http://cpe.mitre.org/language/2.0">'
        '<cpe:platform id="p">'
        '<cpe:logical-test operator="AND" negate="FALSE">'
        '{0}'
        '</cpe:logical-test>'
        '</cpe:platform>'
        '</cpe:platform-specification>'
    ).format(inner)


def exclusion_expression(legacy_versions):
    inner = fact(BASE_OS)
    inner += '<cpe:logical-test operator="OR" negate="TRUE">'
    inner += "".join(fact("cpe:2.3:o:acme:edge_os:{0}:"
                          "*:*:*:*:*:*:*".format(version))
                     for version in legacy_versions)
    inner += '</cpe:logical-test>'
    return platform(inner)


def review(devices, domain=None):
    return {"domain": domain or {}, "devices": devices}


def component(**attributes):
    values = {"part": "o", "vendor": "acme", "product": "edge_os"}
    values.update(attributes)
    return values


def demo_paths():
    root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", ".."))
    demo = os.path.join(root, "examples", "cpe_diff")
    return (
        os.path.join(demo, "old.xml"),
        os.path.join(demo, "new.xml"),
        os.path.join(demo, "review.json"),
    )


def test_demo_marks_only_version_1_2_as_newly_excluded():
    old, new, review_path = demo_paths()
    report = diff_expressions(
        old, new, review_path,
        old_is_file=True, new_is_file=True, review_is_file=True)

    summary = report["summary"]
    assert summary["exclusion_scope"] == "expanded"
    assert summary["new_exclusions"] == ["edge-1.2"]
    assert summary["removed_exclusions"] == []
    assert summary["pending"] == ["edge-version-unconfirmed"]
    assert report["expression_delta"]["fact_refs_added"] == [OS_12]
    assert report["witnesses"]["new_exclusions"][0]["id"] == "edge-1.2"
    assert report["summary"]["scope_conclusive"] is False

    changed = [d for d in report["devices"] if d["id"] == "edge-1.2"][0]
    assert changed["transition"] == "new_exclusion"
    assert changed["old_covered"] is True
    assert changed["new_covered"] is False
    assert changed["witness"]["attributes"][0]["version"] == "1.2"

    text = format_text_report(report)
    assert "exclusion scope: EXPANDED" in text
    assert "edge-1.2" in text


def test_reverse_expression_marks_removed_exclusion():
    old, new, review_path = demo_paths()
    report = diff_expressions(
        new, old, review_path,
        old_is_file=True, new_is_file=True, review_is_file=True)

    assert report["summary"]["exclusion_scope"] == "shrunk"
    assert report["summary"]["removed_exclusions"] == ["edge-1.2"]
    assert report["expression_delta"]["fact_refs_removed"] == [OS_12]


def test_confirmed_field_gives_a_conclusive_witness():
    old = exclusion_expression(["1.0", "1.1"])
    new = exclusion_expression(["1.0", "1.1", "1.2"])
    devices = [{
        "id": "edge-1.2",
        "components": [component(version="1.2")],
    }]

    report = diff_expressions(old, new, review(devices))
    device = report["devices"][0]

    assert device["status"] == "conclusive"
    assert device["transition"] == "new_exclusion"
    assert device["witness"]["attributes"][0]["version"] == "1.2"


def test_unconfirmed_domain_with_mixed_outcomes_is_pending():
    old = exclusion_expression(["1.0", "1.1"])
    new = exclusion_expression(["1.0", "1.1", "1.2"])
    devices = [{
        "id": "edge-any-legacy",
        "components": [component(version=None)],
    }]
    report = diff_expressions(
        old, new, review(devices, {"version": ["1.0", "1.2"]}))
    device = report["devices"][0]

    assert device["status"] == "pending"
    assert device["pending_reasons"][0]["code"] == "ambiguous_over_domain"
    assert len(device["variants"]) == 2
    transitions = set(variant["transition"] for variant in device["variants"])
    assert transitions == {"still_excluded", "new_exclusion"}


def test_unconfirmed_domain_with_one_outcome_is_conclusive():
    old = exclusion_expression(["1.0", "1.1", "1.2"])
    new = exclusion_expression(["1.0", "1.1", "1.2", "2.0"])
    devices = [{
        "id": "edge-legacy-only",
        "components": [component(version=None)],
    }]
    report = diff_expressions(
        old, new, review(devices, {"version": ["1.0", "1.2"]}))
    device = report["devices"][0]

    assert device["status"] == "conclusive"
    assert device["transition"] == "still_excluded"
    assert device["candidate_count"] == 2


def test_unknown_domain_keeps_device_pending():
    old = exclusion_expression(["1.0", "1.1"])
    new = exclusion_expression(["1.0", "1.1", "1.2"])
    devices = [{
        "id": "edge-unknown-version",
        "components": [component(version=None)],
    }]
    report = diff_expressions(old, new, review(devices))
    device = report["devices"][0]

    assert device["status"] == "pending"
    assert device["pending_reasons"][0]["code"] == "no_finite_domain"
    assert device["pending_reasons"][0]["detail"] == {
        "attribute": "version"}


def test_missing_version_is_not_guessed():
    old = exclusion_expression(["1.0", "1.1"])
    new = exclusion_expression(["1.0", "1.1", "1.2"])
    devices = [{
        "id": "edge-no-version",
        "components": [component()],
    }]
    report = diff_expressions(old, new, review(devices))
    device = report["devices"][0]

    assert device["status"] == "pending"
    reason = device["pending_reasons"][0]
    assert reason["code"] == "unknown_or_incomparable"
    assert reason["facts"]
    assert any("version" in fact.get("subset", [])
               for item in reason["facts"]
               for fact in item.get("components", []))


def test_wildcard_device_value_is_incomparable():
    old = exclusion_expression(["1.0", "1.1"])
    new = exclusion_expression(["1.0", "1.1", "1.2"])
    devices = [{
        "id": "edge-major-wildcard",
        "cpes": ["cpe:2.3:o:acme:edge_os:1.*:*:*:*:*:*:*:*"],
    }]
    report = diff_expressions(old, new, review(devices))
    device = report["devices"][0]

    assert device["status"] == "pending"
    facts = device["pending_reasons"][0]["facts"]
    assert any("version" in item.get("undefined", [])
               for fact in facts
               for item in fact.get("components", []))


def test_domain_too_large_is_pending():
    old = exclusion_expression(["1.0", "1.1"])
    new = exclusion_expression(["1.0", "1.1", "1.2"])
    devices = [{
        "id": "edge-too-many",
        "components": [component(version=None)],
    }]
    report = diff_expressions(
        old, new, review(devices, {"version": ["1.0", "1.2"]}),
        max_candidates=1)

    device = report["devices"][0]
    assert device["status"] == "pending"
    assert device["pending_reasons"][0]["code"] == "domain_too_large"


def test_multi_component_device_requires_all_parts():
    expression = platform(fact(BASE_OS) + fact(BASE_APP))
    devices = [
        {
            "id": "with-agent",
            "cpes": [OS_20, "cpe:2.3:a:acme:edge_agent:3.0:"
                            "*:*:*:*:*:*:*"],
        },
        {
            "id": "without-agent",
            "cpes": [OS_20],
        },
    ]
    report = diff_expressions(expression, expression, review(devices))

    by_id = dict((device["id"], device) for device in report["devices"])
    assert by_id["with-agent"]["transition"] == "still_included"
    assert by_id["without-agent"]["transition"] == "still_excluded"


def test_decisive_results_agree_with_existing_language_match():
    old, new, review_path = demo_paths()
    report = diff_expressions(
        old, new, review_path,
        old_is_file=True, new_is_file=True, review_is_file=True)

    old_text = open(old, "r", encoding="utf-8").read()
    language = CPELanguage2_3(old_text)
    for device in report["devices"]:
        if device["status"] != "conclusive":
            continue
        cpes = CPESet2_3()
        for cpe_text in device["witness"]["components"]:
            cpes.append(CPE2_3_WFN(cpe_text))
        expected = language.language_match(cpes)
        assert expected is device["old_covered"]


def test_invalid_domain_attribute_is_rejected():
    old = exclusion_expression(["1.0"])
    devices = [{"id": "d", "cpes": [OS_10]}]
    with pytest.raises(CPEDiffError):
        diff_expressions(
            old, old, {"domain": {"invented": ["x"]}, "devices": devices})


def test_review_requires_at_least_one_device():
    with pytest.raises(CPEDiffError):
        normalize_review({"domain": {"version": ["1.0"]}})


def test_report_is_json_serializable():
    old, new, review_path = demo_paths()
    report = diff_expressions(
        old, new, review_path,
        old_is_file=True, new_is_file=True, review_is_file=True)
    encoded = json.dumps(report)
    assert '"edge-1.2"' in encoded


def test_confirmed_allowlist_marks_other_values_unknown():
    old = exclusion_expression(["1.0", "1.1"])
    new = exclusion_expression(["1.0", "1.1", "1.2"])
    devices = [{
        "id": "edge-version-not-trusted",
        "components": [{
            "part": "o", "vendor": "acme", "product": "edge_os",
            "version": "1.2",
            "confirmed": ["part", "vendor", "product"],
        }],
    }]
    report = diff_expressions(
        old, new, review(devices, {"version": ["1.0", "1.2"]}))
    device = report["devices"][0]

    assert device["status"] == "pending"
    assert device["pending_reasons"][0]["code"] == "ambiguous_over_domain"
    assert report["summary"]["scope_conclusive"] is False


def test_scope_is_conclusive_without_pending_devices():
    old = exclusion_expression(["1.0", "1.1"])
    new = exclusion_expression(["1.0", "1.1", "1.2"])
    devices = [{"id": "edge-1.2", "cpes": [OS_12]}]

    report = diff_expressions(old, new, review(devices))

    assert report["summary"]["scope_conclusive"] is True


def test_confirmed_allowlist_expands_unmentioned_domain_fields():
    old = exclusion_expression(["1.0", "1.1"])
    new = exclusion_expression(["1.0", "1.1", "1.2"])
    devices = [{
        "id": "edge-no-version-field",
        "components": [{
            "part": "o", "vendor": "acme", "product": "edge_os",
            "confirmed": ["part", "vendor", "product"],
        }],
    }]

    report = diff_expressions(
        old, new, review(devices, {"version": ["1.0", "1.2"]}))
    device = report["devices"][0]

    assert device["status"] == "pending"
    assert device["pending_reasons"][0]["code"] == "ambiguous_over_domain"
    assert device["candidate_count"] == 2


def test_confirmed_object_overlays_values():
    old = exclusion_expression(["1.0", "1.1"])
    new = exclusion_expression(["1.0", "1.1", "1.2"])
    devices = [{
        "id": "edge-confirmed-object",
        "components": [{
            "part": "o", "vendor": "acme", "product": "edge_os",
            "confirmed": {"version": "1.2"},
        }],
    }]

    report = diff_expressions(old, new, review(devices))
    device = report["devices"][0]

    assert device["status"] == "conclusive"
    assert device["transition"] == "new_exclusion"
    assert device["witness"]["attributes"][0]["version"] == "1.2"
