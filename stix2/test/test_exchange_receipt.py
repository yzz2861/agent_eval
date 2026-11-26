import copy
import json
from pathlib import Path

import pytest

from stix2 import parse
from stix2.exchange_receipt import build_exchange_receipt


ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_DIR = ROOT / "examples" / "exchange_receipt"


@pytest.fixture()
def exchange_pair():
    before = json.loads((EXAMPLE_DIR / "identity-before.json").read_text(encoding="utf-8"))
    after = json.loads((EXAMPLE_DIR / "identity-after.json").read_text(encoding="utf-8"))
    disclosure = json.loads((EXAMPLE_DIR / "gateway-disclosure.json").read_text(encoding="utf-8"))
    return before, after, disclosure


def test_sample_pair_reports_only_description_as_real_update(exchange_pair):
    before, after, disclosure = exchange_pair

    receipt = build_exchange_receipt(before, after, disclosure)
    summary = receipt["summary"]

    assert receipt["same_id"] is True
    assert summary["real_updates"] == ["description"]
    assert summary["real_update_count"] == 1
    assert summary["only_real_update"] == "description"
    assert "name" in summary["explicitly_transformed"]
    assert "contact_information" in summary["unverifiable"]
    assert "external_references" in summary["order_normalized"]
    assert "modified" in summary["revision_metadata_changes"]
    assert summary["issues"] == []


def test_receipt_accepts_parsed_stix_objects(exchange_pair):
    before, after, disclosure = exchange_pair

    receipt = build_exchange_receipt(
        parse(before, allow_custom=True),
        parse(after, allow_custom=True),
        disclosure,
    )

    assert receipt["summary"]["only_real_update"] == "description"


def test_unknown_change_is_not_absorbed_as_redaction(exchange_pair):
    before, after, disclosure = exchange_pair
    after = copy.deepcopy(after)
    after["roles"][0] = "executive-escalation"

    receipt = build_exchange_receipt(before, after, disclosure)

    assert receipt["summary"]["real_updates"] == ["description", "roles[0]"]
    assert receipt["summary"]["real_update_count"] == 2
    assert receipt["summary"]["only_real_update"] is None


def test_changed_stable_token_is_visible_not_excused(exchange_pair):
    before, after, disclosure = exchange_pair
    after = copy.deepcopy(after)
    after["name"] = "tok_contact_v1_00000000000000000000000000000000"

    receipt = build_exchange_receipt(before, after, disclosure)
    statuses = {field["selector"]: field["status"] for field in receipt["fields"]}

    assert statuses["name"] == "transformed_drift_unproven"
    assert "name" in receipt["summary"]["unverifiable"]
    assert any("name" in issue for issue in receipt["summary"]["issues"])
    assert receipt["summary"]["real_updates"] == ["description"]


def test_unmarked_policy_binding_is_reported(exchange_pair):
    before, after, disclosure = exchange_pair
    before = copy.deepcopy(before)
    after = copy.deepcopy(after)
    before["granular_markings"] = []
    after["granular_markings"] = []

    receipt = build_exchange_receipt(before, after, disclosure)

    assert any("name" in issue and "granular marking" in issue for issue in receipt["summary"]["issues"])


def test_marking_bundle_is_valid_stix():
    bundle = json.loads((EXAMPLE_DIR / "gateway-markings.json").read_text(encoding="utf-8"))

    parsed = parse(bundle, allow_custom=True)

    assert len(parsed.objects) == 2
