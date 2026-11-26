import json
import os
import subprocess
import sys
from pathlib import Path

from bleach import clean
from bleach.html5lib_shim import TAG_TOKEN_TYPE_CHARACTERS

from tests.cleaning_audit import (
    SANITIZER_STAGE,
    TOKENIZER_STAGE,
    audit_clean,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "cleaning_audit.py"

TAG_STRIPPED_HTML = '<div title="Author note">Hello</div>'
ATTRIBUTE_STRIPPED_HTML = '<p title="Author note">Hello</p>'
COMMON_POLICY = {"tags": {"p"}, "attributes": {"p": []}}


def test_visually_identical_samples_have_different_policy_receipts():
    stripped_tag = audit_clean(TAG_STRIPPED_HTML, strip=True, **COMMON_POLICY)
    stripped_attribute = audit_clean(
        ATTRIBUTE_STRIPPED_HTML, strip=False, **COMMON_POLICY
    )

    assert stripped_tag["cleaned"] == "Hello"
    assert stripped_attribute["cleaned"] == "<p>Hello</p>"
    assert (
        clean(TAG_STRIPPED_HTML, strip=True, **COMMON_POLICY) == stripped_tag["cleaned"]
    )
    assert (
        clean(ATTRIBUTE_STRIPPED_HTML, strip=False, **COMMON_POLICY)
        == stripped_attribute["cleaned"]
    )

    tag_receipts = stripped_tag["receipts"]
    attribute_receipt = stripped_attribute["receipts"][0]

    assert [receipt["source_text"] for receipt in tag_receipts] == [
        '<div title="Author note">',
        "</div>",
    ]
    assert {receipt["stage"] for receipt in tag_receipts} == {TOKENIZER_STAGE}
    assert {receipt["action"] for receipt in tag_receipts} == {"strip-tag"}
    assert {receipt["token"]["type"] for receipt in tag_receipts} == {3, 4}
    assert all(
        receipt["result_token"]["type"] == TAG_TOKEN_TYPE_CHARACTERS
        for receipt in tag_receipts
    )
    assert all(
        TAG_STRIPPED_HTML[
            receipt["source_span"]["start"] : receipt["source_span"]["end"]
        ]
        == receipt["source_text"]
        for receipt in tag_receipts
    )
    assert [receipt["cleaned_span"] for receipt in tag_receipts] == [
        {"start": 0, "end": 0},
        {"start": 5, "end": 5},
    ]

    assert attribute_receipt["action"] == "drop-attribute"
    assert attribute_receipt["stage"] == SANITIZER_STAGE
    assert attribute_receipt["source_text"] == 'title="Author note"'
    assert attribute_receipt["token"]["type"] == "StartTag"
    assert attribute_receipt["token"]["name"] == "p"
    assert attribute_receipt["result_token"]["data"] == {}
    assert attribute_receipt["source_span"] == {"start": 3, "end": 22}
    assert (
        ATTRIBUTE_STRIPPED_HTML[
            attribute_receipt["source_span"]["start"] : attribute_receipt[
                "source_span"
            ]["end"]
        ]
        == attribute_receipt["source_text"]
    )
    assert attribute_receipt["cleaned_span"] == {"start": 2, "end": 2}
    assert ATTRIBUTE_STRIPPED_HTML[
        : attribute_receipt["source_span"]["start"]
    ].endswith("<p ")
    assert (
        stripped_attribute["cleaned"][: attribute_receipt["cleaned_span"]["start"]]
        == "<p"
    )


def test_audit_preserves_original_attribute_quote_and_locates_duplicate_tags():
    result = audit_clean(
        "<p title='first'>one</p><p title='second'>two</p>",
        tags={"p"},
        attributes={"p": []},
    )

    assert [receipt["source_text"] for receipt in result["receipts"]] == [
        "title='first'",
        "title='second'",
    ]
    assert result["receipts"][0]["source_span"] == {"start": 3, "end": 16}
    assert result["receipts"][1]["source_span"] == {"start": 27, "end": 41}
    assert result["cleaned"] == "<p>one</p><p>two</p>"


def test_offline_audit_entrypoint_outputs_both_receipt_paths():
    completed = subprocess.run(
        [sys.executable, str(SCRIPT)],
        check=True,
        capture_output=True,
        text=True,
        env={
            key: value
            for key, value in os.environ.items()
            if not key.startswith("PYTEST_")
        },
    )

    receipts = json.loads(completed.stdout)
    assert [result["id"] for result in receipts] == [
        "stripped-element",
        "stripped-attribute",
    ]
    assert receipts[0]["receipts"][0]["stage"] == TOKENIZER_STAGE
    assert receipts[1]["receipts"][0]["stage"] == SANITIZER_STAGE
    assert receipts[0]["receipts"][0]["reason"] != receipts[1]["receipts"][0]["reason"]
