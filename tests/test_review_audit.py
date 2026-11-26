from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from review_audit.audit import (  # noqa: E402
    ACCEPTANCE_REFERENCES,
    EXPECTED_STATEMENT,
    ReviewAuditor,
)
from review_audit.fixture_builder import build_pe  # noqa: E402


@pytest.fixture()
def review_dll(tmp_path: Path) -> Path:
    path = tmp_path / "ReviewSample.dll"
    path.write_bytes(build_pe())
    return path


def test_two_closed_generic_types_are_decoded(review_dll: Path) -> None:
    auditor = ReviewAuditor(review_dll)

    assert auditor.decode_typespec(1)["name"] == "ReviewAudit.Box<int32>"
    assert auditor.decode_typespec(2)["name"] == "ReviewAudit.Box<string>"


def test_entry_sources_are_classified(review_dll: Path) -> None:
    report = ReviewAuditor(review_dll).build_report(ACCEPTANCE_REFERENCES)
    entries = report["entries"]

    assert [entry["primary_kind"] for entry in entries] == [
        "open_generic_definition",
        "instance_implementation",
        "explicit_interface_declaration",
    ]
    assert all(entry["statement_match"] for entry in entries)
    assert all(EXPECTED_STATEMENT in entry["statements"] for entry in entries)

    owner_tokens = [
        entry["sources"][0]["owner_token"] for entry in entries
    ]
    assert owner_tokens == ["0x06000003", "0x06000004", "0x06000002"]


def test_missing_assembly_remains_pending(review_dll: Path) -> None:
    auditor = ReviewAuditor(review_dll)
    report = auditor.build_report(ACCEPTANCE_REFERENCES)

    missing = [ref for ref in report["assembly_refs"] if ref["status"] == "pending_external_assembly"]
    assert [ref["name"] for ref in missing] == ["Missing.Contracts"]
    assert report["external_member_refs"][0]["token"] == "0x0A000003"

    generic_entry = report["entries"][0]
    assert generic_entry["status"] == "supported_with_pending_external_evidence"
    assert generic_entry["pending_assembly_names"] == ["Missing.Contracts"]
