from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest

from dissect.cstruct import NonInferableError, RedactionError, SummaryField, controlled_copy
from tests.util import parsed_state

if TYPE_CHECKING:
    from dissect.cstruct.cstruct import cstruct as cstruct_type


@pytest.fixture
def evidence(cs: cstruct_type, compiled: bool) -> tuple[cstruct_type, bytes]:
    cs.load(
        """
        struct Evidence {
            uint32 case_id;
            uint32 subject_id;
            char   note[4];
            uint32 total;
        };
        """,
        compiled=compiled,
    )
    return cs, struct.pack("<II4sI", 7, 1001, b"abcd", 1008)


def test_masks_requested_fields_and_affected_summary(evidence: tuple[cstruct_type, bytes]) -> None:
    cs, raw = evidence
    result = cs.Evidence(raw)
    before = parsed_state(result)

    copy = result.controlled_copy(
        approved=["case_id", "note", "total"],
        masked=["subject_id"],
        summaries={"total": ("case_id", "subject_id")},
    )

    assert copy.case_id == 7
    assert copy.note == b"abcd"
    assert copy.masked == {"subject_id", "total"}
    assert copy["subject_id"] is None
    assert copy["total"] is None
    assert copy.summary_status["total"] == "masked"

    assert dict(copy.positions) == {"case_id": (0, 4), "note": (8, 4)}
    data = copy.dumps()
    assert data[0:4] == raw[0:4]
    assert data[4:8] == b"\x00" * 4
    assert data[8:12] == raw[8:12]
    assert data[12:16] == b"\x00" * 4

    assert parsed_state(result) == before
    assert result.dumps() == raw


def test_replacement_is_used_to_recompute_summary(evidence: tuple[cstruct_type, bytes]) -> None:
    cs, raw = evidence
    result = cs.Evidence(raw)
    seen: dict[str, object] = {}

    def total(values: dict[str, object]) -> int:
        seen.update(values)
        return int(values["case_id"]) + int(values["subject_id"])

    copy = result.controlled_copy(
        approved=["case_id", "subject_id", "note", "total"],
        masked=["subject_id"],
        replacements={"subject_id": 42},
        summaries={"total": SummaryField("total", ("case_id", "subject_id"), total)},
    )

    assert copy.subject_id == 42
    assert copy.total == 49
    assert seen["subject_id"] == 42
    assert copy.summary_status["total"] == "recomputed"
    assert copy.dumps() == struct.pack("<II4sI", 7, 42, b"abcd", 49)

    assert result.subject_id == 1001
    assert result.total == 1008
    assert result.dumps() == raw


def test_non_inferable_summary_is_omitted(evidence: tuple[cstruct_type, bytes]) -> None:
    cs, raw = evidence
    result = cs.Evidence(raw)

    summary = SummaryField(
        "total",
        ("case_id", "subject_id"),
        lambda values: int(values["case_id"]) + int(values["subject_id"]),
        non_inferable=True,
    )
    copy = result.controlled_copy(
        approved=["case_id", "subject_id", "note", "total"],
        masked=["subject_id"],
        replacements={"subject_id": 42},
        summaries={"total": summary},
        on_non_inferable="omit",
    )

    assert "total" not in copy
    assert copy.summary_status["total"] == "omitted"
    assert "total" not in copy.positions
    assert copy.dumps()[0:4] == raw[0:4]
    assert copy.dumps()[4:8] == struct.pack("<I", 42)
    assert copy.dumps()[8:12] == raw[8:12]
    assert copy.dumps()[12:16] == b"\x00" * 4
    assert result.total == 1008


def test_non_inferable_summary_can_error(evidence: tuple[cstruct_type, bytes]) -> None:
    cs, raw = evidence
    result = cs.Evidence(raw)

    with pytest.raises(NonInferableError):
        result.controlled_copy(
            masked=["subject_id"],
            summaries={"total": ("case_id", "subject_id")},
            on_non_inferable="error",
        )


def test_short_text_replacement_keeps_following_offsets(evidence: tuple[cstruct_type, bytes]) -> None:
    cs, raw = evidence
    result = cs.Evidence(raw)

    copy = result.controlled_copy(
        approved=["case_id", "subject_id", "note", "total"],
        masked=["note"],
        replacements={"note": b"xy"},
        summaries={"total": ("case_id", "subject_id")},
    )

    assert copy.note == b"xy"
    assert copy.total == 1008
    assert copy.summary_status["total"] == "kept"
    assert dict(copy.positions) == {
        "case_id": (0, 4),
        "subject_id": (4, 4),
        "total": (12, 4),
    }
    assert copy.dumps() == raw[:8] + b"xy\x00\x00" + raw[12:]


def test_unaffected_summary_remains_visible(evidence: tuple[cstruct_type, bytes]) -> None:
    cs, raw = evidence
    result = cs.Evidence(raw)

    copy = result.controlled_copy(masked=["note"], summaries={"total": ("case_id", "subject_id")})

    assert copy.note is None
    assert copy.total == 1008
    assert "note" not in copy.positions
    assert copy.positions["total"] == (12, 4)
    assert copy.summary_status["total"] == "kept"
    assert copy.dumps()[12:16] == raw[12:16]


def test_allowlist_masks_everything_else(evidence: tuple[cstruct_type, bytes]) -> None:
    cs, raw = evidence
    result = cs.Evidence(raw)

    copy = result.controlled_copy(approved=["case_id"])

    assert set(copy) == {"case_id", "subject_id", "note", "total"}
    assert copy.masked == {"subject_id", "note", "total"}
    assert copy.positions == {"case_id": (0, 4)}
    assert copy.dumps() == raw[0:4] + b"\x00" * 12


def test_unapproved_policy_can_omit(evidence: tuple[cstruct_type, bytes]) -> None:
    cs, raw = evidence
    result = cs.Evidence(raw)

    copy = result.controlled_copy(approved=["case_id"], on_unapproved="omit")

    assert set(copy) == {"case_id"}
    assert copy.omitted == {"subject_id", "note", "total"}
    assert copy.positions == {"case_id": (0, 4)}
    assert copy.dumps() == raw[0:4] + b"\x00" * 12


def test_does_not_modify_source_bytes(evidence: tuple[cstruct_type, bytes]) -> None:
    cs, raw = evidence
    result = cs.Evidence(raw)
    source = bytearray(raw)

    copy = controlled_copy(result, masked=["subject_id"], summaries={"total": ("case_id", "subject_id")}, source=source)

    assert copy.dumps()[4:8] == b"\x00" * 4
    assert source == bytearray(raw)
    assert result.dumps() == raw


def test_mapping_input_and_base_offset() -> None:
    copy = controlled_copy(
        {"case_id": 7, "subject_id": 1001},
        approved=["case_id"],
        masked=["subject_id"],
        base_offset=4096,
    )

    assert dict(copy) == {"case_id": 7, "subject_id": None}
    assert copy.positions == {}
    with pytest.raises(RedactionError, match="No byte excerpt"):
        copy.dumps()


def test_unknown_fields_and_visible_replacements_are_rejected(evidence: tuple[cstruct_type, bytes]) -> None:
    cs, raw = evidence
    result = cs.Evidence(raw)

    with pytest.raises(ValueError, match="Unknown field"):
        result.controlled_copy(approved=["missing"])

    with pytest.raises(ValueError, match="Unknown field"):
        result.controlled_copy(masked=["missing"])

    with pytest.raises(ValueError, match="only supported for masked"):
        result.controlled_copy(masked=["subject_id"], replacements={"note": b"nope"})
