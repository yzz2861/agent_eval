"""Acceptance tests for the offline dual-copy security settings reader.

The same small layout is used to prove both forensic requirements:

* generation counters wrap around and must not be compared as plain integers;
* a write interrupted by power loss leaves pending/partial evidence that must
  never be reported as the active configuration.
"""

from __future__ import annotations

import io

import pytest

from settingsreader import (
    ChecksumStatus,
    TableLayout,
    WriteState,
    read_settings,
    select_active,
)
from tests.settingsreader.conftest import (
    IMAGE_SIZE,
    RECORD_SIZE,
    REGION_A_OFFSET,
    REGION_B_OFFSET,
    make_image,
    make_layout,
    make_record,
)


def test_newest_committed_region_is_active():
    layout = make_layout()
    image = make_image(
        region_a=make_record(10, 1, b"allow"),
        region_b=make_record(11, 1, b"allow"),
    )

    result = read_settings(image, layout)

    assert result.active_index == 1
    assert result.active.state is WriteState.COMMITTED
    assert result.active.generation == 11
    assert result.evidence_only == []


def test_generation_wraparound_picks_low_counter_as_newest():
    # uint32 counter: region B just wrapped from 0xFFFFFFFF to 1, region A is
    # still at 0xFFFFFFFE.  A naive "largest counter wins" check would pick A.
    layout = make_layout()
    image = make_image(
        region_a=make_record(0xFFFFFFFE, 1, b"old"),
        region_b=make_record(1, 1, b"new"),
    )

    result = read_settings(image, layout)

    assert result.active_index == 1
    assert result.active.generation == 1
    assert result.regions[0].state is WriteState.COMMITTED


def test_wraparound_with_explicit_small_modulus():
    # Force an 8-bit modulus to exercise wrap handling without huge integers.
    layout = make_layout(generation_modulus=256)
    image = make_image(
        region_a=make_record(254, 1),
        region_b=make_record(2, 1),
    )

    result = read_settings(image, layout)

    assert result.active_index == 1
    assert result.active.generation == 2


def test_pending_higher_generation_is_evidence_not_active():
    # Power was lost after the data write but before the commit marker: region B
    # has the higher generation but committed == 0 and must not be selected.
    layout = make_layout()
    image = make_image(
        region_a=make_record(20, 1, b"active-policy"),
        region_b=make_record(21, 0, b"not-yet-live"),
    )

    result = read_settings(image, layout)

    assert result.active_index == 0
    assert result.active.generation == 20
    pending = result.regions[1]
    assert pending.state is WriteState.PENDING
    assert pending.is_evidence_only
    assert result.evidence_only == [pending]
    assert result.active_record.policy.startswith(b"active")


def test_interrupted_write_with_bad_checksum_is_partial():
    layout = make_layout()
    image = make_image(
        region_a=make_record(30, 1, b"good"),
        region_b=make_record(31, 1, b"torn", valid_checksum=False),
    )

    result = read_settings(image, layout)

    assert result.active_index == 0
    torn = result.regions[1]
    assert torn.state is WriteState.PARTIAL
    assert torn.checksum_status is ChecksumStatus.INVALID
    assert torn.is_evidence_only
    assert "interrupted" in torn.error


def test_truncated_region_is_partial():
    # The image itself ends halfway through region B, as it would when power
    # was lost while the new table was still being programmed.
    layout = make_layout()
    image = bytearray(make_image(region_a=make_record(39, 1, b"good")))
    image = bytes(image[: REGION_B_OFFSET + 12])

    result = read_settings(image, layout)

    assert result.active_index == 0
    assert result.regions[1].state is WriteState.PARTIAL
    assert "truncated" in result.regions[1].error


def test_erased_region_is_reported_as_erased():
    layout = make_layout()
    image = make_image(region_a=make_record(7, 1, b"only-copy"))

    result = read_settings(image, layout)

    assert result.active_index == 0
    erased = result.regions[1]
    assert erased.state is WriteState.ERASED
    assert erased.generation is None
    assert not erased.is_evidence_only


def test_no_committed_region_means_no_active_candidate():
    layout = make_layout()
    image = make_image(
        region_a=make_record(5, 0, b"pending-a"),
        region_b=make_record(6, 0, b"pending-b"),
    )

    result = read_settings(image, layout)

    assert result.active is None
    assert result.active_index is None
    assert {region.state for region in result.regions} == {WriteState.PENDING}
    assert len(result.evidence_only) == 2


def test_equal_generation_tie_keeps_lowest_region_and_flags_tie():
    layout = make_layout()
    image = make_image(
        region_a=make_record(9, 1, b"copy-a"),
        region_b=make_record(9, 1, b"copy-b"),
    )

    result = read_settings(image, layout)

    assert result.tie is True
    assert result.active_index == 0


def test_half_turn_distance_is_treated_as_tie():
    layout = make_layout(generation_modulus=16)
    image = make_image(
        region_a=make_record(0, 1),
        region_b=make_record(8, 1),
    )

    result = read_settings(image, layout)

    assert result.tie is True
    assert result.active_index == 0


def test_read_accepts_stream_and_path(tmp_path):
    layout = make_layout()
    image = make_image(
        region_a=make_record(1, 1, b"file"),
        region_b=make_record(2, 1, b"file"),
    )

    stream_result = read_settings(io.BytesIO(image), layout)
    assert stream_result.active_index == 1

    image_path = tmp_path / "device.img"
    image_path.write_bytes(image)
    path_result = read_settings(image_path, layout)
    assert path_result.active_index == 1
    assert image_path.read_bytes() == image


def test_select_active_ignores_non_committed_regions():
    layout = make_layout()
    image = make_image(
        region_a=make_record(100, 1, b"live"),
        region_b=make_record(101, 0, b"pending"),
    )

    result = read_settings(image, layout)
    index, tie = select_active(result.regions, layout)

    assert index == 0
    assert tie is False


def test_layout_validates_field_names():
    layout = make_layout()
    with pytest.raises(ValueError, match="field named"):
        TableLayout(
            layout.record_type,
            (REGION_A_OFFSET, REGION_B_OFFSET),
            commit_field="does_not_exist",
            generation_field="generation",
        )


def test_summary_documents_pending_evidence():
    layout = make_layout()
    image = make_image(
        region_a=make_record(20, 1, b"active"),
        region_b=make_record(21, 0, b"pending"),
    )

    result = read_settings(image, layout)
    summary = result.summary()

    assert "region 0" in summary and "committed" in summary
    assert "region 1" in summary and "pending" in summary
    assert "active: region 0" in summary


def test_record_size_matches_cstruct_layout():
    layout = make_layout()
    assert layout.record_size == RECORD_SIZE
    assert layout.modulus == 1 << 32
    assert len(make_image()) == IMAGE_SIZE
