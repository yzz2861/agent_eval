import asyncio
import io

import pytest

from minidump.minidumpfile import MinidumpFile
from minidump.aminidumpfile import AMinidumpFile
from minidump.restricted import (
    RestrictedMinidumpView,
    RestrictedRangeError,
    RestrictedReadResult,
)

from tests._build_fixture import (
    build_minidump_bytes,
    SEG1_VA,
    SEG1_DATA,
    SEG2_VA,
    SEG2_DATA,
    ALIAS_VA,
    FILL,
    APPROVED_RANGES,
)


class AsyncBytesIO:
    def __init__(self, data):
        self._buffer = io.BytesIO(data)

    async def read(self, n=-1):
        return self._buffer.read(n)

    async def seek(self, n, beg=0):
        return self._buffer.seek(n, beg)

    def tell(self):
        return self._buffer.tell()


@pytest.fixture(scope="module")
def dump_bytes():
    return build_minidump_bytes()


@pytest.fixture(scope="module")
def sync_view(dump_bytes):
    reader = MinidumpFile.parse_bytes(dump_bytes).get_reader()
    return RestrictedMinidumpView.from_reader(reader, APPROVED_RANGES, fill=FILL)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(scope="module")
def async_view(dump_bytes):
    async def build():
        mf = await AMinidumpFile.parse_external(AsyncBytesIO(dump_bytes))
        return await RestrictedMinidumpView.from_async_reader(
            mf.get_reader(), APPROVED_RANGES, fill=FILL
        )

    return run(build())


GAP_FILL = bytes([FILL])


def test_narrow_read_returns_exact_disclosed_bytes(sync_view):
    result = sync_view.read(SEG1_VA, len(SEG1_DATA))

    assert isinstance(result, RestrictedReadResult)
    assert result.size == len(SEG1_DATA)
    assert result.data == SEG1_DATA
    assert result.is_complete is True
    assert result.mask == b"\x01" * len(SEG1_DATA)
    assert result.missing_ranges == []
    assert bytes(result) == SEG1_DATA


def test_cross_range_read_marks_every_missing_byte(sync_view):
    start = SEG1_VA + 4
    size = (SEG2_VA + 4) - start
    result = sync_view.read(start, size)

    assert len(result.data) == size
    # First four bytes come from the tail of segment 1.
    assert result.data[:4] == SEG1_DATA[4:]
    # The unbacked gap between the two segments must be filled, not leaked.
    gap_start = SEG1_VA + len(SEG1_DATA)
    gap_end = SEG2_VA
    for address in range(gap_start, gap_end):
        index = address - start
        assert result.data[index] == FILL
        assert result.available[index] is False
    # Then the head of segment 2.
    assert result.data[-4:] == SEG2_DATA[:4]

    missing = result.missing_ranges
    assert missing == [(gap_start, gap_end)]
    assert result.is_complete is False
    # Every non-gap position is disclosed.
    assert result.available[:4] == [True] * 4
    assert result.available[-4:] == [True] * 4


def test_duplicate_read_is_byte_stable(sync_view):
    first = sync_view.read(SEG2_VA, len(SEG2_DATA))
    second = sync_view.read(SEG2_VA, len(SEG2_DATA))
    third = sync_view.read(SEG2_VA, len(SEG2_DATA))

    assert first.data == SEG2_DATA
    assert first.data == second.data == third.data
    assert first == second == third


def test_alias_keeps_original_disclosure_restriction(sync_view):
    # The alias VA points at the same underlying bytes as segment 1 but was
    # never approved, so it must not become readable through the view.
    assert sync_view.is_approved(SEG1_VA) is True
    assert sync_view.is_approved(ALIAS_VA) is False

    with pytest.raises(RestrictedRangeError):
        sync_view.read(ALIAS_VA, len(SEG1_DATA))

    # The disclosed ranges only mention the approved virtual addresses.
    disclosed = sync_view.disclosed_ranges
    assert (SEG1_VA, SEG1_VA + len(SEG1_DATA)) in disclosed
    assert all(start != ALIAS_VA for start, _ in disclosed)

    # The aliased backing evidence is still the same physical source for the
    # bytes that were legitimately disclosed via segment 1.
    assert len(sync_view.evidence_keys) == 2


def test_async_reads_match_sync_reads(sync_view, async_view):
    cases = [
        (SEG1_VA, len(SEG1_DATA)),
        (SEG1_VA + 4, (SEG2_VA + 4) - (SEG1_VA + 4)),
        (SEG2_VA, len(SEG2_DATA)),
    ]
    for address, size in cases:
        sync_result = sync_view.read(address, size)
        async_result = run(async_view.aread(address, size))
        assert async_result == sync_result
        assert async_result.data == sync_result.data
        assert async_result.available == sync_result.available
        assert async_result.mask == sync_result.mask

    with pytest.raises(RestrictedRangeError):
        run(async_view.aread(ALIAS_VA, 4))


def test_exception_only_references_approved_ranges(sync_view):
    with pytest.raises(RestrictedRangeError) as excinfo:
        sync_view.read(ALIAS_VA, 4)

    message = str(excinfo.value)
    # Approved boundaries may appear; the undisclosed address must not.
    assert hex(ALIAS_VA) not in message
    assert hex(SEG1_VA) in message
    assert hex(SEG2_VA) in message


def test_handoff_serialization_round_trips_bytes(sync_view):
    payload = sync_view.to_bytes()
    restored = RestrictedMinidumpView.from_bytes(payload)

    assert restored.approved_ranges == sync_view.approved_ranges
    assert restored.disclosed_ranges == sync_view.disclosed_ranges

    for address, size in [
        (SEG1_VA, len(SEG1_DATA)),
        (SEG1_VA + 4, (SEG2_VA + 4) - (SEG1_VA + 4)),
        (SEG2_VA, len(SEG2_DATA)),
    ]:
        assert restored.read(address, size) == sync_view.read(address, size)

    with pytest.raises(RestrictedRangeError):
        restored.read(ALIAS_VA, 4)


def test_view_does_not_hold_original_file_handle(sync_view):
    assert not hasattr(sync_view, "file_handle")
    assert not any(hasattr(block, "file_handle") for block in sync_view._blocks)


def test_approved_but_undumped_address_reports_missing(sync_view):
    undumped = SEG2_VA + len(SEG2_DATA)
    view = RestrictedMinidumpView(
        [(undumped, undumped + 8)], fill=FILL
    )
    result = view.read(undumped, 8)
    assert result.data == GAP_FILL * 8
    assert result.available == [False] * 8
    assert result.missing_ranges == [(undumped, undumped + 8)]
