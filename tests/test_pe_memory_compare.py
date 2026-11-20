"""Tests for the read-only disk-vs-memory PE comparison backend.

Everything is synthetic: the PEs are built by tests/synthetic_pe.py and the
post-loader memory images are simulated in pure Python. No sample is ever
executed and no Windows API is involved.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pefile
import pe_memory_compare as pmc
from synthetic_pe import SyntheticPE, loader_memory_image, PAGE


REBASE_DELTA = 0x12340000


def _load(data):
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        ]
    )
    return pe


def _fragments_from_image(image, present_rvas, reference_size):
    # Turn the sparse present-rva set into the minimal contiguous fragments.
    points = sorted(r for r in present_rvas if r < reference_size)
    fragments = []
    if not points:
        return fragments
    start = prev = points[0]
    for rva in points[1:]:
        if rva == prev + 1:
            prev = rva
            continue
        fragments.append(pmc.MemoryFragment(start, image[start:prev + 1]))
        start = prev = rva
    fragments.append(pmc.MemoryFragment(start, image[start:prev + 1]))
    return fragments


def _run(builder, new_base, **loader_kwargs):
    data = builder.build(
        extra_reloc_type=loader_kwargs.pop("extra_reloc_type", None)
    )
    image, present = loader_memory_image(
        builder, data, new_base, **loader_kwargs
    )
    pe = _load(data)
    reference_size = len(pmc.build_reference_image(pe))
    fragments = _fragments_from_image(image, present, reference_size)
    report = pmc.compare_pe_memory(pe, fragments, new_base)
    return builder, pe, report, reference_size


# ---------------------------------------------------------------------------
# Scenario 1: a clean rebased load is fully explained, never suspect.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pe32_plus", [False, True])
def test_clean_rebased_load_has_no_suspect_bytes(pe32_plus):
    builder = SyntheticPE(pe32_plus=pe32_plus)
    new_base = builder.preferred_base + REBASE_DELTA
    _, pe, report, ref_size = _run(builder, new_base)

    assert report.suspect_ranges == []
    assert report.conflicts == []

    # The relocation evidence covers the full pointer slot, while only the
    # bytes the delta actually changes carry an explained difference.
    reloc_rva = builder.reloc_target_rva
    width = builder.pointer_size
    evidence = report.evidence[reloc_rva][0]
    assert isinstance(evidence, pmc.RelocationEvidence)
    assert evidence.span == (reloc_rva, reloc_rva + width)
    assert evidence.delta == REBASE_DELTA
    explained = report.ranges(pmc.VERDICT_EXPLAINED_RELOCATION)
    assert all(reloc_rva <= start and end <= reloc_rva + width
               for start, end in explained)
    assert explained  # at least one byte of the slot changed

    # The IAT evidence covers the full pointer slot even when some bytes of
    # the fake resolved address happen to equal the on-disk value.
    iat_rva = builder.iat_rva
    iat_evidence = [
        e for e in report.evidence[iat_rva]
        if isinstance(e, pmc.IATBindingEvidence) and e.table == "IAT"
    ]
    assert len(iat_evidence) == 1
    assert iat_evidence[0].span == (iat_rva, iat_rva + width)
    assert iat_evidence[0].symbol == "SyntheticFunction"
    assert all(
        iat_rva <= start and end <= iat_rva + width
        for start, end in report.ranges(pmc.VERDICT_EXPLAINED_IAT)
    )


@pytest.mark.parametrize("pe32_plus", [False, True])
def test_zero_delta_relocation_is_not_fabricated(pe32_plus):
    # Loading at the preferred base means the reloc delta is zero and the
    # bytes match; they must not be reported as differences.
    builder = SyntheticPE(pe32_plus=pe32_plus)
    _, pe, report, _ = _run(builder, builder.preferred_base)
    assert report.suspect_ranges == []
    assert report.ranges(pmc.VERDICT_EXPLAINED_RELOCATION) == []
    # Import binding is independent of the base and still explains the IAT.
    assert report.ranges(pmc.VERDICT_EXPLAINED_IAT) != []
    assert report.conflicts == []


# ---------------------------------------------------------------------------
# Scenario 2: an unexplained code patch is reported at its exact bytes.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pe32_plus", [False, True])
def test_code_patch_is_suspect_at_exact_interval(pe32_plus):
    builder = SyntheticPE(pe32_plus=pe32_plus)
    new_base = builder.preferred_base + REBASE_DELTA
    patch_rva = builder.code_patch_rva
    patch = {
        patch_rva: 0xCC,
        patch_rva + 1: 0xCC,
        patch_rva + 2: 0x90,  # unchanged byte inside the patched region
        patch_rva + 3: 0xCC,
    }
    _, pe, report, _ = _run(builder, new_base, patch=patch)

    # Only the three actually changed bytes are suspect; the unchanged 0x90
    # is not part of any difference range.
    assert report.suspect_ranges == [
        (patch_rva, patch_rva + 2),
        (patch_rva + 3, patch_rva + 4),
    ]
    diffs = [d for d in report.differences if d.verdict == pmc.VERDICT_SUSPECT]
    assert sorted(d.rva for d in diffs) == [
        patch_rva,
        patch_rva + 1,
        patch_rva + 3,
    ]
    for diff in diffs:
        assert diff.evidence == ()

    # Loader-explained bytes remain explained and no conflict is raised.
    assert report.conflicts == []
    assert report.explained_ranges  # relocation + IAT still explained


# ---------------------------------------------------------------------------
# Scenario 3: IAT binding is explained; an ILT rewrite is handled by policy.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pe32_plus", [False, True])
def test_iat_binding_is_explained_not_suspect(pe32_plus):
    builder = SyntheticPE(pe32_plus=pe32_plus)
    new_base = builder.preferred_base + REBASE_DELTA
    _, pe, report, _ = _run(builder, new_base, bind_iat=True)

    width = builder.pointer_size
    iat_rva = builder.iat_rva
    explained = report.ranges(pmc.VERDICT_EXPLAINED_IAT)
    # Every explained byte lies inside the IAT slot, and at least one byte
    # changed (high zero bytes of the fake address may match the disk value).
    assert explained
    assert all(
        iat_rva <= start and end <= iat_rva + width for start, end in explained
    )
    iat_diffs = [
        d for d in report.differences
        if iat_rva <= d.rva < iat_rva + width
    ]
    assert iat_diffs
    assert all(d.verdict == pmc.VERDICT_EXPLAINED_IAT for d in iat_diffs)
    assert report.suspect_ranges == []


def test_ilt_rewrite_is_suspect_when_ilt_not_trusted():
    # With include_ilt=False the ILT is not considered loader-owned, so an
    # observed ILT overwrite must surface as suspect rather than be hidden.
    builder = SyntheticPE(pe32_plus=False)
    new_base = builder.preferred_base + REBASE_DELTA
    data = builder.build()
    image, present = loader_memory_image(builder, data, new_base)

    # Simulate something rewriting the (normally read-only) ILT slot.
    ilt_rva = builder.ilt_rva
    image[ilt_rva:ilt_rva + 4] = b"\xDE\xAD\xBE\xEF"

    pe = _load(data)
    ref_size = len(pmc.build_reference_image(pe))
    fragments = _fragments_from_image(image, present, ref_size)
    report = pmc.compare_pe_memory(
        pe, fragments, new_base, include_ilt=False
    )
    assert (ilt_rva, ilt_rva + 4) in report.suspect_ranges


# ---------------------------------------------------------------------------
# Scenario 4: missing pages are undeterminable, never zero-filled tampering.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pe32_plus", [False, True])
def test_missing_page_is_undetermined_not_suspect(pe32_plus):
    builder = SyntheticPE(pe32_plus=pe32_plus)
    new_base = builder.preferred_base + REBASE_DELTA
    dropped_page = builder.RDATA_RVA // PAGE
    _, pe, report, ref_size = _run(
        builder, new_base, drop_pages=[dropped_page]
    )

    page_start = dropped_page * PAGE
    page_end = min(page_start + PAGE, ref_size)
    assert (page_start, page_end) in report.missing_page_ranges
    assert report.ranges(pmc.VERDICT_UNDETERMINED_MISSING_PAGE) == [
        (page_start, page_end)
    ]
    for start, end in report.suspect_ranges:
        assert not (start < page_end and end > page_start)

    reloc_ranges = report.ranges(pmc.VERDICT_EXPLAINED_RELOCATION)
    reloc_rva = builder.reloc_target_rva
    assert reloc_ranges
    assert all(
        reloc_rva <= start and end <= reloc_rva + builder.pointer_size
        for start, end in reloc_ranges
    )


def test_missing_page_even_if_disk_bytes_nonzero():
    builder = SyntheticPE(pe32_plus=False)
    new_base = builder.preferred_base + REBASE_DELTA
    dropped_page = builder.RDATA_RVA // PAGE
    _, pe, report, _ = _run(
        builder, new_base, drop_pages=[dropped_page]
    )
    undetermined = report.ranges(pmc.VERDICT_UNDETERMINED_MISSING_PAGE)
    assert any(
        builder.iat_rva in range(start, end) for start, end in undetermined
    )
    assert report.suspect_ranges == []


# ---------------------------------------------------------------------------
# Edge case: unknown relocation types never silence a whole section.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pe32_plus", [False, True])
def test_unknown_relocation_type_marks_only_its_slot(pe32_plus):
    builder = SyntheticPE(pe32_plus=pe32_plus)
    new_base = builder.preferred_base + REBASE_DELTA
    # Type 0x0B (MIPS_JMPADDR16 / IA64_IMM64) is not modelled for x86/x64.
    _, pe, report, _ = _run(
        builder, new_base, extra_reloc_type=0x0B
    )

    unknown_ranges = report.unknown_reloc_ranges
    width = builder.pointer_size
    expected_rva = builder.unknown_reloc_rva
    assert unknown_ranges == [(expected_rva, expected_rva + width)]

    # The unknown slot is undetermined, not silently explained or ignored,
    # regardless of whether its captured bytes happen to match.
    for rva in range(expected_rva, expected_rva + width):
        assert report.verdicts[rva] == (
            pmc.VERDICT_UNDETERMINED_UNKNOWN_RELOC
        )
        assert any(
            isinstance(e, pmc.UnknownRelocationEvidence)
            for e in report.evidence[rva]
        )
    # Only the slot is affected; the surrounding .text page is still judged.
    text_page = builder.TEXT_RVA // PAGE
    affected_pages = {
        rva // PAGE for start, end in unknown_ranges
        for rva in range(start, end)
    }
    assert affected_pages == {text_page}
    assert any(
        "unmodelled relocation type" in warning
        for warning in report.warnings
    )


# ---------------------------------------------------------------------------
# Edge case: two distinct explanations on one byte produce a conflict.
# ---------------------------------------------------------------------------


def test_overlapping_relocation_and_iat_is_reported_as_conflict():
    builder = SyntheticPE(pe32_plus=False)
    new_base = builder.preferred_base + REBASE_DELTA
    data = builder.build()
    image, present = loader_memory_image(builder, data, new_base)
    pe = _load(data)
    ref_size = len(pmc.build_reference_image(pe))

    # Hand-craft an extra relocation that lands inside the IAT slot, which
    # the IAT binding evidence already covers.
    pe.DIRECTORY_ENTRY_BASERELOC[0].entries.append(
        pefile.RelocationData(
            struct=None,
            type=pefile.RELOCATION_TYPE["IMAGE_REL_BASED_HIGHLOW"],
            base_rva=builder.TEXT_RVA,
            rva=builder.iat_rva,
        )
    )
    fragments = _fragments_from_image(image, present, ref_size)
    report = pmc.compare_pe_memory(pe, fragments, new_base)

    conflict_rvas = {conflict.rva for conflict in report.conflicts}
    assert builder.iat_rva in conflict_rvas
    conflict = next(
        c for c in report.conflicts if c.rva == builder.iat_rva
    )
    kinds = {e.kind for e in conflict.evidences}
    assert "relocation" in kinds and "iat_binding" in kinds
    assert report.verdicts[builder.iat_rva] == pmc.VERDICT_CONFLICT


# ---------------------------------------------------------------------------
# Guard rails: unsupported architecture and overlapping fragments.
# ---------------------------------------------------------------------------


def test_unsupported_architecture_raises():
    builder = SyntheticPE(pe32_plus=False)
    data = builder.build()
    pe = _load(data)
    pe.FILE_HEADER.Machine = 0x01C0  # IMAGE_FILE_MACHINE_ARM, not modelled
    with pytest.raises(pmc.UnsupportedArchitecture):
        pmc.compare_pe_memory(pe, [], builder.preferred_base)


def test_overlapping_fragments_are_rejected():
    builder = SyntheticPE(pe32_plus=False)
    data = builder.build()
    pe = _load(data)
    with pytest.raises(pmc.InvalidMemoryMap):
        pmc.compare_pe_memory(
            pe,
            [
                pmc.MemoryFragment(0x1000, b"\x00\x00"),
                pmc.MemoryFragment(0x1001, b"\x00"),
            ],
            builder.preferred_base,
        )


def test_disk_pe_is_not_mutated():
    builder = SyntheticPE(pe32_plus=False)
    data = builder.build()
    new_base = builder.preferred_base + REBASE_DELTA
    image, present = loader_memory_image(builder, data, new_base)
    pe = _load(data)
    before = pe.OPTIONAL_HEADER.ImageBase
    ref_size = len(pmc.build_reference_image(pe))
    fragments = _fragments_from_image(image, present, ref_size)
    pmc.compare_pe_memory(pe, fragments, new_base)
    # The read-only backend must not rebase or otherwise mutate the PE.
    assert pe.OPTIONAL_HEADER.ImageBase == before
    assert pe.get_dword_at_rva(builder.reloc_target_rva) == builder.preferred_base


# ---------------------------------------------------------------------------
# Edge case: captured bytes beyond the mapped image.
# ---------------------------------------------------------------------------


def test_capture_beyond_image_is_suspect_out_of_image():
    builder = SyntheticPE(pe32_plus=False)
    new_base = builder.preferred_base + REBASE_DELTA
    data = builder.build()
    image, _ = loader_memory_image(builder, data, new_base)
    pe = _load(data)
    ref_size = len(pmc.build_reference_image(pe))
    fragments = [
        pmc.MemoryFragment(0, bytes(image[:ref_size])),
        pmc.MemoryFragment(ref_size, b"\xAA\xBB"),
    ]
    report = pmc.compare_pe_memory(pe, fragments, new_base)
    assert report.ranges(pmc.VERDICT_SUSPECT_OUT_OF_IMAGE) == [
        (ref_size, ref_size + 2)
    ]
    assert report.out_of_image_bytes[ref_size] == 0xAA
    assert report.out_of_image_bytes[ref_size + 1] == 0xBB


def test_missing_page_takes_precedence_over_unknown_relocation():
    # When the page hosting an unsupported relocation is not captured, the
    # verdict must stay missing-page rather than unknown-relocation.
    builder = SyntheticPE(pe32_plus=False)
    new_base = builder.preferred_base + REBASE_DELTA
    data = builder.build(extra_reloc_type=0x0B)
    image, _ = loader_memory_image(
        builder, data, new_base, extra_reloc_type=0x0B
    )
    pe = _load(data)
    ref_size = len(pmc.build_reference_image(pe))
    dropped = builder.TEXT_RVA // PAGE
    present = [rva for rva in range(ref_size) if rva // PAGE != dropped]
    fragments = _fragments_from_image(image, present, ref_size)
    report = pmc.compare_pe_memory(pe, fragments, new_base)
    assert report.unknown_reloc_ranges == []
    assert (builder.TEXT_RVA, builder.TEXT_RVA + PAGE) in (
        report.missing_page_ranges
    )
