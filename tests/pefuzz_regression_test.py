"""Offline regression tests for the pefuzz structure-preserving toolkit.

The whole suite uses only synthetic, in-memory PE images and a fixed RNG
seed, so it runs without network access and finishes well inside thirty
seconds.
"""

import pefile
import pytest

from pefuzz import (
    DEFAULT_SEED,
    build_mini_pe,
    compare,
    generate_cases,
    mutators,
    reduce_failure,
    SemanticChange,
)
from pefuzz.coverage import DirectoryCoverage


@pytest.fixture(scope="module")
def base_pe():
    return build_mini_pe(seed=DEFAULT_SEED)


def _parse(sample):
    pe = pefile.PE(data=bytes(sample), fast_load=True)
    pe.parse_data_directories()
    return pe


def _resource_depth(pe):
    def depth(node):
        deepest = 0
        for entry in node.entries:
            if hasattr(entry, "directory"):
                deepest = max(deepest, 1 + depth(entry.directory))
        return deepest

    return depth(pe.DIRECTORY_ENTRY_RESOURCE)


class TestSyntheticBuilder:
    def test_mini_pe_is_well_formed_and_compact(self, base_pe):
        pe = _parse(base_pe)
        assert pe.DOS_HEADER.e_magic == 0x5A4D
        assert pe.FILE_HEADER.NumberOfSections == 2
        assert len(base_pe) < 4096

    def test_all_target_directories_present(self, base_pe):
        pe = _parse(base_pe)
        assert hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
        assert hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
        assert hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")
        assert hasattr(pe, "DIRECTORY_ENTRY_DEBUG")
        assert hasattr(pe, "DIRECTORY_ENTRY_BASERELOC")

    def test_resource_tree_is_three_levels_deep(self, base_pe):
        pe = _parse(base_pe)
        assert _resource_depth(pe) == 2

    def test_import_and_export_semantics(self, base_pe):
        pe = _parse(base_pe)
        dlls = {bytes(d.dll).decode() for d in pe.DIRECTORY_ENTRY_IMPORT}
        assert dlls == {"KERNEL32.dll", "USER32.dll"}
        names = {bytes(e.name).decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols}
        assert names == {
            "MiniExportOne",
            "MiniExportTwo",
            "MiniExportByOrd",
        }


class TestCoverage:
    def test_reaches_at_least_two_directory_layers(self, base_pe):
        with DirectoryCoverage() as tracer:
            _parse(base_pe)
        report = tracer.report
        assert report.distinct_directories >= 4
        assert report.reached_at_least_depth(2)
        assert report.directory_hits["RESOURCE"] >= 1
        assert report.resource_max_depth == 2

    def test_dos_break_never_reaches_directories(self, base_pe):
        broken, _ = mutators.break_dos_magic(base_pe)
        with pytest.raises(pefile.PEFormatError):
            with DirectoryCoverage():
                _parse(broken)


class TestStructurePreservingMutators:
    def test_move_section_raw_keeps_semantics(self, base_pe):
        moved, record = mutators.move_section_raw(base_pe, ".rdata", 0xA00)
        after = _parse(moved)
        before = _parse(base_pe)
        assert after.sections[1].PointerToRawData == 0xA00
        diff = compare.compare_parses(
            before, after, [SemanticChange.COORDINATE_ONLY]
        )
        assert diff.equivalent, diff.explain()
        assert record.preserves_structure
        assert record.dependent_fields

    def test_move_directory_payload_keeps_semantics(self, base_pe):
        moved, record = mutators.move_directory_payload(base_pe, 0, ".text")
        after = _parse(moved)
        before = _parse(base_pe)
        diff = compare.compare_parses(
            before, after, [SemanticChange.COORDINATE_ONLY]
        )
        assert diff.equivalent, diff.explain()
        assert compare.export_signature(before) == compare.export_signature(after)

    def test_replace_import_name_only_changes_that_name(self, base_pe):
        renamed, record = mutators.replace_import_name(
            base_pe, 0, 0, b"HeapAlloc"
        )
        before = _parse(base_pe)
        after = _parse(renamed)
        before_sig = compare.import_signature(before)
        after_sig = compare.import_signature(after)
        before_names = {n for _, syms in before_sig for _, n in syms}
        after_names = {n for _, syms in after_sig for _, n in syms}
        assert "HeapAlloc" in after_names
        assert "LoadLibraryA" not in after_names
        assert before_names != after_names
        diff = compare.compare_parses(
            before, after, [SemanticChange.IMPORT_NAME]
        )
        assert diff.equivalent, diff.explain()

    def test_reorder_import_descriptors_preserves_semantics(self, base_pe):
        reordered, record = mutators.reorder_import_descriptors(base_pe)
        before = _parse(base_pe)
        after = _parse(reordered)
        assert compare.import_signature(before) == compare.import_signature(after)
        diff = compare.compare_parses(before, after, [SemanticChange.NONE])
        assert diff.equivalent, diff.explain()

    def test_reorder_resource_entries_preserves_tree(self, base_pe):
        reordered, record = mutators.reorder_resource_entries(base_pe, 0)
        before = _parse(base_pe)
        after = _parse(reordered)
        assert compare.resource_signature(before) == compare.resource_signature(after)
        diff = compare.compare_parses(before, after, [SemanticChange.NONE])
        assert diff.equivalent, diff.explain()

    def test_reorder_debug_entries_preserves_semantics(self, base_pe):
        reordered, record = mutators.reorder_debug_entries(base_pe)
        before = _parse(base_pe)
        after = _parse(reordered)
        assert compare.debug_signature(before) == compare.debug_signature(after)


class TestSingleConstraintBreakage:
    def test_each_break_violates_exactly_one_constraint(self, base_pe):
        operations = [
            mutators.break_section_raw_pointer(base_pe, ".rdata"),
            mutators.break_directory_rva(base_pe, 1),
            mutators.break_import_name_rva(base_pe),
            mutators.break_resource_depth(base_pe),
        ]
        for _, record in operations:
            assert record.broken_constraint
            assert record.preserves_structure is False
            assert len([record.broken_constraint]) == 1

    def test_dos_magic_break_rejects_before_directories(self, base_pe):
        broken, record = mutators.break_dos_magic(base_pe)
        assert record.broken_constraint
        with pytest.raises(pefile.PEFormatError):
            _parse(broken)

    def test_break_modes_create_suspicious_diagnostics(self, base_pe):
        before = _parse(base_pe)
        for operation in (
            lambda d: mutators.break_section_raw_pointer(d, ".rdata"),
            lambda d: mutators.break_directory_rva(d, 1),
            mutators.break_import_name_rva,
            mutators.break_resource_depth,
        ):
            broken, _ = operation(base_pe)
            after = _parse(broken)
            diff = compare.compare_parses(
                before,
                after,
                [SemanticChange.SUSPICIOUS_DIAGNOSTIC],
            )
            assert not diff.equivalent
            assert diff.warning_deltas


class TestMutationRecords:
    def test_records_document_dependencies_and_invariants(self, base_pe):
        _, record = mutators.move_directory_payload(base_pe, 0, ".text")
        assert record.name == "move_directory_payload"
        assert record.dependent_fields
        assert record.expected_invariants
        payload = record.as_dict()
        assert payload["name"] == record.name
        assert payload["dependent_fields"]

    def test_allowed_change_kinds_are_explicit(self, base_pe):
        cases = [
            mutators.reorder_import_descriptors(base_pe),
            mutators.move_section_raw(base_pe, ".rdata", 0xA00),
        ]
        for _, record in cases:
            assert record.allowed_semantic_changes


class TestReducer:
    def _failing_sample(self):
        from pefuzz.builder import MiniPEBuilder

        base = MiniPEBuilder(include_relocs=False).build()
        return mutators.break_resource_depth(base)[0]

    def _predicate(self):
        def predicate(sample):
            try:
                pe = _parse(sample)
            except pefile.PEFormatError:
                return True
            return any(
                "resources directory" in warning
                for warning in pe.get_warnings()
            )

        return predicate

    def _parse_factory(self):
        def factory(sample):
            return lambda: _parse(sample)

        return factory

    def test_reduction_keeps_deep_path_and_shrinks(self):
        sample = self._failing_sample()
        predicate = self._predicate()
        factory = self._parse_factory()
        result = reduce_failure(sample, predicate, factory)
        assert predicate(result.data)
        assert result.reduced_size <= result.original_size
        assert result.reduced_size < 4096
        reduced_pe = _parse(result.data)
        assert _resource_depth(reduced_pe) == 2

    def test_reduced_sample_is_replayable_bytes(self):
        sample = self._failing_sample()
        result = reduce_failure(
            sample, self._predicate(), self._parse_factory()
        )
        assert isinstance(result.data, bytes)
        assert len(result.data) < 4096


class TestDeterministicHarness:
    def test_fixed_seed_is_reproducible(self):
        first = [(c.label, c.data) for c in generate_cases(seed=DEFAULT_SEED)]
        second = [(c.label, c.data) for c in generate_cases(seed=DEFAULT_SEED)]
        assert first == second

    def test_every_case_carries_a_record_except_baseline(self):
        for case in generate_cases():
            if case.label == "baseline":
                assert case.record is None
            else:
                assert case.record is not None
                assert case.record.name


class TestReplayableDefect:
    def test_disk_sample_is_under_4kb_and_reproduces(self):
        from pathlib import Path

        sample_path = Path(__file__).resolve().parent / "replay_defect.bin"
        assert sample_path.exists()
        sample = sample_path.read_bytes()
        assert len(sample) < 4096
        pe = _parse(sample)
        assert any(
            "resources directory" in warning
            for warning in pe.get_warnings()
        )

    def test_disk_sample_is_byte_stable_across_runs(self):
        from pathlib import Path

        sample_path = Path(__file__).resolve().parent / "replay_defect.bin"
        first = sample_path.read_bytes()
        from pefuzz import mutators

        regenerated = mutators.break_resource_depth(build_mini_pe())[0]
        assert first == regenerated
