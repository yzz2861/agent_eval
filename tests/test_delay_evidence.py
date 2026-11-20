"""End-to-end tests for the read-only delay-load evidence view."""

from __future__ import annotations

import pathlib

import pytest

from delay_evidence.analyzer import analyze
from delay_evidence.compare import compare
from delay_evidence.loader import LoaderError, load_bytes, load_path
from delay_evidence.make_samples import write_samples
from delay_evidence.model import EvidenceKind, EvidenceLevel
from delay_evidence.removal import remove_target
from delay_evidence.report import render_markdown, render_text


PACKAGES = pathlib.Path(__file__).resolve().parent.parent / "delay_evidence"


def _module(result, dll_name):
    return next(module for module in result.modules if module.dll == dll_name)


def _symbol(module, name):
    return next(symbol for symbol in module.symbols if symbol.symbol == name)


def _kinds(symbol):
    return [node.kind for node in symbol.chain]


def test_synthetic_pe_parses_without_loader(loaded_a):
    result = analyze(loaded_a)
    dlls = [module.dll for module in result.modules]
    assert "appcrt140.dll" in dlls
    assert "kernel32.dll" in dlls
    assert result.load_config is not None


def test_ordinal_import_is_index_only(loaded_a):
    result = analyze(loaded_a)
    module = _module(result, "appcrt140.dll")
    ordinal_symbol = _symbol(module, "#1234")
    assert ordinal_symbol.by_ordinal is True
    assert EvidenceKind.INDEX_ONLY in _kinds(ordinal_symbol)
    assert all(node.kind is not EvidenceKind.FILE_POINTER
               for node in ordinal_symbol.chain
               if node.level in (EvidenceLevel.L3_NAME_TABLE,
                                 EvidenceLevel.L4_THUNK_TABLE))


def test_bound_import_keeps_file_pointer(loaded_a):
    result = analyze(loaded_a)
    module = _module(result, "appcrt140.dll")
    bound_symbol = _symbol(module, "crt_initialize")
    iat_nodes = [node for node in bound_symbol.chain
                 if node.level is EvidenceLevel.L4_THUNK_TABLE]
    assert iat_nodes and iat_nodes[0].kind is EvidenceKind.FILE_POINTER
    assert iat_nodes[0].value == 0x140070000


def test_unbound_import_runtime_slot(loaded_a):
    result = analyze(loaded_a)
    module = _module(result, "kernel32.dll")
    sleep = _symbol(module, "Sleep")
    assert sleep.still_viable is True
    assert any(node.level is EvidenceLevel.L9_CODE_REFERENCE and
               node.kind is EvidenceKind.RUNTIME_UNRESOLVED
               for node in sleep.chain)


def test_module_handle_is_runtime_unresolved(loaded_a):
    result = analyze(loaded_a)
    module = _module(result, "kernel32.dll")
    phmod = [node for node in module.module_evidence
             if node.level is EvidenceLevel.L7_MODULE_HANDLE]
    assert phmod and phmod[0].kind is EvidenceKind.RUNTIME_UNRESOLVED


def test_guard_table_cross_references_delay_iat(loaded_a):
    result = analyze(loaded_a)
    guard_nodes = [
        node for _m, _s, node in result.walk_evidence()
        if node.level is EvidenceLevel.L8_LOAD_CONFIG
    ]
    assert any("GuardAddressTakenIatEntry" in node.location
               for node in guard_nodes)
    assert result.load_config.guard_flags == 0x10500


def test_module_removal_breaks_l2_keeps_other_dll(loaded_a):
    result = analyze(loaded_a)
    broken_levels = remove_target(result, "appcrt140.dll")
    assert EvidenceLevel.L2_DESCRIPTOR in broken_levels
    remaining = [module.dll for module in result.modules]
    assert "appcrt140.dll" not in remaining
    kernel = _module(result, "kernel32.dll")
    assert all(symbol.still_viable for symbol in kernel.symbols)


def test_symbol_removal_breaks_l3_only(loaded_a):
    result = analyze(loaded_a)
    broken_levels = remove_target(result, "appcrt140.dll!#1234")
    assert EvidenceLevel.L3_NAME_TABLE in broken_levels
    module = _module(result, "appcrt140.dll")
    names = [symbol.symbol for symbol in module.symbols]
    assert "#1234" not in names
    assert _symbol(module, "crt_initialize").still_viable is True
    kernel = _module(result, "kernel32.dll")
    assert all(symbol.still_viable for symbol in kernel.symbols)


def test_fragment_analysis(tmp_path, sample_a_bytes):
    paths = write_samples(str(tmp_path))
    loaded = load_path(paths["fragment"],
                       fragment_base_rva=paths["fragment_base_rva"])
    result = analyze(loaded)
    assert result.is_fragment is True
    dlls = [module.dll for module in result.modules]
    assert "appcrt140.dll" in dlls and "kernel32.dll" in dlls
    module = _module(result, "appcrt140.dll")
    kinds = [node.kind for symbol in module.symbols for node in symbol.chain]
    assert EvidenceKind.INDEX_ONLY in kinds
    assert EvidenceKind.FILE_POINTER in kinds


def test_fragment_requires_base_rva():
    with pytest.raises(LoaderError):
        load_bytes(b"\\x01\\x02\\x03\\x04", source="raw")


def test_compare_flags_generation_difference(loaded_a, loaded_b):
    left = analyze(loaded_a)
    right = analyze(loaded_b)
    comparison = compare(left, right)
    assert "appcrt140.dll" in comparison["shared_dlls"]
    diffs = {(row["dll"], row["symbol"]) for row in comparison["differences"]}
    assert ("appcrt140.dll", "crt_initialize") in diffs
    assert ("kernel32.dll", "Sleep") in diffs


def test_reports_render(loaded_a):
    result = analyze(loaded_a)
    text = render_text(result)
    markdown = render_markdown(result)
    assert "FILE_POINTER" in text
    assert "## Evidence classification totals" in markdown
    assert "appcrt140.dll" in markdown




def test_input_bytes_are_not_modified(loaded_a, sample_a_bytes):
    snapshot = bytes(sample_a_bytes)
    result = analyze(loaded_a)
    remove_target(result, "appcrt140.dll")
    assert loaded_a.data == snapshot
def test_no_loader_apis_in_package():
    import ast
    forbidden = {"ctypes", "subprocess", "dlopen", "winreg"}
    for source_path in PACKAGES.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = {node.module.split(".")[0]}
            else:
                continue
            assert not (names & forbidden), (source_path.name, names & forbidden)


