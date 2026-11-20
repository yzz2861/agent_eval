"""Side-by-side comparison of two PEs focusing on same-named delay DLLs."""

from __future__ import annotations

from .model import EvidenceKind


def _index_modules(result):
    return {module.dll.lower(): module for module in result.modules}


def _kind_signature(module):
    signature = {}
    for symbol in module.symbols:
        signature[symbol.symbol] = sorted(
            node.kind.value for node in symbol.chain
        )
    return signature


def compare(left, right):
    """Return rows describing differences for DLLs present in both images."""
    left_index = _index_modules(left)
    right_index = _index_modules(right)
    shared = sorted(set(left_index) & set(right_index))
    rows = []
    for name in shared:
        left_module = left_index[name]
        right_module = right_index[name]
        left_sig = _kind_signature(left_module)
        right_sig = _kind_signature(right_module)
        symbols = sorted(set(left_sig) | set(right_sig))
        for symbol in symbols:
            left_kinds = left_sig.get(symbol)
            right_kinds = right_sig.get(symbol)
            if left_kinds != right_kinds:
                rows.append({
                    "dll": left_module.dll,
                    "symbol": symbol,
                    "left": left_kinds,
                    "right": right_kinds,
                })
    only_left = sorted(set(left_index) - set(right_index))
    only_right = sorted(set(right_index) - set(left_index))
    return {
        "shared_dlls": shared,
        "differences": rows,
        "only_left": only_left,
        "only_right": only_right,
    }


def render_compare_markdown(left, right, comparison):
    lines = []
    lines.append("# Same-named delay DLL comparison")
    lines.append("")
    lines.append("- left: `" + left.source + "`")
    lines.append("- right: `" + right.source + "`")
    lines.append("")
    lines.append("Shared delay-loaded DLLs: " + ", ".join(comparison["shared_dlls"]))
    lines.append("")
    if comparison["differences"]:
        lines.append("## Structural evidence differences")
        lines.append("")
        lines.append("| DLL | Symbol | Left evidence classes | Right evidence classes |")
        lines.append("| --- | --- | --- | --- |")
        for row in comparison["differences"]:
            lines.append("| " + row["dll"] + " | `" + row["symbol"] + "` | " + str(row["left"]) + " | " + str(row["right"]) + " |")
    else:
        lines.append("No classifiable evidence differences on shared DLL symbols.")
    if comparison["only_left"] or comparison["only_right"]:
        lines.append("")
        lines.append("## DLLs seen on only one side")
        lines.append("")
        lines.append("- left only: " + ", ".join(comparison["only_left"]))
        lines.append("- right only: " + ", ".join(comparison["only_right"]))
    return chr(10).join(lines)
