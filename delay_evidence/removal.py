"""In-memory removal simulation.

Removal is purely logical: the input bytes are never touched. The matching
evidence nodes are flagged ``removed=True`` and every dependent level of the
chain loses its proof, which is exactly what the report surfaces.
"""

from __future__ import annotations

from .model import EvidenceLevel


def _matches_module(target, dll):
    return target.lower() == dll.lower()


def _matches_symbol(target, dll, symbol, by_ordinal, ordinal):
    if "!" not in target:
        return False
    target_dll, target_symbol = target.split("!", 1)
    if not _matches_module(target_dll, dll):
        return False
    if target_symbol.startswith("#"):
        return by_ordinal and str(ordinal) == target_symbol[1:]
    return target_symbol.lower() == symbol.lower()


def remove_target(result, target):
    """Flag evidence belonging to ``target`` as removed and report impact."""
    target = target.strip()
    removed_at = set()
    surviving_modules = []
    for module in result.modules:
        module_hit = _matches_module(target, module.dll)
        if module_hit and "!" not in target:
            for node in module.module_evidence:
                node.removed = True
            for symbol in module.symbols:
                for node in symbol.chain:
                    node.removed = True
            removed_at.add(EvidenceLevel.L2_DESCRIPTOR)
            continue
        surviving_symbols = []
        for symbol in module.symbols:
            hit = module_hit or _matches_symbol(
                target, module.dll, symbol.symbol,
                symbol.by_ordinal, symbol.ordinal
            )
            if hit:
                for node in symbol.chain:
                    node.removed = True
                if symbol.broken_level is not None:
                    removed_at.add(symbol.broken_level)
            else:
                surviving_symbols.append(symbol)
        module.symbols = surviving_symbols
        surviving_modules.append(module)
    if "!" not in target:
        result.modules = surviving_modules
    result.removed_targets.append(target)
    return sorted(removed_at, key=list(EvidenceLevel).index)
