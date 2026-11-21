"""Approval validation for PE artifacts based on pefile static import data.

Feeds pefile's static import information (regular imports plus delay-load
imports) into a sign-off check. Each dependency is classified against the
policy of a declared purpose ("environment"):

- REQUIRED: statically linked third-party library the purpose mandates.
- RUNTIME_OPTIONAL: delay-loaded library the purpose allows to be chosen
  at runtime.
- IDENTITY_INCOMPLETE: ordinal-only imports whose symbol names cannot be
  resolved even with the supplied symbol directory.

Anything the policy cannot explain (unknown DLL, disallowed load kind,
unresolvable identity) is surfaced in the review view.
"""

from dataclasses import dataclass, field

import pefile

# Classification outcomes
REQUIRED = "required"
RUNTIME_OPTIONAL = "runtime_optional"
IDENTITY_INCOMPLETE = "identity_incomplete"
UNEXPLAINED = "unexplained"


@dataclass
class PurposePolicy:
    """Approval policy for one declared purpose (usage environment).

    required: DLL names approved as mandatory static imports.
    runtime_optional: DLL names approved as delay-loaded runtime choices.
    """

    name: str
    required: frozenset = frozenset()
    runtime_optional: frozenset = frozenset()

    def __post_init__(self):
        object.__setattr__(
            self, "required", frozenset(d.lower() for d in self.required)
        )
        object.__setattr__(
            self,
            "runtime_optional",
            frozenset(d.lower() for d in self.runtime_optional),
        )


@dataclass
class Symbol:
    name: str | None
    ordinal: int | None
    resolved_by: str | None = None  # "import-table" or "symbol-directory"


@dataclass
class Dependency:
    dll: str
    delay_loaded: bool
    symbols: list = field(default_factory=list)


@dataclass
class Finding:
    dependency: Dependency
    classification: str
    reason: str


def _normalize_dll(dll):
    if isinstance(dll, bytes):
        dll = dll.decode("utf-8", errors="replace")
    return dll.lower()


def extract_dependencies(pe, symbol_directory=None):
    """Pull static and delay-load dependencies out of a parsed pefile.PE.

    symbol_directory: optional ordlookup-style mapping
    {b"dllname.dll": {ordinal: b"SymbolName"}} used to give names to
    ordinal-only imports.
    """
    symbol_directory = symbol_directory or {}
    dependencies = []
    for attr, delay_loaded in (
        ("DIRECTORY_ENTRY_IMPORT", False),
        ("DIRECTORY_ENTRY_DELAY_IMPORT", True),
    ):
        for entry in getattr(pe, attr, []):
            dll = _normalize_dll(entry.dll)
            symbols = []
            for imp in entry.imports:
                if imp.name is not None:
                    symbols.append(
                        Symbol(
                            name=imp.name.decode("utf-8", errors="replace"),
                            ordinal=imp.ordinal,
                            resolved_by="import-table",
                        )
                    )
                    continue
                name = None
                resolved_by = None
                table = symbol_directory.get(dll.encode()) or symbol_directory.get(dll)
                if table and imp.ordinal in table:
                    raw = table[imp.ordinal]
                    name = raw.decode() if isinstance(raw, bytes) else raw
                    resolved_by = "symbol-directory"
                symbols.append(
                    Symbol(name=name, ordinal=imp.ordinal, resolved_by=resolved_by)
                )
            dependencies.append(
                Dependency(dll=dll, delay_loaded=delay_loaded, symbols=symbols)
            )
    return dependencies


def classify_dependency(dep, policy):
    """Classify one dependency against a purpose policy."""
    unnamed = [s for s in dep.symbols if s.name is None]
    if unnamed:
        ordinals = ", ".join(f"#{s.ordinal}" for s in unnamed)
        return Finding(
            dep,
            IDENTITY_INCOMPLETE,
            f"ordinal-only imports with unknown identity: {ordinals}",
        )
    if dep.delay_loaded:
        if dep.dll in policy.runtime_optional:
            return Finding(
                dep,
                RUNTIME_OPTIONAL,
                f"delay-loaded and allowed as runtime choice for '{policy.name}'",
            )
        return Finding(
            dep,
            UNEXPLAINED,
            f"delay-loaded library not in runtime-optional list for '{policy.name}'",
        )
    if dep.dll in policy.required:
        return Finding(
            dep,
            REQUIRED,
            f"static import mandated by '{policy.name}'",
        )
    return Finding(
        dep,
        UNEXPLAINED,
        f"static import not in required list for '{policy.name}'",
    )


def evaluate(pe, policy, symbol_directory=None):
    """Evaluate a PE against a purpose policy.

    Returns (findings, review_view). review_view holds every finding the
    approver must look at: identity-incomplete and unexplained entries.
    """
    findings = [
        classify_dependency(dep, policy)
        for dep in extract_dependencies(pe, symbol_directory)
    ]
    review_view = [
        f
        for f in findings
        if f.classification in (IDENTITY_INCOMPLETE, UNEXPLAINED)
    ]
    return findings, review_view


def evaluate_path(path, policy, symbol_directory=None):
    """Convenience wrapper: parse a PE file and evaluate it."""
    pe = pefile.PE(path)
    try:
        return evaluate(pe, policy, symbol_directory)
    finally:
        pe.close()


def render_report(pe_name, policy, findings, review_view):
    """Human-readable approval report."""
    lines = [f"Artifact: {pe_name}  Purpose: {policy.name}", "-" * 60]
    for f in findings:
        dep = f.dependency
        kind = "delay-load" if dep.delay_loaded else "static"
        syms = ", ".join(
            s.name if s.name is not None else f"ord#{s.ordinal}" for s in dep.symbols
        )
        lines.append(f"[{f.classification.upper():<19}] {dep.dll} ({kind}; {syms})")
        lines.append(f"{'':>23}{f.reason}")
    lines.append("-" * 60)
    if review_view:
        lines.append(f"REVIEW VIEW ({len(review_view)} item(s) need an approver):")
        for f in review_view:
            lines.append(f"  * {f.dependency.dll}: {f.reason}")
    else:
        lines.append("REVIEW VIEW: empty, artifact can be signed off.")
    return "\n".join(lines)
