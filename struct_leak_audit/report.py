"""Public entry point: parse C source and report structure leaks.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from pycparser import CParser

from .analyzer import AuditConfig
from .engine import AuditEngine
from .model import FunctionReport, Severity


@dataclass
class AuditResult:
    public_struct: str
    reports: list[FunctionReport] = field(default_factory=list)

    @property
    def verdict(self) -> Severity:
        if not self.reports:
            return Severity.SAFE
        return max(report.verdict for report in self.reports)

    def as_dict(self) -> dict:
        return {
            "public_struct": self.public_struct,
            "verdict": self.verdict.name,
            "functions": [report.as_dict() for report in self.reports],
        }


def _strip_comments(source: str) -> str:
    out = []
    i = 0
    n = len(source)
    state = "code"
    quote = ""
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch in (chr(39), chr(34)):
                quote = ch
                state = "string"
                out.append(ch)
                i += 1
            elif ch == "/" and nxt == "/":
                state = "line"
                i += 2
            elif ch == "/" and nxt == "*":
                state = "block"
                i += 2
            else:
                out.append(ch)
                i += 1
        elif state == "string":
            out.append(ch)
            if ch == chr(92) and i + 1 < n:
                out.append(source[i + 1])
                i += 2
                continue
            if ch == quote:
                state = "code"
            i += 1
        elif state == "line":
            if ch == chr(10):
                state = "code"
                out.append(ch)
            i += 1
        else:
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
            else:
                out.append(ch if ch == chr(10) else " ")
                i += 1
    return "".join(out)


def audit_source(source: str, config: AuditConfig, filename: str = "<snippet>") -> AuditResult:
    parser = CParser()
    ast = parser.parse(_strip_comments(source), filename=filename)
    reports = AuditEngine(ast, config).run()
    return AuditResult(public_struct=config.public_struct, reports=reports)


def audit_file(path: str | Path, config: AuditConfig) -> AuditResult:
    text = Path(path).read_text()
    return audit_source(text, config, filename=str(path))


def to_json(result: AuditResult) -> str:
    return json.dumps(result.as_dict(), indent=2, ensure_ascii=False)


def to_text(result: AuditResult) -> str:
    lines = [
        f"struct leak audit: {result.public_struct}",
        f"overall verdict: {result.verdict.name}",
        "",
    ]
    for report in result.reports:
        lines.append(f"function {report.name}  ({report.coord})  -> {report.verdict.name}")
        if not report.findings:
            lines.append("    no tracked construction or exit found")
        for finding in report.findings:
            lines.append(
                f"    [{finding.severity.name:6}] {finding.code} "
                f"@ {finding.coord} var={finding.variable or "-"}: {finding.message}"
            )
            if finding.source:
                lines.append(f"             source: {finding.source}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
