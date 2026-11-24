import ast
import io
from dataclasses import dataclass
from typing import Protocol

from bandit.core import meta_ast
from bandit.core import metrics
from bandit.core import node_visitor
from bandit.core import test_set
from bandit.core import config as bandit_config


@dataclass(frozen=True)
class ScanFinding:
    test_id: str
    line: int
    name: str


class ScanBackend(Protocol):
    def scan(self, source: str) -> tuple[ScanFinding, ...]:
        ...


class BanditScanBackend:
    def __init__(self) -> None:
        self._config = bandit_config.BanditConfig()
        self._test_set = test_set.BanditTestSet(self._config)

    def scan(self, source: str) -> tuple[ScanFinding, ...]:
        ast.parse(source)
        data = source.encode("utf-8")
        visitor = node_visitor.BanditNodeVisitor(
            "<semantic-mutation>",
            io.BytesIO(data),
            meta_ast.BanditMetaAst(),
            self._test_set,
            False,
            {},
            metrics.Metrics(),
        )
        visitor.process(data)
        return tuple(
            ScanFinding(
                test_id=result.test_id,
                line=result.lineno,
                name=result.test,
            )
            for result in visitor.tester.results
        )


class ShadowingScanBackend:
    """Deterministic test backend with an injected alias-shadowing defect."""

    def __init__(self) -> None:
        self._inner = BanditScanBackend()

    def scan(self, source: str) -> tuple[ScanFinding, ...]:
        tree = ast.parse(source)
        findings = list(self._inner.scan(source))
        shadowed_imports = _shadowed_imports(tree)
        return tuple(
            finding
            for finding in findings
            if not _is_shadowed_finding(tree, finding, shadowed_imports)
        )


def _shadowed_imports(tree: ast.AST) -> set[str]:
    imported: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = node.lineno

    shadowed = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in imported:
                if node.lineno > imported[target.id]:
                    shadowed.add(target.id)
    return shadowed


def _is_shadowed_finding(
    tree: ast.AST,
    finding: ScanFinding,
    shadowed_imports: set[str],
) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno != finding.line:
            continue
        func = node.func
        names = set()
        if isinstance(func, ast.Name):
            names.add(func.id)
        elif isinstance(func, ast.Attribute):
            names.add(func.attr)
            if isinstance(func.value, ast.Name):
                names.add(func.value.id)
        if names.intersection(shadowed_imports):
            return True
    return False
