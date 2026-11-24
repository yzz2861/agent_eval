from __future__ import annotations

import ast
import builtins
import copy
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = 1
CONFIG_NODE = "node:policy-config"


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"Object of type {type(value)!r} is not JSON serializable")


def stable_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Rule:
    callee: str
    rule_id: str
    message: str = ""
    severity: str = "HIGH"
    confidence: str = "HIGH"
    sanitizer_can_mitigate: bool = False
    require_keywords: tuple[tuple[str, Any], ...] = ()

    def matches_keywords(self, keywords: Mapping[str, Any]) -> bool:
        return all(keywords.get(key) == expected for key, expected in self.require_keywords)

    def to_dict(self) -> dict[str, Any]:
        return {
            "callee": self.callee,
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity,
            "confidence": self.confidence,
            "sanitizer_can_mitigate": self.sanitizer_can_mitigate,
            "require_keywords": [list(item) for item in self.require_keywords],
        }


DEFAULT_RULES = (
    Rule("eval", "B307", "Use of eval or an eval-like library call"),
    Rule("exec", "B102", "Use of exec or an exec-like library call"),
    Rule("os.system", "B605", "os.system call permits shell command injection"),
    Rule(
        "subprocess.run",
        "B602",
        "subprocess call with shell=True permits shell injection",
        require_keywords=(("shell", True),),
    ),
)

DEFAULT_SANITIZERS = frozenset(
    {"html.escape", "shlex.quote", "markupsafe.escape", "markupsafe.Markup.escape"}
)


@dataclass(frozen=True)
class Policy:
    version: str = "incremental-library-policy/v1"
    rules: tuple[Rule, ...] = DEFAULT_RULES
    sanitizers: frozenset[str] = DEFAULT_SANITIZERS
    analyzer_version: int = 1
    config_hash: str = ""

    @classmethod
    def coerce(
        cls,
        policy: "Policy | Mapping[str, Any] | None" = None,
        *,
        version: str | None = None,
        rules: Any = None,
        sanitizers: Any = None,
        config_hash: str = "",
    ) -> "Policy":
        if isinstance(policy, Policy):
            result = policy
        elif isinstance(policy, Mapping):
            result = cls.from_dict(policy)
        elif policy is None:
            result = cls()
        else:
            raise TypeError("policy must be a Policy, mapping, or None")

        if version is not None:
            result = replace(result, version=str(version))
        if rules is not None:
            result = replace(result, rules=_normalize_rules(rules))
        if sanitizers is not None:
            result = replace(result, sanitizers=frozenset(sanitizers))
        if config_hash:
            result = replace(result, config_hash=config_hash)
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Policy":
        return cls(
            version=str(data.get("version", cls.version)),
            rules=_normalize_rules(data.get("rules", DEFAULT_RULES)),
            sanitizers=frozenset(data.get("sanitizers", DEFAULT_SANITIZERS)),
            analyzer_version=int(data.get("analyzer_version", 1)),
            config_hash=str(data.get("config_hash", "")),
        )

    def fingerprint(self) -> str:
        material = {
            "version": self.version,
            "analyzer_version": self.analyzer_version,
            "config_hash": self.config_hash,
            "sanitizers": sorted(self.sanitizers),
            "rules": [rule.to_dict() for rule in sorted(self.rules, key=lambda item: (item.callee, item.rule_id))],
        }
        return stable_hash(material)

    def match(self, callee: str | None, keywords: Mapping[str, Any]) -> Rule | None:
        if not callee:
            return None
        for rule in self.rules:
            if rule.callee == callee and rule.matches_keywords(keywords):
                return rule
        return None

    def rule_by_id(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None


def _normalize_rules(rules: Any) -> tuple[Rule, ...]:
    if isinstance(rules, Mapping):
        normalized = []
        for callee, spec in rules.items():
            if isinstance(spec, Rule):
                normalized.append(spec)
            elif isinstance(spec, str):
                normalized.append(Rule(str(callee), spec))
            elif isinstance(spec, Mapping):
                normalized.append(
                    Rule(
                        callee=str(spec.get("callee", callee)),
                        rule_id=str(spec.get("rule_id", spec.get("id", "LIB000"))),
                        message=str(spec.get("message", "")),
                        severity=str(spec.get("severity", "HIGH")),
                        confidence=str(spec.get("confidence", "HIGH")),
                        sanitizer_can_mitigate=bool(spec.get("sanitizer_can_mitigate", False)),
                        require_keywords=tuple(
                            sorted((spec.get("require_keywords") or {}).items())
                        ),
                    )
                )
            else:
                raise TypeError(f"unsupported rule spec for {callee}")
        return tuple(normalized)
    if isinstance(rules, (list, tuple, frozenset)):
        normalized = []
        for item in rules:
            if isinstance(item, Rule):
                normalized.append(item)
            elif isinstance(item, Mapping):
                callee = item.get("callee")
                if not callee:
                    raise ValueError("rule mapping requires callee")
                normalized.extend(_normalize_rules({callee: item}))
            else:
                raise TypeError("rule entries must be Rule or mapping")
        return tuple(normalized)
    raise TypeError("rules must be a mapping or sequence")


@dataclass(frozen=True)
class Policy:
    version: str = "incremental-library-policy/v1"
    rules: tuple[Rule, ...] = DEFAULT_RULES
    sanitizers: frozenset[str] = DEFAULT_SANITIZERS
    analyzer_version: int = 1
    config_hash: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Policy":
        rules = data.get("rules", DEFAULT_RULES)
        sanitizers = data.get("sanitizers", DEFAULT_SANITIZERS)
        return cls(
            version=str(data.get("version", cls.version)),
            rules=_normalize_rules(rules),
            sanitizers=frozenset(sanitizers),
            analyzer_version=int(data.get("analyzer_version", cls.analyzer_version)),
            config_hash=str(data.get("config_hash", "")),
        )

    def with_config_hash(self, config_hash: str) -> "Policy":
        return replace(self, config_hash=config_hash)

    def fingerprint(self) -> str:
        material = {
            "version": self.version,
            "analyzer_version": self.analyzer_version,
            "config_hash": self.config_hash,
            "sanitizers": sorted(self.sanitizers),
            "rules": [rule.to_dict() for rule in sorted(self.rules, key=lambda r: (r.callee, r.rule_id))],
        }
        return stable_hash(material)

    def match(self, callee: str | None, keywords: Mapping[str, Any] | None = None) -> Rule | None:
        if not callee:
            return None
        keywords = keywords or {}
        for rule in self.rules:
            if rule.callee == callee and rule.matches_keywords(keywords):
                return rule
        return None

    def rule_by_id(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None


def coerce_policy(
    policy: Any = None,
    *,
    policy_version: str | None = None,
    rules: Any = None,
    sanitizers: Any = None,
    config_hash: str = "",
) -> Policy:
    if policy is None:
        result = Policy()
    elif isinstance(policy, Policy):
        result = policy
    elif isinstance(policy, Mapping):
        result = Policy.from_dict(policy)
    else:
        raise TypeError("policy must be a Policy, mapping, or None")

    if policy_version is not None:
        result = replace(result, version=str(policy_version))
    if rules is not None:
        result = replace(result, rules=_normalize_rules(rules))
    if sanitizers is not None:
        result = replace(result, sanitizers=frozenset(sanitizers))
    if config_hash:
        result = result.with_config_hash(config_hash)
    return result


def hash_config(
    config: Any = None,
    config_path: str | os.PathLike[str] | None = None,
    config_hash: str | None = None,
) -> str:
    if config_hash is not None:
        return hashlib.sha256(str(config_hash).encode("utf-8")).hexdigest()
    if config_path is not None:
        return hashlib.sha256(Path(config_path).read_bytes()).hexdigest()
    if config is not None:
        if isinstance(config, (bytes, bytearray)):
            return hashlib.sha256(bytes(config)).hexdigest()
        if isinstance(config, str):
            return hashlib.sha256(config.encode("utf-8")).hexdigest()
        return stable_hash(config)
    return ""


SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
CONFIDENCE_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule_id: str = ""
    message: str = ""
    column: int = 0
    severity: str = "HIGH"
    confidence: str = "HIGH"
    symbol: str = ""
    test_id: str = ""
    source: str = "library"
    via: tuple[str, ...] = ()
    origins: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = field(default=(), compare=False, hash=False)

    def __post_init__(self) -> None:
        if not self.test_id:
            object.__setattr__(self, "test_id", self.rule_id)

    @property
    def key(self) -> tuple[Any, ...]:
        return (
            self.source,
            self.file,
            self.line,
            self.column,
            self.rule_id,
            self.test_id,
            self.message,
            self.symbol,
            self.severity,
            self.confidence,
            self.via,
            self.origins,
        )

    def to_dict(self) -> dict[str, Any]:
        data = {key: value for key, value in self.__dict__.items()}
        for key in ("via", "origins", "depends_on"):
            data[key] = list(data[key])
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Finding":
        values = dict(data)
        for key in ("via", "origins", "depends_on"):
            values[key] = tuple(values.get(key) or ())
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{key: value for key, value in values.items() if key in known})


class ScanCounter:
    """Deterministic per-scan visitor counter."""

    def __init__(self) -> None:
        self.scan_count = 0
        self.total_file_visits = 0
        self.reset()

    def reset(self) -> None:
        self.file_visits = 0
        self.stat_calls = 0
        self.source_reads = 0
        self.bandit_visits = 0
        self.visited_files: list[str] = []

    def begin_scan(self) -> None:
        self.reset()
        self.scan_count += 1

    def visit(self, path: str) -> None:
        self.file_visits += 1
        self.total_file_visits += 1
        self.visited_files.append(path)

    def record_stat(self, path: str | None = None) -> None:
        self.stat_calls += 1

    def record_source_read(self, path: str | None = None) -> None:
        self.source_reads += 1

    def visit_bandit(self, path: str | None = None) -> None:
        self.bandit_visits += 1

    def snapshot(self) -> dict[str, Any]:
        return {
            "scan_count": self.scan_count,
            "file_visits": self.file_visits,
            "stat_calls": self.stat_calls,
            "source_reads": self.source_reads,
            "bandit_visits": self.bandit_visits,
            "visited_files": list(self.visited_files),
        }


class DependencyGraph:
    """Small JSON-friendly directed graph.

    An edge (source, target, kind) means source depends on target.
    """

    def __init__(
        self,
        nodes: Mapping[str, Mapping[str, Any]] | None = None,
        edges: list[tuple[str, str, str]] | set[tuple[str, str, str]] | None = None,
    ) -> None:
        self.nodes: dict[str, dict[str, Any]] = {
            str(key): dict(value) for key, value in (nodes or {}).items()
        }
        self.edges: set[tuple[str, str, str]] = {
            (str(source), str(target), str(kind)) for source, target, kind in (edges or set())
        }

    def add_node(self, node_id: str, **attrs: Any) -> None:
        self.nodes.setdefault(node_id, {}).update(attrs)

    def add_edge(self, source: str, target: str, kind: str = "depends") -> None:
        self.add_node(source)
        self.add_node(target)
        self.edges.add((source, target, kind))

    def remove_node(self, node_id: str) -> None:
        self.nodes.pop(node_id, None)
        self.edges = {
            edge
            for edge in self.edges
            if edge[0] != node_id and edge[1] != node_id
        }

    def reverse_closure(self, seeds: Iterable[str]) -> set[str]:
        pending = list(dict.fromkeys(seeds))
        seen: set[str] = set()
        while pending:
            node_id = pending.pop()
            if node_id in seen:
                continue
            seen.add(node_id)
            for source, target, _kind in self.edges:
                if target == node_id and source not in seen:
                    pending.append(source)
        return seen

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": {key: self.nodes[key] for key in sorted(self.nodes)},
            "edges": sorted(self.edges),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "DependencyGraph":
        if not data:
            return cls()
        nodes = data.get("nodes") or {}
        raw_edges = data.get("edges") or []
        if not isinstance(nodes, Mapping):
            raise ValueError("graph nodes must be an object")
        edges = []
        for edge in raw_edges:
            if not isinstance(edge, (list, tuple)) or len(edge) != 3:
                raise ValueError("graph edges must be [source, target, kind]")
            edges.append((edge[0], edge[1], edge[2]))
        return cls(nodes=nodes, edges=edges)


class JsonCacheStore:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)

    def load(self) -> tuple[dict[str, Any] | None, bool, str | None, str | None]:
        if not self.path.exists():
            return None, False, None, None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("cache root must be an object")
            if data.get("schema_version") != SCHEMA_VERSION:
                raise ValueError("unsupported cache schema")
            DependencyGraph.from_dict(data.get("graph"))
            if not isinstance(data.get("files", {}), Mapping):
                raise ValueError("cache files must be an object")
            return data, False, None, None
        except Exception as exc:
            backup = self.quarantine()
            return None, True, f"{type(exc).__name__}: {exc}", backup

    def quarantine(self) -> str | None:
        backup = self.path.with_name(self.path.name + ".corrupt")
        try:
            os.replace(self.path, backup)
            return str(backup)
        except OSError:
            return None

    def save(self, data: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=self.path.parent,
            text=True,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, sort_keys=True, indent=2, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.path)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    analyzed_files: tuple[str, ...] = ()
    affected_files: tuple[str, ...] = ()
    cached_files: tuple[str, ...] = ()
    deleted_files: tuple[str, ...] = ()
    full_scan: bool = False
    recovered: bool = False
    recovery_reason: str | None = None
    corrupt_cache: str | None = None
    policy_changed: bool = False
    cache_path: str | None = None
    counter: dict[str, Any] = field(default_factory=dict)
    policy_fingerprint: str = ""

    @property
    def finding_set(self) -> set[Finding]:
        return set(self.findings)

    def finding_keys(self) -> set[tuple[Any, ...]]:
        return {finding.key for finding in self.findings}

    def to_dicts(self) -> list[dict[str, Any]]:
        return [finding.to_dict() for finding in self.findings]


SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        "build",
        "dist",
    }
)


def discover_python_files(targets: str | os.PathLike[str] | Iterable[str | os.PathLike[str]]) -> list[Path]:
    if isinstance(targets, (str, os.PathLike)):
        target_values = [targets]
    else:
        target_values = list(targets)

    paths: set[Path] = set()
    for target_value in target_values:
        target = Path(target_value)
        if target.is_dir():
            for root, directories, files in os.walk(target):
                directories[:] = sorted(
                    directory
                    for directory in directories
                    if directory not in SKIP_DIRECTORIES and not directory.startswith(".")
                )
                for filename in sorted(files):
                    if filename.endswith(".py"):
                        paths.add((Path(root) / filename).resolve())
        elif target.exists():
            paths.add(target.resolve())
    return sorted(paths, key=lambda path: str(path))


BUILTIN_NAMES = frozenset(
    {
        "abs", "all", "any", "ascii", "bin", "bool", "breakpoint", "bytearray",
        "bytes", "callable", "chr", "classmethod", "compile", "complex",
        "delattr", "dict", "dir", "divmod", "enumerate", "eval", "exec",
        "filter", "float", "format", "frozenset", "getattr", "globals",
        "hasattr", "hash", "help", "hex", "id", "input", "int", "isinstance",
        "issubclass", "iter", "len", "list", "locals", "map", "max",
        "memoryview", "min", "next", "object", "oct", "open", "ord", "pow",
        "print", "property", "range", "repr", "reversed", "round", "set",
        "setattr", "slice", "sorted", "staticmethod", "str", "sum", "super",
        "tuple", "type", "vars", "zip", "__import__",
    }
)


class PythonFileAnalyzer(ast.NodeVisitor):
    """Collect imports, calls, and lightweight function summaries."""

    def __init__(self, module_name: str, package_name: str = "") -> None:
        self.module_name = module_name
        self.package_name = package_name
        self.imports: dict[str, str] = {}
        self.functions: dict[str, dict[str, Any]] = {}
        self._qualifier: list[str] = []
        self._class_stack: list[str] = []
        self._function_stack: list[str] = []
        self._self_scopes: list[dict[str, str]] = []

    def analyze(self, source: bytes | str) -> dict[str, Any]:
        tree = ast.parse(source)
        module_id = f"{self.module_name}.<module>"
        self.functions[module_id] = self._new_function(
            module_id, "<module>", "<module>", 0, False
        )
        self._function_stack.append(module_id)
        self.generic_visit(tree)
        self._function_stack.pop()
        return {
            "module": self.module_name,
            "package": self.package_name,
            "imports": dict(sorted(self.imports.items())),
            "functions": self.functions,
        }

    def _new_function(
        self,
        function_id: str,
        name: str,
        qualname: str,
        lineno: int,
        is_async: bool,
    ) -> dict[str, Any]:
        return {
            "id": function_id,
            "name": name,
            "qualname": qualname,
            "line": lineno,
            "is_async": is_async,
            "calls": [],
            "return_callees": [],
            "dependencies": [],
            "is_sanitizer": False,
            "is_dangerous": False,
            "origins": [],
            "labels": [],
            "summary_hash": "",
        }

    @property
    def _current_function(self) -> str:
        return self._function_stack[-1]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self._qualifier.append(node.name)
        self.generic_visit(node)
        self._qualifier.pop()
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, True)

    def _visit_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool
    ) -> None:
        qualname = ".".join(self._qualifier + [node.name])
        function_id = f"{self.module_name}.{qualname}"
        self.functions[function_id] = self._new_function(
            function_id, node.name, qualname, node.lineno, is_async
        )
        self._function_stack.append(function_id)
        self._qualifier.append(node.name)

        scope: dict[str, str] = {}
        if self._class_stack and node.args.args:
            first_arg = node.args.args[0].arg
            if first_arg in {"self", "cls"}:
                class_id = self.module_name + "." + ".".join(self._class_stack)
                scope[first_arg] = class_id
        self._self_scopes.append(scope)

        self.generic_visit(node)

        self._self_scopes.pop()
        self._qualifier.pop()
        self._function_stack.pop()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.imports[alias.asname] = alias.name
            else:
                self.imports[alias.name.split(".", 1)[0]] = alias.name.split(".", 1)[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = self._relative_base(node)
        for alias in node.names:
            if alias.name == "*":
                continue
            target = f"{base}.{alias.name}" if base else alias.name
            self.imports[alias.asname or alias.name] = target
        self.generic_visit(node)

    def _relative_base(self, node: ast.ImportFrom) -> str:
        parts = self.package_name.split(".") if self.package_name else []
        if node.level:
            remove = node.level - 1
            if remove:
                parts = parts[: max(0, len(parts) - remove)]
        if node.module:
            parts.extend(node.module.split("."))
        return ".".join(parts)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            current = self.functions[self._current_function]
            for subnode in ast.walk(node.value):
                if isinstance(subnode, ast.Call):
                    callee = self.resolve(subnode.func)
                    if callee:
                        current["return_callees"].append(callee)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        current = self.functions[self._current_function]
        callee = self.resolve(node.func)
        argument_callees: list[str] = []
        values = list(node.args) + [keyword.value for keyword in node.keywords]
        for value in values:
            for subnode in ast.walk(value):
                if isinstance(subnode, ast.Call):
                    argument_callee = self.resolve(subnode.func)
                    if argument_callee:
                        argument_callees.append(argument_callee)
        current["calls"].append(
            {
                "line": node.lineno,
                "column": node.col_offset,
                "expression": ast.unparse(node.func),
                "callee": callee,
                "keywords": self._keyword_values(node.keywords),
                "argument_callees": sorted(set(argument_callees)),
            }
        )
        self.generic_visit(node)

    @staticmethod
    def _keyword_values(keywords: list[ast.keyword]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for keyword in keywords:
            if keyword.arg is None:
                continue
            try:
                result[keyword.arg] = ast.literal_eval(keyword.value)
            except (ValueError, SyntaxError):
                result[keyword.arg] = "<expression>"
        return result

    def resolve(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Name):
            return self.resolve_name(node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            return self.resolve(node.func)
        return None

    def resolve_name(self, name: str) -> str:
        if name in self.imports:
            return self.imports[name]
        for scope in reversed(self._self_scopes):
            if name in scope:
                return scope[name]
        if name in BUILTIN_NAMES:
            return name
        return f"{self.module_name}.{name}"


def _empty_cache(fingerprint: str, policy: "Policy | None" = None) -> dict[str, Any]:
    policy_value = policy or Policy()
    return {
        "schema_version": SCHEMA_VERSION,
        "policy_fingerprint": fingerprint,
        "policy_version": policy_value.version,
        "config_hash": policy_value.config_hash,
        "files": {},
        "graph": DependencyGraph().to_dict(),
    }


class IncrementalScanSession:
    """Incremental library-call scanner with an atomic JSON dependency cache."""

    def __init__(
        self,
        cache_path: "str | os.PathLike[str] | None" = None,
        root: "str | os.PathLike[str] | None" = None,
        policy: "Policy | Mapping[str, Any] | None" = None,
        *,
        policy_version: str | None = None,
        rules: Any = None,
        sanitizers: Any = None,
        config: Any = None,
        config_path: "str | os.PathLike[str] | None" = None,
        config_hash: str | None = None,
        counter: ScanCounter | None = None,
        cache_file: "str | os.PathLike[str] | None" = None,
        project_root: "str | os.PathLike[str] | None" = None,
        base_dir: "str | os.PathLike[str] | None" = None,
        targets: Any = None,
        trust_stat: bool = True,
        run_bandit: bool = False,
        bandit_config: Any = None,
        bandit_profile: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        selected_cache = cache_path or cache_file or kwargs.get("cache")
        if selected_cache == ":memory:":
            selected_cache = None
        self.cache_path = Path(selected_cache).resolve() if selected_cache else None
        selected_root = root or project_root or base_dir or kwargs.get("workdir")
        self.root = Path(selected_root).resolve() if selected_root else None
        self.targets = targets
        self.trust_stat = trust_stat
        self.run_bandit = run_bandit
        self.bandit_config = bandit_config
        self.bandit_profile = dict(bandit_profile or {})
        self.config_source = config
        self.config_path_value = (
            Path(config_path).resolve() if config_path is not None else None
        )
        self.explicit_config_hash = config_hash
        self.config_hash = hash_config(config, config_path, config_hash)
        self.policy = coerce_policy(
            policy,
            policy_version=policy_version,
            rules=rules,
            sanitizers=sanitizers,
            config_hash=self.config_hash,
        )
        self.counter = counter or ScanCounter()
        self.store = JsonCacheStore(self.cache_path) if self.cache_path else None
        self._cache: dict[str, Any] | None = None
        self.graph = DependencyGraph()
        self.last_result: ScanResult | None = None
        self.last_recovery: tuple[bool, str | None, str | None] = (False, None, None)

    def scan(
        self,
        targets: Any = None,
        *,
        force: bool = False,
        full_scan: bool = False,
    ) -> ScanResult:
        self._call_counter("begin_scan")
        current_config_hash = self._current_config_hash()
        if current_config_hash != self.config_hash:
            self.config_hash = current_config_hash
            self.policy = coerce_policy(
                self.policy, config_hash=current_config_hash
            )
        target_values = self._target_values(targets)
        files = discover_python_files(target_values)
        self._ensure_root(target_values, files)
        current_files = {self.relative_path(path): path for path in files}

        data, recovered, recovery_reason, corrupt_cache = self._load_cache()
        fingerprint = self.policy.fingerprint()
        policy_changed = data.get("policy_fingerprint") != fingerprint
        if policy_changed:
            data["policy_fingerprint"] = fingerprint
            data["policy_version"] = self.policy.version
            data["config_hash"] = self.policy.config_hash

        old_graph = DependencyGraph.from_dict(data.get("graph"))
        self.graph = old_graph
        source_states = self._source_states(current_files, data)
        changed_files = {
            relative
            for relative, state in source_states.items()
            if state["changed"]
        }
        deleted_files = sorted(
            relative
            for relative in data.get("files", {})
            if relative not in current_files
        )
        affected_files = self._affected_files(
            current_files=current_files,
            data=data,
            graph=old_graph,
            changed_files=changed_files,
            deleted_files=deleted_files,
            force=force or full_scan,
            policy_changed=policy_changed,
            recovered=recovered,
        )

        analyzed: dict[str, dict[str, Any]] = {}
        for relative in sorted(affected_files):
            path = current_files[relative]
            analyzed[relative] = self._analyze_file(
                relative, path, source_states[relative].get("bytes")
            )

        new_data, new_graph = self._build_cache(
            data=data,
            current_files=current_files,
            source_states=source_states,
            affected_files=affected_files,
            deleted_files=deleted_files,
            analyzed=analyzed,
            fingerprint=fingerprint,
        )
        findings = tuple(
            sorted(
                {
                    Finding.from_dict(finding)
                    for record in new_data["files"].values()
                    for finding in record.get("findings", [])
                },
                key=lambda finding: finding.key,
            )
        )
        result = ScanResult(
            findings=findings,
            analyzed_files=tuple(sorted(affected_files)),
            affected_files=tuple(sorted(affected_files | set(deleted_files))),
            cached_files=tuple(sorted(set(current_files) - affected_files)),
            deleted_files=tuple(deleted_files),
            full_scan=len(affected_files) == len(current_files),
            recovered=recovered,
            recovery_reason=recovery_reason,
            corrupt_cache=corrupt_cache,
            policy_changed=policy_changed,
            cache_path=str(self.cache_path) if self.cache_path else None,
            counter=self.counter.snapshot() if hasattr(self.counter, "snapshot") else {},
            policy_fingerprint=fingerprint,
        )

        if self.store is not None:
            self.store.save(new_data)
        self._cache = new_data
        self.graph = new_graph
        self.last_result = result
        self.last_recovery = (recovered, recovery_reason, corrupt_cache)
        return result

    def _target_values(self, targets: Any) -> list[Any]:
        selected = targets if targets is not None else self.targets
        if selected is None:
            if self.root is not None:
                return [self.root]
            return ["."]
        if isinstance(selected, (str, os.PathLike)):
            return [selected]
        return list(selected)

    def _current_config_hash(self) -> str:
        if self.explicit_config_hash is not None:
            return self.config_hash
        return hash_config(self.config_source, self.config_path_value)

    def _ensure_root(self, target_values: list[Any], files: list[Path]) -> None:
        if self.root is not None:
            return
        directories = [Path(value).resolve() for value in target_values if Path(value).is_dir()]
        if directories:
            roots = directories
        else:
            roots = [path.parent for path in files]
        if not roots:
            self.root = Path.cwd().resolve()
        elif len(roots) == 1:
            self.root = roots[0]
        else:
            self.root = Path(os.path.commonpath([str(root) for root in roots])).resolve()

    def relative_path(self, path: str | os.PathLike[str] | Path) -> str:
        path = Path(path).resolve()
        if self.root is None:
            return path.as_posix()
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def _call_counter(self, method: str, *args: Any) -> None:
        callback = getattr(self.counter, method, None)
        if callable(callback):
            callback(*args)

    def _load_cache(self) -> tuple[dict[str, Any], bool, str | None, str | None]:
        if self.store is not None:
            data, recovered, reason, backup = self.store.load()
            if data is not None:
                return data, recovered, reason, backup
            return _empty_cache(self.policy.fingerprint(), self.policy), recovered, reason, backup
        if self._cache is not None:
            return copy.deepcopy(self._cache), False, None, None
        return _empty_cache(self.policy.fingerprint(), self.policy), False, None, None

    def _source_states(
        self, current_files: Mapping[str, Path], data: Mapping[str, Any]
    ) -> dict[str, dict[str, Any]]:
        states: dict[str, dict[str, Any]] = {}
        old_files = data.get("files", {})
        for relative, path in current_files.items():
            self._call_counter("record_stat", relative)
            stat_result = path.stat()
            old_record = old_files.get(relative) or {}
            source_hash = old_record.get("source_hash")
            unchanged_stat = (
                self.trust_stat
                and source_hash
                and old_record.get("mtime_ns") == stat_result.st_mtime_ns
                and old_record.get("size") == stat_result.st_size
            )
            if unchanged_stat:
                states[relative] = {
                    "hash": source_hash,
                    "mtime_ns": stat_result.st_mtime_ns,
                    "size": stat_result.st_size,
                    "changed": False,
                    "bytes": None,
                }
                continue
            source = path.read_bytes()
            self._call_counter("record_source_read", relative)
            source_hash = hashlib.sha256(source).hexdigest()
            states[relative] = {
                "hash": source_hash,
                "mtime_ns": stat_result.st_mtime_ns,
                "size": stat_result.st_size,
                "changed": source_hash != old_record.get("source_hash"),
                "bytes": source,
            }
        return states

    def _affected_files(
        self,
        *,
        current_files: Mapping[str, Path],
        data: Mapping[str, Any],
        graph: DependencyGraph,
        changed_files: set[str],
        deleted_files: list[str],
        force: bool,
        policy_changed: bool,
        recovered: bool,
    ) -> set[str]:
        if force or policy_changed or recovered or not data.get("files"):
            return set(current_files)
        seeds = [f"file:{relative}" for relative in sorted(changed_files | set(deleted_files))]
        closure = graph.reverse_closure(seeds)
        affected = set(changed_files)
        for node_id in closure:
            attrs = graph.nodes.get(node_id, {})
            candidate = attrs.get("file")
            if candidate in current_files:
                affected.add(str(candidate))
            elif node_id.startswith("file:"):
                candidate = node_id[5:]
                if candidate in current_files:
                    affected.add(str(candidate))
        return affected


    def _module_names(self, relative: str) -> tuple[str, str]:
        without_suffix = relative[:-3] if relative.endswith(".py") else relative
        parts = [part for part in without_suffix.split("/") if part]
        is_init = bool(parts and parts[-1] == "__init__")
        if is_init:
            parts = parts[:-1]
        module_name = ".".join(parts)
        if is_init:
            package_name = module_name
        else:
            package_name = module_name.rpartition(".")[0]
        return module_name, package_name

    def _analyze_file(
        self, relative: str, path: Path, source: bytes | None
    ) -> dict[str, Any]:
        self._call_counter("visit", relative)
        if source is None:
            source = path.read_bytes()
            self._call_counter("record_source_read", relative)
        module_name, package_name = self._module_names(relative)
        file_data = PythonFileAnalyzer(module_name, package_name).analyze(source)
        bandit_findings: list[dict[str, Any]] = []
        if self.run_bandit:
            self._call_counter("visit_bandit", relative)
            bandit_findings = [
                finding.to_dict()
                for finding in self._run_bandit_for_file(relative, path)
            ]
        return {"file_data": file_data, "bandit_findings": bandit_findings}

    def _run_bandit_for_file(self, relative: str, path: Path) -> list[Finding]:
        runner = getattr(self, "_bandit_runner", None)
        if runner is None:
            runner = BanditFileRunner(
                config=self.bandit_config, profile=self.bandit_profile
            )
            self._bandit_runner = runner
        issues = runner.scan_file(path)
        findings: list[Finding] = []
        for issue in issues:
            findings.append(
                Finding(
                    file=relative,
                    line=int(getattr(issue, "lineno", 1) or 1),
                    column=int(getattr(issue, "col_offset", 0) or 0),
                    rule_id=str(getattr(issue, "test_id", "") or "B000"),
                    message=str(getattr(issue, "text", "") or ""),
                    severity=str(getattr(issue, "severity", "MEDIUM") or "MEDIUM").upper(),
                    confidence=str(
                        getattr(issue, "confidence", "MEDIUM") or "MEDIUM"
                    ).upper(),
                    symbol=str(getattr(issue, "test", "") or ""),
                    test_id=str(getattr(issue, "test_id", "") or ""),
                    source="bandit",
                )
            )
        return findings

    def _remove_file_state(
        self, data: dict[str, Any], graph: DependencyGraph, relative: str
    ) -> None:
        data.get("files", {}).pop(relative, None)
        for node_id in list(graph.nodes):
            attrs = graph.nodes.get(node_id, {})
            if node_id == f"file:{relative}" or attrs.get("file") == relative:
                graph.remove_node(node_id)

    def _build_cache(
        self,
        *,
        data: dict[str, Any],
        current_files: Mapping[str, Path],
        source_states: Mapping[str, Mapping[str, Any]],
        affected_files: set[str],
        deleted_files: list[str],
        analyzed: Mapping[str, Mapping[str, Any]],
        fingerprint: str,
    ) -> tuple[dict[str, Any], DependencyGraph]:
        new_data = copy.deepcopy(data)
        new_data["schema_version"] = SCHEMA_VERSION
        new_data["policy_fingerprint"] = fingerprint
        new_data["policy_version"] = self.policy.version
        new_data["config_hash"] = self.policy.config_hash
        new_data.setdefault("files", {})
        new_graph = DependencyGraph.from_dict(new_data.get("graph"))
        new_graph.add_node(
            CONFIG_NODE,
            kind="policy",
            fingerprint=fingerprint,
            policy_version=self.policy.version,
            config_hash=self.policy.config_hash,
        )

        for relative in sorted(affected_files | set(deleted_files)):
            self._remove_file_state(new_data, new_graph, relative)

        for relative in sorted(affected_files):
            item = analyzed[relative]
            file_data = item["file_data"]
            state = source_states[relative]
            record = {
                "module": file_data.get("module", ""),
                "package": file_data.get("package", ""),
                "imports": file_data.get("imports", {}),
                "source_hash": state["hash"],
                "mtime_ns": state["mtime_ns"],
                "size": state["size"],
                "analyzer_version": self.policy.analyzer_version,
                "functions": file_data.get("functions", {}),
                "findings": list(item.get("bandit_findings", [])),
            }
            new_data["files"][relative] = record
            new_graph.add_node(
                f"file:{relative}",
                kind="source",
                file=relative,
                source_hash=record["source_hash"],
            )
            new_graph.add_edge(f"file:{relative}", CONFIG_NODE, "policy-config")

        for relative in current_files:
            if relative in affected_files or relative not in new_data["files"]:
                continue
            state = source_states[relative]
            record = new_data["files"][relative]
            record["mtime_ns"] = state["mtime_ns"]
            record["size"] = state["size"]
            if state.get("hash"):
                record["source_hash"] = state["hash"]

        function_file: dict[str, str] = {}
        all_functions: dict[str, dict[str, Any]] = {}
        for relative, record in new_data["files"].items():
            for function_id, function_record in record.get("functions", {}).items():
                function_file[function_id] = relative
                all_functions[function_id] = function_record

        for function_id, function_record in all_functions.items():
            dependencies = set()
            for call in function_record.get("calls", []):
                callee = call.get("callee")
                if callee in all_functions:
                    dependencies.add(callee)
            function_record["dependencies"] = sorted(dependencies)

        self._propagate_summaries(all_functions)

        for function_id, function_record in all_functions.items():
            function_record["summary_hash"] = stable_hash(
                {
                    "calls": function_record.get("calls", []),
                    "return_callees": function_record.get("return_callees", []),
                    "dependencies": function_record.get("dependencies", []),
                    "labels": function_record.get("labels", []),
                }
            )
            relative = function_file[function_id]
            function_node = f"func:{function_id}"
            new_graph.add_node(
                function_node,
                kind="function-summary",
                file=relative,
                summary_hash=function_record["summary_hash"],
                is_dangerous=function_record.get("is_dangerous", False),
                is_sanitizer=function_record.get("is_sanitizer", False),
            )
            new_graph.add_edge(function_node, f"file:{relative}", "source")
            new_graph.add_edge(function_node, CONFIG_NODE, "policy")
            for dependency in function_record.get("dependencies", []):
                new_graph.add_edge(function_node, f"func:{dependency}", "call")

        for relative in sorted(affected_files):
            record = new_data["files"][relative]
            findings = list(record.get("findings", []))
            for function_id, function_record in sorted(record["functions"].items()):
                for call in function_record.get("calls", []):
                    finding = self._finding_for_call(
                        relative,
                        function_id,
                        function_record,
                        call,
                        all_functions,
                    )
                    if finding is not None:
                        findings.append(finding.to_dict())
            record["findings"] = self._dedupe_finding_dicts(findings)

        new_data["graph"] = new_graph.to_dict()
        return new_data, new_graph

    def _propagate_summaries(
        self, functions: Mapping[str, dict[str, Any]]
    ) -> None:
        function_ids = sorted(functions)
        previous = {
            function_id: {
                "sanitizer": False,
                "dangerous": False,
                "origins": frozenset(),
            }
            for function_id in function_ids
        }
        for _iteration in range(max(1, len(function_ids) + 1)):
            following: dict[str, dict[str, Any]] = {}
            for function_id in function_ids:
                record = functions[function_id]
                sanitizer = any(
                    callee in self.policy.sanitizers
                    or (
                        callee in previous
                        and previous[callee]["sanitizer"]
                    )
                    for callee in record.get("return_callees", [])
                )
                origins: set[str] = set()
                for call in record.get("calls", []):
                    callee = call.get("callee") or ""
                    keywords = call.get("keywords") or {}
                    rule = self.policy.match(callee, keywords)
                    if rule is not None:
                        mitigated = False
                        if rule.sanitizer_can_mitigate:
                            mitigated = any(
                                self._callee_is_sanitizer(argument, previous)
                                or self._summary_is_sanitizer(argument, functions)
                                for argument in call.get("argument_callees", [])
                            )
                        if not mitigated:
                            origins.add(rule.rule_id)
                    for dependency in record.get("dependencies", []):
                        dependency_state = previous.get(dependency)
                        if dependency_state and dependency_state["dangerous"]:
                            origins.update(
                                dependency_state["origins"] or {"LIB001"}
                            )
                following[function_id] = {
                    "sanitizer": sanitizer,
                    "dangerous": bool(origins),
                    "origins": frozenset(origins),
                }
            if following == previous:
                previous = following
                break
            previous = following

        for function_id in function_ids:
            state = previous[function_id]
            record = functions[function_id]
            origins = sorted(state["origins"])
            record["is_sanitizer"] = bool(state["sanitizer"])
            record["is_dangerous"] = bool(state["dangerous"])
            record["origins"] = origins
            labels = []
            if state["sanitizer"]:
                labels.append("sanitizer")
            labels.extend(f"danger:{origin}" for origin in origins)
            record["labels"] = sorted(labels)

    def _callee_is_sanitizer(
        self, callee: str, state: Mapping[str, Mapping[str, Any]]
    ) -> bool:
        return callee in self.policy.sanitizers or bool(
            callee in state and state[callee].get("sanitizer")
        )

    def _summary_is_sanitizer(
        self, callee: str, functions: Mapping[str, dict[str, Any]]
    ) -> bool:
        summary = functions.get(callee)
        return bool(summary and summary.get("is_sanitizer"))

    def _finding_for_call(
        self,
        relative: str,
        function_id: str,
        function_record: Mapping[str, Any],
        call: Mapping[str, Any],
        all_functions: Mapping[str, dict[str, Any]],
    ) -> Finding | None:
        callee = str(call.get("callee") or "")
        keywords = call.get("keywords") or {}
        rule = self.policy.match(callee, keywords)
        expression = str(call.get("expression") or "")
        if rule is None and "." not in expression:
            rule = self.policy.match(expression, keywords)
        depends_on = sorted(
            {
                f"file:{relative}",
                CONFIG_NODE,
                f"func:{function_id}",
            }
        )

        if rule is not None:
            mitigated = False
            if rule.sanitizer_can_mitigate:
                mitigated = any(
                    argument in self.policy.sanitizers
                    or self._summary_is_sanitizer(argument, all_functions)
                    for argument in call.get("argument_callees", [])
                )
            if not mitigated:
                return Finding(
                    file=relative,
                    line=int(call.get("line", 1) or 1),
                    column=int(call.get("column", 0) or 0),
                    rule_id=rule.rule_id,
                    message=rule.message
                    or f"Dangerous library call {callee}",
                    severity=rule.severity,
                    confidence=rule.confidence,
                    symbol=callee,
                    test_id=rule.rule_id,
                    depends_on=tuple(depends_on),
                )

        summary = all_functions.get(callee)
        if summary is None or not summary.get("is_dangerous"):
            return None

        origins = tuple(summary.get("origins") or ("LIB001",))
        primary_rule = self._primary_origin_rule(origins)
        severity = primary_rule.severity if primary_rule else "HIGH"
        confidence = primary_rule.confidence if primary_rule else "MEDIUM"
        primary_id = primary_rule.rule_id if primary_rule else sorted(origins)[0]
        dependent_nodes = depends_on + [f"func:{callee}"]
        return Finding(
            file=relative,
            line=int(call.get("line", 1) or 1),
            column=int(call.get("column", 0) or 0),
            rule_id=primary_id,
            message=(
                f"Call reaches unsafe wrapper {callee}; "
                f"dangerous summary origins: {', '.join(sorted(origins))}"
            ),
            severity=severity,
            confidence=confidence,
            symbol=callee,
            test_id=primary_id,
            via=(callee,),
            origins=tuple(sorted(origins)),
            depends_on=tuple(sorted(set(dependent_nodes))),
        )

    def _primary_origin_rule(self, origins: tuple[str, ...]) -> Rule | None:
        rules = [self.policy.rule_by_id(origin) for origin in origins]
        valid_rules = [rule for rule in rules if rule is not None]
        if not valid_rules:
            return None
        return max(
            valid_rules,
            key=lambda rule: (
                SEVERITY_RANK.get(rule.severity.upper(), 0),
                CONFIDENCE_RANK.get(rule.confidence.upper(), 0),
            ),
        )

    def _dedupe_finding_dicts(
        self, findings: list[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        unique: dict[tuple[Any, ...], Finding] = {}
        for item in findings:
            finding = item if isinstance(item, Finding) else Finding.from_dict(item)
            unique[finding.key] = finding
        return [
            finding.to_dict()
            for finding in sorted(unique.values(), key=lambda item: item.key)
        ]


class BanditFileRunner:
    """Run stock Bandit on one file without changing the default CLI path."""

    def __init__(self, config: Any = None, profile: Mapping[str, Any] | None = None):
        self.config = config
        self.profile = dict(profile or {})
        self._bandit_config = None

    def scan_file(self, path: str | os.PathLike[str] | Path) -> list[Any]:
        from bandit.core import config as bandit_config
        from bandit.core import manager as bandit_manager

        if self._bandit_config is None:
            self._bandit_config = self.config or bandit_config.BanditConfig()
        manager = bandit_manager.BanditManager(
            self._bandit_config,
            "file",
            quiet=True,
            profile=self.profile,
        )
        manager.files_list = [os.fspath(path)]
        manager.run_tests()
        return list(manager.results)


def _empty_cache(fingerprint: str, policy: Policy | None = None) -> dict[str, Any]:
    policy = policy or Policy()
    return {
        "schema_version": SCHEMA_VERSION,
        "policy_fingerprint": fingerprint,
        "policy_version": policy.version,
        "config_hash": policy.config_hash,
        "files": {},
        "graph": DependencyGraph().to_dict(),
    }


def scan_full(targets: Any = None, **kwargs: Any) -> ScanResult:
    kwargs.setdefault("cache_path", None)
    session = IncrementalScanSession(**kwargs)
    return session.scan(targets, force=True)


BanditIncrementalSession = type(
    "BanditIncrementalSession",
    (IncrementalScanSession,),
    {
        "__init__": lambda self, *args, **kwargs: (
            kwargs.setdefault("run_bandit", True),
            IncrementalScanSession.__init__(self, *args, **kwargs),
        )[1],
        "__doc__": "Incremental session that also runs stock Bandit per affected file.",
    },
)

IncrementalScanner = IncrementalScanSession
IncrementalSession = IncrementalScanSession
ScanSession = IncrementalScanSession
IncrementalDependencySession = IncrementalScanSession
JsonDependencyCache = JsonCacheStore
ScanCache = JsonCacheStore
DependencyCache = JsonCacheStore


APPEND_MARKER = "ok"



# Public compatibility aliases

IncrementalScanSession.update = IncrementalScanSession.scan

IncrementalScanSession.run = IncrementalScanSession.scan

IncrementalScanSession.incremental_scan = IncrementalScanSession.scan

DeterministicCounter = ScanCounter

VisitCounter = ScanCounter

IncrementalCache = JsonCacheStore

create_session = IncrementalScanSession
