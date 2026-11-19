# SPDX-License-Identifier: Apache-2.0
"""Flow-sensitive taint engine for sensitive logging diagnostics.

Tracks values from explicitly configured sensitive sources through local
aliases, dictionary updates and trusted sanitizers up to structured logging
sinks. Analysis is intra-procedural; only data that can actually reach a log
call is reported.
"""

import ast


class Taint:
    """Abstract state of a value observed by the data-flow engine."""

    CLEAN = "clean"
    TAINTED = "tainted"
    UNKNOWN = "unknown"

    def __init__(self, state, origins=None, unknown_calls=None):
        self.state = state
        self.origins = list(origins or [])
        self.unknown_calls = list(unknown_calls or [])

    @classmethod
    def clean(cls):
        return cls(cls.CLEAN)

    @classmethod
    def tainted(cls, origins):
        return cls(cls.TAINTED, origins=list(origins))

    @classmethod
    def unknown(cls, unknown_calls=None):
        return cls(cls.UNKNOWN, unknown_calls=list(unknown_calls or []))

    @property
    def is_tainted(self):
        return self.state == self.TAINTED

    @property
    def is_unknown(self):
        return self.state == self.UNKNOWN

    def union(self, other):
        if other is None:
            return self
        if self.state == self.TAINTED and other.state == self.TAINTED:
            return Taint.tainted(_merge_origins(self.origins, other.origins))
        if self.state == other.state:
            calls = _merge_unknown(self.unknown_calls, other.unknown_calls)
            return Taint(self.state, origins=self.origins,
                         unknown_calls=calls)
        return Taint.unknown(_merge_unknown(self.unknown_calls,
                                            other.unknown_calls))


class Origin:
    """A sensitive field that contributed taint to a value."""

    def __init__(self, source, field, node):
        self.source = source
        self.field = field
        self.node = node

    @property
    def lineno(self):
        return getattr(self.node, "lineno", 0)

    def key(self):
        return self.source, self.field, self.lineno

    def __eq__(self, other):
        return isinstance(other, Origin) and self.key() == other.key()

    def __hash__(self):
        return hash(self.key())


def _merge_origins(left, right):
    merged = {}
    for origin in list(left) + list(right):
        merged[origin.key()] = origin
    return list(merged.values())


def _merge_unknown(left, right):
    merged = {}
    for call in list(left) + list(right):
        merged[(call["name"], call["lineno"])] = call
    return list(merged.values())


def _entry_name(entry):
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return entry.get("name", "")
    return ""


def _entry_fields(entry):
    if isinstance(entry, dict) and entry.get("fields"):
        return set(entry["fields"])
    return None


class NameMatcher:
    """Matches configured callables against AST call nodes."""

    def __init__(self, entries):
        self.entries = [e for e in entries or [] if _entry_name(e)]

    def match(self, node, aliases):
        qualified = _qualified_name(node, aliases)
        if not qualified:
            return None
        for entry in self.entries:
            name = _entry_name(entry)
            if qualified == name:
                return entry
            short = name.rsplit(".", 1)[-1]
            if qualified == short and not aliases.defines(short):
                return entry
            # Treat any receiver as a logger instance for configured
            # instance methods such as logging.Logger.error.
            if qualified.endswith("." + short) and "." in name:
                return entry
        return None

    def match_origin(self, node, aliases):
        entry = self.match(node, aliases)
        if entry is None:
            return None
        fields = _entry_fields(entry)
        field = _source_field(node, fields) if fields is not None else None
        return entry, field


def _source_field(node, fields):
    for keyword in node.keywords:
        if keyword.arg in fields:
            return keyword.arg
    if node.args:
        return sorted(fields)[0]
    return None


def _qualified_name(node, aliases):
    func = node.func if isinstance(node, ast.Call) else node
    if isinstance(func, ast.Name):
        return aliases.resolve(func.id)
    if isinstance(func, ast.Attribute):
        base = _attribute_base(func)
        if base is None:
            return func.attr
        return f"{aliases.resolve(base)}.{func.attr}"
    return None


def _attribute_base(node):
    current = node.value
    parts = []
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None

class ImportAliases:
    """Maps local import bindings back to qualified module names."""

    def __init__(self):
        self.modules = {}
        self.functions = {}

    def record_import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.modules[local] = alias.name

    def record_import_from(self, node):
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.functions[local] = f"{module}.{alias.name}"

    def resolve(self, name):
        if name in self.functions:
            return self.functions[name]
        if name in self.modules:
            return self.modules[name]
        return name

    def defines(self, name):
        return name in self.modules or name in self.functions


class SensitiveLogConfig:
    """Validated view over the plugin YAML configuration."""

    DEFAULT_SINKS = [
        "logging.Logger.debug",
        "logging.Logger.info",
        "logging.Logger.warning",
        "logging.Logger.error",
        "logging.Logger.exception",
        "logging.Logger.critical",
        "logging.Logger.log",
        "logging.debug",
        "logging.info",
        "logging.warning",
        "logging.error",
        "logging.exception",
        "logging.critical",
        "logging.log",
        "structlog.get_logger",
        "logger.info",
        "logger.error",
        "logger.warning",
        "logger.exception",
        "logger.debug",
        "logger.critical",
    ]

    def __init__(self, raw):
        raw = raw or {}
        self.sources = NameMatcher(raw.get("sensitive_sources", []))
        self.sanitizers = NameMatcher(raw.get("trusted_sanitizers", []))
        self.sinks = NameMatcher(raw.get("log_sinks", self.DEFAULT_SINKS))
        self.local_only = bool(raw.get("local_only", True))
        self.local_paths = [
            p for p in raw.get("local_paths", []) if isinstance(p, str)
        ]

    def is_local_file(self, filename):
        if not self.local_only:
            return True
        normalized = filename.replace("\\\\", "/")
        if self.local_paths:
            candidates = [p.replace("\\", "/").rstrip("/") for p in
                          self.local_paths]
            for allowed in candidates:
                if normalized == allowed:
                    return True
                if normalized.startswith(allowed + "/"):
                    return True
                # Allow project-relative roots such as 'examples' to match
                # absolute scanner paths ending in that root.
                if normalized.endswith("/" + allowed):
                    return True
                if ("/" + allowed + "/") in normalized:
                    return True
            return False
        markers = (
            "/site-packages/",
            "/dist-packages/",
            "/.venv/",
            "/venv/",
            "/env/",
        )
        return not any(marker in normalized for marker in markers)


class Finding:
    """Diagnostic produced by the analyzer."""

    LEAK = "leak"
    UNKNOWN = "unknown"

    def __init__(self, kind, text, lineno, col_offset, source=None,
                 field=None, origin_lineno=None, call_name=None):
        self.kind = kind
        self.text = text
        self.lineno = lineno
        self.col_offset = col_offset
        self.source = source
        self.field = field
        self.origin_lineno = origin_lineno
        self.call_name = call_name


class FunctionAnalyzer:
    """Intra-procedural flow-sensitive taint analysis for one scope."""

    def __init__(self, config, aliases):
        self.config = config
        self.aliases = aliases
        self.env = {}
        self.findings = []

    def analyze(self, body):
        self._exec_stmts(body, self.env)
        return self.findings

    def _exec_stmts(self, stmts, env):
        for stmt in stmts:
            self._exec_stmt(stmt, env)

    def _exec_stmt(self, node, env):
        method = getattr(self, f"_exec_{type(node).__name__}", None)
        if method is not None:
            method(node, env)

    def _exec_Assign(self, node, env):
        value = self._eval(node.value, env)
        for target in node.targets:
            self._assign(target, value, env)

    def _exec_AnnAssign(self, node, env):
        if node.value is not None:
            self._assign(node.target, self._eval(node.value, env), env)

    def _exec_AugAssign(self, node, env):
        current = self._load(node.target, env) or Taint.clean()
        added = self._eval(node.value, env)
        self._assign(node.target, current.union(added), env)

    def _exec_If(self, node, env):
        self._eval(node.test, env)
        for branch in (node.body, node.orelse):
            branch_env = dict(env)
            self._exec_stmts(branch, branch_env)
            self._merge(env, branch_env)

    def _exec_For(self, node, env):
        iter_taint = self._eval(node.iter, env)
        loop_env = dict(env)
        self._assign(node.target, iter_taint, loop_env)
        self._exec_stmts(node.body, loop_env)
        self._exec_stmts(node.orelse, loop_env)
        self._merge(env, loop_env)

    _exec_AsyncFor = _exec_For

    def _exec_While(self, node, env):
        self._eval(node.test, env)
        loop_env = dict(env)
        self._exec_stmts(node.body, loop_env)
        self._exec_stmts(node.orelse, loop_env)
        self._merge(env, loop_env)

    def _exec_Try(self, node, env):
        handler_env = dict(env)
        self._exec_stmts(node.body, handler_env)
        for handler in node.handlers:
            self._exec_stmts(handler.body, handler_env)
        self._merge(env, handler_env)
        for stmt in node.orelse:
            self._exec_stmt(stmt, env)
        for stmt in node.finalbody:
            self._exec_stmt(stmt, env)


    def _exec_With(self, node, env):
        for item in node.items:
            self._eval(item.context_expr, env)
            if item.optional_vars is not None:
                self._assign(item.optional_vars,
                             self._eval(item.context_expr, env), env)
        self._exec_stmts(node.body, env)

    _exec_AsyncWith = _exec_With

    def _exec_Return(self, node, env):
        if node.value is not None:
            self._eval(node.value, env)

    def _exec_Expr(self, node, env):
        taint = self._eval(node.value, env)
        self._write_in_place(node.value, taint, env)

    def _write_in_place(self, call, taint, env):
        """Persist taint from in-place container mutations."""
        if not isinstance(call, ast.Call):
            return
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr == "update":
            name = _store_name(func.value)
            if name:
                current = env.get(name)
                env[name] = _combine(current, taint)

    def _exec_Raise(self, node, env):
        if node.exc is not None:
            self._eval(node.exc, env)

    def _exec_Assert(self, node, env):
        self._eval(node.test, env)
        if node.msg is not None:
            self._eval(node.msg, env)

    def _exec_FunctionDef(self, node, env):
        analyzer = FunctionAnalyzer(self.config, self.aliases)
        self.findings.extend(analyzer.analyze(node.body))

    _exec_AsyncFunctionDef = _exec_FunctionDef

    def _merge(self, base, branch):
        for name, branch_taint in branch.items():
            if name in base:
                base[name] = base[name].union(branch_taint)
            else:
                base[name] = branch_taint

    def _assign(self, target, taint, env):
        if isinstance(target, ast.Name):
            env[target.id] = taint
        elif isinstance(target, (ast.Tuple, ast.List)):
            elements = self._iter_elements(taint, len(target.elts))
            for element, element_taint in zip(target.elts, elements):
                self._assign(element, element_taint, env)
        elif isinstance(target, ast.Attribute):
            base = self._load(target.value, env)
            if base is not None and base.is_tainted:
                env[_store_name(target)] = Taint.tainted(
                    _with_field(base.origins, target.attr))
        elif isinstance(target, ast.Subscript):
            self._subscript_assign(target, taint, env)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, taint, env)


    def _subscript_assign(self, node, taint, env):
        key = _literal_key(node.slice)
        base = self._load(node.value, env)
        store_name = _store_name(node.value)
        if key is None:
            if base is not None:
                self._assign(node.value, base.union(taint), env)
            return
        fields = {}
        if base is not None and base.is_tainted:
            for origin in base.origins:
                fields[origin.field] = Taint.tainted([origin])
        fields[key] = taint
        if any(value.is_tainted for value in fields.values()):
            origins = []
            for value in fields.values():
                if value.is_tainted:
                    origins.extend(value.origins)
            env[store_name] = Taint.tainted(origins)
        else:
            env[store_name] = Taint.clean()

    def _iter_elements(self, taint, count):
        return [taint for _ in range(max(count, 1))]

    def _eval(self, node, env):
        if node is None:
            return Taint.clean()
        method = getattr(self, f"_eval_{type(node).__name__}", None)
        if method is not None:
            return method(node, env)
        return Taint.clean()

    def _eval_Name(self, node, env):
        return env.get(node.id, Taint.clean())

    def _eval_Constant(self, node, env):
        return Taint.clean()

    def _eval_Attribute(self, node, env):
        base = self._load(node.value, env)
        if base is None or not base.is_tainted:
            return Taint.clean()
        matching = [
            Origin(origin.source, node.attr, origin.node)
            for origin in base.origins
            if origin.field in (None, node.attr)
        ]
        return Taint.tainted(matching) if matching else Taint.clean()


    def _eval_Subscript(self, node, env):
        key = _literal_key(node.slice)
        base = self._load(node.value, env)
        if base is None or base.state == Taint.CLEAN:
            return Taint.clean()
        if key is not None and base.is_tainted:
            matching = [
                Origin(origin.source, key, origin.node)
                for origin in base.origins
                if origin.field in (None, key)
            ]
            if matching:
                return Taint.tainted(matching)
        return Taint.unknown(base.unknown_calls)

    def _eval_Tuple(self, node, env):
        return self._eval_sequence(node.elts, env)

    _eval_List = _eval_Tuple

    def _eval_sequence(self, elements, env):
        result = Taint.clean()
        for element in elements:
            result = result.union(self._eval(element, env))
        return result

    def _eval_Starred(self, node, env):
        return self._eval(node.value, env)

    def _eval_Dict(self, node, env):
        origins = []
        unknown_calls = []
        for key, value in zip(node.keys, node.values):
            if key is None:
                unpacked = self._eval(value, env)
                if unpacked.is_tainted:
                    origins.extend(unpacked.origins)
                unknown_calls.extend(unpacked.unknown_calls)
                continue
            value_taint = self._eval(value, env)
            if value_taint.is_tainted:
                field = _literal_key(key)
                for origin in value_taint.origins:
                    origins.append(Origin(origin.source,
                                          field or origin.field,
                                          origin.node))
            unknown_calls.extend(value_taint.unknown_calls)
        if origins:
            return Taint.tainted(origins)
        if unknown_calls:
            return Taint.unknown(unknown_calls)
        return Taint.clean()


    def _eval_BinOp(self, node, env):
        return self._eval(node.left, env).union(self._eval(node.right, env))

    def _eval_JoinedStr(self, node, env):
        result = Taint.clean()
        for value in node.values:
            result = result.union(self._eval(value, env))
        return result

    def _eval_FormattedValue(self, node, env):
        return self._eval(node.value, env)

    def _eval_IfExp(self, node, env):
        return self._eval(node.body, env).union(
            self._eval(node.orelse, env))

    def _eval_BoolOp(self, node, env):
        result = Taint.clean()
        for value in node.values:
            result = result.union(self._eval(value, env))
        return result

    def _eval_UnaryOp(self, node, env):
        return self._eval(node.operand, env)

    def _eval_Compare(self, node, env):
        result = self._eval(node.left, env)
        for comparator in node.comparators:
            result = result.union(self._eval(comparator, env))
        return result

    def _eval_Lambda(self, node, env):
        return Taint.clean()

    def _load(self, node, env):
        if isinstance(node, ast.Name):
            return env.get(node.id)
        return self._eval(node, env)


    def _eval_Call(self, node, env):
        source = self.config.sources.match_origin(node, self.aliases)
        if source is not None:
            entry, field = source
            return Taint.tainted([Origin(_entry_name(entry), field, node)])
        if self.config.sanitizers.match(node, self.aliases):
            return self._sanitized_call(node, env)
        if self.config.sinks.match(node, self.aliases):
            return self._sink_call(node, env)
        method_taint = self._eval_known_method(node, env)
        if method_taint is not None:
            return method_taint
        return self._unknown_call(node, env)

    def _eval_known_method(self, node, env):
        """Model well understood container methods and constructors."""
        func = node.func
        if isinstance(func, ast.Attribute):
            receiver = self._load(func.value, env)
            method = func.attr
            if method == "update" and receiver is not None:
                return _combine(receiver, self._argument_taint(node, env))
            if method in ("copy", "setdefault") and receiver is not None:
                return receiver
            if method in ("get", "pop"):
                key = _literal_key(node.args[0]) if node.args else None
                return self._subscript_like(receiver, key)
        if isinstance(func, ast.Name) and func.id in ("dict", "list", "set",
                                                       "tuple", "frozenset"):
            return self._argument_taint(node, env)
        return None

    def _subscript_like(self, receiver, key):
        if receiver is None or receiver.state == Taint.CLEAN:
            return Taint.clean()
        if key is not None and receiver.is_tainted:
            matching = [
                Origin(origin.source, key, origin.node)
                for origin in receiver.origins
                if origin.field in (None, key)
            ]
            if matching:
                return Taint.tainted(matching)
        return Taint.unknown(receiver.unknown_calls)

    def _sanitized_call(self, node, env):
        return Taint.clean()

    def _sink_call(self, node, env):
        for argument in node.args:
            self._check_sink_value(argument, env, node)
        for keyword in node.keywords:
            self._check_sink_value(keyword.value, env, node)
        return Taint.clean()

    def _check_sink_value(self, node, env, sink_node):
        taint = self._eval(node, env)
        if taint.is_tainted:
            for origin in taint.origins:
                field = origin.field or "<unknown-field>"
                text = (
                    f"Sensitive field {field!r} from source "
                    f"{origin.source!r} reaches a structured log call "
                    f"without a trusted sanitizer (source line "
                    f"{origin.lineno})"
                )
                self.findings.append(Finding(
                    Finding.LEAK, text, sink_node.lineno,
                    sink_node.col_offset, source=origin.source,
                    field=field, origin_lineno=origin.lineno,
                    call_name=_call_display(sink_node, self.aliases)))
        if taint.is_unknown:
            for call in taint.unknown_calls:
                call_name = call["name"]
                call_line = call["lineno"]
                text = (
                    f"Value entering a structured log call depends on "
                    f"external call {call_name!r} (line {call_line}); "
                    f"sanitization cannot be confirmed statically"
                )
                self.findings.append(Finding(
                    Finding.UNKNOWN, text, sink_node.lineno,
                    sink_node.col_offset, call_name=call_name))


    def _unknown_call(self, node, env):
        arg_taint = self._argument_taint(node, env)
        name = _call_display(node, self.aliases)
        if arg_taint.is_tainted or arg_taint.is_unknown:
            return Taint.unknown([{"name": name, "lineno": node.lineno}])
        return Taint.clean()

    def _argument_taint(self, node, env):
        result = Taint.clean()
        for argument in node.args:
            result = _combine(result, self._eval(argument, env))
        for keyword in node.keywords:
            result = _combine(result, self._eval(keyword.value, env))
        return result



def _combine(left, right):
    """Union where clean values never downgrade tainted or unknown ones."""
    if left is None:
        return right
    if right is None:
        return left
    if left.state == Taint.CLEAN:
        return right
    if right.state == Taint.CLEAN:
        return left
    return left.union(right)


def _with_field(origins, field):
    """Return origin copies bound to a new field, never mutating originals."""
    return [Origin(origin.source, field, origin.node) for origin in origins]


def _store_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _attribute_base(node) or node.attr
    if isinstance(node, ast.Subscript):
        return _store_name(node.value)
    return ""


def _literal_key(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
        return str(node.value)
    return None


def _call_display(node, aliases):
    return _qualified_name(node, aliases) or "<unknown-call>"


class ModuleAnalyzer:
    """Runs the taint engine over a whole module AST."""

    def __init__(self, config):
        self.config = config
        self.aliases = ImportAliases()
        self.findings = []

    def analyze(self, tree):
        for node in tree.body:
            self._visit_top_level(node)
        return self.findings

    def _visit_top_level(self, node):
        if isinstance(node, ast.Import):
            self.aliases.record_import(node)
        elif isinstance(node, ast.ImportFrom):
            self.aliases.record_import_from(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            analyzer = FunctionAnalyzer(self.config, self.aliases)
            self.findings.extend(analyzer.analyze(node.body))
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef,
                                      ast.AsyncFunctionDef)):
                    analyzer = FunctionAnalyzer(self.config, self.aliases)
                    self.findings.extend(analyzer.analyze(child.body))
        elif isinstance(node, ast.If):
            self._visit_conditional_module(node)

    def _visit_conditional_module(self, node):
        for child in node.body + node.orelse:
            self._visit_top_level(child)


def analyze_source(source, config):
    """Parse source text and return analyzer findings."""
    tree = ast.parse(source)
    analyzer = ModuleAnalyzer(SensitiveLogConfig(config))
    return analyzer.analyze(tree)
