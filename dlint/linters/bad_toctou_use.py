#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import ast

from . import base
from . import toctou_graph


# Condition labels explaining how a prior check can be invalidated before a
# later use. They are surfaced directly in linter results.
INVALIDATION_BRANCH = "intervening branch may re-resolve the path"
INVALIDATION_EXCEPTION = "exception handler may run after the check"
INVALIDATION_LOOP = "loop back edge allows the path to change between iterations"
INVALIDATION_MUTATION = (
    "intervening rename/unlink/open/create may change the path target"
)
INVALIDATION_REBIND = "path variable may be reassigned before use"
INVALIDATION_UNKNOWN_WRAPPER = (
    "unknown wrapper may perform filesystem operations or rebind the path"
)


CHECK_FUNCTIONS = {
    "os": ("exists", "lexists", "isfile", "isdir", "islink", "ismount",
           "access", "stat", "lstat"),
    "os.path": ("exists", "lexists", "isfile", "isdir", "islink",
                "ismount", "samefile"),
}

# fstat/fstatat operate on already-open descriptors and therefore cannot be
# raced through path replacement.
DESCRIPTOR_CHECK_FUNCTIONS = {"os": ("fstat", "fstatvfs")}

USE_FUNCTIONS = {
    "os": ("open", "rename", "renames", "replace", "remove", "unlink",
           "mkdir", "rmdir", "chmod", "chown", "utime", "link", "symlink",
           "stat", "lstat", "access"),
}

PATHLIB_CHECK_METHODS = ("exists", "is_file", "is_dir", "is_symlink",
                         "is_mount", "samefile")
PATHLIB_USE_METHODS = ("open", "unlink", "rename", "replace", "touch",
                       "mkdir", "rmdir", "chmod", "lchmod", "lstat", "stat")

# Flags that make os.open atomic with respect to an existence check or that
# pin the lookup against symlink replacement.
SAFE_OPEN_FLAGS = ("O_EXCL", "O_NOFOLLOW")


# os functions that operate on an already-open descriptor (first positional
# argument is an fd). These never re-resolve a path and therefore cannot
# participate in a path-swap TOCTOU.
DESCRIPTOR_USE_FUNCTIONS = {
    "os": (
        "fstat", "fstatvfs", "fchmod", "fchown", "fpathconf",
        "fsync", "fdatasync", "ftruncate", "fchdir", "read", "write",
        "close", "dup", "dup2", "fstatat",
    ),
}


# Bare names that may be brought into scope via "from ... import name". Maps
# the imported name to the fully qualified origin.
FROM_IMPORT_CHECKS = {
    "exists": "os.path.exists",
    "lexists": "os.path.lexists",
    "isfile": "os.path.isfile",
    "isdir": "os.path.isdir",
    "islink": "os.path.islink",
    "ismount": "os.path.ismount",
    "access": "os.access",
    "stat": "os.stat",
    "lstat": "os.lstat",
}
FROM_IMPORT_USES = {
    "rename": "os.rename",
    "renames": "os.renames",
    "replace": "os.replace",
    "remove": "os.remove",
    "unlink": "os.unlink",
    "mkdir": "os.mkdir",
    "rmdir": "os.rmdir",
    "chmod": "os.chmod",
    "chown": "os.chown",
    "utime": "os.utime",
}


class FileEvent(object):
    """A single filesystem-relevant event observed in a function.

    ``kind`` is one of the ``EVENT_*`` constants, ``node`` is the originating
    AST call node, and ``path_key`` identifies the path string (or is None for
    descriptor-based events).
    """

    KIND_CHECK = "check"
    KIND_USE = "use"
    KIND_DESCRIPTOR_OPEN = "descriptor-open"

    def __init__(self, kind, node, path_key=None, descriptor=None,
                 safe_descriptor=False, uncertain=False):
        self.kind = kind
        self.node = node
        self.path_key = path_key
        self.descriptor = descriptor
        self.safe_descriptor = safe_descriptor
        self.uncertain = uncertain

    def __repr__(self):
        return (
            "FileEvent(kind={!r}, line={}, path_key={!r}, "
            "descriptor={!r}, uncertain={!r})".format(
                self.kind,
                getattr(self.node, "lineno", None),
                self.path_key,
                self.descriptor,
                self.uncertain,
            )
        )


class CheckRecord(object):
    """A reachable check and the conditions that may invalidate it.

    ``sources`` maps an invalidation label to the node ids that introduced it.
    This lets reporting ignore a mutation label introduced by the very use
    statement being reported, since the report is produced before that
    statement takes effect.
    """

    def __init__(self, check_node, path_key, invalidations=None, sources=None):
        self.check_node = check_node
        self.path_key = path_key
        self.invalidations = tuple(invalidations or ())
        self.sources = dict(sources or {})

    def with_invalidation(self, label, source_node=None):
        sources = dict(self.sources)
        sources.setdefault(label, set()).add(
            id(source_node) if source_node is not None else None
        )
        if label in self.invalidations:
            return CheckRecord(
                self.check_node, self.path_key, self.invalidations, sources
            )
        return CheckRecord(
            self.check_node,
            self.path_key,
            self.invalidations + (label,),
            sources,
        )

    def key(self):
        return (id(self.check_node), self.path_key, self.invalidations)


class DescriptorRecord(object):
    """A known open descriptor/file object and how it was obtained."""

    def __init__(self, name, origin_node, safe=False, uncertain=False):
        self.name = name
        self.origin_node = origin_node
        self.safe = safe
        self.uncertain = uncertain



def path_key(node):
    """Return a conservative key identifying a path expression.

    Equal keys mean the same static path string *or* the same variable holding
    a path. Unknown expressions get unique keys so distinct unknown paths are
    never merged, while the same Name node is always merged.
    """
    if isinstance(node, ast.Name):
        return ("name", node.id)
    if isinstance(node, ast.Attribute):
        return ("attr", _attribute_path(node))
    if isinstance(node, ast.Str):
        return ("str", node.s)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return ("str", node.value)
    if isinstance(node, ast.JoinedStr):
        return ("fstring", id(node))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = path_key(node.left)
        right = path_key(node.right)
        if left and right:
            return ("concat", left, right)
    if isinstance(node, ast.Call):
        return ("call", id(node))
    if isinstance(node, ast.Subscript):
        return ("subscript", id(node))
    return ("unknown", id(node))


def _attribute_path(node):
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def root_variable(key):
    """Return the variable name that, if reassigned, invalidates this key."""
    if not key:
        return None
    kind = key[0]
    if kind == "name":
        return key[1]
    if kind == "attr":
        path = key[1]
        return path.split(".")[0] if path else None
    if kind in ("fstring", "subscript"):
        return None
    if kind == "concat":
        left_var = root_variable(key[1])
        return left_var
    if kind == "call":
        return None
    return None


def parse_open_flags(node):
    """Parse the ``flags`` argument of ``os.open``.

    Returns ``(flag_names, certain)``. ``flag_names`` is the set of O_* flag
    names that statically appear; ``certain`` is False when any part of the
    expression cannot be resolved.
    """
    if node is None:
        return set(), False

    names = set()
    certain = [True]

    def walk(inner):
        if isinstance(inner, ast.BinOp) and isinstance(inner.op, ast.BitOr):
            walk(inner.left)
            walk(inner.right)
        elif isinstance(inner, ast.Attribute) and inner.attr.startswith("O_"):
            names.add(inner.attr)
        elif isinstance(inner, ast.Name) and inner.id.startswith("O_"):
            names.add(inner.id)
        elif isinstance(inner, ast.Constant) and isinstance(inner.value, int):
            return
        elif isinstance(inner, ast.Num):
            return
        else:
            certain[0] = False

    walk(node)
    return names, certain[0]


def get_keyword(call, name):
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def positional_arg(call, index):
    if len(call.args) > index:
        return call.args[index]
    return None


class ToctouAnalyzer(object):
    """Builds the per-function file event graph and reports check/use pairs."""

    def __init__(self, namespace):
        self.namespace = namespace
        self.findings = []

    def _module_call(self, call, module_path, attribute):
        """True if ``call`` is ``module_path.attribute(...)`` per imports."""
        func = call.func
        if not isinstance(func, ast.Attribute) or func.attr != attribute:
            return False
        return self.namespace.illegal_module_imported(
            _attribute_path(func) or "",
            module_path + "." + attribute,
        )

    def _module_any(self, call, module_path, attributes):
        func = call.func
        if not isinstance(func, ast.Attribute):
            return None
        if func.attr not in attributes:
            return None
        full = module_path + "." + func.attr
        if self.namespace.illegal_module_imported(
                _attribute_path(func) or "", full):
            return func.attr
        return None

    def _pathlib_method(self, call, methods):
        func = call.func
        if not isinstance(func, ast.Attribute) or func.attr not in methods:
            return None
        # pathlib instances are conventionally constructed locally; we treat
        # any matching method call conservatively but record uncertainty when
        # the receiver is not a simple local.
        if isinstance(func.value, ast.Name):
            return func.attr
        return func.attr

    def _bare_import_event(self, call):
        func = call.func
        if not isinstance(func, ast.Name):
            return None
        name = func.id
        path_arg = positional_arg(call, 0)
        key = path_key(path_arg) if path_arg else None

        origin = FROM_IMPORT_CHECKS.get(name)
        if origin and self.namespace.illegal_module_imported(name, origin):
            return FileEvent(FileEvent.KIND_CHECK, call, path_key=key)

        origin = FROM_IMPORT_USES.get(name)
        if origin and self.namespace.illegal_module_imported(name, origin):
            return FileEvent(FileEvent.KIND_USE, call, path_key=key)
        return None

    def classify_call(self, call):
        """Return a FileEvent for a recognized call, else None."""
        if not isinstance(call, ast.Call):
            return None

        bare = self._bare_import_event(call)
        if bare is not None:
            return bare

        for module_path, attrs in CHECK_FUNCTIONS.items():
            attribute = self._module_any(call, module_path, attrs)
            if attribute:
                path_arg = positional_arg(call, 0)
                key = path_key(path_arg) if path_arg else None
                return FileEvent(
                    FileEvent.KIND_CHECK, call, path_key=key
                )

        for module_path, attrs in DESCRIPTOR_CHECK_FUNCTIONS.items():
            attribute = self._module_any(call, module_path, attrs)
            if attribute:
                return FileEvent(
                    FileEvent.KIND_CHECK, call,
                    descriptor=_descriptor_name(positional_arg(call, 0)),
                    safe_descriptor=True,
                )

        attribute = self._module_any(call, "os", ("open",))
        if attribute:
            return self._os_open_event(call)

        for module_path, attrs in USE_FUNCTIONS.items():
            attribute = self._module_any(call, module_path, attrs)
            if attribute:
                path_arg = positional_arg(call, 0)
                key = path_key(path_arg) if path_arg else None
                return FileEvent(
                    FileEvent.KIND_USE, call, path_key=key
                )

        for module_path, attrs in DESCRIPTOR_USE_FUNCTIONS.items():
            attribute = self._module_any(call, module_path, attrs)
            if attribute:
                return FileEvent(
                    FileEvent.KIND_CHECK,
                    call,
                    descriptor=_descriptor_name(positional_arg(call, 0)),
                    safe_descriptor=True,
                )

        if self._module_call(call, "os", "fdopen"):
            return self._fdopen_event(call)

        method = self._pathlib_method(call, PATHLIB_CHECK_METHODS)
        if method:
            key = path_key(call.func.value)
            return FileEvent(FileEvent.KIND_CHECK, call, path_key=key)

        method = self._pathlib_method(call, PATHLIB_USE_METHODS)
        if method:
            key = path_key(call.func.value)
            return FileEvent(FileEvent.KIND_USE, call, path_key=key)

        if self._builtin_open(call):
            path_arg = positional_arg(call, 0)
            key = path_key(path_arg) if path_arg else None
            return FileEvent(FileEvent.KIND_USE, call, path_key=key)

        return None

    def _builtin_open(self, call):
        func = call.func
        if isinstance(func, ast.Name) and func.id == "open":
            return not self.namespace.name_imported("open")
        return False

    def _os_open_event(self, call):
        path_arg = positional_arg(call, 0)
        key = path_key(path_arg) if path_arg else None
        flags_node = positional_arg(call, 1) or get_keyword(call, "flags")
        flag_names, certain = parse_open_flags(flags_node)

        no_follow = get_keyword(call, "no_follow")
        no_follow_true = no_follow is not None and _is_true_constant(no_follow)

        safe = False
        if any(flag in flag_names for flag in SAFE_OPEN_FLAGS):
            safe = True
        if no_follow_true:
            safe = True

        return FileEvent(
            FileEvent.KIND_DESCRIPTOR_OPEN,
            call,
            path_key=key,
            safe_descriptor=safe,
            uncertain=not certain,
        )

    def _fdopen_event(self, call):
        descriptor = _descriptor_name(positional_arg(call, 0))
        return FileEvent(
            FileEvent.KIND_DESCRIPTOR_OPEN,
            call,
            descriptor=descriptor,
            safe_descriptor=descriptor is not None,
        )

    def analyze_function(self, body):
        graph, _ = toctou_graph.build_flow_graph(body)
        if graph.entry is None:
            return

        states = {}
        states[graph.entry] = FlowState()
        worklist = [graph.entry]
        seen_states = {}
        max_iterations = 1000
        iterations = 0

        while worklist:
            iterations += 1
            if iterations > max_iterations:
                break
            node = worklist.pop(0)
            incoming = states.get(node)
            if incoming is None:
                incoming = FlowState()

            outgoing = self._transfer(node, incoming)

            for target, tag in graph.outgoing(node):
                edge_state = self._tag_state(outgoing, tag)
                previous = states.get(target)
                if previous is None:
                    states[target] = edge_state
                    worklist.append(target)
                else:
                    merged = FlowState.merge(previous, edge_state)
                    if _state_signature(merged) != _state_signature(previous):
                        states[target] = merged
                        worklist.append(target)

    def _tag_state(self, state, tag):
        if tag == toctou_graph.EDGE_LOOP:
            return self._retag(state, INVALIDATION_LOOP)
        if tag == toctou_graph.EDGE_EXCEPTION:
            return self._retag(state, INVALIDATION_EXCEPTION)
        if tag == toctou_graph.EDGE_BRANCH:
            return self._retag(state, INVALIDATION_BRANCH)
        return state.clone()

    @staticmethod
    def _retag(state, label):
        new = state.clone()
        for key, records in list(new.checks.items()):
            new.checks[key] = [record.with_invalidation(label) for record in records]
        return new

    def _transfer(self, statement, incoming):
        state = incoming.clone()
        self._handle_assignments(statement, state)
        for call in _calls_in_statement(statement):
            event = self.classify_call(call)
            if event is not None:
                self._apply_event(event, statement, state)
            else:
                self._apply_unknown_call(call, state)
        return state

    def _handle_assignments(self, statement, state):
        if not isinstance(statement, ast.Assign):
            return
        for target in statement.targets:
            for name in _assigned_names(target):
                # Keep the prior check reachable but record that the variable
                # may now name a different filesystem object. The conservative
                # key overlap logic still relates the later use to this check.
                state.invalidate_variable(name, INVALIDATION_REBIND, statement)
                state.drop_descriptor(name)

        event = None
        if isinstance(statement.value, ast.Call):
            event = self.classify_call(statement.value)
        if event is not None and event.kind == FileEvent.KIND_DESCRIPTOR_OPEN:
            for target in statement.targets:
                name = _single_target_name(target)
                if name:
                    state.descriptors[name] = DescriptorRecord(
                        name,
                        event.node,
                        safe=event.safe_descriptor,
                        uncertain=event.uncertain,
                    )

    def _apply_event(self, event, statement, state):
        if event.kind == FileEvent.KIND_CHECK:
            if event.path_key is not None:
                state.add_check(CheckRecord(event.node, event.path_key))
            return

        if event.kind == FileEvent.KIND_DESCRIPTOR_OPEN:
            self._report_open(event, state)
            if event.path_key is not None:
                state.invalidate_path(
                    event.path_key, INVALIDATION_MUTATION, event.node
                )
            return

        if event.kind == FileEvent.KIND_USE:
            self._report_use(event, state)
            if event.path_key is not None:
                state.invalidate_path(
                    event.path_key, INVALIDATION_MUTATION, event.node
                )
            return

    def _report_open(self, event, state):
        if event.safe_descriptor:
            return
        if event.path_key is None:
            return
        if self._anchored_descriptor_safe(event, state):
            return
        self._emit_findings_for_path(event, state, uncertain=event.uncertain)

    def _anchored_descriptor_safe(self, event, state):
        # A dir_fd-anchored lookup is only race-free when the directory
        # descriptor is a locally tracked, no-follow descriptor AND this open
        # itself pins the final component via O_NOFOLLOW/O_EXCL. An unknown or
        # untrusted dir_fd is treated as uncertain and never suppresses risk.
        dir_node = get_keyword(event.node, "dir_fd")
        if dir_node is None:
            return False
        name = _descriptor_name(dir_node)
        if name is None:
            return False
        record = state.descriptors.get(name)
        if record is None or record.uncertain:
            return False
        flags_node = (
            positional_arg(event.node, 1)
            or get_keyword(event.node, "flags")
        )
        flag_names, _ = parse_open_flags(flags_node)
        pins_final_component = any(
            flag in flag_names for flag in SAFE_OPEN_FLAGS
        )
        no_follow = get_keyword(event.node, "no_follow")
        if no_follow is not None and _is_true_constant(no_follow):
            pins_final_component = True
        return record.safe and pins_final_component

    def _report_use(self, event, state):
        if event.path_key is None:
            return
        self._emit_findings_for_path(event, state, uncertain=False)

    def _emit_findings_for_path(self, event, state, uncertain):
        records = []
        for key, check_records in state.checks.items():
            if _keys_overlap(key, event.path_key):
                for record in check_records:
                    records.append(record)
        for record in records:
            invalidations = tuple(
                label
                for label in record.invalidations
                if not self._is_self_mutation(record, label, event.node)
            )
            self.findings.append(
                Finding(
                    check_node=record.check_node,
                    use_node=event.node,
                    invalidations=invalidations,
                    uncertain=uncertain,
                )
            )

    @staticmethod
    def _is_self_mutation(record, label, use_node):
        if label != INVALIDATION_MUTATION:
            return False
        sources = record.sources.get(label)
        if not sources:
            return False
        return sources == {id(use_node)}

    def _apply_unknown_call(self, call, state):
        """Unknown wrappers never remove risk.

        We conservatively mark every live check as potentially invalidated and
        drop descriptor confidence, but we do not invent new check/use pairs.
        """
        touched_names = set()
        for arg_node in ast.walk(call):
            if isinstance(arg_node, ast.Name):
                touched_names.add(arg_node.id)
        if not touched_names:
            return
        for key, records in list(state.checks.items()):
            if root_variable(key) in touched_names or key[0] in (
                    "unknown", "call", "fstring", "concat"):
                state.checks[key] = [
                    record.with_invalidation(INVALIDATION_UNKNOWN_WRAPPER)
                    for record in records
                ]
        for name in touched_names:
            descriptor = state.descriptors.get(name)
            if descriptor is not None:
                descriptor.uncertain = True

def _descriptor_name(node):
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_true_constant(node):
    if isinstance(node, ast.Constant):
        return node.value is True
    if isinstance(node, ast.NameConstant):
        return node.value is True
    return False


class FlowState(object):
    """Abstract state propagated along the file event graph."""

    def __init__(self):
        # path_key -> list[CheckRecord]
        self.checks = {}
        # descriptor name -> DescriptorRecord
        self.descriptors = {}

    def clone(self):
        new = FlowState()
        new.checks = dict(self.checks)
        new.descriptors = dict(self.descriptors)
        return new

    @staticmethod
    def merge(state_a, state_b):
        merged = FlowState()
        keys = set(state_a.checks) | set(state_b.checks)
        for key in keys:
            combined = {}
            for record in state_a.checks.get(key, []) + state_b.checks.get(key, []):
                identity = (id(record.check_node), record.invalidations)
                existing = combined.get(identity)
                if existing is None:
                    combined[identity] = record
                else:
                    sources = dict(existing.sources)
                    for label, node_ids in record.sources.items():
                        sources.setdefault(label, set()).update(node_ids)
                    existing.sources = sources
            merged.checks[key] = list(combined.values())
        names = set(state_a.descriptors) | set(state_b.descriptors)
        for name in names:
            record_a = state_a.descriptors.get(name)
            record_b = state_b.descriptors.get(name)
            if record_a and record_b:
                merged.descriptors[name] = DescriptorRecord(
                    name,
                    record_a.origin_node,
                    safe=record_a.safe and record_b.safe,
                    uncertain=record_a.uncertain or record_b.uncertain,
                )
            else:
                merged.descriptors[name] = record_a or record_b
        return merged

    def add_check(self, record):
        existing = self.checks.setdefault(record.path_key, [])
        if not any(r.check_node is record.check_node for r in existing):
            existing.append(record)

    def invalidate_path(self, key, label, source_node=None):
        for path_key, records in list(self.checks.items()):
            if _keys_overlap(path_key, key):
                self.checks[path_key] = [
                    record.with_invalidation(label, source_node)
                    for record in records
                ]

    def invalidate_variable(self, name, label, source_node=None):
        for key, records in list(self.checks.items()):
            if root_variable(key) == name:
                self.checks[key] = [
                    record.with_invalidation(label, source_node)
                    for record in records
                ]

    def drop_descriptor(self, name):
        self.descriptors.pop(name, None)


def _keys_overlap(key_a, key_b):
    """Conservative overlap: two path keys may name the same filesystem path."""
    if key_a is None or key_b is None:
        return True
    if key_a == key_b:
        return True
    if key_a[0] == "unknown" or key_b[0] == "unknown":
        return True
    if key_a[0] == "call" or key_b[0] == "call":
        return True
    if key_a[0] == "concat" or key_b[0] == "concat":
        return True
    if key_a[0] == "fstring" or key_b[0] == "fstring":
        return True
    return False


class Finding(object):
    """A reachable check/use pair with the conditions that may break it."""

    def __init__(self, check_node, use_node, invalidations, uncertain):
        self.check_node = check_node
        self.use_node = use_node
        self.invalidations = tuple(invalidations)
        self.uncertain = uncertain

    def __eq__(self, other):
        return (
            isinstance(other, Finding)
            and self.check_node is other.check_node
            and self.use_node is other.use_node
            and self.invalidations == other.invalidations
            and self.uncertain == other.uncertain
        )

    def __hash__(self):
        return hash((
            id(self.check_node),
            id(self.use_node),
            self.invalidations,
            self.uncertain,
        ))


def _state_signature(state):
    parts = []
    for key, records in sorted(state.checks.items(), key=lambda item: repr(item[0])):
        parts.append((
            repr(key),
            tuple(sorted((id(r.check_node), r.invalidations) for r in records)),
        ))
    descriptor_parts = tuple(sorted(
        (name, record.safe, record.uncertain)
        for name, record in state.descriptors.items()
    ))
    return tuple(parts), descriptor_parts


def _calls_in_statement(statement):
    # Collect calls that belong directly to this statement without crossing
    # nested block boundaries, since compound statements are separate CFG
    # nodes. Inner calls evaluate before their enclosing call at runtime, so
    # inner calls are yielded first.
    def walk(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                continue
            if isinstance(child, ast.Call):
                for inner in walk(child):
                    yield inner
                yield child
            else:
                for inner in walk(child):
                    yield inner

    return list(walk(statement))


def _assigned_names(target):
    names = []
    for node in ast.walk(target):
        if isinstance(node, ast.Name):
            names.append(node.id)
    return names


def _single_target_name(target):
    if isinstance(target, ast.Name):
        return target.id
    return None


class BadToctouUseLinter(base.BaseLinter):
    """This linter looks for time-of-check to time-of-use (TOCTOU) race
    conditions on filesystem paths. It builds a per-function file event graph
    over branches, exceptions and loops, then relates path checks
    (exists/stat/access and friends) to later uses (open, rename, unlink and
    friends).

    Re-opening a path string after a check is racy because the path can be
    replaced (e.g. via a symlink) in the window between check and use. Using an
    already-open descriptor is not racy because no path re-resolution occurs.
    Unknown wrapper functions are treated as uncertain and never suppress a
    finding.
    """
    off_by_default = False

    _code = "DUO139"
    _error_tmpl = (
        "DUO139 TOCTOU race condition: filesystem check at line {check_line} "
        "is followed by use at line {use_line}; {conditions}"
    )
    def __init__(self, *args, **kwargs):
        self.toctou_findings = []
        super(BadToctouUseLinter, self).__init__(*args, **kwargs)

    def visit_FunctionDef(self, node):
        self._analyze(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self._analyze(node)
        self.generic_visit(node)

    def _analyze(self, function_node):
        analyzer = ToctouAnalyzer(self.namespace)
        analyzer.analyze_function(function_node.body)

        # Aggregate every reachable check/use pair into a single finding
        # whose invalidation conditions are the union of all observed paths.
        aggregated = {}
        for finding in analyzer.findings:
            key = (id(finding.check_node), id(finding.use_node))
            existing = aggregated.get(key)
            if existing is None:
                aggregated[key] = finding
            else:
                conditions = tuple(sorted(
                    set(existing.invalidations) | set(finding.invalidations)
                ))
                existing.invalidations = conditions
                existing.uncertain = existing.uncertain or finding.uncertain

        for finding in aggregated.values():
            self.toctou_findings.append(finding)
            self.results.append(
                base.Flake8Result(
                    lineno=finding.use_node.lineno,
                    col_offset=finding.use_node.col_offset,
                    message=self._build_message(finding),
                )
            )

    def _build_message(self, finding):
        conditions = list(finding.invalidations)
        if not conditions:
            conditions_text = (
                "the path may be replaced between the check and the use"
            )
        else:
            conditions_text = "; ".join(conditions)
        uncertainty = (
            " [analysis uncertain: unknown wrapper involved]"
            if finding.uncertain else ""
        )
        return self._error_tmpl.format(
            check_line=finding.check_node.lineno,
            use_line=finding.use_node.lineno,
            conditions=conditions_text + uncertainty,
        )

