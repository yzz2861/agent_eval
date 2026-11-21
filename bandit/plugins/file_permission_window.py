#
# SPDX-License-Identifier: Apache-2.0
r"""
================================================================
B114: file permissions are widened before external publication
================================================================

This plugin performs a deliberately limited, module-local analysis of the
Python source that Bandit is already scanning.  It does not import, resolve or
execute any code from other modules.

The analysis links three pieces of evidence:

1. how a file was created (``open``, ``os.open``, ``tempfile.mkstemp`` and
   friends, including a known restrictive umask);
2. aliases of the same file object (descriptors, file objects, ``.name``
   values and path variables); and
3. the first point where that file is published outside the function (for
   example a ``return``, a ``yield``, or a call that hands the path or file
   object to another function).

An issue is reported when restricted data was written to the file, its
permissions were widened, and the file was published while those wider
permissions were still in effect.  A later ``chmod`` does not remove the
issue: the early publication already happened.  If the creation mode, the
``chmod`` target or the publication cannot be tied to the same file, the
plugin stays silent instead of guessing.

:Example:

.. code-block:: none

    >> Issue: Restricted file (tmp.name) is externally published while
       permissions are permissive (0o644).  Permissions were widened on line
       5; restoring them later does not undo the exposure.
       Severity: High   Confidence: High
       CWE: CWE-732 (https://cwe.mitre.org/data/definitions/732.html)
       Location: examples/file-permission-window.py:6

.. seealso::

 - https://cwe.mitre.org/data/definitions/732.html
 - https://security.openstack.org/guidelines/dg_apply-restrictive-file-permissions.html

.. versionadded:: 1.8.0

"""  # noqa: E501

import ast
import copy
import os
import stat

import bandit
from bandit.core import constants
from bandit.core import issue
from bandit.core import test_properties as test

_GROUP_OTHER_MASK = stat.S_IRWXG | stat.S_IRWXO
_TRY_NODES = (ast.Try,)
if hasattr(ast, "TryStar"):
    _TRY_NODES = (ast.Try, ast.TryStar)
_WORLD_MASK = stat.S_IRWXO
_OPEN_MODE = 0o666
_TEMP_MODE = 0o600

_TEMP_APIS = {
    "mkstemp",
    "NamedTemporaryFile",
    "TemporaryFile",
    "SpooledTemporaryFile",
}

_MODE_FUNCS = {"chmod", "fchmod", "lchmod"}
_CLOSE_FUNCS = {"close"}
_WRITE_FUNCS = {"write", "writev", "pwrite", "pwritev"}
_WRITE_METHODS = {
    "write",
    "writelines",
    "write_text",
    "write_bytes",
    "writerow",
    "writerows",
    "writestr",
    "dump",
    "dump_all",
}
_CLOSE_METHODS = {"close"}
_MODE_METHODS = {"chmod"}

_DUMP_FUNCS = {"dump", "dump_all"}
_DUMP_TARGET_KEYWORDS = {"fp", "file", "stream"}
_COPY_TO_DST_FUNCS = {"copy", "copy2", "copyfile", "copyfileobj"}
_MOVE_FUNCS = {"move", "rename", "replace", "link", "symlink"}
_SENDFILE_FUNCS = {"sendfile"}

_PASS_THROUGH_FUNCS = {
    "Path",
    "PurePath",
    "PurePosixPath",
    "PureWindowsPath",
    "fspath",
    "str",
    "abspath",
    "realpath",
    "normpath",
    "expanduser",
    "relpath",
}
_PATH_JOIN_FUNCS = {"join"}
_PATH_CONSTRUCTORS = {
    "Path",
    "PurePath",
    "PurePosixPath",
    "PureWindowsPath",
}
_PATH_SPLIT_FUNCS = {
    "basename",
    "dirname",
    "split",
    "splitext",
}
_STRING_PASS_THROUGH_METHODS = {
    "upper",
    "lower",
    "strip",
    "lstrip",
    "rstrip",
    "replace",
    "format",
    "join",
    "split",
    "rsplit",
    "removeprefix",
    "removesuffix",
    "with_suffix",
    "with_name",
    "joinpath",
    "resolve",
    "absolute",
    "encode",
}

_METADATA_FUNCS = {
    "access",
    "commonpath",
    "commonprefix",
    "exists",
    "getatime",
    "getctime",
    "getmtime",
    "getsize",
    "isabs",
    "isdir",
    "isfile",
    "islink",
    "ismount",
    "lexists",
    "lstat",
    "samefile",
    "sameopenfile",
    "stat",
    "statvfs",
}

_NO_PUBLISH_FUNCS = {
    "chown",
    "copymode",
    "copystat",
    "fchdir",
    "fchown",
    "fdatasync",
    "fstat",
    "fstatvfs",
    "fsync",
    "ftruncate",
    "fwalk",
    "isatty",
    "lchown",
    "listdir",
    "lseek",
    "makedirs",
    "mkdir",
    "pread",
    "preadv",
    "read",
    "readv",
    "removedirs",
    "remove",
    "rmdir",
    "rmtree",
    "scandir",
    "truncate",
    "unlink",
    "utime",
    "utimes",
    "walk",
}

_PUBLISHING_NAME_HINTS = (
    "publish",
    "upload",
    "share",
    "expose",
    "handoff",
    "export",
    "transmit",
    "deliver",
    "dispatch",
    "transfer",
    "send",
    "post",
    "put",
)

_FILE_WRAPPER_FUNCS = {
    "BZ2File",
    "BufferedReader",
    "BufferedWriter",
    "DictWriter",
    "GzipFile",
    "LZMAFile",
    "Pickler",
    "RandomAccessFile",
    "TarFile",
    "TextIOWrapper",
    "ZipFile",
    "writer",
}

_READ_FUNCS = {
    "load",
    "loads",
    "safe_load",
    "unsafe_load",
    "reader",
    "DictReader",
    "read_csv",
    "read_excel",
    "read_json",
}

_READ_METHODS = {
    "read",
    "readline",
    "readlines",
    "read_text",
    "read_bytes",
    "flush",
    "seek",
    "tell",
    "truncate",
    "fsync",
    "fdatasync",
    "isatty",
    "readable",
    "writable",
    "seekable",
}

_SAFE_BUILTINS = {
    "bool",
    "callable",
    "hash",
    "id",
    "isinstance",
    "len",
    "type",
}

_EXTERNAL_PREFIXES = (
    "os.",
    "shutil.",
    "tempfile.",
    "socket.",
    "requests.",
    "httpx.",
    "urllib.",
    "subprocess.",
    "logging.",
    "json.",
    "pickle.",
    "yaml.",
    "marshal.",
    "csv.",
    "stat.",
)


def _tail(name):
    return name.rsplit(".", 1)[-1]


def _is_path_call(qualname, names):
    if not qualname:
        return False
    if qualname.startswith(("os.path.", "posixpath.", "ntpath.")):
        return _tail(qualname) in names
    return False


def _is_wide(mode):
    return bool(mode & _GROUP_OTHER_MASK)


def _wider_mode(first, second):
    if first is None:
        return second
    if second is None:
        return first
    if bool(first & _WORLD_MASK) != bool(second & _WORLD_MASK):
        return first if first & _WORLD_MASK else second
    if (first & _GROUP_OTHER_MASK) >= (second & _GROUP_OTHER_MASK):
        return first
    return second


def _severity_for_mode(mode):
    if mode & _WORLD_MASK:
        return bandit.HIGH
    return bandit.MEDIUM


def _confidence_floor(*values):
    rank = constants.RANKING
    return min(values, key=rank.index)


def _unparse(node):
    try:
        text = ast.unparse(node)
    except Exception:
        return "file"
    if len(text) > 80:
        text = text[:77] + "..."
    return text


def _expr_signature(node):
    if node is None:
        return None
    try:
        return ast.unparse(node)
    except Exception:
        return None


def _node_key(node):
    if node is None:
        return None
    return (type(node).__name__, node.lineno, node.col_offset)


def _qualify(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _qualify(node.value, aliases)
        if base:
            return base + "." + node.attr
    return None


def _constant_int(node, aliases, constants):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return None
        if isinstance(node.value, int):
            return node.value
        return None

    if isinstance(node, ast.Name):
        value = constants.get(node.id)
        if isinstance(value, int):
            return value
        qualname = aliases.get(node.id)
        if qualname:
            return _int_from_qualified_name(qualname)
        return None

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        value = _constant_int(node.operand, aliases, constants)
        return -value if value is not None else None

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
        value = _constant_int(node.operand, aliases, constants)
        return ~value if value is not None else None

    if isinstance(node, ast.BinOp):
        left = _constant_int(node.left, aliases, constants)
        right = _constant_int(node.right, aliases, constants)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.BitAnd):
            return left & right
        if isinstance(node.op, ast.BitXor):
            return left ^ right
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.LShift):
            return left << right
        return None

    if isinstance(node, ast.Attribute):
        qualname = _qualify(node, aliases)
        if qualname and qualname.startswith("stat."):
            value = getattr(stat, qualname.split(".", 1)[1], None)
            return value if isinstance(value, int) else None
        if qualname and qualname.startswith("os."):
            value = getattr(os, qualname.split(".", 1)[1], None)
            return value if isinstance(value, int) else None
        return None

    if isinstance(node, ast.Call):
        qualname = _qualify(node.func, aliases)
        if qualname == "stat.S_IMODE" and len(node.args) == 1:
            value = _constant_int(node.args[0], aliases, constants)
            if value is not None:
                return stat.S_IMODE(value)
    return None


def _int_from_qualified_name(qualname):
    if qualname.startswith("stat."):
        value = getattr(stat, qualname.split(".", 1)[1], None)
        return value if isinstance(value, int) else None
    if qualname.startswith("os."):
        value = getattr(os, qualname.split(".", 1)[1], None)
        return value if isinstance(value, int) else None
    return None


def _static_opener_mode(node, aliases, constants, openers):
    if isinstance(node, ast.Name):
        return openers.get(node.id)
    if isinstance(node, ast.Lambda):
        body = node.body
        if isinstance(body, ast.Call):
            tail = _tail(_qualify(body.func, aliases) or "")
            if tail == "open" and len(body.args) > 2:
                return _constant_int(body.args[2], aliases, constants)
    if isinstance(node, ast.Call):
        tail = _tail(_qualify(node.func, aliases) or "")
        if tail == "partial":
            for keyword in node.keywords:
                if keyword.arg in ("mode", "perm"):
                    return _constant_int(keyword.value, aliases, constants)
    return None


def _constant_str(node, aliases, constants):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value

    if isinstance(node, ast.Name):
        value = constants.get(node.id)
        return value if isinstance(value, str) else None

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_str(node.left, aliases, constants)
        right = _constant_str(node.right, aliases, constants)
        if left is not None and right is not None:
            return left + right
        return None

    if isinstance(node, ast.Call):
        qualname = _qualify(node.func, aliases) or ""
        if _tail(qualname) in _PASS_THROUGH_FUNCS and len(node.args) == 1:
            return _constant_str(node.args[0], aliases, constants)
        if _is_path_call(qualname, _PATH_JOIN_FUNCS) and node.args:
            parts = [
                _constant_str(arg, aliases, constants) for arg in node.args
            ]
            if all(part is not None for part in parts):
                return os.path.join(*parts)
    return None


def _collect_import_aliases(tree):
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    aliases[alias.name.split(".", 1)[0]] = alias.name.split(
                        ".", 1
                    )[0]
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                qualified = node.module + "." + alias.name
                aliases[alias.asname or alias.name] = qualified
    return aliases


def _collect_module_constants(tree, aliases):
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                value = _constant_int(node.value, aliases, constants)
                if value is None:
                    value = _constant_str(node.value, aliases, constants)
                if value is not None:
                    constants[target.id] = value
        elif (
            isinstance(node, ast.AnnAssign)
            and node.value is not None
            and isinstance(node.target, ast.Name)
        ):
            value = _constant_int(node.value, aliases, constants)
            if value is None:
                value = _constant_str(node.value, aliases, constants)
            if value is not None:
                constants[node.target.id] = value
    return constants


def _collect_module_openers(tree, aliases, constants):
    openers = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            mode = _static_opener_mode(node.value, aliases, constants, openers)
            if mode is not None:
                openers[node.targets[0].id] = mode
    return openers


def _collect_internal_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            names.add(node.name)
    return names


class _Event:
    __slots__ = ("lineno", "mode", "confidence")

    def __init__(self, lineno, mode, confidence):
        self.lineno = lineno
        self.mode = mode
        self.confidence = confidence


class _FileState:
    __slots__ = (
        "key",
        "display",
        "path",
        "mode",
        "mode_confidence",
        "written",
        "handles_open",
        "opened",
        "wide_since",
        "peak_mode",
        "reported",
    )

    def __init__(self, key, display, path=None, mode=None, confidence=None):
        self.key = key
        self.display = display
        self.path = path
        self.mode = mode
        self.mode_confidence = confidence or bandit.HIGH
        self.written = False
        self.handles_open = 0
        self.opened = False
        self.wide_since = None
        self.peak_mode = None
        self.reported = False


class _Finding:
    __slots__ = (
        "node_key",
        "lineno",
        "col_offset",
        "severity",
        "confidence",
        "text",
    )

    def __init__(
        self,
        node,
        severity,
        confidence,
        text,
        lineno=None,
        col_offset=None,
        node_key=None,
    ):
        self.node_key = _node_key(node) if node_key is None else node_key
        self.lineno = node.lineno if lineno is None else lineno
        self.col_offset = node.col_offset if col_offset is None else col_offset
        self.severity = severity
        self.confidence = confidence
        self.text = text

    def to_issue(self):
        b_issue = bandit.Issue(
            severity=self.severity,
            confidence=self.confidence,
            cwe=issue.Cwe.INCORRECT_PERMISSION_ASSIGNMENT,
            text=self.text,
            lineno=self.lineno,
            col_offset=self.col_offset,
        )
        b_issue.linerange = [self.lineno]
        return b_issue


class _ScopeAnalyzer:
    def __init__(
        self, findings, constants, aliases, internal_names, openers=None
    ):
        self.findings = findings
        self.constants = dict(constants)
        self.aliases = dict(aliases)
        self.internal_names = internal_names
        self.files = {}
        self.names = {}
        self.call_keys = {}
        self.path_lookup = {}
        self.expr_lookup = {}
        self.umask = None
        self.openers = dict(openers or {})
        self.anon = 0

    def process_body(self, body):
        for stmt in body:
            self._process_stmt(stmt)

    def _process_stmt(self, stmt):
        if isinstance(stmt, ast.Assign):
            self._process_assign(stmt.targets, stmt.value)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self._process_assign([stmt.target], stmt.value)
            else:
                self._eval_expr(stmt.annotation)
        elif isinstance(stmt, ast.AugAssign):
            self._eval_expr(stmt.value)
        elif isinstance(stmt, ast.Expr):
            self._eval_expr(stmt.value)
        elif isinstance(stmt, ast.Return):
            if stmt.value is not None:
                keys = self._eval_expr(stmt.value)
                self._publish(keys, stmt, "by a return")
        elif isinstance(stmt, ast.If):
            self._eval_expr(stmt.test)
            base = self._snapshot()
            self.process_body(stmt.body)
            body = self._snapshot()
            base["anon"] = body["anon"]
            self._restore(base)
            self.process_body(stmt.orelse)
            other = self._snapshot()
            self._restore(self._merge_snapshots(body, other))
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            iteration_keys = self._eval_expr(stmt.iter)
            self._bind(stmt.target, iteration_keys)
            self.process_body(stmt.body)
            self.process_body(stmt.orelse)
        elif isinstance(stmt, ast.While):
            self._eval_expr(stmt.test)
            self.process_body(stmt.body)
            self.process_body(stmt.orelse)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            self._process_with(stmt)
        elif isinstance(stmt, _TRY_NODES):
            self.process_body(stmt.body)
            for handler in stmt.handlers:
                if handler.type is not None:
                    self._eval_expr(handler.type)
                if handler.name:
                    self._unbind_name(handler.name)
                self.process_body(handler.body)
            self.process_body(stmt.orelse)
            self.process_body(stmt.finalbody)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in stmt.decorator_list:
                self._eval_expr(decorator)
            for default in stmt.args.defaults:
                self._eval_expr(default)
            for default in stmt.args.kw_defaults:
                if default is not None:
                    self._eval_expr(default)
        elif isinstance(stmt, ast.ClassDef):
            for decorator in stmt.decorator_list:
                self._eval_expr(decorator)
            for base in stmt.bases:
                self._eval_expr(base)
            for keyword in stmt.keywords:
                self._eval_expr(keyword.value)
        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                self._unbind(target)
        elif isinstance(stmt, ast.Raise):
            if stmt.exc is not None:
                self._eval_expr(stmt.exc)
            if stmt.cause is not None:
                self._eval_expr(stmt.cause)
        elif isinstance(stmt, ast.Assert):
            self._eval_expr(stmt.test)
            if stmt.msg is not None:
                self._eval_expr(stmt.msg)
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.asname:
                    self.aliases[alias.asname] = alias.name
                else:
                    root = alias.name.split(".", 1)[0]
                    self.aliases[root] = root
        elif isinstance(stmt, ast.ImportFrom):
            if stmt.module is not None:
                for alias in stmt.names:
                    if alias.name != "*":
                        self.aliases[alias.asname or alias.name] = (
                            stmt.module + "." + alias.name
                        )
        elif isinstance(stmt, ast.Match):
            self._eval_expr(stmt.subject)
            for case in stmt.cases:
                self.process_body(case.body)

    def _snapshot(self):
        return {
            "files": copy.deepcopy(self.files),
            "names": {name: set(keys) for name, keys in self.names.items()},
            "expr_lookup": {
                expr: set(keys) for expr, keys in self.expr_lookup.items()
            },
            "path_lookup": dict(self.path_lookup),
            "umask": self.umask,
            "constants": dict(self.constants),
            "openers": dict(self.openers),
            "anon": self.anon,
        }

    def _restore(self, snapshot):
        self.files = snapshot["files"]
        self.names = snapshot["names"]
        self.expr_lookup = snapshot["expr_lookup"]
        self.path_lookup = snapshot["path_lookup"]
        self.umask = snapshot["umask"]
        self.constants = snapshot["constants"]
        self.openers = snapshot["openers"]
        self.anon = snapshot["anon"]

    def _merge_snapshots(self, first, second):
        files = {}
        for key in set(first["files"]) | set(second["files"]):
            left = first["files"].get(key)
            right = second["files"].get(key)
            if left is None:
                files[key] = right
            elif right is None:
                files[key] = left
            else:
                files[key] = self._merge_files(left, right)
        names = {}
        for source in (first["names"], second["names"]):
            for name, keys in source.items():
                names.setdefault(name, set()).update(keys)
        expr_lookup = {}
        for source in (first["expr_lookup"], second["expr_lookup"]):
            expr_lookup.update(source)
        path_lookup = dict(first["path_lookup"])
        path_lookup.update(second["path_lookup"])
        umask = first["umask"] if first["umask"] == second["umask"] else None
        constants = dict(first["constants"])
        for name, value in second["constants"].items():
            if name in constants and constants[name] != value:
                constants.pop(name, None)
            elif name not in constants:
                constants[name] = value
        openers = dict(first["openers"])
        for name, mode in second["openers"].items():
            if openers.get(name) != mode:
                openers.pop(name, None)
        return {
            "files": files,
            "names": names,
            "expr_lookup": expr_lookup,
            "path_lookup": path_lookup,
            "umask": umask,
            "constants": constants,
            "openers": openers,
            "anon": max(first["anon"], second["anon"]),
        }

    def _merge_files(self, left, right):
        state = copy.deepcopy(left)
        state.written = left.written or right.written
        state.opened = left.opened or right.opened
        state.handles_open = max(left.handles_open, right.handles_open)
        state.reported = left.reported and right.reported
        candidates = [
            event
            for event in (left.wide_since, right.wide_since)
            if event is not None
        ]
        state.peak_mode = None
        for item in (left, right):
            if item.wide_since is not None:
                state.peak_mode = _wider_mode(state.peak_mode, item.peak_mode)
        state.wide_since = (
            min(candidates, key=lambda event: event.lineno)
            if candidates
            else None
        )
        if left.mode == right.mode:
            state.mode = left.mode
            state.mode_confidence = _confidence_floor(
                left.mode_confidence, right.mode_confidence
            )
        else:
            wide_sides = [
                item
                for item in (left, right)
                if item.wide_since is not None and item.mode is not None
            ]
            if wide_sides:
                chosen = max(
                    wide_sides,
                    key=lambda item: bool(item.mode & _WORLD_MASK),
                )
                state.mode = chosen.mode
                state.mode_confidence = _confidence_floor(
                    chosen.mode_confidence, bandit.MEDIUM
                )
            else:
                state.mode = None
                state.mode_confidence = _confidence_floor(
                    left.mode_confidence, right.mode_confidence
                )
        state.display = left.display or right.display
        state.path = left.path or right.path
        return state

    def _process_with(self, stmt):
        pending_close = []
        umask_entries = []
        for item in stmt.items:
            context_expr = item.context_expr
            if self._is_umask_context(context_expr):
                old_umask = self.umask
                new_umask = self._mode_of_call_arg(context_expr, 0, "mask")
                self.umask = new_umask
                umask_entries.append(old_umask)

            keys = self._eval_expr(context_expr)
            if item.optional_vars is not None:
                self._bind(item.optional_vars, keys)
            if keys and self._opens_handle(context_expr):
                pending_close.extend(keys)

        self.process_body(stmt.body)

        for old_umask in reversed(umask_entries):
            self.umask = old_umask
        for key in pending_close:
            self._close_key(key)

    def _process_assign(self, targets, value):
        if (
            len(targets) == 1
            and isinstance(targets[0], (ast.Tuple, ast.List))
            and isinstance(value, (ast.Tuple, ast.List))
            and len(targets[0].elts) == len(value.elts)
        ):
            for target, element in zip(targets[0].elts, value.elts):
                self._process_assign([target], element)
            return

        keys = self._eval_expr(value)

        if (
            len(targets) == 1
            and isinstance(targets[0], (ast.Tuple, ast.List))
            and isinstance(value, ast.Call)
            and _tail(_qualify(value.func, self.aliases) or "") == "mkstemp"
        ):
            for target in targets[0].elts:
                self._bind(target, keys)
        else:
            for target in targets:
                self._bind(target, keys)

        opener_mode = self._opener_mode(value)
        if opener_mode is not None:
            for target in targets:
                if isinstance(target, ast.Name):
                    self.openers[target.id] = opener_mode

        for target in targets:
            if isinstance(target, ast.Name) and not keys:
                constant = _constant_int(value, self.aliases, self.constants)
                if constant is None:
                    constant = _constant_str(
                        value, self.aliases, self.constants
                    )
                if constant is not None:
                    self.constants[target.id] = constant

    def _bind(self, target, keys):
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind(element, keys)
            return

        name = self._dotted_name(target)
        if name is None:
            return

        self._unbind_name(name)
        if keys:
            self.names[name] = set(keys)

    def _unbind(self, target):
        if isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._unbind(element)
            return
        name = self._dotted_name(target)
        if name is not None:
            self._unbind_name(name)

    def _unbind_name(self, name):
        self.names.pop(name, None)
        self.constants.pop(name, None)
        self.openers.pop(name, None)

    def _dotted_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._dotted_name(node.value)
            if base:
                return base + "." + node.attr
        return None

    def _eval_expr(self, node):
        if node is None:
            return set()

        if isinstance(node, ast.Call):
            return self._eval_call(node)

        if isinstance(node, ast.Name):
            return set(self.names.get(node.id, ()))

        if isinstance(node, ast.Attribute):
            name = self._dotted_name(node)
            if name and name in self.names:
                return set(self.names[name])
            if node.attr in ("name", "file", "parent"):
                return self._eval_expr(node.value)
            return set()

        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                key = self.path_lookup.get(os.path.normpath(node.value))
                if key is not None:
                    return {key}
            return set()

        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            keys = set()
            for element in node.elts:
                keys.update(self._eval_expr(element))
            return keys

        if isinstance(node, ast.Dict):
            keys = set()
            for value in node.values:
                keys.update(self._eval_expr(value))
            return keys

        if isinstance(node, ast.JoinedStr):
            keys = set()
            for value in node.values:
                keys.update(self._eval_expr(value))
            return keys

        if isinstance(node, ast.FormattedValue):
            return self._eval_expr(node.value)

        if isinstance(node, ast.BinOp):
            keys = self._eval_expr(node.left)
            keys.update(self._eval_expr(node.right))
            return keys

        if isinstance(node, ast.BoolOp):
            keys = set()
            for value in node.values:
                keys.update(self._eval_expr(value))
            return keys

        if isinstance(node, ast.IfExp):
            keys = self._eval_expr(node.body)
            keys.update(self._eval_expr(node.orelse))
            return keys

        if isinstance(node, ast.Await):
            return self._eval_expr(node.value)

        if isinstance(node, ast.Starred):
            return self._eval_expr(node.value)

        if isinstance(node, ast.NamedExpr):
            keys = self._eval_expr(node.value)
            self._bind(node.target, keys)
            return keys

        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            keys = self._eval_expr(node.value)
            self._publish(keys, node, "by a yield")
            return set()

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            for generator in node.generators:
                self._eval_expr(generator.iter)
                for condition in generator.ifs:
                    self._eval_expr(condition)
            return self._eval_expr(node.elt)

        if isinstance(node, ast.DictComp):
            for generator in node.generators:
                self._eval_expr(generator.iter)
                for condition in generator.ifs:
                    self._eval_expr(condition)
            keys = self._eval_expr(node.key)
            keys.update(self._eval_expr(node.value))
            return keys

        if isinstance(node, ast.Subscript):
            return self._eval_expr(node.value)

        if isinstance(node, ast.Compare):
            self._eval_expr(node.left)
            for comparator in node.comparators:
                self._eval_expr(comparator)
            return set()

        if isinstance(node, ast.Lambda):
            return set()

        return set()

    def _eval_call(self, node):
        cached = self.call_keys.get(id(node))
        if cached is not None:
            return set(cached)

        signature = _expr_signature(node)
        if signature is not None and signature in self.expr_lookup:
            result_keys = set(self.expr_lookup[signature])
            self.call_keys[id(node)] = frozenset(result_keys)
            return result_keys

        qualname = _qualify(node.func, self.aliases) or ""
        tail = _tail(qualname)

        object_keys = set()
        if isinstance(node.func, ast.Attribute):
            object_keys = self._eval_expr(node.func.value)

        arg_keys = [self._eval_expr(arg) for arg in node.args]
        keyword_keys = {}
        for keyword in node.keywords:
            if keyword.arg:
                keyword_keys[keyword.arg] = self._eval_expr(keyword.value)
            else:
                self._eval_expr(keyword.value)

        result_keys = set()

        # Methods on a file object or path object are kept separate from
        # module-level functions such as ``os.write``.
        if object_keys:
            if tail in _MODE_METHODS:
                self._apply_mode(
                    object_keys, self._call_mode(node, arg_keys, 0), node
                )
            elif tail in _CLOSE_METHODS:
                for key in object_keys:
                    self._close_key(key)
            elif tail in _WRITE_METHODS:
                self._mark_written(object_keys)
            elif tail == "open":
                result_keys = self._reopen_path(
                    node, object_keys, arg_keys, keyword_keys
                )
            elif tail in _MOVE_FUNCS:
                keys = set(object_keys)
                for keyset in arg_keys:
                    keys.update(keyset)
                self._publish(keys, node, "by a move")
            elif tail in _SENDFILE_FUNCS:
                self._publish(object_keys, node, "by a sendfile")
            elif self._name_suggests_publication(tail):
                keys = set(object_keys)
                for keyset in arg_keys:
                    keys.update(keyset)
                self._publish(
                    keys,
                    node,
                    "to " + _unparse(node.func),
                    bandit.MEDIUM,
                )
            elif tail == "fileno":
                result_keys = set(object_keys)
            elif tail in _READ_METHODS:
                result_keys = set()
            elif tail in _STRING_PASS_THROUGH_METHODS:
                result_keys = set(object_keys)
        elif tail in _MODE_FUNCS:
            target_keys = arg_keys[0] if arg_keys else set()
            mode = self._call_mode(node, arg_keys, 1)
            self._apply_mode(target_keys, mode, node)
        elif tail in _CLOSE_FUNCS:
            for key in arg_keys[0] if arg_keys else ():
                self._close_key(key)
        elif tail in _WRITE_FUNCS and arg_keys:
            self._mark_written(arg_keys[0])
        elif tail in _DUMP_FUNCS:
            self._mark_written(self._dump_target(node, arg_keys, keyword_keys))
        elif tail == "print":
            self._mark_written(keyword_keys.get("file", set()))
            published = set()
            for keys in arg_keys:
                published.update(keys)
            self._publish(published, node, "by printing")
        elif tail in _COPY_TO_DST_FUNCS:
            if len(arg_keys) > 1:
                self._mark_written(arg_keys[1])
            if arg_keys:
                self._publish(arg_keys[0], node, "by a copy")
        elif tail in _MOVE_FUNCS:
            keys = set()
            for keyset in arg_keys:
                keys.update(keyset)
            self._publish(keys, node, "by a move")
        elif tail in _SENDFILE_FUNCS:
            if len(arg_keys) > 1:
                self._publish(arg_keys[1], node, "by a sendfile")
            elif arg_keys:
                self._publish(arg_keys[0], node, "by a sendfile")
        elif qualname == "os.open" or (
            tail == "open" and qualname.startswith("os.")
        ):
            result_keys = self._create_os_open(node, arg_keys, keyword_keys)
        elif tail in _TEMP_APIS:
            result_keys = self._create_temp(node, tail)
        elif tail == "open":
            result_keys = self._create_open(node, arg_keys, keyword_keys)
        elif tail in ("fdopen", "dup", "dup2", "fileno"):
            result_keys = set(arg_keys[0]) if arg_keys else set(object_keys)
            if tail == "dup" and result_keys:
                for key in result_keys:
                    state = self.files.get(key)
                    if state is not None:
                        state.handles_open += 1
                        state.opened = True
        elif _is_path_call(qualname, _PATH_JOIN_FUNCS):
            for keys in arg_keys:
                result_keys.update(keys)
        elif _is_path_call(qualname, _PATH_SPLIT_FUNCS):
            if arg_keys:
                result_keys = set(arg_keys[0])
        elif tail in _PASS_THROUGH_FUNCS:
            if arg_keys:
                result_keys = set(arg_keys[0])
            if not result_keys and node.args:
                result_keys = self._key_for_path_node(node.args[0])
            if not result_keys and tail in _PATH_CONSTRUCTORS:
                result_keys = self._anonymous_state(node)
                self._bind_path_node(
                    node.args[0] if node.args else None, result_keys
                )
        elif tail == "umask":
            self.umask = self._call_mode(node, arg_keys, 0)
            result_keys = set()
        elif tail in _NO_PUBLISH_FUNCS:
            result_keys = set()
        elif tail in _METADATA_FUNCS:
            result_keys = set()
        elif tail in _FILE_WRAPPER_FUNCS:
            result_keys = set(arg_keys[0]) if arg_keys else set()
            for name in ("file", "fp", "stream"):
                if name in keyword_keys:
                    result_keys.update(keyword_keys[name])
        elif tail in _READ_FUNCS:
            result_keys = set()
        elif tail in _SAFE_BUILTINS:
            result_keys = set()
        elif self._is_local_call(qualname):
            if self._name_suggests_publication(tail):
                published = set()
                for keys in arg_keys:
                    published.update(keys)
                for keys in keyword_keys.values():
                    published.update(keys)
                self._publish(
                    published,
                    node,
                    "to " + _unparse(node.func),
                    bandit.MEDIUM,
                )
            result_keys = set()
        else:
            published = set()
            for keys in arg_keys:
                published.update(keys)
            for keys in keyword_keys.values():
                published.update(keys)
            if published:
                self._publish(published, node, "to " + _unparse(node.func))

        if not result_keys:
            signature = _expr_signature(node)
            if signature is not None:
                result_keys.update(self.expr_lookup.get(signature, ()))

        self.call_keys[id(node)] = frozenset(result_keys)
        return result_keys

    def _reopen_path(self, node, object_keys, arg_keys, keyword_keys):
        mode_text = "r"
        mode_node = None
        if node.args:
            mode_node = node.args[0]
        else:
            for keyword in node.keywords:
                if keyword.arg == "mode":
                    mode_node = keyword.value
                    break
        if mode_node is not None:
            constant = _constant_str(mode_node, self.aliases, self.constants)
            if constant is None:
                constant = "r"
            mode_text = constant

        if any(flag in mode_text for flag in ("w", "a", "x", "+")):
            mode = None
            if self.umask is not None:
                mode = _OPEN_MODE & ~self.umask
            for key in object_keys:
                state = self.files.get(key)
                if state is not None and state.mode is None and mode:
                    state.mode = mode
                    state.mode_confidence = bandit.MEDIUM

        self._increment_handle(object_keys)
        return set(object_keys)

    def _name_suggests_publication(self, name):
        lowered = name.lower()
        return any(
            lowered == hint
            or lowered.startswith(hint + "_")
            or lowered.endswith("_" + hint)
            for hint in _PUBLISHING_NAME_HINTS
        )

    def _is_local_call(self, qualname):
        if not qualname:
            return False
        if qualname.startswith(("self.", "cls.")):
            return _tail(qualname) in self.internal_names
        if qualname in self.internal_names:
            return True
        if qualname.startswith(_EXTERNAL_PREFIXES):
            return False
        return _tail(qualname) in self.internal_names

    def _call_mode(self, node, arg_keys, position):
        mode_node = None
        if len(node.args) > position:
            mode_node = node.args[position]
        else:
            for keyword in node.keywords:
                if keyword.arg in ("mode", "mask", "perm"):
                    mode_node = keyword.value
                    break
        if mode_node is None:
            return None
        return _constant_int(mode_node, self.aliases, self.constants)

    def _mode_of_call_arg(self, node, position, keyword_name):
        if not isinstance(node, ast.Call):
            return None
        if len(node.args) > position:
            return _constant_int(
                node.args[position], self.aliases, self.constants
            )
        for keyword in node.keywords:
            if keyword.arg == keyword_name:
                return _constant_int(
                    keyword.value, self.aliases, self.constants
                )
        return None

    def _is_umask_context(self, node):
        if not isinstance(node, ast.Call):
            return False
        qualname = _qualify(node.func, self.aliases) or ""
        if qualname == "os.umask":
            return False
        return _tail(qualname).endswith("umask")

    def _dump_target(self, node, arg_keys, keyword_keys):
        for name in _DUMP_TARGET_KEYWORDS:
            if name in keyword_keys:
                return keyword_keys[name]
        if len(arg_keys) > 1:
            return arg_keys[1]
        return set()

    def _mark_written(self, keys):
        for key in keys:
            state = self.files.get(key)
            if state is not None:
                state.written = True

    def _close_key(self, key):
        state = self.files.get(key)
        if state is None:
            return
        state.handles_open = max(0, state.handles_open - 1)

    def _create_temp(self, node, tail):
        key = ("temp", self.anon)
        self.anon += 1
        state = _FileState(
            key,
            _unparse(node),
            mode=_TEMP_MODE,
            confidence=bandit.HIGH,
        )
        state.handles_open = 1
        state.opened = True
        self.files[key] = state
        return {key}

    def _create_open(self, node, arg_keys, keyword_keys):
        mode_node = None
        if len(node.args) > 1:
            mode_node = node.args[1]
        else:
            for keyword in node.keywords:
                if keyword.arg == "mode":
                    mode_node = keyword.value
                    break

        mode_text = "r"
        if mode_node is not None:
            constant = _constant_str(mode_node, self.aliases, self.constants)
            if constant is None:
                keys = set(arg_keys[0]) if arg_keys else set()
                if not keys:
                    keys = self._key_for_path_node(
                        node.args[0] if node.args else None
                    )
                if not keys:
                    keys = self._anonymous_state(node)
                self._bind_path_node(node.args[0] if node.args else None, keys)
                self._increment_handle(keys)
                return keys
            mode_text = constant

        if not any(flag in mode_text for flag in ("w", "a", "x", "+")):
            keys = set(arg_keys[0]) if arg_keys else set()
            if not keys:
                keys = self._key_for_path_node(
                    node.args[0] if node.args else None
                )
            self._increment_handle(keys)
            return keys

        mode = None
        confidence = bandit.HIGH
        opener = self._opener_node(node)
        if opener is not None:
            mode = self._opener_mode(opener)
            if mode is not None:
                if self.umask is not None:
                    mode &= ~self.umask
                    confidence = bandit.MEDIUM
                elif _is_wide(mode):
                    mode = None
        elif self.umask is not None:
            mode = _OPEN_MODE & ~self.umask
            confidence = bandit.MEDIUM

        return self._key_for_created_path(
            node.args[0] if node.args else None,
            arg_keys[0] if arg_keys else set(),
            mode,
            confidence,
            node,
        )

    def _opener_node(self, node):
        for keyword in node.keywords:
            if keyword.arg == "opener":
                return keyword.value
        return None

    def _opener_mode(self, opener):
        return _static_opener_mode(
            opener, self.aliases, self.constants, self.openers
        )

    def _create_os_open(self, node, arg_keys, keyword_keys):
        flags = None
        if len(node.args) > 1:
            flags = _constant_int(node.args[1], self.aliases, self.constants)
        else:
            for keyword in node.keywords:
                if keyword.arg == "flags":
                    flags = _constant_int(
                        keyword.value, self.aliases, self.constants
                    )
        mode = None
        if len(node.args) > 2:
            mode = _constant_int(node.args[2], self.aliases, self.constants)
        else:
            for keyword in node.keywords:
                if keyword.arg == "mode":
                    mode = _constant_int(
                        keyword.value, self.aliases, self.constants
                    )

        confidence = bandit.HIGH
        if mode is not None:
            if self.umask is not None:
                mode &= ~self.umask
                confidence = bandit.MEDIUM
            elif _is_wide(mode):
                mode = None

        creates = flags is None or bool(
            flags & (os.O_CREAT | getattr(os, "O_TMPFILE", 0))
        )
        if not creates:
            keys = set(arg_keys[0]) if arg_keys else set()
            if not keys:
                keys = self._key_for_path_node(
                    node.args[0] if node.args else None
                )
            self._increment_handle(keys)
            return keys

        return self._key_for_created_path(
            node.args[0] if node.args else None,
            arg_keys[0] if arg_keys else set(),
            mode,
            confidence,
            node,
        )

    def _anonymous_state(self, node, mode=None, confidence=None):
        key = ("temp", self.anon)
        self.anon += 1
        state = _FileState(
            key, _unparse(node), mode=mode, confidence=confidence
        )
        self.files[key] = state
        return {key}

    def _key_for_created_path(
        self, path_node, path_keys, mode, confidence, creation_node
    ):
        keys = set(path_keys)
        path = (
            _constant_str(path_node, self.aliases, self.constants)
            if path_node is not None
            else None
        )
        if path is not None:
            normalized = os.path.normpath(path)
            key = ("path", normalized)
            keys.add(key)
            self.path_lookup[normalized] = key
            state = self.files.get(key)
            if state is None:
                state = _FileState(
                    key,
                    path,
                    path=path,
                    mode=mode,
                    confidence=confidence,
                )
                self.files[key] = state
        elif not keys:
            keys = self._anonymous_state(creation_node, mode, confidence)

        self._bind_path_node(path_node, keys)
        signature = _expr_signature(path_node)
        if signature is not None and keys:
            self.expr_lookup[signature] = set(keys)

        for key in keys:
            state = self.files.get(key)
            if state is None:
                state = _FileState(
                    key,
                    _unparse(creation_node),
                    mode=mode,
                    confidence=confidence,
                )
                self.files[key] = state
            elif state.mode is None and mode is not None:
                state.mode = mode
                state.mode_confidence = confidence
            state.handles_open += 1
            state.opened = True
        return keys

    def _key_for_path_node(self, path_node):
        if path_node is None:
            return set()
        path = _constant_str(path_node, self.aliases, self.constants)
        if path is None:
            return set()
        normalized = os.path.normpath(path)
        key = ("path", normalized)
        if key not in self.files:
            self.files[key] = _FileState(key, path, path=path, mode=None)
        self.path_lookup[normalized] = key
        self._bind_path_node(path_node, {key})
        signature = _expr_signature(path_node)
        if signature is not None:
            self.expr_lookup[signature] = {key}
        return {key}

    def _bind_path_node(self, path_node, keys):
        if path_node is None or not keys:
            return
        name = self._dotted_name(path_node)
        if name is not None:
            self.names[name] = set(keys)

    def _increment_handle(self, keys):
        for key in keys:
            state = self.files.get(key)
            if state is not None:
                state.handles_open += 1
                state.opened = True

    def _opens_handle(self, node):
        if not isinstance(node, ast.Call):
            return False
        tail = _tail(_qualify(node.func, self.aliases) or "")
        return tail in ({"open", "fdopen", "mkstemp", "dup"} | _TEMP_APIS)

    def _apply_mode(self, keys, mode, node):
        for key in keys:
            state = self.files.get(key)
            if state is None:
                continue
            if mode is None:
                state.mode = None
                state.wide_since = None
                state.peak_mode = None
                state.reported = False
                continue

            if _is_wide(mode):
                if (
                    state.mode is not None
                    and not _is_wide(state.mode)
                    and state.wide_since is None
                ):
                    state.wide_since = _Event(
                        node.lineno, mode, state.mode_confidence
                    )
                    state.peak_mode = mode
                    state.reported = False
                elif state.wide_since is not None:
                    state.peak_mode = _wider_mode(state.peak_mode, mode)
            else:
                state.wide_since = None
                state.peak_mode = None
                state.reported = False

            state.mode = mode
            state.mode_confidence = bandit.HIGH

    def _publish(self, keys, node, reason, confidence=None):
        for key in keys:
            state = self.files.get(key)
            if (
                state is None
                or not state.written
                or state.wide_since is None
                or state.reported
            ):
                continue
            report_mode = state.peak_mode or state.mode
            if report_mode is None or not _is_wide(report_mode):
                continue

            state.reported = True
            confidence = _confidence_floor(
                state.mode_confidence,
                state.wide_since.confidence,
                confidence or bandit.HIGH,
            )
            if not state.opened:
                lifecycle = ""
            elif state.handles_open:
                lifecycle = " before the handle was closed"
            else:
                lifecycle = " after the handle was closed"
            text = (
                "Restricted file (%s) is externally published %s%s while "
                "permissions are permissive (%s). Permissions were widened "
                "on line %d; restoring them later does not undo the "
                "exposure."
            ) % (
                state.display,
                reason,
                lifecycle,
                oct(report_mode),
                state.wide_since.lineno,
            )
            self.findings.append(
                _Finding(
                    node,
                    _severity_for_mode(report_mode),
                    confidence,
                    text,
                )
            )


def _iter_scopes(node):
    if isinstance(node, ast.Module):
        yield node.body
    for child in ast.walk(node):
        if isinstance(
            child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            yield child.body


def _merge_findings(first, second):
    rank = constants.RANKING
    severity = max((first.severity, second.severity), key=rank.index)
    confidence = min((first.confidence, second.confidence), key=rank.index)
    text = first.text
    if second.text not in text:
        text = text + " " + second.text
    return _Finding(
        None,
        severity,
        confidence,
        text,
        lineno=first.lineno,
        col_offset=first.col_offset,
        node_key=first.node_key,
    )


def analyze_source(source):
    """Analyze one module's source without importing or executing it."""
    tree = ast.parse(source)
    aliases = _collect_import_aliases(tree)
    constants = _collect_module_constants(tree, aliases)
    internal_names = _collect_internal_names(tree)
    openers = _collect_module_openers(tree, aliases, constants)
    findings = []

    for body in _iter_scopes(tree):
        analyzer = _ScopeAnalyzer(
            findings, constants, aliases, internal_names, openers
        )
        analyzer.process_body(body)

    findings.sort(key=lambda finding: (finding.lineno, finding.col_offset))
    return findings


_CACHE = {}


def _findings_for_context(context):
    fdata = context.file_data
    cache_key = id(fdata)

    cached = _CACHE.get(cache_key)
    if cached is not None and cached["fdata"] is fdata:
        return cached

    fdata.seek(0)
    data = fdata.read()
    fdata.seek(0)

    try:
        findings = analyze_source(data)
    except (SyntaxError, ValueError):
        findings = []

    by_node = {}
    for finding in findings:
        existing = by_node.get(finding.node_key)
        if existing is None:
            by_node[finding.node_key] = finding
        else:
            by_node[finding.node_key] = _merge_findings(existing, finding)

    if len(_CACHE) > 32:
        _CACHE.clear()
    merged_findings = sorted(
        by_node.values(),
        key=lambda finding: (finding.lineno, finding.col_offset),
    )
    result = {
        "fdata": fdata,
        "findings": merged_findings,
        "by_node": by_node,
        "returned": set(),
    }
    _CACHE[cache_key] = result
    return result


@test.checks("File", "Call", "Return", "Yield", "YieldFrom")
@test.test_id("B114")
def file_permission_window(context):
    if context.file_data is None:
        return None

    cached = _findings_for_context(context)
    node = context._context.get("node")

    if node is not None:
        finding = cached["by_node"].get(_node_key(node))
        if finding is not None and id(finding) not in cached["returned"]:
            cached["returned"].add(id(finding))
            return finding.to_issue()
        return None

    for finding in cached["findings"]:
        if id(finding) not in cached["returned"]:
            cached["returned"].add(id(finding))
            return finding.to_issue()
    return None
