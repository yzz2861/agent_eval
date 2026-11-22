
"""
Opt-in safe export of configuration data for different audiences.

``safe_export`` produces two YAML renderings of the same object graph:

* ``internal`` keeps every value and the ordinary sharing structure, so it
  can be read back with ``yaml.safe_load`` and shared nodes stay shared.
* ``external`` replaces caller-marked sensitive values with a placeholder
  and cuts anchors/aliases that would otherwise expose a marked value
  through a shared node.

Sensitive values are marked explicitly by the caller, either by wrapping
them in ``Sensitive`` or by passing them in the ``sensitive`` iterable.
Matching is done by object identity, which also covers values shared
through YAML merge keys (``<<``) after ``safe_load`` has flattened them.

The returned ``ExportResult`` carries both documents plus a list of
warnings (for example about values that cannot be serialized safely and
were substituted) so the caller can review the outcome before sharing.
"""

__all__ = ['Sensitive', 'ExportResult', 'safe_export']

from .dumper import SafeDumper

DEFAULT_PLACEHOLDER = '***REDACTED***'


class Sensitive:
    """
    Wrapper marking a value as sensitive for ``safe_export``.

    The wrapped value (and everything it contains) is redacted in the
    external document and unwrapped again in the internal document.
    """

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return 'Sensitive(...)'


class ExportResult:
    """
    Outcome of ``safe_export`` for caller review.

    Attributes:
        internal: YAML document with all values intact.
        external: YAML document with marked values redacted.
        warnings: human-readable notes about substitutions made.
        redacted: number of nodes replaced by the placeholder.
    """

    def __init__(self, internal, external, warnings, redacted):
        self.internal = internal
        self.external = external
        self.warnings = warnings
        self.redacted = redacted

    def __iter__(self):
        return iter((self.internal, self.external))

    def __repr__(self):
        return 'ExportResult(redacted=%r, warnings=%r)' % (
                self.redacted, len(self.warnings))


def _is_safe_representable(value):
    # Mirror BaseRepresenter.represent_data's lookup, but treat the
    # None fallback as unrepresentable: SafeRepresenter maps it to
    # represent_undefined, which raises RepresenterError.
    mro = type(value).__mro__
    if mro[0] in SafeDumper.yaml_representers:
        return True
    for cls in mro[1:]:
        if cls in SafeDumper.yaml_multi_representers:
            return True
    return False


class _Scanner:
    """Collect identity-based facts about the object graph."""

    def __init__(self):
        self.marked = set()     # ids explicitly marked as sensitive
        self.tainted = set()    # marked ids plus all their ancestors
        self.refcount = {}      # id -> number of inbound references
        self.parents = {}       # id -> set of parent ids
        self.visited = set()

    def scan(self, root, extra_sensitive):
        for value in extra_sensitive:
            self._mark_subtree(value)
        stack = [(root, None)]
        while stack:
            node, parent = stack.pop()
            oid = id(node)
            self.refcount[oid] = self.refcount.get(oid, 0) + 1
            if parent is not None:
                self.parents.setdefault(oid, set()).add(parent)
            if oid in self.visited:
                continue
            self.visited.add(oid)
            if isinstance(node, Sensitive):
                self.marked.add(oid)
                self._mark_subtree(node.value)
                continue
            if isinstance(node, dict):
                for key, value in node.items():
                    stack.append((key, oid))
                    stack.append((value, oid))
            elif isinstance(node, (list, tuple, set, frozenset)):
                for item in node:
                    stack.append((item, oid))

    def _mark_subtree(self, node):
        stack = [node]
        while stack:
            node = stack.pop()
            oid = id(node)
            if oid in self.marked:
                continue
            self.marked.add(oid)
            if isinstance(node, Sensitive):
                stack.append(node.value)
            elif isinstance(node, dict):
                stack.extend(node.keys())
                stack.extend(node.values())
            elif isinstance(node, (list, tuple, set, frozenset)):
                stack.extend(node)

    def propagate(self):
        # A container is tainted when its subtree holds a marked node.
        queue = list(self.marked)
        self.tainted = set(self.marked)
        while queue:
            oid = queue.pop()
            for pid in self.parents.get(oid, ()):
                if pid not in self.tainted:
                    self.tainted.add(pid)
                    queue.append(pid)

    def is_cut(self, oid):
        # Shared nodes whose subtree exposes a marked value must not be
        # emitted as anchor/alias pairs in the external document.
        return oid in self.tainted and self.refcount.get(oid, 1) > 1


class _Context:
    def __init__(self, scanner, placeholder):
        self.scanner = scanner
        self.placeholder = placeholder
        self.warnings = []
        self.redacted = 0
        self.tuples_in_progress = set()

    def warn(self, message):
        self.warnings.append(message)

    def fallback(self, node, path):
        self.warn("cannot safely serialize value of type %s at %s; "
                "substituted a plain placeholder"
                % (type(node).__name__, path))
        return '<unserializable: %s>' % type(node).__name__


def _check_key(new_key, path, ctx):
    try:
        hash(new_key)
    except TypeError:
        ctx.warn("mapping key at %s is not hashable after export "
                "processing; substituted a plain placeholder" % path)
        return '<unserializable key>'
    return new_key


def _internal_key(key, memo, path, ctx):
    return _check_key(_internal(key, memo, path + '.<key>', ctx), path, ctx)


def _external_key(key, memo, local, path, ctx):
    return _check_key(_external(key, memo, local, path + '.<key>', ctx),
            path, ctx)


def _transform_tuple(node, transform_item, path, ctx):
    # Tuples are immutable, so they cannot be memoized before their
    # items are transformed.  A tuple can only be recursive through a
    # mutable intermediary; guard against re-entering it.
    oid = id(node)
    if oid in ctx.tuples_in_progress:
        ctx.warn("recursive tuple at %s cannot be preserved; "
                "cut the cycle" % path)
        return ctx.fallback(node, path)
    ctx.tuples_in_progress.add(oid)
    try:
        return tuple(transform_item(item, index)
                for index, item in enumerate(node))
    finally:
        ctx.tuples_in_progress.discard(oid)


def _internal(node, memo, path, ctx):
    if isinstance(node, Sensitive):
        return _internal(node.value, memo, path, ctx)
    oid = id(node)
    if isinstance(node, dict):
        if oid in memo:
            return memo[oid]
        new = {}
        memo[oid] = new
        for key, value in node.items():
            new[_internal_key(key, memo, path, ctx)] = _internal(
                    value, memo, '%s.%s' % (path, key), ctx)
        return new
    if isinstance(node, list):
        if oid in memo:
            return memo[oid]
        new = []
        memo[oid] = new
        new.extend(_internal(item, memo, '%s[%d]' % (path, index), ctx)
                for index, item in enumerate(node))
        return new
    if isinstance(node, tuple):
        if oid in memo:
            return memo[oid]
        new = _transform_tuple(node,
                lambda item, index: _internal(item, memo,
                    '%s[%d]' % (path, index), ctx),
                path, ctx)
        memo[oid] = new
        return new
    if isinstance(node, set):
        if oid in memo:
            return memo[oid]
        new = set(_internal(item, memo, '%s[*]' % path, ctx) for item in node)
        memo[oid] = new
        return new
    if not _is_safe_representable(node):
        return ctx.fallback(node, path)
    return node


def _external(node, memo, local, path, ctx):
    oid = id(node)
    if isinstance(node, Sensitive) or oid in ctx.scanner.marked:
        ctx.redacted += 1
        return ctx.placeholder
    if oid in memo:
        return memo[oid]
    if oid in local:
        return local[oid]
    if isinstance(node, dict):
        new = {}
        if ctx.scanner.is_cut(oid):
            # Cut the reference: this copy is not shared through the
            # global memo, so no anchor/alias can expose the redacted
            # subtree.  Recursive back-edges still resolve locally.
            child_local = dict(local)
            child_local[oid] = new
        else:
            memo[oid] = new
            child_local = local
        for key, value in node.items():
            new[_external_key(key, memo, child_local, path, ctx)] = \
                    _external(value, memo, child_local,
                        '%s.%s' % (path, key), ctx)
        return new
    if isinstance(node, list):
        new = []
        if ctx.scanner.is_cut(oid):
            child_local = dict(local)
            child_local[oid] = new
        else:
            memo[oid] = new
            child_local = local
        new.extend(_external(item, memo, child_local,
                '%s[%d]' % (path, index), ctx)
                for index, item in enumerate(node))
        return new
    if isinstance(node, tuple):
        new = _transform_tuple(node,
                lambda item, index: _external(item, memo, local,
                    '%s[%d]' % (path, index), ctx),
                path, ctx)
        if not ctx.scanner.is_cut(oid):
            memo[oid] = new
        return new
    if isinstance(node, set):
        new = set(_external(item, memo, local, '%s[*]' % path, ctx)
                for item in node)
        if not ctx.scanner.is_cut(oid):
            memo[oid] = new
        return new
    if not _is_safe_representable(node):
        return ctx.fallback(node, path)
    return node


def safe_export(data, sensitive=(), placeholder=DEFAULT_PLACEHOLDER, **kwds):
    """
    Export ``data`` as a pair of YAML documents for internal and
    external audiences and return an ``ExportResult``.

    ``sensitive`` is an iterable of additional values to treat as
    sensitive; values wrapped in ``Sensitive`` are always treated as
    sensitive.  Matching is by object identity, so every reference to a
    marked object is redacted in the external document, no matter under
    which name it appears.  Extra keyword arguments are passed to
    ``yaml.safe_dump``.
    """
    from . import safe_dump
    scanner = _Scanner()
    scanner.scan(data, sensitive)
    scanner.propagate()
    ctx = _Context(scanner, placeholder)
    internal_data = _internal(data, {}, '$', ctx)
    external_data = _external(data, {}, {}, '$', ctx)
    internal_yaml = safe_dump(internal_data, **kwds)
    external_yaml = safe_dump(external_data, **kwds)
    return ExportResult(internal_yaml, external_yaml,
            ctx.warnings, ctx.redacted)
