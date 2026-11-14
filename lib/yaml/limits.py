__all__ = ['ResourceLimits', 'ResourceBudgetExceeded']

from .error import YAMLError


class ResourceBudgetExceeded(YAMLError):
    """Raised when parsing a YAML stream exceeds its configured resource
    budget.

    The exception is raised while the representation tree is still being
    built, so a malicious document cannot exhaust memory before it is
    rejected.
    """

    def __init__(self, resource, limit, used, mark=None):
        self.resource = resource
        self.limit = limit
        self.used = used
        self.mark = mark

    def __str__(self):
        location = ''
        if self.mark is not None:
            location = '\n  in "%s", line %d, column %d' % (
                    self.mark.name, self.mark.line + 1, self.mark.column + 1)
        return ('resource budget exceeded: %s limit is %d, but at least %d '
                'units were requested' % (
                        self.resource, self.limit, self.used)) + location


class ResourceLimits(object):
    """Configurable resource budget enforced while parsing YAML.

    Every limit is checked incrementally: each consumed unit is charged as
    soon as it is read or composed, before the full representation tree or
    Python object graph is constructed. A value of ``None`` disables the
    corresponding limit; passing ``None`` for every limit disables the whole
    budget and is only exposed through the explicitly unsafe loader entries.

    Parameters:
        max_bytes: maximum amount of input accepted by the reader: string
            length for unicode input and raw byte length for bytes/stream
            input (the stream figure therefore matches a gateway that only
            inspects the upload size).
        max_scalar_length: sum of the lengths of every scalar value, with
            aliases charged every time an alias references a scalar node.
        max_nodes: number of composed nodes, excluding alias events, which
            return a previously composed node.
        max_aliases: number of alias expansions, i.e. ``*anchor`` events.
        max_depth: maximum nesting depth of collections.
        max_anchor_refs: maximum number of aliases that may reference a
            single anchor name.
    """

    # The defaults are deliberately generous enough for ordinary, even fairly
    # large, configuration documents while keeping a single document's peak
    # memory usage bounded.
    DEFAULT_MAX_BYTES = 10 * 1024 * 1024
    DEFAULT_MAX_SCALAR_LENGTH = 10 * 1024 * 1024
    DEFAULT_MAX_NODES = 1_000_000
    DEFAULT_MAX_ALIASES = 100_000
    # Stays below the recursion ceiling of the pure-Python parser so the
    # dedicated budget exception is raised before a native RecursionError.
    DEFAULT_MAX_DEPTH = 400
    DEFAULT_MAX_ANCHOR_REFS = 100_000

    def __init__(self, max_bytes=DEFAULT_MAX_BYTES,
            max_scalar_length=DEFAULT_MAX_SCALAR_LENGTH,
            max_nodes=DEFAULT_MAX_NODES,
            max_aliases=DEFAULT_MAX_ALIASES,
            max_depth=DEFAULT_MAX_DEPTH,
            max_anchor_refs=DEFAULT_MAX_ANCHOR_REFS):
        self.max_bytes = max_bytes
        self.max_scalar_length = max_scalar_length
        self.max_nodes = max_nodes
        self.max_aliases = max_aliases
        self.max_depth = max_depth
        self.max_anchor_refs = max_anchor_refs

        self.bytes_read = 0
        self.scalar_length = 0
        self.nodes = 0
        self.aliases = 0
        self.depth = 0
        self.anchor_references = {}

    @classmethod
    def unlimited(cls):
        """Return a budget with every limit disabled.

        This restores the historical, unbounded parsing behaviour and must
        only be used with trusted input.
        """
        return cls(None, None, None, None, None, None)

    @property
    def enabled(self):
        return (
                self.max_bytes is not None
                or self.max_scalar_length is not None
                or self.max_nodes is not None
                or self.max_aliases is not None
                or self.max_depth is not None
                or self.max_anchor_refs is not None)

    def enforce(self, resource, used, limit, mark=None):
        """Raise if the cumulative ``used`` amount passes ``limit``."""
        if limit is None or used <= limit:
            return
        raise ResourceBudgetExceeded(resource, limit, used, mark)

    def charge_bytes(self, amount, mark=None):
        self.bytes_read += amount
        self.enforce('input byte', self.bytes_read, self.max_bytes, mark)

    def charge_scalar(self, length, mark=None):
        self.scalar_length += length
        self.enforce('scalar length', self.scalar_length,
                self.max_scalar_length, mark)

    def charge_node(self, mark=None):
        self.nodes += 1
        self.enforce('node', self.nodes, self.max_nodes, mark)

    def charge_alias(self, anchor, mark=None):
        self.aliases += 1
        self.enforce('alias expansion', self.aliases,
                self.max_aliases, mark)
        references = self.anchor_references.get(anchor, 0) + 1
        self.anchor_references[anchor] = references
        self.enforce('anchor reference width for %r' % anchor,
                references, self.max_anchor_refs, mark)

    def enter_collection(self, mark=None):
        self.depth += 1
        self.enforce('collection depth', self.depth, self.max_depth, mark)

    def leave_collection(self):
        self.depth -= 1
