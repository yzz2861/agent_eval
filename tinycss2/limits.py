"""
Configurable resource limits for the tokenizer.

Limits protect callers against pathological inputs (unclosed strings or
comments, deeply nested blocks, huge identifiers, runaway escape sequences
or token explosions) while keeping a generous headroom for legitimate large
stylesheets such as long ``data:`` URIs.

Every call to a parsing entry point creates a fresh :class:`_Budget`, so
limits are never shared between parses and no global mutable state is used.

"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceLimits:
    """Resource limits enforced while tokenizing a single CSS string.

    Each limit can be raised up to the corresponding absolute maximum.  A
    value of :obj:`None` selects the documented default; values must be
    positive integers and cannot exceed the absolute maximum.

    .. attribute:: max_characters

        Maximum number of Unicode code points accepted in a single input.

    .. attribute:: max_token_bytes

        Maximum UTF-8 size, in bytes, of a single token (identifier,
        string, URL, comment, ...).

    .. attribute:: max_nesting

        Maximum nesting depth of blocks and maximum number of nested
        comment openers (``/*``) contained in one comment.

    .. attribute:: max_consecutive_escapes

        Maximum number of escape sequences consumed while building a single
        token.

    .. attribute:: max_tokens

        Maximum number of tokens (including comments and parse errors)
        produced by one parse.

    """

    max_characters: int | None = None
    max_token_bytes: int | None = None
    max_nesting: int | None = None
    max_consecutive_escapes: int | None = None
    max_tokens: int | None = None

    ABSOLUTE_MAX_CHARACTERS = 100_000_000
    ABSOLUTE_MAX_TOKEN_BYTES = 50_000_000
    ABSOLUTE_MAX_NESTING = 10_000
    ABSOLUTE_MAX_CONSECUTIVE_ESCAPES = 1_000_000
    ABSOLUTE_MAX_TOKENS = 10_000_000

    DEFAULT_MAX_CHARACTERS = 10_000_000
    DEFAULT_MAX_TOKEN_BYTES = 2_000_000
    DEFAULT_MAX_NESTING = 100
    DEFAULT_MAX_CONSECUTIVE_ESCAPES = 10_000
    DEFAULT_MAX_TOKENS = 100_000

    def __post_init__(self):
        checks = (
            ('max_characters', self.max_characters,
             self.DEFAULT_MAX_CHARACTERS,
             self.ABSOLUTE_MAX_CHARACTERS),
            ('max_token_bytes', self.max_token_bytes,
             self.DEFAULT_MAX_TOKEN_BYTES,
             self.ABSOLUTE_MAX_TOKEN_BYTES),
            ('max_nesting', self.max_nesting,
             self.DEFAULT_MAX_NESTING,
             self.ABSOLUTE_MAX_NESTING),
            ('max_consecutive_escapes', self.max_consecutive_escapes,
             self.DEFAULT_MAX_CONSECUTIVE_ESCAPES,
             self.ABSOLUTE_MAX_CONSECUTIVE_ESCAPES),
            ('max_tokens', self.max_tokens,
             self.DEFAULT_MAX_TOKENS,
             self.ABSOLUTE_MAX_TOKENS),
        )
        for name, value, default, absolute_max in checks:
            if value is None:
                value = default
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value <= 0 or value > absolute_max):
                raise ValueError(
                    f'{name} must be an integer between 1 and '
                    f'{absolute_max}, got {value!r}')
            object.__setattr__(self, name, value)


class _Budget:
    """Per-parse mutable resource accounting.

    A new instance is created at the start of every parse, which guarantees
    that counters can never leak between calls.

    """

    def __init__(self, limits):
        if limits is None:
            limits = ResourceLimits()
        elif not isinstance(limits, ResourceLimits):
            raise TypeError(
                'limits must be a ResourceLimits instance or None, got '
                f'{type(limits).__name__}')
        self.limits = limits
        self.token_count = 0
        self.token_bytes = 0
        self.escape_count = 0

    def begin_token(self):
        """Reset counters that are scoped to a single token."""
        self.token_bytes = 0
        self.escape_count = 0

    def add_token_bytes(self, chunk):
        """Account for a (unicode) chunk appended to the current token.

        Returns an error tuple when the per-token byte limit is exceeded,
        :obj:`None` otherwise.

        """
        if not chunk:
            return None
        self.token_bytes += len(chunk.encode('utf-8', 'surrogatepass'))
        if self.token_bytes > self.limits.max_token_bytes:
            return ('token-too-long',
                    f'Token exceeds {self.limits.max_token_bytes} bytes')
        return None

    def charge_escape(self):
        """Account for one escape inside the current token."""
        self.escape_count += 1
        if self.escape_count > self.limits.max_consecutive_escapes:
            return ('too-many-escapes',
                    'Token contains more than '
                    f'{self.limits.max_consecutive_escapes} escapes')
        return None

    def add_token(self):
        """Account for one emitted output token."""
        self.token_count += 1
        if self.token_count > self.limits.max_tokens:
            return ('too-many-tokens',
                    f'Parsing produced more than {self.limits.max_tokens} '
                    'tokens')
        return None
