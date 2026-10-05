"""Source location metadata for tokens."""

import codecs


class SourceRange:
    """A half-open character range in the original SQL source."""

    __slots__ = ("end", "source", "start")

    def __init__(self, start, end, source=None):
        self.start = start
        self.end = end
        self.source = source

    def __iter__(self):
        yield self.start
        yield self.end

    def __eq__(self, other):
        if isinstance(other, SourceRange):
            other = other.start, other.end
        if isinstance(other, tuple):
            return (self.start, self.end) == other
        return NotImplemented

    def __hash__(self):
        return hash((self.start, self.end))

    def __repr__(self):
        return f"SourceRange({self.start!r}, {self.end!r})"

    def byte_range(self, encoding="utf-8", errors="strict"):
        """Return the corresponding half-open byte range."""
        if self.source is None:
            raise ValueError("source text is required to calculate bytes")

        incremental_encoder = codecs.getincrementalencoder(encoding)
        start = len(incremental_encoder(errors).encode(
            self.source[:self.start], False))
        end = len(incremental_encoder(errors).encode(
            self.source[:self.end], False))
        return start, end
