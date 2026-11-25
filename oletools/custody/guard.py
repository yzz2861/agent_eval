"""Read guards that make it impossible to read outside an approved range.

The progressive workflow is only safe if no code path can accidentally
consume bytes of an object that has not been approved yet.  :class:`RangeGate`
describes the byte ranges that are currently approved and
:class:`GuardedFile` wraps any binary file-like object so that reads are
checked *before* touching the underlying file.  This guarantees that an
automated check never reads unapproved content first, even if a parser
misbehaves.
"""

from __future__ import print_function

from .errors import AccessDeniedError


class RangeGate(object):
    """Immutable description of the byte ranges that may be read.

    Ranges are half-open intervals ``[start, end)`` expressed as absolute
    byte offsets in the guarded file.  An empty gate denies every read; a
    gate containing ``(0, filesize)`` allows reading the whole file.
    """

    def __init__(self, ranges=None):
        normalized = []
        for start, end in (ranges or ()):
            if start < 0 or end < start:
                raise ValueError('invalid range: {0!r}'.format((start, end)))
            if start != end:
                normalized.append((int(start), int(end)))
        normalized.sort()
        merged = []
        for start, end in normalized:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        self._ranges = tuple(merged)

    @classmethod
    def deny_all(cls):
        """Return a gate that rejects every read."""
        return cls()

    @classmethod
    def allow_all(cls, size):
        """Return a gate that allows reading the first ``size`` bytes."""
        return cls(((0, size),))

    @property
    def ranges(self):
        """Tuple of merged, sorted, half-open byte ranges."""
        return self._ranges

    def is_allowed(self, start, length):
        """Return ``True`` only if the whole interval is covered."""
        if length < 0:
            raise ValueError('length must not be negative')
        if length == 0:
            return True
        end = start + length
        for range_start, range_end in self._ranges:
            if range_start <= start and end <= range_end:
                return True
            if start < range_start:
                return False
        return False

    def to_dict(self):
        """Serialize to plain JSON-compatible data."""
        return [{'start': start, 'end': end} for start, end in self._ranges]

    @classmethod
    def from_dict(cls, data):
        """Rebuild a gate from :meth:`to_dict` output."""
        ranges = tuple((item['start'], item['end']) for item in (data or ()))
        return cls(ranges)

    def __eq__(self, other):
        return isinstance(other, RangeGate) and other._ranges == self._ranges

    def __repr__(self):
        return 'RangeGate({0!r})'.format(self._ranges)


class GuardedFile(object):
    """Binary file-like wrapper enforcing a :class:`RangeGate`.

    Every ``read``/``seek``/``tell`` call is validated before delegating to
    the wrapped stream.  Reads that would cross an approved boundary raise
    :class:`~oletools.custody.errors.AccessDeniedError` without returning any
    byte, so callers cannot partially consume unapproved data.
    """

    def __init__(self, stream, gate, name='<stream>'):
        self._stream = stream
        self._gate = gate
        self.name = name
        self._closed = False
        self._position = self._stream.tell()

    @property
    def gate(self):
        return self._gate

    def readable(self):
        return True

    def seekable(self):
        return True

    def writable(self):
        return False

    def tell(self):
        self._ensure_open()
        return self._position

    def seek(self, offset, whence=0):
        self._ensure_open()
        if whence == 0:
            target = offset
        elif whence == 1:
            target = self._position + offset
        elif whence == 2:
            raise ValueError('seeking relative to end is not supported')
        else:
            raise ValueError('invalid whence: {0!r}'.format(whence))
        if target < 0:
            raise ValueError('negative seek position: {0}'.format(target))
        self._position = target
        self._stream.seek(target)
        return target

    def read(self, size=-1):
        self._ensure_open()
        if size is None or size < 0:
            raise AccessDeniedError(
                'unbounded read on {0!r} is forbidden; only approved ranges '
                'may be read'.format(self.name))
        if size == 0:
            return b''
        if not self._gate.is_allowed(self._position, size):
            raise AccessDeniedError(
                'read of {0} byte(s) at offset {1} on {2!r} is outside the '
                'approved ranges {3!r}'.format(
                    size, self._position, self.name, self._gate.ranges))
        data = self._stream.read(size)
        self._position += len(data)
        return data

    def read_exact(self, size):
        """Read exactly ``size`` bytes or raise :class:`AccessDeniedError`."""
        data = self.read(size)
        if len(data) != size:
            raise AccessDeniedError(
                'short read on {0!r}: wanted {1} bytes, got {2}'.format(
                    self.name, size, len(data)))
        return data

    def read_range(self, start, length):
        """Read a specific approved range in one call."""
        self.seek(start)
        return self.read_exact(length)

    def close(self):
        if not self._closed:
            self._closed = True
            self._stream.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _ensure_open(self):
        if self._closed:
            raise ValueError('I/O operation on closed GuardedFile')
