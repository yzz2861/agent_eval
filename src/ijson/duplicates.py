'''
Helpers for the explicit duplicate map-key policy used by the object builders.
'''
import enum


class DuplicateKeyPolicy(str, enum.Enum):
    '''
    Policy applied when the same key appears more than once in one JSON object.

    ``first`` keeps the first value, ``last`` keeps the last value (without
    changing the position of the key in the resulting object), and ``reject``
    raises :class:`ijson.common.DuplicateKeyError`.
    '''
    FIRST = 'first'
    LAST = 'last'
    REJECT = 'reject'


# Friendly aliases for callers that prefer a different spelling.
DuplicateKeys = DuplicateKeyPolicy
DuplicateKeyStrategy = DuplicateKeyPolicy


_ALIASES = {
    'first': DuplicateKeyPolicy.FIRST,
    'keep-first': DuplicateKeyPolicy.FIRST,
    'keep_first': DuplicateKeyPolicy.FIRST,
    'last': DuplicateKeyPolicy.LAST,
    'keep-last': DuplicateKeyPolicy.LAST,
    'keep_last': DuplicateKeyPolicy.LAST,
    'reject': DuplicateKeyPolicy.REJECT,
    'error': DuplicateKeyPolicy.REJECT,
    'raise': DuplicateKeyPolicy.REJECT,
}


def normalize_duplicate_keys(value):
    '''
    Convert a public duplicate-key policy value into a ``DuplicateKeyPolicy``.

    ``None`` means the legacy behaviour (last value wins while constructing
    objects, and ``kvitems`` keeps yielding every member).
    '''
    if value is None:
        return None
    if isinstance(value, DuplicateKeyPolicy):
        return value
    if isinstance(value, str):
        try:
            return _ALIASES[value.strip().lower()]
        except KeyError:
            pass
    raise ValueError(
        "duplicate_keys must be one of 'first', 'last' or 'reject', got %r"
        % (value,)
    )


def join_path(parent, key):
    '''Join a map prefix and a key using ijson's dotted-prefix convention.'''
    return '%s.%s' % (parent, key) if parent else key


class EventPosition(object):
    '''
    Position of the first parsing event that contributes a duplicated value.

    Positions are counted in the event stream consumed by ``items``/``kvitems``
    (starting at zero), so they are identical for every backend, for synchronous
    and asynchronous iterators, and also for user-supplied parse events.  The
    object compares equal to that integer, and also carries the path and event
    name for callers that want more context.
    '''
    __slots__ = ('index', 'path', 'key', 'event', 'byte_offset')

    def __init__(self, index, path, key=None, event=None, byte_offset=None):
        self.index = index
        self.path = path
        self.key = key
        self.event = event
        self.byte_offset = byte_offset

    @property
    def position(self):
        return self.index

    @property
    def event_index(self):
        return self.index

    @property
    def value(self):
        return self.index

    def __int__(self):
        return self.index

    def __index__(self):
        return self.index

    def __eq__(self, other):
        if isinstance(other, EventPosition):
            return self.index == other.index
        if isinstance(other, int):
            return self.index == other
        return NotImplemented

    def __hash__(self):
        return hash(self.index)

    def __repr__(self):
        return 'EventPosition(%d, path=%r, key=%r, event=%r)' % (
            self.index, self.path, self.key, self.event
        )

    def __str__(self):
        return str(self.index)
