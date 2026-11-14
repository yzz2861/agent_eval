"""The jsonpickle.tags module provides the custom tags
used for pickling and unpickling Python objects.

These tags are keys into the flattened dictionaries
created by the Pickler class.  The Unpickler uses
these custom key names to identify dictionaries
that need to be specially handled.
"""

BYTES: str = "py/bytes"
BYTEARRAY: str = "py/bytea"
B64: str = "py/b64"
B85: str = "py/b85"
FUNCTION: str = "py/function"
ID: str = "py/id"
INITARGS: str = "py/initargs"
ITERATOR: str = "py/iterator"
JSON_KEY: str = "json://"
MEMORYVIEW: str = "py/memoryview"
MODULE: str = "py/mod"
NEWARGS: str = "py/newargs"
NEWARGSEX: str = "py/newargsex"
NEWOBJ: str = "py/newobj"
OBJECT: str = "py/object"
PROPERTY: str = "py/property"
REDUCE: str = "py/reduce"
DEFAULT_FACTORY: str = "py/default_factory"
REF: str = "py/ref"
REPR: str = "py/repr"
SEQ: str = "py/seq"
SET: str = "py/set"
STATE: str = "py/state"
TUPLE: str = "py/tuple"
TYPE: str = "py/type"

# All reserved tag names
RESERVED: set[str] = {
    B64,
    B85,
    BYTES,
    BYTEARRAY,
    FUNCTION,
    ID,
    INITARGS,
    ITERATOR,
    MEMORYVIEW,
    MODULE,
    NEWARGS,
    NEWARGSEX,
    NEWOBJ,
    OBJECT,
    PROPERTY,
    REDUCE,
    DEFAULT_FACTORY,
    REF,
    REPR,
    SEQ,
    SET,
    STATE,
    TUPLE,
    TYPE,
}

# Tags that identify the restoration path for a protocol mapping.
PRIMARY: frozenset[str] = frozenset(
    {
        TUPLE,
        SET,
        B64,
        B85,
        BYTEARRAY,
        MEMORYVIEW,
        ID,
        ITERATOR,
        OBJECT,
        TYPE,
        REDUCE,
        FUNCTION,
        MODULE,
        REPR,
    }
)

# Tags permitted alongside an object marker.
OBJECT_TAGS: frozenset[str] = frozenset(
    {
        OBJECT,
        INITARGS,
        NEWARGS,
        NEWARGSEX,
        SEQ,
        STATE,
        DEFAULT_FACTORY,
        PROPERTY,
        REF,
    }
)
