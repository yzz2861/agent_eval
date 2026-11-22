"""Single-pass extraction and verification of selected JSON observations.

The functions in this module are meant for workflows where a small number of
values must travel with a ticket while the source JSON document stays where it
is.  The source is always consumed through the existing ``ijson.parse`` event
interface; the document is never materialised with ``json.loads``.

Each exported observation carries:

* a typed path (object keys and array indices are different segment kinds),
* the physical occurrence of a duplicate object key and its order among all
  siblings,
* a commitment to that path,
* a commitment to the sibling prefix and the observation's position, and
* a value commitment, plus the root commitment of the complete upstream event
  stream.

Verification recomputes the root commitment, resolves the caller-supplied paths
again, and compares the individual commitments.  Sibling values are never put
into the evidence package; only their rolling commitment is carried.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from decimal import Decimal
from json.decoder import scanstring


FORMAT = "ijson-evidence/1"
ALGORITHM = "sha256"

NUMBER_MODES = ("decimal", "exact", "binary64")
_NUMBER_EVENTS = frozenset(("number", "integer", "double"))
_NUMBER_REPRESENTATIONS = frozenset(("integer", "decimal", "float"))


__all__ = [
    "ALGORITHM",
    "FORMAT",
    "NUMBER_MODES",
    "EvidenceBundle",
    "EvidenceError",
    "EvidenceVerificationError",
    "IndexSegment",
    "KeySegment",
    "Observation",
    "Selection",
    "SelectionEvidence",
    "SelectionNotFound",
    "VerificationResult",
    "Violation",
    "canonical_number",
    "check_evidence",
    "extract",
    "extract_evidence",
    "extract_observed",
    "extract_observations",
    "format_path",
    "make_evidence",
    "numbers_equal",
    "parse_path",
    "path_commitment",
    "path_to_dicts",
    "root_commitment",
    "selection_commitment",
    "verify",
    "verify_evidence",
    "verify_observed",
    "verify_observations",
    "verify_observation",
    "value_commitment",
]


class EvidenceError(Exception):
    """Base exception for extraction and verification errors."""


class SelectionNotFound(EvidenceError):
    """Raised when a requested observation path is absent."""

    def __init__(self, paths):
        self.paths = tuple(paths)
        rendered = ", ".join(format_path(path) for path in self.paths)
        super().__init__("observation path(s) not found: " + rendered)


class EvidenceVerificationError(EvidenceError):
    """Raised by :func:`verify_evidence` when ``raise_on_error`` is true."""

    def __init__(self, result):
        self.result = result
        codes = ", ".join(sorted(result.violated_commitments)) or "unknown"
        super().__init__("evidence verification failed: " + codes)


# ---------------------------------------------------------------------------
# Canonical hashing and number handling

def _encode_part(part):
    if isinstance(part, bytes):
        return part
    if isinstance(part, str):
        return part.encode("utf-8")
    return json.dumps(
        part, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _hash(*parts):
    digest = hashlib.new(ALGORITHM)
    for part in parts:
        data = _encode_part(part)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return ALGORITHM + ":" + digest.hexdigest()


class _HashStream:
    def __init__(self, *parts):
        self._digest = hashlib.new(ALGORITHM)
        self.update(*parts)

    def update(self, *parts):
        for part in parts:
            data = _encode_part(part)
            self._digest.update(len(data).to_bytes(8, "big"))
            self._digest.update(data)

    def hexdigest(self):
        return ALGORITHM + ":" + self._digest.hexdigest()


def _check_number_mode(numbers):
    if numbers not in NUMBER_MODES:
        raise ValueError(
            "numbers must be one of %r, got %r" % (NUMBER_MODES, numbers)
        )


def _as_decimal(value):
    if isinstance(value, bool):
        raise TypeError("booleans are not numbers")
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("JSON numbers must be finite")
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return Decimal(repr(value))
    if isinstance(value, str):
        return Decimal(value)
    raise TypeError("unsupported number value: %r" % (value,))


def _decimal_token(value):
    """Return an exact, context-free decimal token.

    Trailing fractional zeroes are removed and zero has a single
    representation.  Unlike ``Decimal.normalize`` this does not apply the
    current decimal context, so very large or very precise values are not
    rounded.
    """
    decimal_value = _as_decimal(value)
    sign, digits, exponent = decimal_value.as_tuple()
    digits = list(digits)
    if not digits or all(digit == 0 for digit in digits):
        return "0E0"
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    sign_prefix = "-" if sign else ""
    return sign_prefix + "".join(str(digit) for digit in digits) + "E" + str(exponent)


def _number_representation(value):
    if isinstance(value, bool):
        raise TypeError("booleans are not numbers")
    if isinstance(value, int):
        return "integer"
    if isinstance(value, Decimal):
        return "decimal"
    if isinstance(value, float):
        return "float"
    return "decimal"


def _number_text(value):
    representation = _number_representation(value)
    if representation == "float":
        return repr(value)
    return str(value)


def canonical_number(value, numbers="decimal"):
    """Return the canonical token used to compare a JSON number.

    ``decimal`` treats numerically equal JSON numbers as equivalent (``1``,
    ``1.0`` and ``1e0`` all canonicalise to the same token).  ``exact`` keeps
    the parser representation distinct, and ``binary64`` compares through
    IEEE-754 double precision.
    """
    _check_number_mode(numbers)
    if numbers == "decimal":
        return "dec:" + _decimal_token(value)
    if numbers == "exact":
        representation = _number_representation(value)
        if representation == "integer":
            return "int:" + str(int(value))
        if representation == "decimal":
            return "decimal:" + str(value)
        return "float:" + float(value).hex()
    return "f64:" + float(value).hex()


def numbers_equal(left, right, numbers="decimal"):
    """Compare two JSON numbers using the requested equivalence convention."""
    return canonical_number(left, numbers) == canonical_number(right, numbers)


def _number_wire(value, numbers):
    representation = _number_representation(value)
    return {
        "type": "number",
        "representation": representation,
        "value": _number_text(value),
        "canonical": canonical_number(value, numbers),
        "equivalence": numbers,
    }


def _number_from_wire(wire):
    representation = wire.get("representation")
    text = wire.get("value")
    if representation == "integer":
        return int(text)
    if representation == "float":
        return float(text)
    if representation == "decimal":
        return Decimal(text)
    # Be liberal with hand-written evidence: let decimal parsing infer it.
    return Decimal(text)


def _scalar_wire(event, value, numbers):
    if event == "null":
        return {"type": "null", "value": None}
    if event == "boolean":
        return {"type": "boolean", "value": bool(value)}
    if event in _NUMBER_EVENTS:
        return _number_wire(value, numbers)
    return {"type": "string", "value": value}


def _canonical_scalar(event, value, numbers):
    if event == "null":
        return ["null"]
    if event == "boolean":
        return ["boolean", bool(value)]
    if event in _NUMBER_EVENTS:
        return ["number", canonical_number(value, numbers)]
    return ["string", value]


def _canonical_from_wire(wire, numbers):
    kind = wire.get("type")
    if kind == "null":
        return ["null"]
    if kind == "boolean":
        return ["boolean", bool(wire.get("value"))]
    if kind == "number":
        value = _number_from_wire(wire)
        return ["number", canonical_number(value, numbers)]
    if kind == "array":
        return [
            "array",
            [_canonical_from_wire(item, numbers) for item in wire.get("items", ())],
        ]
    if kind == "object":
        return [
            "object",
            [
                [key, _canonical_from_wire(item, numbers)]
                for key, item in wire.get("items", ())
            ],
        ]
    return ["string", wire.get("value")]


def _value_commitment_from_canonical(canonical):
    return _hash("value", canonical)


def _canonical_from_python(value, numbers):
    if isinstance(value, dict) and value.get("type") in (
        "null", "boolean", "number", "string", "array", "object"
    ):
        return _canonical_from_wire(value, numbers)
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["boolean", value]
    if isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
        return ["number", canonical_number(value, numbers)]
    if isinstance(value, str):
        return ["string", value]
    if isinstance(value, (list, tuple)):
        return ["array", [_canonical_from_python(item, numbers) for item in value]]
    if isinstance(value, dict):
        return [
            "object",
            [
                [key, _canonical_from_python(item, numbers)]
                for key, item in value.items()
            ],
        ]
    raise TypeError("unsupported JSON value: %r" % (value,))


def _value_commitment_from_wire(wire, numbers):
    return _value_commitment_from_canonical(_canonical_from_wire(wire, numbers))


def value_commitment(value, numbers="decimal"):
    """Recompute a value commitment from a native value or wire value."""
    _check_number_mode(numbers)
    return _value_commitment_from_canonical(
        _canonical_from_python(value, numbers)
    )


# ---------------------------------------------------------------------------
# Typed paths

@dataclass(frozen=True)
class KeySegment:
    """A member of a JSON object.

    ``occurrence`` is the zero-based physical occurrence of this key in its
    parent object.  It disambiguates duplicate keys without changing the key's
    type.
    """

    key: str
    occurrence: int = 0

    def __post_init__(self):
        if not isinstance(self.key, str):
            raise TypeError("object key must be a string")
        if not isinstance(self.occurrence, int) or isinstance(self.occurrence, bool):
            raise TypeError("occurrence must be an integer")
        if self.occurrence < 0:
            raise ValueError("occurrence must be non-negative")

    @property
    def kind(self):
        return "key"

    @property
    def container(self):
        return "object"

    def to_dict(self):
        return {
            "kind": "key",
            "type": "object",
            "key": self.key,
            "occurrence": self.occurrence,
        }


@dataclass(frozen=True)
class IndexSegment:
    """A zero-based position in a JSON array."""

    index: int

    def __post_init__(self):
        if not isinstance(self.index, int) or isinstance(self.index, bool):
            raise TypeError("array index must be an integer")
        if self.index < 0:
            raise ValueError("array index must be non-negative")

    @property
    def kind(self):
        return "index"

    @property
    def container(self):
        return "array"

    def to_dict(self):
        return {"kind": "index", "type": "array", "index": self.index}


_SEGMENT_TAGS = frozenset(("key", "object", "index", "array"))


def _segment_tuple(value):
    if not isinstance(value, tuple) or len(value) not in (2, 3):
        return None
    if not value or value[0] not in _SEGMENT_TAGS:
        return None
    tag = value[0]
    if tag in ("index", "array"):
        if len(value) != 2:
            raise ValueError("array index segment takes one value")
        return IndexSegment(value[1])
    occurrence = value[2] if len(value) == 3 else 0
    return KeySegment(value[1], occurrence)


def _segment_mapping(value):
    if not isinstance(value, dict):
        return None
    if "path" in value:
        return None
    kind = value.get("kind", value.get("type"))
    if kind in ("index", "array") or ("index" in value and "key" not in value):
        return IndexSegment(value["index"])
    if "key" in value:
        return KeySegment(
            value["key"],
            value.get("occurrence", 0),
        )
    return None


def _normalise_segment(value):
    if isinstance(value, (KeySegment, IndexSegment)):
        return value
    if isinstance(value, bool):
        raise TypeError("a boolean is not a path segment")
    if isinstance(value, int):
        return IndexSegment(value)
    if isinstance(value, dict):
        segment = _segment_mapping(value)
        if segment is not None:
            return segment
    if isinstance(value, tuple):
        segment = _segment_tuple(value)
        if segment is not None:
            return segment
    raise TypeError("unsupported path segment: %r" % (value,))


def _parse_canonical_path(text):
    segments = []
    length = len(text)
    position = 1
    while position < length:
        if text[position] != "[":
            raise ValueError(
                "invalid canonical path at character %d: %r" % (position, text)
            )
        position += 1
        if position < length and text[position] == '"':
            key, position = scanstring(text, position + 1)
            if position >= length or text[position] != "]":
                raise ValueError("unterminated key segment in %r" % (text,))
            position += 1
            occurrence = 0
            if position < length and text[position] == "#":
                position += 1
                start = position
                while position < length and text[position].isdigit():
                    position += 1
                if start == position:
                    raise ValueError("missing duplicate-key occurrence in %r" % (text,))
                occurrence = int(text[start:position])
            segments.append(KeySegment(key, occurrence))
            continue
        start = position
        while position < length and text[position].isdigit():
            position += 1
        if start == position or position >= length or text[position] != "]":
            raise ValueError("invalid array index segment in %r" % (text,))
        segments.append(IndexSegment(int(text[start:position])))
        position += 1
    return tuple(segments)


def _parse_plain_path(text):
    segments = []
    length = len(text)
    position = 0
    while position < length:
        char = text[position]
        if char == ".":
            position += 1
            continue
        if char == "[":
            position += 1
            if position < length and text[position] == '"':
                key, position = scanstring(text, position + 1)
                if position >= length or text[position] != "]":
                    raise ValueError("unterminated key segment in %r" % (text,))
                position += 1
                segments.append(KeySegment(key))
                continue
            start = position
            while position < length and text[position].isdigit():
                position += 1
            if start == position or position >= length or text[position] != "]":
                raise ValueError("invalid array index segment in %r" % (text,))
            segments.append(IndexSegment(int(text[start:position])))
            position += 1
            continue

        chars = []
        while position < length and text[position] not in ".[#":
            if text[position] == "\\":
                position += 1
                if position >= length:
                    raise ValueError("trailing escape in path %r" % (text,))
            chars.append(text[position])
            position += 1
        key = "".join(chars)
        occurrence = 0
        if position < length and text[position] == "#":
            position += 1
            start = position
            while position < length and text[position].isdigit():
                position += 1
            if start == position:
                raise ValueError("missing duplicate-key occurrence in %r" % (text,))
            occurrence = int(text[start:position])
        segments.append(KeySegment(key, occurrence))
    return tuple(segments)


def parse_path(path):
    """Normalise a path into a tuple of :class:`KeySegment` objects.

    Accepted forms are typed segments, lists/tuples of segments, canonical
    strings such as ``$["a"]#1[0]`` and the compact form ``a#1[0]``.  A plain
    word is always an object key; it is never interpreted as an array index, so
    a key literally named ``item`` remains addressable.
    """
    if isinstance(path, (KeySegment, IndexSegment)):
        return (path,)
    if path is None:
        return ()
    if isinstance(path, str):
        text = path.strip()
        if not text or text == "$":
            return ()
        if text.startswith("$"):
            return _parse_canonical_path(text)
        return _parse_plain_path(text)
    if isinstance(path, dict):
        segment = _segment_mapping(path)
        if segment is not None:
            return (segment,)
        raise TypeError("not a path: %r" % (path,))
    if isinstance(path, tuple) and _segment_tuple(path) is not None:
        return (_segment_tuple(path),)
    if isinstance(path, (list, tuple)):
        return tuple(_normalise_segment(item) for item in path)
    raise TypeError("unsupported path: %r" % (path,))


def path_to_dicts(path):
    """Return the JSON-safe list-of-segments representation of ``path``."""
    return [segment.to_dict() for segment in parse_path(path)]


def format_path(path):
    """Return the canonical string form of ``path``."""
    parts = ["$"]
    for segment in parse_path(path):
        if isinstance(segment, KeySegment):
            parts.append("[" + json.dumps(segment.key, ensure_ascii=False) + "]")
            if segment.occurrence:
                parts.append("#" + str(segment.occurrence))
        else:
            parts.append("[" + str(segment.index) + "]")
    return "".join(parts)


def _segment_dicts(path):
    return [segment.to_dict() for segment in path]


def _selection_path_commitment(selection_index, path):
    return _hash("selection-path", selection_index, _segment_dicts(path))


def _selection_set_commitment(paths):
    return _hash(
        "selection-set",
        [[index, _segment_dicts(path)] for index, path in enumerate(paths)],
    )


def path_commitment(path, selection_index=0):
    """Recompute the commitment carried by one observation path."""
    return _selection_path_commitment(int(selection_index), parse_path(path))


def selection_commitment(paths):
    """Recompute the commitment over an ordered list of selected paths."""
    selections = _normalise_selections(paths)
    return _selection_set_commitment([selection.path for selection in selections])


# ---------------------------------------------------------------------------
# Selections

@dataclass(frozen=True)
class Selection:
    index: int
    id: str
    path: tuple

    def to_dict(self):
        return {
            "index": self.index,
            "id": self.id,
            "path": _segment_dicts(self.path),
            "path_string": format_path(self.path),
            "path_commitment": _selection_path_commitment(self.index, self.path),
        }


def _looks_like_single_segment(value):
    if isinstance(value, (KeySegment, IndexSegment, int)):
        return True
    if isinstance(value, tuple) and _segment_tuple(value) is not None:
        return True
    if isinstance(value, dict) and "path" not in value:
        return _segment_mapping(value) is not None
    return False


def _looks_like_path_item(value):
    if isinstance(value, (str, KeySegment, IndexSegment, int, dict)):
        if isinstance(value, dict) and "path" in value:
            return True
        return True
    if isinstance(value, tuple):
        if _segment_tuple(value) is not None:
            return True
        return len(value) == 2 and isinstance(value[0], str)
    if isinstance(value, (list, tuple)):
        return True
    return False


def _selection_from_item(item, index):
    if isinstance(item, Selection):
        return Selection(index, item.id, item.path)
    if isinstance(item, dict) and "path" in item:
        selection_id = item.get("id", item.get("name", item.get("label")))
        path = parse_path(item["path"])
        return Selection(index, selection_id or "obs-%d" % index, path)
    if isinstance(item, tuple) and len(item) == 2:
        if _segment_tuple(item) is None and isinstance(item[0], str):
            return Selection(index, item[0], parse_path(item[1]))
    return Selection(index, "obs-%d" % index, parse_path(item))


def _normalise_selections(selections):
    if selections is None:
        raise ValueError("at least one observation selection is required")
    if isinstance(selections, Selection):
        return [Selection(0, selections.id, selections.path)]
    if isinstance(selections, dict):
        if "path" in selections:
            return [_selection_from_item(selections, 0)]
        if _segment_mapping(selections) is not None:
            return [Selection(0, "obs-0", parse_path(selections))]
        return [
            Selection(index, str(selection_id), parse_path(path))
            for index, (selection_id, path) in enumerate(selections.items())
        ]
    if isinstance(selections, (str, KeySegment, IndexSegment)):
        return [Selection(0, "obs-0", parse_path(selections))]
    if isinstance(selections, tuple) and _segment_tuple(selections) is not None:
        return [Selection(0, "obs-0", parse_path(selections))]
    if isinstance(selections, (list, tuple)):
        if not selections:
            return []
        # A list of typed segments is one path; a list of strings is a list of
        # paths.  This keeps ``["a", "b"]`` convenient while still allowing
        # explicit typed paths for unusual key names.
        if (
            any(not isinstance(item, str) for item in selections)
            and all(_looks_like_single_segment(item) for item in selections)
            and not any(
                isinstance(item, dict) and "path" in item for item in selections
            )
        ):
            return [Selection(0, "obs-0", parse_path(selections))]
        if all(_looks_like_path_item(item) for item in selections):
            return [
                _selection_from_item(item, index)
                for index, item in enumerate(selections)
            ]
    return [_selection_from_item(selections, 0)]


# ---------------------------------------------------------------------------
# Values and observations

class _ValueBuilder:
    """Build a selected subtree from parse events.

    Objects are kept as ordered key/value pairs in the wire representation so
    duplicate keys remain visible.  The Python value is a normal dict/list (a
    duplicate key therefore has last-write-wins semantics there).
    """

    def __init__(self, numbers):
        self.numbers = numbers
        self.stack = []
        self.parent_key = None
        self.native = None
        self.wire = None
        self.canonical = None

    def _attach(self, node, native, wire, canonical):
        if node is None:
            self.native = native
            self.wire = wire
            self.canonical = canonical
            return
        if node["kind"] == "array":
            node["native"].append(native)
            node["wire_items"].append(wire)
            node["canonical_items"].append(canonical)
            return
        key = node["pending_key"]
        if key is None:
            raise EvidenceError("object value without a map_key event")
        node["pending_key"] = None
        node["pairs"].append([key, wire])
        node["canonical_pairs"].append([key, canonical])
        node["native"][key] = native

    def _scalar(self, event, value):
        self._attach(
            self.stack[-1] if self.stack else None,
            value,
            _scalar_wire(event, value, self.numbers),
            _canonical_scalar(event, value, self.numbers),
        )

    def event(self, event, value):
        if event == "map_key":
            if not self.stack or self.stack[-1]["kind"] != "object":
                raise EvidenceError("map_key outside an object")
            self.stack[-1]["pending_key"] = value
            return
        if event in ("start_map", "start_array"):
            kind = "object" if event == "start_map" else "array"
            if self.stack:
                parent = self.stack[-1]
                if parent["kind"] == "object":
                    key = parent["pending_key"]
                    if key is None:
                        raise EvidenceError("object value without a map_key event")
                    parent["pending_key"] = None
                else:
                    key = None
            else:
                parent = None
                key = None
            node = {
                "kind": kind,
                "parent": parent,
                "parent_key": key,
                "pending_key": None,
                "native": {} if kind == "object" else [],
                "pairs": [],
                "canonical_pairs": [],
                "wire_items": [],
                "canonical_items": [],
            }
            self.stack.append(node)
            return
        if event in ("end_map", "end_array"):
            if not self.stack:
                raise EvidenceError("end event without a matching start event")
            node = self.stack.pop()
            expected = "object" if event == "end_map" else "array"
            if node["kind"] != expected:
                raise EvidenceError("mismatched container end event")
            if expected == "object":
                wire = {"type": "object", "items": node["pairs"]}
                canonical = ["object", node["canonical_pairs"]]
                native = node["native"]
            else:
                wire = {"type": "array", "items": node["wire_items"]}
                canonical = ["array", node["canonical_items"]]
                native = node["native"]
            parent = node["parent"]
            if parent is not None and parent["kind"] == "object":
                # The key was consumed when the child container started; put
                # it back so the common attachment path can consume it.
                parent["pending_key"] = node["parent_key"]
            self._attach(parent, native, wire, canonical)
            return
        self._scalar(event, value)


@dataclass
class Observation:
    selection_index: int
    id: str
    path: tuple
    value: object = None
    wire_value: object = None
    position: dict = field(default_factory=dict)
    parent_path: tuple = ()
    found: bool = True
    path_commitment: str | None = None
    order_commitment: str | None = None
    value_commitment: str | None = None
    sibling_prefix_commitment: str | None = None
    root_commitment: str | None = None
    number_equivalence: str | None = None

    @property
    def path_string(self):
        return format_path(self.path)

    def to_dict(self, native=True):
        value = self.value if native else self.wire_value
        return {
            "selection_index": self.selection_index,
            "id": self.id,
            "path": _segment_dicts(self.path),
            "path_string": self.path_string,
            "parent_path": _segment_dicts(self.parent_path),
            "position": dict(self.position),
            "value": value,
            "wire_value": self.wire_value,
            "found": self.found,
            "path_commitment": self.path_commitment,
            "order_commitment": self.order_commitment,
            "value_commitment": self.value_commitment,
            "sibling_prefix_commitment": self.sibling_prefix_commitment,
            "root_commitment": self.root_commitment,
            "number_equivalence": self.number_equivalence,
            "commitments": {
                "path": self.path_commitment,
                "order": self.order_commitment,
                "value": self.value_commitment,
                "root": self.root_commitment,
            },
        }

    def __getitem__(self, key):
        return self.to_dict()[key]


@dataclass
class SelectionEvidence:
    index: int
    id: str
    path: tuple
    found: bool
    path_commitment: str

    def to_dict(self):
        return {
            "index": self.index,
            "id": self.id,
            "path": _segment_dicts(self.path),
            "path_string": format_path(self.path),
            "found": self.found,
            "path_commitment": self.path_commitment,
        }

    def __getitem__(self, key):
        return self.to_dict()[key]


@dataclass
class EvidenceBundle:
    root: str
    number_equivalence: str
    selections: list
    observations: list
    selection_commitment: str

    @property
    def root_commitment(self):
        return self.root

    @property
    def manifest(self):
        return {
            "format": FORMAT,
            "algorithm": ALGORITHM,
            "root": self.root,
            "root_commitment": self.root,
            "number_equivalence": self.number_equivalence,
            "selection_commitment": self.selection_commitment,
        }

    def to_dict(self, native=True):
        return {
            "format": FORMAT,
            "algorithm": ALGORITHM,
            "root": self.root,
            "root_commitment": self.root,
            "number_equivalence": self.number_equivalence,
            "selection_commitment": self.selection_commitment,
            "manifest": self.manifest,
            "selections": [item.to_dict() for item in self.selections],
            "observations": [
                item.to_dict(native=native) for item in self.observations
            ],
        }

    def to_jsonable(self):
        return self.to_dict(native=False)

    def to_json(self, **kwargs):
        kwargs.setdefault("ensure_ascii", False)
        kwargs.setdefault("indent", 2)
        kwargs.setdefault("sort_keys", False)
        return json.dumps(self.to_jsonable(), **kwargs)

    def __getitem__(self, key):
        if isinstance(key, str):
            return self.to_dict()[key]
        return self.observations[key]

    def __iter__(self):
        return iter(self.observations)

    def __len__(self):
        return len(self.observations)


@dataclass
class Violation:
    commitment: str
    message: str
    selection_index: int | None = None
    path: tuple | None = None
    expected: object = None
    actual: object = None

    @property
    def code(self):
        return self.commitment

    def to_dict(self):
        return {
            "commitment": self.commitment,
            "code": self.commitment,
            "message": self.message,
            "selection_index": self.selection_index,
            "path": _segment_dicts(self.path) if self.path is not None else None,
            "path_string": format_path(self.path) if self.path is not None else None,
            "expected": self.expected,
            "actual": self.actual,
        }

    def __getitem__(self, key):
        return self.to_dict()[key]


@dataclass
class VerificationResult:
    ok: bool
    root_commitment: str
    trusted_root: str | None
    violations: list
    observations: list = field(default_factory=list)
    trusted_paths: bool = True

    @property
    def valid(self):
        return self.ok

    @property
    def violated_commitments(self):
        return {violation.commitment for violation in self.violations}

    @property
    def errors(self):
        return self.violations

    def to_dict(self):
        return {
            "ok": self.ok,
            "valid": self.ok,
            "root_commitment": self.root_commitment,
            "trusted_root": self.trusted_root,
            "trusted_paths": self.trusted_paths,
            "violated_commitments": sorted(self.violated_commitments),
            "violations": [violation.to_dict() for violation in self.violations],
        }

    def __bool__(self):
        return self.ok

    def __eq__(self, other):
        if isinstance(other, bool):
            return self.ok is other
        if isinstance(other, VerificationResult):
            return (
                self.ok == other.ok
                and self.root_commitment == other.root_commitment
                and self.violated_commitments == other.violated_commitments
            )
        return NotImplemented

    def __getitem__(self, key):
        return self.to_dict()[key]


# ---------------------------------------------------------------------------
# Scanner

@dataclass
class _ChildContext:
    path: tuple
    segment: object
    order: int
    prefix_commitment: str
    order_commitment: str | None = None


@dataclass
class _Frame:
    kind: str
    path: tuple
    sequence_commitment: str
    next_order: int = 0
    next_index: int = 0
    key_occurrences: dict = field(default_factory=dict)
    pending_key: tuple | None = None
    active_child: _ChildContext | None = None


class _Capture:
    def __init__(self, builder, target_path):
        self.builder = builder
        self.target_path = target_path
        self.depth = 0
        self.complete = False

    def feed(self, event, value):
        if self.complete:
            return
        if event in ("start_map", "start_array"):
            self.depth += 1
        self.builder.event(event, value)
        if event in ("end_map", "end_array"):
            self.depth -= 1
            if self.depth == 0:
                self.complete = True


class _Scanner:
    def __init__(self, selections, numbers):
        self.selections = list(selections)
        self.numbers = numbers
        self.by_path = {}
        for selection in self.selections:
            self.by_path.setdefault(selection.path, []).append(selection.index)
        self.root_hash = _HashStream(
            FORMAT,
            ALGORITHM,
            "numbers",
            numbers,
        )
        self.frames = []
        self.captures = []
        self.observations = {}
        self.root_selected = ()

    @staticmethod
    def _position(segment, order):
        if isinstance(segment, KeySegment):
            return {
                "kind": "key",
                "type": "object",
                "key": segment.key,
                "occurrence": segment.occurrence,
                "order": order,
            }
        return {
            "kind": "index",
            "type": "array",
            "index": segment.index,
            "order": order,
        }

    def _claim_child(self, parent):
        if parent.kind == "object":
            if parent.pending_key is None:
                raise EvidenceError("object value without a map_key event")
            segment, order = parent.pending_key
            parent.pending_key = None
        else:
            order = parent.next_index
            parent.next_index += 1
            segment = IndexSegment(order)
        path = parent.path + (segment,)
        context = _ChildContext(
            path=path,
            segment=segment,
            order=order,
            prefix_commitment=parent.sequence_commitment,
        )
        parent.active_child = context
        return context

    def _complete_child(self, parent, context, _value_commitment=None):
        if isinstance(context.segment, KeySegment):
            descriptor = [
                "key",
                context.segment.key,
                context.segment.occurrence,
                context.order,
            ]
        else:
            descriptor = [
                "index",
                context.segment.index,
                context.order,
            ]
        context.order_commitment = _hash(
            "order",
            parent.kind,
            _segment_dicts(parent.path),
            context.prefix_commitment,
            descriptor,
        )
        parent.sequence_commitment = _hash(
            "sequence",
            parent.sequence_commitment,
            descriptor,
        )
        return context.order_commitment

    def _record(
        self,
        selection_index,
        path,
        native,
        wire,
        canonical,
        position,
        parent_path,
        order_commitment,
        sibling_prefix,
    ):
        if selection_index in self.observations:
            return
        selection = self.selections[selection_index]
        value_commitment = _value_commitment_from_canonical(canonical)
        self.observations[selection_index] = Observation(
            selection_index=selection_index,
            id=selection.id,
            path=path,
            value=native,
            wire_value=wire,
            position=position,
            parent_path=parent_path,
            found=True,
            path_commitment=_selection_path_commitment(selection_index, selection.path),
            order_commitment=order_commitment,
            value_commitment=value_commitment,
            sibling_prefix_commitment=sibling_prefix,
            number_equivalence=self.numbers,
        )

    def _record_child_selections(self, context, native, wire, canonical, order_commitment):
        for selection_index in self.by_path.get(context.path, ()):
            parent_path = context.path[:-1]
            self._record(
                selection_index,
                context.path,
                native,
                wire,
                canonical,
                self._position(context.segment, context.order),
                parent_path,
                order_commitment,
                context.prefix_commitment,
            )

    def _record_root_selections(self, native, wire, canonical):
        value_commitment = _value_commitment_from_canonical(canonical)
        order_commitment = _hash("order", "root", value_commitment)
        for selection_index in self.by_path.get((), ()):
            self._record(
                selection_index,
                (),
                native,
                wire,
                canonical,
                {"kind": "root", "type": "root", "order": 0},
                (),
                order_commitment,
                None,
            )

    def feed(self, prefix, event, value):
        if event == "map_key":
            if not self.frames or self.frames[-1].kind != "object":
                raise EvidenceError("map_key outside an object")
            frame = self.frames[-1]
            occurrence = frame.key_occurrences.get(value, 0)
            frame.key_occurrences[value] = occurrence + 1
            order = frame.next_order
            frame.next_order += 1
            frame.pending_key = (KeySegment(value, occurrence), order)
            self.root_hash.update(
                "key",
                _segment_dicts(frame.path),
                value,
                occurrence,
                order,
            )
            for capture in self.captures:
                capture.feed(event, value)
            return

        if event in ("start_map", "start_array"):
            kind = "object" if event == "start_map" else "array"
            if self.frames:
                parent = self.frames[-1]
                context = self._claim_child(parent)
                path = context.path
            else:
                context = None
                path = ()
            self.root_hash.update(
                "start",
                kind,
                _segment_dicts(path),
            )
            frame = _Frame(
                kind=kind,
                path=path,
                sequence_commitment=_hash(
                    "sequence-start",
                    kind,
                    _segment_dicts(path),
                ),
            )
            self.frames.append(frame)
            if context is None:
                self.root_selected = tuple(self.by_path.get(path, ()))
            if path in self.by_path:
                self.captures.append(
                    _Capture(_ValueBuilder(self.numbers), path)
                )
            for capture in self.captures:
                capture.feed(event, value)
            return

        if event in ("end_map", "end_array"):
            for capture in self.captures:
                capture.feed(event, value)
            frame = self.frames.pop()
            self.root_hash.update(
                "end",
                frame.kind,
                _segment_dicts(frame.path),
            )

            completed = [
                capture
                for capture in self.captures
                if capture.complete and capture.target_path == frame.path
            ]
            if completed:
                builder = completed[-1].builder
                native = builder.native
                wire = builder.wire
                canonical = builder.canonical
            else:
                native = None
                wire = None
                canonical = None

            if self.frames:
                parent = self.frames[-1]
                context = parent.active_child
                if context is None or context.path != frame.path:
                    raise EvidenceError("container end without an active child")
                order_commitment = self._complete_child(parent, context)
                self._record_child_selections(
                    context,
                    native,
                    wire,
                    canonical,
                    order_commitment,
                )
                parent.active_child = None
            else:
                self._record_root_selections(native, wire, canonical)

            self.captures = [
                capture for capture in self.captures if not capture.complete
            ]
            return

        wire = _scalar_wire(event, value, self.numbers)
        canonical = _canonical_scalar(event, value, self.numbers)
        value_commitment = _value_commitment_from_canonical(canonical)
        if self.frames:
            parent = self.frames[-1]
            context = self._claim_child(parent)
            self.root_hash.update(
                "value",
                _segment_dicts(context.path),
                canonical,
            )
            for capture in self.captures:
                capture.feed(event, value)
            order_commitment = self._complete_child(
                parent, context, value_commitment
            )
            self._record_child_selections(
                context,
                value,
                wire,
                canonical,
                order_commitment,
            )
            parent.active_child = None
        else:
            self.root_hash.update("value", [], canonical)
            for capture in self.captures:
                capture.feed(event, value)
            self._record_root_selections(value, wire, canonical)

    def finish(self, require_all=True):
        root = self.root_hash.hexdigest()
        missing = [
            selection
            for selection in self.selections
            if selection.index not in self.observations
        ]
        if require_all and missing:
            raise SelectionNotFound([selection.path for selection in missing])
        for selection in missing:
            self.observations[selection.index] = Observation(
                selection_index=selection.index,
                id=selection.id,
                path=selection.path,
                value=None,
                wire_value=None,
                position={},
                parent_path=selection.path[:-1],
                found=False,
                path_commitment=_selection_path_commitment(
                    selection.index, selection.path
                ),
                number_equivalence=self.numbers,
            )
        observations = [
            self.observations[index] for index in sorted(self.observations)
        ]
        for observation in observations:
            observation.root_commitment = root
        return root, observations


def _parse_source(source, buf_size=64 * 1024, backend=None):
    # Imported here to avoid a circular import while ijson.__init__ exposes
    # these helpers.
    import ijson

    parse = ijson.parse if backend is None else ijson.get_backend(backend).parse
    if isinstance(source, (bytes, bytearray, memoryview)):
        source = bytes(source)
    elif not (isinstance(source, str) or hasattr(source, "read")):
        raise TypeError("source must be bytes, str, or a readable file-like object")
    return parse(source, buf_size=buf_size)


def _scan(source, selections, numbers, buf_size, backend, require_all):
    scanner = _Scanner(selections, numbers)
    for prefix, event, value in _parse_source(source, buf_size, backend):
        scanner.feed(prefix, event, value)
    return scanner.finish(require_all=require_all)


def root_commitment(
    source,
    *,
    numbers="decimal",
    buf_size=64 * 1024,
    backend=None,
):
    """Compute the upstream manifest commitment without selecting values."""
    _check_number_mode(numbers)
    root, _observations = _scan(
        source,
        [],
        numbers,
        buf_size,
        backend,
        False,
    )
    return root


def extract_evidence(
    source,
    selections=None,
    *,
    paths=None,
    numbers="decimal",
    require_all=True,
    buf_size=64 * 1024,
    backend=None,
):
    """Extract selected observations in one pass over ``source``.

    Parameters
    ----------
    source:
        Raw bytes, text, or a file-like object accepted by ``ijson.parse``.
    selections:
        One path, or a list/mapping of paths.  A path can be a canonical string
        (``$["a"]#1[0]``), a compact string (``a#1[0]``), a typed segment
        list, or ``(id, path)``/``{"id": ..., "path": ...}`` descriptors.
    paths:
        Alias for ``selections``.
    numbers:
        Numeric equivalence convention: ``decimal`` (default), ``exact`` or
        ``binary64``.
    require_all:
        Raise :class:`SelectionNotFound` if a requested path is absent.
    """
    if paths is not None:
        if selections is not None:
            raise TypeError("pass either selections or paths, not both")
        selections = paths
    _check_number_mode(numbers)
    selections = _normalise_selections(selections)
    root, observations = _scan(
        source,
        selections,
        numbers,
        buf_size,
        backend,
        require_all,
    )
    selection_evidence = [
        SelectionEvidence(
            index=selection.index,
            id=selection.id,
            path=selection.path,
            found=selection.index in {
                observation.selection_index
                for observation in observations
                if observation.found
            },
            path_commitment=_selection_path_commitment(
                selection.index, selection.path
            ),
        )
        for selection in selections
    ]
    return EvidenceBundle(
        root=root,
        number_equivalence=numbers,
        selections=selection_evidence,
        observations=observations,
        selection_commitment=_selection_set_commitment(
            [selection.path for selection in selections]
        ),
    )


# ---------------------------------------------------------------------------
# Verification

def _coerce_evidence(evidence):
    if isinstance(evidence, EvidenceBundle):
        return evidence.to_dict(native=True)
    if not isinstance(evidence, dict):
        raise TypeError("evidence must be an EvidenceBundle or a mapping")
    return evidence


def _evidence_root(evidence):
    root = evidence.get("root_commitment", evidence.get("root"))
    if root is None and isinstance(evidence.get("manifest"), dict):
        root = evidence["manifest"].get("root_commitment")
    if not isinstance(root, str):
        raise ValueError("evidence does not contain a root commitment")
    return root


def _evidence_mode(evidence):
    numbers = evidence.get("number_equivalence")
    if numbers is None and isinstance(evidence.get("manifest"), dict):
        numbers = evidence["manifest"].get("number_equivalence")
    if numbers is None:
        # Old/hand-written packages default to the library's decimal convention.
        numbers = "decimal"
    _check_number_mode(numbers)
    return numbers


def _evidence_observation_map(evidence):
    observations = evidence.get("observations", ())
    result = {}
    for position, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise TypeError("evidence observations must be mappings")
        selection_index = observation.get("selection_index")
        if selection_index is None:
            selection_index = position
        if selection_index in result:
            raise ValueError("duplicate selection_index in evidence observations")
        result[selection_index] = observation
    return result


def _check_number_wire(wire, numbers, path=()):
    violations = []
    if not isinstance(wire, dict):
        return violations
    kind = wire.get("type")
    if kind == "number":
        declared_mode = wire.get("equivalence")
        if declared_mode is not None and declared_mode != numbers:
            violations.append(
                Violation(
                    "number_equivalence",
                    "number evidence declares %r but verification uses %r"
                    % (declared_mode, numbers),
                    path=path,
                    expected=numbers,
                    actual=declared_mode,
                )
            )
            return violations
        try:
            value = _number_from_wire(wire)
            actual = canonical_number(value, numbers)
        except (TypeError, ValueError, ArithmeticError) as exc:
            violations.append(
                Violation(
                    "number_equivalence",
                    "cannot re-evaluate number evidence: %s" % (exc,),
                    path=path,
                )
            )
            return violations
        declared = wire.get("canonical")
        if declared != actual:
            violations.append(
                Violation(
                    "number_equivalence",
                    "declared canonical number %r does not match %r under %r"
                    % (declared, actual, numbers),
                    path=path,
                    expected=actual,
                    actual=declared,
                )
            )
        return violations
    if kind == "array":
        for child in wire.get("items", ()):
            violations.extend(_check_number_wire(child, numbers, path))
    elif kind == "object":
        for _key, child in wire.get("items", ()):
            violations.extend(_check_number_wire(child, numbers, path))
    return violations


def _canonical_path_key(path):
    return tuple(
        tuple(sorted(segment.items())) for segment in _segment_dicts(path)
    )


def verify_evidence(
    source,
    evidence,
    root=None,
    selections=None,
    *,
    paths=None,
    root_commitment=None,
    trusted_root=None,
    numbers=None,
    buf_size=64 * 1024,
    backend=None,
    raise_on_error=False,
):
    """Verify evidence against ``source`` and a caller-trusted root.

    The caller should pass the root commitment and paths from a source of truth
    they already trust (for example, the commitment recorded on the ticket),
    rather than the values embedded in the supplied evidence mapping.  If
    ``root`` is omitted, the evidence's own root is used as a compatibility
    fallback and ``trusted_paths``/verification still works, but this is not a
    substitute for an independently trusted commitment.
    """
    if paths is not None:
        if selections is not None:
            raise TypeError("pass either selections or paths, not both")
        selections = paths
    if root is None:
        root = root_commitment
    if root is None:
        root = trusted_root

    evidence_dict = _coerce_evidence(evidence)
    embedded_root = _evidence_root(evidence_dict)
    embedded_mode = _evidence_mode(evidence_dict)
    verification_mode = numbers or embedded_mode
    _check_number_mode(verification_mode)

    violations = []
    if numbers is not None and numbers != embedded_mode:
        violations.append(
            Violation(
                "number_equivalence",
                "evidence declares %r but caller requires %r"
                % (embedded_mode, numbers),
                expected=numbers,
                actual=embedded_mode,
            )
        )

    if selections is not None:
        trusted_selections = _normalise_selections(selections)
        trusted_paths = True
    else:
        raw_selections = evidence_dict.get("selections")
        if raw_selections:
            trusted_selections = [
                Selection(
                    index=item.get("index", position),
                    id=item.get("id", "obs-%d" % position),
                    path=parse_path(item["path"]),
                )
                for position, item in enumerate(raw_selections)
            ]
        else:
            trusted_selections = []
        trusted_paths = False

    if trusted_paths:
        expected_selection_commitment = _selection_set_commitment(
            [selection.path for selection in trusted_selections]
        )
        declared = evidence_dict.get("selection_commitment")
        if declared is None and isinstance(evidence_dict.get("manifest"), dict):
            declared = evidence_dict["manifest"].get("selection_commitment")
        if declared is not None and declared != expected_selection_commitment:
            violations.append(
                Violation(
                    "selection_commitment",
                    "selection manifest commitment does not match the "
                    "caller-specified paths",
                    expected=expected_selection_commitment,
                    actual=declared,
                )
            )

    actual_root, actual_observations = _scan(
        source,
        trusted_selections,
        verification_mode,
        buf_size,
        backend,
        require_all=False,
    )
    actual_by_selection = {
        observation.selection_index: observation
        for observation in actual_observations
    }

    expected_root = root if root is not None else embedded_root
    if root is not None and embedded_root != root:
        violations.append(
            Violation(
                "root_commitment",
                "evidence manifest root does not match caller-trusted root",
                expected=root,
                actual=embedded_root,
            )
        )
    if actual_root != expected_root:
        violations.append(
            Violation(
                "root_commitment",
                "recomputed root commitment does not match the trusted root",
                expected=expected_root,
                actual=actual_root,
            )
        )

    try:
        evidence_by_selection = _evidence_observation_map(evidence_dict)
    except ValueError as exc:
        violations.append(
            Violation(
                "selection_commitment",
                str(exc),
            )
        )
        evidence_by_selection = {}

    for position, observation in enumerate(evidence_dict.get("observations", ())):
        if not isinstance(observation, dict):
            continue
        declared_index = observation.get("selection_index", position)
        if declared_index != position:
            violations.append(
                Violation(
                    "order_commitment",
                    "evidence observations are not in selection manifest order",
                    selection_index=position,
                )
            )

    for selection in trusted_selections:
        index = selection.index
        evidence_observation = evidence_by_selection.get(index)
        actual_observation = actual_by_selection.get(index)
        expected_path_commitment = _selection_path_commitment(
            index, selection.path
        )

        if evidence_observation is None:
            violations.append(
                Violation(
                    "selection_commitment",
                    "evidence has no observation for selection %d" % index,
                    selection_index=index,
                    path=selection.path,
                )
            )
            continue

        evidence_path = _coerce_evidence_path(evidence_observation, selection)
        if evidence_path != selection.path:
            violations.append(
                Violation(
                    "path_commitment",
                    "observation path does not match the caller-specified path",
                    selection_index=index,
                    path=selection.path,
                    expected=_segment_dicts(selection.path),
                    actual=_segment_dicts(evidence_path),
                )
            )
        declared_path_commitment = evidence_observation.get("path_commitment")
        if declared_path_commitment is None:
            violations.append(
                Violation(
                    "path_commitment",
                    "observation is missing its path commitment",
                    selection_index=index,
                    path=selection.path,
                )
            )
        elif declared_path_commitment != expected_path_commitment:
            violations.append(
                Violation(
                    "path_commitment",
                    "observation path commitment does not match the "
                    "caller-specified path",
                    selection_index=index,
                    path=selection.path,
                    expected=expected_path_commitment,
                    actual=declared_path_commitment,
                )
            )

        if actual_observation is None or not actual_observation.found:
            violations.append(
                Violation(
                    "path_commitment",
                    "caller-specified path does not occur in the source",
                    selection_index=index,
                    path=selection.path,
                )
            )
            continue

        if evidence_observation.get("found", True) is not True:
            violations.append(
                Violation(
                    "selection_commitment",
                    "evidence marks an existing observation as not found",
                    selection_index=index,
                    path=selection.path,
                )
            )

        declared_value_commitment = evidence_observation.get("value_commitment")
        if declared_value_commitment is None:
            violations.append(
                Violation(
                    "value_commitment",
                    "observation is missing its value commitment",
                    selection_index=index,
                    path=selection.path,
                )
            )
        else:
            if declared_value_commitment != actual_observation.value_commitment:
                violations.append(
                    Violation(
                        "value_commitment",
                        "observation value commitment does not match the source "
                        "value at the specified path",
                        selection_index=index,
                        path=selection.path,
                        expected=actual_observation.value_commitment,
                        actual=declared_value_commitment,
                    )
                )
            evidence_wire = evidence_observation.get("wire_value")
            if isinstance(evidence_wire, dict):
                recomputed_value_commitment = _value_commitment_from_wire(
                    evidence_wire, verification_mode
                )
                if recomputed_value_commitment != declared_value_commitment:
                    violations.append(
                        Violation(
                            "value_commitment",
                            "exported value does not match its declared value "
                            "commitment",
                            selection_index=index,
                            path=selection.path,
                            expected=declared_value_commitment,
                            actual=recomputed_value_commitment,
                        )
                    )

        evidence_position = evidence_observation.get("position")
        if isinstance(evidence_position, dict):
            if _position_key(evidence_position) != _position_key(
                actual_observation.position
            ):
                violations.append(
                    Violation(
                        "order_commitment",
                        "observation sibling position does not match the source",
                        selection_index=index,
                        path=selection.path,
                        expected=actual_observation.position,
                        actual=evidence_position,
                    )
                )

        declared_order = evidence_observation.get("order_commitment")
        if declared_order is None:
            violations.append(
                Violation(
                    "order_commitment",
                    "observation is missing its order commitment",
                    selection_index=index,
                    path=selection.path,
                )
            )
        elif declared_order != actual_observation.order_commitment:
            violations.append(
                Violation(
                    "order_commitment",
                    "observation sibling/order commitment does not match the "
                    "source",
                    selection_index=index,
                    path=selection.path,
                    expected=actual_observation.order_commitment,
                    actual=declared_order,
                )
            )

        declared_prefix = evidence_observation.get("sibling_prefix_commitment")
        if declared_prefix is not None and (
            declared_prefix != actual_observation.sibling_prefix_commitment
        ):
            violations.append(
                Violation(
                    "order_commitment",
                    "upstream sibling-prefix commitment does not match the "
                    "source",
                    selection_index=index,
                    path=selection.path,
                    expected=actual_observation.sibling_prefix_commitment,
                    actual=declared_prefix,
                )
            )

        wire = evidence_observation.get("wire_value")
        if isinstance(wire, dict):
            violations.extend(_check_number_wire(wire, verification_mode, selection.path))
        elif isinstance(evidence_observation.get("value"), dict):
            # A mapping value may itself be a wire value when evidence came
            # back through JSON without ``wire_value``.
            value = evidence_observation["value"]
            if value.get("type") in ("null", "boolean", "number", "string", "array", "object"):
                violations.extend(
                    _check_number_wire(value, verification_mode, selection.path)
                )

    # Observations in the evidence that are not among the trusted selections
    # indicate a modified selection manifest.
    trusted_indexes = {selection.index for selection in trusted_selections}
    for index in evidence_by_selection:
        if index not in trusted_indexes:
            violations.append(
                Violation(
                    "selection_commitment",
                    "evidence contains an observation outside the "
                    "caller-specified selections",
                    selection_index=index,
                )
            )

    # Deduplicate by (commitment, selection, path, message).
    unique = []
    seen = set()
    for violation in violations:
        key = (
            violation.commitment,
            violation.selection_index,
            _canonical_path_key(violation.path) if violation.path is not None else None,
            violation.message,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(violation)

    result = VerificationResult(
        ok=not unique,
        root_commitment=actual_root,
        trusted_root=root,
        violations=unique,
        observations=actual_observations,
        trusted_paths=trusted_paths,
    )
    if raise_on_error and not result.ok:
        raise EvidenceVerificationError(result)
    return result


def _coerce_evidence_path(observation, selection):
    if "path" in observation:
        return parse_path(observation["path"])
    return selection.path


def _position_key(position):
    kind = position.get("kind", position.get("type"))
    if kind in ("key", "object"):
        return (
            "key",
            position.get("key"),
            position.get("occurrence", 0),
            position.get("order"),
        )
    if kind in ("index", "array"):
        return (
            "index",
            position.get("index"),
            position.get("order"),
        )
    return (kind, position.get("order"))


def verify_observation(
    source,
    observation,
    root,
    *,
    path=None,
    numbers=None,
    **kwargs,
):
    """Verify one observation mapping against a trusted root and path."""
    if isinstance(observation, Observation):
        observation = observation.to_dict()
    if not isinstance(observation, dict):
        raise TypeError("observation must be an Observation or mapping")
    if path is None:
        if "path" not in observation:
            raise ValueError("an observation path is required")
        path = observation["path"]
    evidence = {
        "root": root,
        "root_commitment": root,
        "number_equivalence": numbers
        or observation.get("number_equivalence", "decimal"),
        "selections": [
            {
                "index": 0,
                "id": observation.get("id", "obs-0"),
                "path": path_to_dicts(path),
            }
        ],
        "observations": [dict(observation, selection_index=0)],
    }
    return verify_evidence(
        source,
        evidence,
        root,
        [path],
        numbers=numbers,
        **kwargs,
    )


# Friendly aliases, kept small so callers can choose a domain word.
extract = extract_evidence
verify = verify_evidence
extract_observations = extract_evidence
verify_observations = verify_evidence
extract_observed = extract_evidence
verify_observed = verify_evidence
make_evidence = extract_evidence
check_evidence = verify_evidence
