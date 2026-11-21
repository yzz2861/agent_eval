"""
Safe consumption of sealed CBOR logs that use shared values.

CBOR logs produced with value sharing (semantic tags 28 and 29) decode into object
graphs where several positions reference the *same* Python object. That is fine for
a single consumer, but when multiple independent components review the same decoded
log, one component annotating a shared object silently changes what the others see.

This module provides a safe consumption path for such logs:

* :func:`loads_evidence` / :func:`load_evidence` decode a CBOR artifact exactly once,
  into an immutable object graph (the *original evidence*), and record a digest that
  establishes the evidence's identity.
* Each consumer calls :meth:`Evidence.view` to obtain its own private, mutable
  :class:`EvidenceView`. Annotations made through one view never leak into the
  original evidence or into any other consumer's view.
* Callers can declare *critical fields* (key paths where shared references are not
  allowed) via ``protected_paths``. If a shared value materializes at or around such
  a field, :exc:`SharedReferenceError` is raised with a precise diagnostic.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Hashable, Iterable, Mapping
from copy import deepcopy
from hashlib import sha256
from typing import IO, Any

from ._cbor2 import CBORDecodeError, CBORTag, loads

__all__ = [
    "Evidence",
    "EvidenceView",
    "SharedReferenceError",
    "load_evidence",
    "loads_evidence",
]

#: Type of a path from the root of a decoded structure to one of its members
Path = tuple[Hashable, ...]

# Containers whose sharing is tracked. Immutable scalars (strings, numbers, ...)
# are harmless when shared, so they are not tracked. Empty tuples and frozensets
# are excluded because the interpreter may intern them, which would produce false
# positives.
_TRACKED_TYPES = (Mapping, tuple, list, set, frozenset, bytearray, CBORTag)

# Maximum number of occurrences recorded per shared value. Two occurrences suffice
# to prove sharing; a few more are kept to produce useful diagnostics.
_MAX_TRACKED_OCCURRENCES = 8


class SharedReferenceError(CBORDecodeError):
    """
    Raised when a shared reference (semantic tag 29) materializes where the decoding
    policy does not allow one, such as at a caller-declared critical field or, when
    ``forbid_shared_keys`` is in effect, as a map key.
    """


def _is_tracked(node: Any) -> bool:
    if not isinstance(node, _TRACKED_TYPES):
        return False
    # Empty tuples/frozensets may be interned singletons, not genuinely shared values
    if isinstance(node, (tuple, frozenset)) and not node:
        return False
    return True


def _iter_children(node: Any) -> Iterable[tuple[Hashable, Any, bool]]:
    """Yield ``(path_component, child, is_map_key)`` for each child of *node*."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            yield key, key, True
            yield key, value, False
    elif isinstance(node, (tuple, list, set, frozenset)):
        for index, item in enumerate(node):
            yield index, item, False
    elif isinstance(node, CBORTag):
        yield "<value>", node.value, False


def _format_path(path: Path) -> str:
    parts = ["$"]
    for component in path:
        if isinstance(component, str) and component.isidentifier():
            parts.append(f".{component}")
        else:
            parts.append(f"[{component!r}]")
    return "".join(parts)


def _find_shared_occurrences(root: Any) -> dict[int, list[tuple[Path, bool]]]:
    """
    Walk the decoded object graph and return, for every tracked container, the list
    of ``(path, is_map_key)`` occurrences found, keyed by ``id()``. Containers are
    expanded only on their first encounter; any descendant of a shared container is
    reachable through every occurrence of its ancestor, so shared locations further
    down are covered by prefix matching against the ancestor's paths.
    """
    occurrences: dict[int, list[tuple[Path, bool]]] = {}
    queue: deque[tuple[Any, Path, bool]] = deque([(root, (), False)])
    while queue:
        node, path, is_key = queue.popleft()
        if not _is_tracked(node):
            continue
        node_occurrences = occurrences.setdefault(id(node), [])
        if len(node_occurrences) >= _MAX_TRACKED_OCCURRENCES:
            continue
        node_occurrences.append((path, is_key))
        if len(node_occurrences) > 1:
            continue
        for component, child, child_is_key in _iter_children(node):
            queue.append((child, (*path, component), child_is_key))
    return {oid: occs for oid, occs in occurrences.items() if len(occs) > 1}


def _paths_conflict(first: Path, second: Path) -> bool:
    """Return True if either path is equal to or a prefix of the other."""
    return first[: len(second)] == second or second[: len(first)] == first


def _check_shared_value_policy(
    shared: dict[int, list[tuple[Path, bool]]],
    protected_paths: Iterable[Path],
    forbid_shared_keys: bool,
) -> None:
    protected = [tuple(path) for path in protected_paths]
    for occurrences in shared.values():
        paths = [path for path, _ in occurrences]
        if forbid_shared_keys:
            key_paths = [path for path, is_key in occurrences if is_key]
            if key_paths:
                locations = ", ".join(_format_path(path) for path in paths)
                raise SharedReferenceError(
                    f"shared reference used as a map key at "
                    f"{_format_path(key_paths[0])} (value reachable at: {locations})"
                )
        for protected_path in protected:
            if any(_paths_conflict(protected_path, path) for path in paths):
                locations = ", ".join(_format_path(path) for path in paths)
                raise SharedReferenceError(
                    f"shared reference not allowed at critical field "
                    f"{_format_path(protected_path)} (value reachable at: {locations})"
                )


def _mutable_copy(node: Any, memo: dict[int, Any]) -> Any:
    """
    Build a mutable deep copy of *node*, preserving aliasing *within* the copy (two
    references to a shared value become two references to the same copy). Map keys
    and set elements are reused as-is, since only hashable (and, for decoded CBOR,
    immutable) objects can occupy those positions.
    """
    existing = memo.get(id(node))
    if existing is not None:
        return existing
    if isinstance(node, Mapping):
        result: Any = {}
        memo[id(node)] = result
        for key, value in node.items():
            result[key] = _mutable_copy(value, memo)
        return result
    if isinstance(node, (tuple, list)):
        result = []
        memo[id(node)] = result
        result.extend(_mutable_copy(item, memo) for item in node)
        return result
    if isinstance(node, (set, frozenset)):
        result = set(node)
        memo[id(node)] = result
        return result
    if isinstance(node, bytearray):
        result = bytearray(node)
        memo[id(node)] = result
        return result
    if isinstance(node, CBORTag):
        result = CBORTag(node.tag, _mutable_copy(node.value, memo))
        memo[id(node)] = result
        return result
    # Immutable scalars are returned as-is by deepcopy(); anything else (for example
    # custom objects produced by hooks) is copied so that it cannot be shared with
    # the original evidence
    return deepcopy(node, memo)


class Evidence:
    """
    The immutable, identity-preserving decode of a sealed CBOR artifact.

    Instances are created with :func:`loads_evidence` or :func:`load_evidence`. The
    decoded content is exposed as :attr:`root`, an immutable object graph in which
    shared values remain aliased, so the structure of the original artifact is
    preserved exactly. Consumers must not mutate :attr:`root`; instead, each
    consumer calls :meth:`view` to get its own mutable working copy.
    """

    __slots__ = ("_data", "_digest", "_root", "_shared_paths")

    def __init__(self, data: bytes, root: Any, shared_paths: tuple[Path, ...]) -> None:
        self._data = data
        self._digest = sha256(data).hexdigest()
        self._root = root
        self._shared_paths = shared_paths

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(digest={self._digest!r}, "
            f"shared_values={len(self._shared_paths)})"
        )

    @property
    def data(self) -> bytes:
        """The raw CBOR bytes of the artifact."""
        return self._data

    @property
    def digest(self) -> str:
        """The SHA-256 digest of the raw artifact, establishing its identity."""
        return self._digest

    @property
    def root(self) -> Any:
        """The decoded content as an immutable object graph."""
        return self._root

    @property
    def shared_paths(self) -> tuple[Path, ...]:
        """
        Paths at which a shared reference (semantic tag 29) materialized, beyond the
        first occurrence of each shared value.
        """
        return self._shared_paths

    def view(self) -> EvidenceView:
        """
        Return a new, caller-private mutable view of the decoded content. Mutations
        (such as review annotations) made through the returned view affect neither
        this evidence nor any other view.
        """
        return EvidenceView(self, _mutable_copy(self._root, {}))


class EvidenceView:
    """
    A single caller's mutable, processable view of an :class:`Evidence`.

    The view's :attr:`data` is a deep copy of the evidence's decoded content with
    mutable containers (``dict``, ``list``, ``set``) in place of the immutable ones.
    Aliasing is preserved *within* the view: two positions that referenced the same
    shared value in the artifact reference the same copy here, so the view stays
    faithful to the original structure while remaining isolated from the evidence
    and from every other view.
    """

    __slots__ = ("_data", "_evidence")

    def __init__(self, evidence: Evidence, data: Any) -> None:
        self._evidence = evidence
        self._data = data

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(evidence={self._evidence!r})"

    @property
    def evidence(self) -> Evidence:
        """The original evidence this view was derived from."""
        return self._evidence

    @property
    def data(self) -> Any:
        """This caller's private, mutable copy of the decoded content."""
        return self._data


def _build_evidence(
    data: bytes,
    protected_paths: Iterable[Path],
    forbid_shared_keys: bool,
    decode_kwargs: dict[str, Any],
) -> Evidence:
    root = loads(data, immutable=True, **decode_kwargs)
    shared = _find_shared_occurrences(root)
    _check_shared_value_policy(shared, protected_paths, forbid_shared_keys)
    shared_paths = tuple(path for occurrences in shared.values() for path, _ in occurrences[1:])
    return Evidence(data, root, shared_paths)


def loads_evidence(
    data: bytes,
    *,
    protected_paths: Iterable[Path] = (),
    forbid_shared_keys: bool = False,
    **decode_kwargs: Any,
) -> Evidence:
    """
    Decode a CBOR artifact as :class:`Evidence`, decoding exactly once into an
    immutable object graph that preserves the identity of the original artifact.

    :param data: the serialized artifact (a bytes-like object)
    :param protected_paths: key paths (sequences of map keys/indices, relative to
        the root) designating critical fields where shared references are not
        allowed; if a shared value materializes at, below, or around any of these
        paths, :exc:`SharedReferenceError` is raised
    :param forbid_shared_keys: if :data:`True`, raise :exc:`SharedReferenceError`
        when a shared reference is used as a map key
    :param decode_kwargs: additional keyword arguments are forwarded to
        :func:`~cbor2.loads` (``immutable`` is always :data:`True`)
    :return: the decoded evidence

    """
    if "immutable" in decode_kwargs:
        raise TypeError("loads_evidence() always decodes with immutable=True")
    return _build_evidence(bytes(data), protected_paths, forbid_shared_keys, decode_kwargs)


def load_evidence(
    fp: IO[bytes],
    *,
    protected_paths: Iterable[Path] = (),
    forbid_shared_keys: bool = False,
    **decode_kwargs: Any,
) -> Evidence:
    """
    Decode a CBOR artifact read from a file as :class:`Evidence`.

    This is the file-reading counterpart of :func:`loads_evidence`; the entire
    content of *fp* is read so that the evidence digest can be computed.

    :param fp: a file-like object opened for reading in binary mode
    :param protected_paths: see :func:`loads_evidence`
    :param forbid_shared_keys: see :func:`loads_evidence`
    :param decode_kwargs: additional keyword arguments are forwarded to
        :func:`~cbor2.loads` (``immutable`` is always :data:`True`)
    :return: the decoded evidence

    """
    if "immutable" in decode_kwargs:
        raise TypeError("load_evidence() always decodes with immutable=True")
    return _build_evidence(bytes(fp.read()), protected_paths, forbid_shared_keys, decode_kwargs)
