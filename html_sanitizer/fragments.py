"""
Sanitize and merge independently authored HTML fragments.

The regular :meth:`Sanitizer.sanitize` method treats every fragment as a
standalone document.  That is fine until several sanitized fragments are
concatenated into one page: two fragments may both contain an element with
``id="attachment"`` (or a legacy ``name="attachment"`` anchor), and a local
``href="#attachment"`` may then point at the other author's element.

This module keeps the existing sanitize pipeline untouched and adds a small
post-processing pass on top of it.  Every retained fragment-local anchor is
given a deterministic, source-scoped name.  Fragment-local links and IDREF
attributes (``aria-labelledby``, ``aria-describedby``, ``for``, ...) are
rewritten together with the anchors they refer to.

The mapping is deliberately derived from ``(source, local_id)`` only -- never
from the position of a fragment in the input -- so importing fragments in a
different order, or sanitizing one fragment again on its own, doesn't move any
other fragment's links.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import unquote

import lxml.html

from .sanitizer import Sanitizer as _SanitizerLike


__all__ = (
    "FragmentIssue",
    "FragmentMergeResult",
    "FragmentReference",
    "merge_fragments",
    "sanitize_fragments",
)


# Attributes whose values are whitespace-separated lists of element IDs.
# ARIA defines these as ID reference lists.  ``headers`` is the table
# accessibility equivalent.  The other entries are common HTML IDREF
# attributes which have the same "renaming an id must rename its references"
# problem.
IDREF_ATTRIBUTES = frozenset(
    {
        "aria-activedescendant",
        "aria-controls",
        "aria-describedby",
        "aria-details",
        "aria-errormessage",
        "aria-flowto",
        "aria-labelledby",
        "aria-owns",
        "commandfor",
        "for",
        "form",
        "headers",
        "itemref",
        "list",
        "popovertarget",
    }
)

_FRAGMENT_HREF_RE = re.compile(r"^#(.*)$", re.DOTALL)
_EMPTY_FRAGMENT_RE = re.compile(r"^\s*$")
_UNSAFE_SCOPE_RE = re.compile(r"[\s#%?/&\"'<>`]+")
_REPEATED_DASH_RE = re.compile(r"-{2,}")


@dataclass(frozen=True)
class FragmentIssue:
    """
    A reviewable problem found while merging fragments.

    ``kind`` is one of ``"ambiguous"``, ``"empty"`` or ``"unresolved"``.
    ``candidates`` contains the effective IDs which could be meant, and
    ``sources`` contains the source names which define them.
    """

    kind: str
    source: str
    attribute: str
    value: str = ""
    tag: str | None = None
    candidates: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    message: str = ""

    @property
    def type(self):
        return self.kind

    @property
    def status(self):
        return self.kind

    @property
    def target(self):
        return None

    @property
    def local(self):
        return self.value

    @property
    def scope(self):
        return self.source

    @property
    def attr(self):
        return self.attribute

    @property
    def reference(self):
        return self.value

    @property
    def targets(self):
        return self.candidates

    @property
    def reason(self):
        return self.message

    def __str__(self):
        return self.message or (
            f"{self.kind} {self.attribute} reference {self.value!r} "
            f"in source {self.source!r}"
        )

    def as_dict(self):
        return {
            "kind": self.kind,
            "source": self.source,
            "attribute": self.attribute,
            "value": self.value,
            "tag": self.tag,
            "candidates": list(self.candidates),
            "sources": list(self.sources),
            "message": self.message,
        }


@dataclass(frozen=True)
class FragmentReference:
    """A link or IDREF attribute considered while merging fragments."""

    source: str
    tag: str
    attribute: str
    value: str
    target: str | None
    status: str = "resolved"
    candidates: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()

    @property
    def kind(self):
        return self.status

    @property
    def attr(self):
        return self.attribute

    @property
    def reference(self):
        return self.value

    @property
    def anchor(self):
        return self.target

    @property
    def resolved(self):
        return self.status in {"resolved", "shared"}

    @property
    def rewritten(self):
        return self.target is not None and self.target != self.value

    def as_dict(self):
        return {
            "source": self.source,
            "tag": self.tag,
            "attribute": self.attribute,
            "value": self.value,
            "target": self.target,
            "status": self.status,
            "candidates": list(self.candidates),
            "sources": list(self.sources),
        }


class FragmentMergeResult(str):
    """
    The merged HTML as a string, with reviewable merge diagnostics attached.

    Subclassing ``str`` keeps the new entry point a drop-in replacement for
    code which joins the results of ``Sanitizer.sanitize`` calls.  ``html`` /
    ``output`` are aliases for the string itself.
    """

    def __new__(
        cls,
        html,
        *,
        id_map=None,
        anchors=None,
        references=None,
        issues=None,
        shared_ids=(),
    ):
        result = super().__new__(cls, html)
        result.id_map = id_map or {}
        result.anchors = anchors or {}
        result.references = references or []
        result.issues = issues or []
        result.shared_ids = frozenset(shared_ids)
        return result

    @property
    def html(self):
        return str(self)

    @property
    def output(self):
        return str(self)

    @property
    def merged(self):
        return str(self)

    @property
    def report(self):
        return self

    @property
    def ids(self):
        return self.anchors

    @property
    def anchor_map(self):
        return self.id_map

    @property
    def anchor_ids(self):
        return frozenset(self.anchors)

    @property
    def effective_ids(self):
        return tuple(self.anchors)

    @property
    def links(self):
        return self.references

    @property
    def diagnostics(self):
        return self.issues

    @property
    def problems(self):
        return self.issues

    @property
    def ambiguous(self):
        return [issue for issue in self.issues if issue.kind == "ambiguous"]

    @property
    def ambiguous_references(self):
        return self.ambiguous

    @property
    def empty(self):
        return [issue for issue in self.issues if issue.kind == "empty"]

    @property
    def empty_references(self):
        return self.empty

    @property
    def unresolved(self):
        return [issue for issue in self.issues if issue.kind == "unresolved"]

    @property
    def unresolved_references(self):
        return self.unresolved

    @property
    def duplicates(self):
        return [
            issue
            for issue in self.issues
            if issue.kind == "ambiguous" and issue.attribute in {"id", "name"}
        ]

    @property
    def ambiguous_definitions(self):
        return self.duplicates

    @property
    def warnings(self):
        return self.issues

    @property
    def ok(self):
        return not self.issues

    def as_dict(self):
        return {
            "html": str(self),
            "id_map": {
                source: dict(mapping) for source, mapping in self.id_map.items()
            },
            "anchors": dict(self.anchors),
            "references": [reference.as_dict() for reference in self.references],
            "issues": [issue.as_dict() for issue in self.issues],
            "ambiguous": [issue.as_dict() for issue in self.ambiguous],
            "empty": [issue.as_dict() for issue in self.empty],
            "unresolved": [issue.as_dict() for issue in self.unresolved],
        }

    def to_dict(self):
        return self.as_dict()

    def keys(self):
        return self.as_dict().keys()

    def values(self):
        return self.as_dict().values()

    def items(self):
        return self.as_dict().items()

    def get(self, key, default=None):
        return self.as_dict().get(key, default)

    def __getitem__(self, key):
        # Allow result["html"] / result["ambiguous"] without losing normal
        # string indexing.
        if isinstance(key, str):
            return self.as_dict()[key]
        return super().__getitem__(key)


@dataclass
class _Definition:
    source: str
    local: str
    effective: str
    shared: bool
    element: object
    attributes: tuple[str, ...]


def _scope_name(source):
    """Turn an arbitrary source label into a stable, fragment-safe prefix."""
    value = _UNSAFE_SCOPE_RE.sub("-", str(source).strip())
    value = _REPEATED_DASH_RE.sub("-", value).strip("-")
    return value or "fragment"


def _scoped_id(scope, local, separator):
    return f"{scope}{separator}{local}"


def _parse_fragment(html):
    return lxml.html.fromstring("<div>%s</div>" % html)


def _serialize_fragment(root):
    html = lxml.html.tostring(root, encoding="unicode")
    return re.sub(r"^<div>|</div>$", "", html)


def _iter_fragments(fragments, sources=None):
    """Yield ``(source, html)`` pairs from the supported input shapes."""
    if sources is not None:
        if isinstance(fragments, str):
            raise TypeError("When passing sources, fragments must be an iterable")
        fragments = list(fragments)
        sources = list(sources)
        if len(fragments) != len(sources):
            raise ValueError("fragments and sources must have the same length")
        yield from zip(sources, fragments, strict=True)
        return

    if isinstance(fragments, Mapping):
        yield from fragments.items()
        return

    if isinstance(fragments, str):
        raise TypeError(
            "fragments must be a mapping or an iterable of (source, html) pairs"
        )

    for item in fragments:
        if isinstance(item, Mapping):
            source = item.get(
                "source",
                item.get(
                    "scope", item.get("key", item.get("source_id", item.get("id")))
                ),
            )
            html = item.get(
                "html", item.get("content", item.get("fragment", item.get("markup")))
            )
            if source is None or html is None:
                raise TypeError(
                    "Fragment mappings need 'source'/'scope' and 'html'/'content'"
                )
        elif hasattr(item, "html") and (
            hasattr(item, "source")
            or hasattr(item, "scope")
            or hasattr(item, "source_id")
        ):
            source = getattr(item, "source", None)
            if source is None:
                source = getattr(item, "scope", None)
            if source is None:
                source = item.source_id
            html = item.html
        else:
            try:
                first, second = item
            except (TypeError, ValueError) as exc:
                raise TypeError("Each fragment must be a (source, html) pair") from exc
            if (
                isinstance(first, str)
                and first.lstrip().startswith("<")
                and not (isinstance(second, str) and second.lstrip().startswith("<"))
            ):
                source, html = second, first
            else:
                source, html = first, second
        yield source, html


def _anchor_locations(element):
    """
    Return ``{local_id: (attributes...)}`` for anchors retained on an element.

    ``id`` is a document-wide anchor on every element.  ``name`` is only an
    anchor on ``<a>`` tags.
    """
    locations = {}
    element_id = element.get("id")
    if element_id:
        locations.setdefault(element_id, []).append("id")
    if element.tag == "a":
        name = element.get("name")
        if name:
            locations.setdefault(name, []).append("name")
    return locations


def _unique(items):
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return tuple(result)


def _unique_elements(elements):
    seen = set()
    result = []
    for element in elements:
        marker = id(element)
        if marker not in seen:
            seen.add(marker)
            result.append(element)
    return result


class _Merger:
    def __init__(self, sanitizer, *, shared_ids=(), id_separator="--", separator=""):
        self.sanitizer = sanitizer
        self.shared_ids = frozenset(str(value) for value in (shared_ids or ()))
        self.id_separator = id_separator
        self.separator = separator

        self.fragments = []
        self.definitions = []
        self.definitions_by_source = {}
        self.definitions_by_local = {}
        self.issues = []
        self.references = []
        self.id_map = {}
        self.anchors = {}

    def run(self, fragments, sources=None):
        for raw_source, html in _iter_fragments(fragments, sources):
            source = str(raw_source)
            sanitized = self.sanitizer.sanitize(html)
            root = _parse_fragment(sanitized)
            self.fragments.append((source, root))

        self._collect_definitions()
        self._rewrite_definitions()
        self._rewrite_references()

        html = self.separator.join(
            _serialize_fragment(root) for _source, root in self.fragments
        )
        return FragmentMergeResult(
            html,
            id_map=self.id_map,
            anchors=self.anchors,
            references=self.references,
            issues=self.issues,
            shared_ids=self.shared_ids,
        )

    def _collect_definitions(self):
        empty_locations = []

        for source, root in self.fragments:
            scope = _scope_name(source)
            source_map = self.id_map.setdefault(source, {})
            source_definitions = self.definitions_by_source.setdefault(source, {})

            for element in root.iter():
                if not isinstance(element.tag, str):
                    continue

                element_id = element.get("id")
                if element_id is not None and not element_id.strip():
                    empty_locations.append((source, element, "id", element_id))
                if element.tag == "a":
                    name = element.get("name")
                    if name is not None and not name.strip():
                        empty_locations.append((source, element, "name", name))

                for local, attributes in _anchor_locations(element).items():
                    shared = local in self.shared_ids
                    effective = (
                        local if shared else _scoped_id(scope, local, self.id_separator)
                    )
                    definition = _Definition(
                        source=source,
                        local=local,
                        effective=effective,
                        shared=shared,
                        element=element,
                        attributes=tuple(attributes),
                    )
                    self.definitions.append(definition)
                    source_definitions.setdefault(local, []).append(definition)
                    self.definitions_by_local.setdefault(local, []).append(definition)

                    source_map.setdefault(local, effective)
                    self.anchors.setdefault(effective, source)

        for source, element, attribute, value in empty_locations:
            self.issues.append(
                FragmentIssue(
                    kind="empty",
                    source=source,
                    tag=element.tag,
                    attribute=attribute,
                    value=value,
                    message=(
                        f"Empty {attribute!r} anchor in source {source!r} "
                        "was not scoped"
                    ),
                )
            )

        self._report_duplicate_definitions()

    def _report_duplicate_definitions(self):
        reported = set()

        for definitions in self.definitions_by_local.values():
            elements = _unique_elements(
                definition.element for definition in definitions
            )
            if len(elements) < 2:
                continue

            # Duplicate local names in different sources are fine when they are
            # scoped.  They are only ambiguous when they deliberately share one
            # global name, or when the same source defines the same name twice.
            effective_ids = _unique(definition.effective for definition in definitions)
            shared = any(definition.shared for definition in definitions)
            same_source = len({definition.source for definition in definitions}) == 1
            if not shared and not same_source:
                continue

            marker = (definitions[0].local, effective_ids)
            if marker in reported:
                continue
            reported.add(marker)

            sources = _unique(definition.source for definition in definitions)
            message = (
                f"Anchor {definitions[0].local!r} is defined more than once"
                f" ({', '.join(repr(source) for source in sources)})"
            )
            if shared:
                message += " and was explicitly shared"

            self.issues.append(
                FragmentIssue(
                    kind="ambiguous",
                    source=sources[0],
                    tag=definitions[0].element.tag,
                    attribute="id",
                    value=definitions[0].local,
                    candidates=effective_ids,
                    sources=sources,
                    message=message,
                )
            )

    def _rewrite_definitions(self):
        for definition in self.definitions:
            for attribute in definition.attributes:
                definition.element.set(attribute, definition.effective)

    def _effective_definitions(self, token):
        return self.definitions_by_local.get(token, ())

    def _resolve(self, source, token):
        """
        Return ``(effective_id, status, candidates, sources)``.

        A source-local definition always wins over same-named anchors in other
        sources.  That is what makes ``#attachment`` mean "this author's
        attachment" instead of whichever fragment happened to come first.
        """
        if token in self.shared_ids:
            definitions = self._effective_definitions(token)
            elements = _unique_elements(
                definition.element for definition in definitions
            )
            candidates = _unique(definition.effective for definition in definitions)
            sources = _unique(definition.source for definition in definitions)
            if len(elements) > 1:
                return None, "ambiguous", candidates, sources
            return token, "shared", candidates or (token,), sources

        local_definitions = self.definitions_by_source.get(source, {}).get(token, ())
        if local_definitions:
            candidates = _unique(
                definition.effective for definition in local_definitions
            )
            sources = _unique(definition.source for definition in local_definitions)
            return candidates[0], "resolved", candidates, sources

        definitions = self._effective_definitions(token)
        if not definitions:
            return None, "unresolved", (), ()

        candidates = _unique(definition.effective for definition in definitions)
        sources = _unique(definition.source for definition in definitions)
        if len(candidates) == 1:
            return candidates[0], "resolved", candidates, sources
        return None, "ambiguous", candidates, sources

    def _record_reference(self, source, element, attribute, value, resolved):
        target, status, candidates, sources = resolved
        self.references.append(
            FragmentReference(
                source=source,
                tag=element.tag,
                attribute=attribute,
                value=value,
                target=target,
                status=status,
                candidates=candidates,
                sources=sources,
            )
        )

        if status == "ambiguous":
            self.issues.append(
                FragmentIssue(
                    kind="ambiguous",
                    source=source,
                    tag=element.tag,
                    attribute=attribute,
                    value=value,
                    candidates=candidates,
                    sources=sources,
                    message=(
                        f"{attribute} reference {value!r} in source {source!r}"
                        f" is ambiguous between {', '.join(repr(c) for c in candidates)}"
                    ),
                )
            )
        elif status == "unresolved":
            self.issues.append(
                FragmentIssue(
                    kind="unresolved",
                    source=source,
                    tag=element.tag,
                    attribute=attribute,
                    value=value,
                    message=(
                        f"{attribute} reference {value!r} in source {source!r}"
                        " does not point at a retained anchor"
                    ),
                )
            )
        elif status == "empty":
            self.issues.append(
                FragmentIssue(
                    kind="empty",
                    source=source,
                    tag=element.tag,
                    attribute=attribute,
                    value=value,
                    message=(f"{attribute} reference in source {source!r} is empty"),
                )
            )

        return target

    def _rewrite_href(self, source, element):
        href = element.get("href")
        if href is None:
            return

        match = _FRAGMENT_HREF_RE.match(href)
        if match is None:
            return

        fragment = match.group(1)
        if _EMPTY_FRAGMENT_RE.match(fragment):
            self._record_reference(
                source, element, "href", href, (None, "empty", (), ())
            )
            return

        token = unquote(fragment)
        resolved = self._resolve(source, token)
        target = self._record_reference(source, element, "href", href, resolved)
        if target is not None:
            element.set("href", f"#{target}")

    def _rewrite_idref(self, source, element, attribute):
        value = element.get(attribute)
        if value is None:
            return

        tokens = value.split()
        if not tokens:
            self._record_reference(
                source, element, attribute, value, (None, "empty", (), ())
            )
            return

        rewritten = []
        for token in tokens:
            resolved = self._resolve(source, token)
            target = self._record_reference(source, element, attribute, token, resolved)
            rewritten.append(target if target is not None else token)
        element.set(attribute, " ".join(rewritten))

    def _rewrite_references(self):
        for source, root in self.fragments:
            for element in root.iter():
                if not isinstance(element.tag, str):
                    continue

                self._rewrite_href(source, element)

                for attribute in element.attrib:
                    normalized_attribute = attribute.lower()
                    if normalized_attribute in IDREF_ATTRIBUTES:
                        self._rewrite_idref(source, element, normalized_attribute)


def sanitize_fragments(
    fragments,
    sanitizer=None,
    shared_ids=(),
    *,
    shared_anchors=None,
    shared_names=None,
    global_ids=None,
    sources=None,
    source_ids=None,
    separator="",
    id_separator="--",
    source_separator=None,
    **kwargs,
):
    """
    Sanitize and merge fragments, scoping anchors by their source.

    ``fragments`` may be a mapping of ``source -> html`` or an iterable of
    ``(source, html)`` pairs.  Each fragment is passed through the regular
    sanitizer first; IDs or attributes which the sanitizer configuration drops
    are not magically preserved here.

    ``shared_ids`` (also accepted as ``shared_anchors``/``shared_names``) lists
    the small set of anchors which should stay global instead of being scoped.

    Returns a :class:`FragmentMergeResult`: it *is* the merged HTML string and
    also exposes ``ambiguous``, ``empty`` and ``unresolved`` diagnostics.
    """
    if kwargs:
        unexpected = next(iter(kwargs))
        raise TypeError(f"Unexpected argument {unexpected!r}")

    if isinstance(fragments, _SanitizerLike):
        fragments, sanitizer = sanitizer, fragments

    if sanitizer is not None and not isinstance(sanitizer, _SanitizerLike):
        # Support ``sanitize_fragments(fragments, {"shared"})`` as well as the
        # ``sanitize_fragments(fragments, sanitizer, ...)`` form.
        if shared_ids:
            raise TypeError("shared_ids specified more than once")
        shared_ids = sanitizer
        sanitizer = None

    if sanitizer is None:
        sanitizer = _SanitizerLike()

    for alias, candidate in (
        ("shared_anchors", shared_anchors),
        ("shared_names", shared_names),
        ("global_ids", global_ids),
    ):
        if candidate is None:
            continue
        shared = candidate
        if isinstance(shared, Mapping):
            shared = shared.keys()
        if shared_ids:
            raise TypeError(f"shared_ids and {alias} cannot be used at the same time")
        shared_ids = shared
        break

    if isinstance(shared_ids, str):
        shared_ids = (shared_ids,)

    if source_separator is not None and id_separator == "--":
        id_separator = source_separator

    if sources is None:
        sources = source_ids

    return _Merger(
        sanitizer,
        shared_ids=shared_ids,
        id_separator=id_separator,
        separator=separator,
    ).run(fragments, sources)


merge_fragments = sanitize_fragments
