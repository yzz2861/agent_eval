"""Read-only navigation forensics for PDF documents.

The helpers in this module inspect the navigation structures which are already
present in a PDF file:

* the document outline (bookmarks),
* link annotations on pages, and
* the named destinations in the ``/Names`` and legacy ``/Dests`` trees.

They never follow an external action or open a referenced file. External
targets are reported as evidence only.

Every navigation source is resolved into a small chain of hops. A direct array
resolves to its page in one hop. A named destination takes two hops: the first
hop records the name referenced by the source, and the second hop resolves the
name-tree registration to a page. If a named destination registration is
removed, the original two-hop navigation therefore reports
broken_at_hop == 2.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from ._configuration import get_configuration
from .generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NullObject,
    NumberObject,
    TextStringObject,
    is_null_or_none,
)

if TYPE_CHECKING:
    from ._doc_common import PdfDocCommon


__all__ = [
    "DuplicateNameGroup",
    "NamedDestinationEntry",
    "NavigationChain",
    "NavigationFinding",
    "NavigationForensics",
    "NavigationHop",
    "NavigationReport",
    "Source",
    "analyze_navigation",
    "audit_navigation",
    "collect_navigation_evidence",
    "inspect_navigation",
    "navigation_forensics",
]


_EXTERNAL_ACTIONS = {
    "/GoToE",
    "/GoToR",
    "/ImportData",
    "/Launch",
    "/Rendition",
    "/SubmitForm",
    "/URI",
}


class _MappingView:
    """Offer a small read-only mapping facade on top of the result objects."""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        raise NotImplementedError

    def as_dict(self) -> dict[str, Any]:
        """Alias for :meth:`to_dict`."""
        return self.to_dict()

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        """Return an attribute or a default value."""
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and hasattr(self, key)

    def keys(self) -> Any:
        """Return the keys of the mapping representation."""
        return self.to_dict().keys()

    def items(self) -> Any:
        """Return the items of the mapping representation."""
        return self.to_dict().items()


def _object_id(value: Any) -> tuple[int, int] | None:
    reference = value if isinstance(value, IndirectObject) else getattr(value, "indirect_reference", None)
    if isinstance(reference, IndirectObject):
        return reference.idnum, reference.generation
    return None


def _ref_string(value: Any) -> str | None:
    object_id = _object_id(value)
    if object_id is None:
        return None
    return f"{object_id[0]} {object_id[1]} R"


def _decode_name(value: Any) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.decode("latin-1")
    return str(value)


def _canonical_name(value: Any) -> str:
    name = _decode_name(value)
    if isinstance(value, NameObject) and name.startswith("/"):
        return name[1:]
    return name


def _as_object(value: Any) -> Any:
    try:
        if isinstance(value, IndirectObject):
            return value.get_object()
        getter = getattr(value, "get_object", None)
        if callable(getter):
            return getter()
    except Exception:
        # A dangling reference is evidence of a missing target, not a reason to
        # abort the whole inspection.
        return None
    return value


def _as_dict(value: Any) -> DictionaryObject | None:
    value = _as_object(value)
    return value if isinstance(value, DictionaryObject) else None


def _json_safe(  # noqa: PLR0911
    value: Any, *, depth: int = 0, seen: set[int] | None = None
) -> Any:
    if seen is None:
        seen = set()
    if depth > 12:
        return "<maximum depth reached>"
    if isinstance(value, IndirectObject):
        return {"ref": _ref_string(value), "object_id": [value.idnum, value.generation]}
    if isinstance(value, NullObject):
        return None
    if isinstance(value, ArrayObject):
        if id(value) in seen:
            return {"ref": _ref_string(value), "cycle": True}
        seen.add(id(value))
        result = [_json_safe(item, depth=depth + 1, seen=seen) for item in value]
        seen.remove(id(value))
        return result
    if isinstance(value, DictionaryObject):
        if id(value) in seen:
            return {"ref": _ref_string(value), "cycle": True}
        seen.add(id(value))
        result = {str(key): _json_safe(item, depth=depth + 1, seen=seen) for key, item in value.items()}
        seen.remove(id(value))
        return result
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("latin-1")
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    reference = _object_id(value)
    if reference is not None:
        return {"ref": _ref_string(value), "object_id": [reference[0], reference[1]]}
    return str(value)


@dataclass(frozen=True)
class Source(_MappingView):
    """Location of one piece of navigation evidence inside the PDF."""

    kind: str
    label: str
    page_index: int | None = None
    annotation_index: int | None = None
    outline_path: tuple[int, ...] | None = None
    name_tree_path: tuple[int | str, ...] | None = None
    registry: str | None = None
    key: str | None = None
    title: str | None = None
    object_id: tuple[int, int] | None = None

    @property
    def ref(self) -> str | None:
        """The indirect object reference, if the source is an indirect object."""
        if self.object_id is None:
            return None
        return f"{self.object_id[0]} {self.object_id[1]} R"

    @property
    def page(self) -> int | None:
        """Alias for :attr:`page_index`."""
        return self.page_index

    def __str__(self) -> str:
        return self.label

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "kind": self.kind,
            "label": self.label,
            "page_index": self.page_index,
            "annotation_index": self.annotation_index,
            "outline_path": list(self.outline_path) if self.outline_path is not None else None,
            "name_tree_path": list(self.name_tree_path) if self.name_tree_path is not None else None,
            "registry": self.registry,
            "key": self.key,
            "title": self.title,
            "object_id": list(self.object_id) if self.object_id is not None else None,
            "ref": self.ref,
        }


@dataclass
class NamedDestinationEntry(_MappingView):
    """A single named-destination registration and its provenance."""

    name: str
    source: Source
    value: Any = None
    raw_name: str | None = None
    page_index: int | None = None
    status: str = "ok"
    reason: str | None = None
    is_direct: bool = False
    value_object_id: tuple[int, int] | None = None
    alias_of: str | None = None
    duplicate: bool = False

    @property
    def destination_page(self) -> int | None:
        """Alias for :attr:`page_index`."""
        return self.page_index

    @property
    def page(self) -> int | None:
        """Alias for page_index."""
        return self.page_index

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "name": self.name,
            "raw_name": self.raw_name,
            "source": self.source.to_dict(),
            "value": _json_safe(self.value),
            "value_object_id": list(self.value_object_id) if self.value_object_id is not None else None,
            "page_index": self.page_index,
            "status": self.status,
            "reason": self.reason,
            "is_direct": self.is_direct,
            "alias_of": self.alias_of,
            "duplicate": self.duplicate,
        }


@dataclass
class NavigationHop(_MappingView):
    """One resolution step of a navigation chain."""

    index: int
    kind: str
    status: str
    source: Source
    value: Any = None
    name: str | None = None
    target_page_index: int | None = None
    message: str | None = None
    followed: bool = True

    @property
    def reason(self) -> str | None:
        """Alias for :attr:`message`."""
        return self.message

    @property
    def target_page(self) -> int | None:
        """Alias for :attr:`target_page_index`."""
        return self.target_page_index

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "index": self.index,
            "kind": self.kind,
            "status": self.status,
            "source": self.source.to_dict(),
            "value": _json_safe(self.value),
            "name": self.name,
            "target_page_index": self.target_page_index,
            "message": self.message,
            "followed": self.followed,
        }


@dataclass
class NavigationFinding(_MappingView):
    """A navigation defect or an explicitly preserved reference."""

    kind: str
    message: str
    source: Source
    value: Any = None
    hop_index: int | None = None
    name: str | None = None
    target_page_index: int | None = None
    hop_source: Source | None = None
    duplicate_of: Source | None = None
    external_target: str | None = None
    followed: bool = True

    @property
    def category(self) -> str:
        """Alias for :attr:`kind`."""
        return self.kind

    @property
    def reason(self) -> str:
        """Alias for :attr:`message`."""
        return self.message

    @property
    def hop(self) -> int | None:
        """Alias for :attr:`hop_index`."""
        return self.hop_index

    @property
    def provenance(self) -> tuple[Source, ...]:
        """All source locations relevant to this finding."""
        result = [self.source]
        if self.hop_source is not None and self.hop_source != self.source:
            result.append(self.hop_source)
        if self.duplicate_of is not None and self.duplicate_of not in result:
            result.append(self.duplicate_of)
        return tuple(result)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "kind": self.kind,
            "message": self.message,
            "source": self.source.to_dict(),
            "value": _json_safe(self.value),
            "hop_index": self.hop_index,
            "name": self.name,
            "target_page_index": self.target_page_index,
            "hop_source": self.hop_source.to_dict() if self.hop_source is not None else None,
            "duplicate_of": self.duplicate_of.to_dict() if self.duplicate_of is not None else None,
            "external_target": self.external_target,
            "followed": self.followed,
            "provenance": [source.to_dict() for source in self.provenance],
        }


@dataclass
class NavigationChain(_MappingView):
    """A source and the hops used to resolve its destination."""

    id: str
    origin: Source
    hops: list[NavigationHop] = field(default_factory=list)
    status: str = "resolved"
    target_page_index: int | None = None
    broken_at_hop: int | None = None
    break_reason: str | None = None
    ambiguous: bool = False

    @property
    def source(self) -> Source:
        """Alias for :attr:`origin`."""
        return self.origin

    @property
    def evidence(self) -> list[NavigationHop]:
        """Alias for :attr:`hops`."""
        return self.hops

    @property
    def hop_count(self) -> int:
        """The number of resolution hops in this chain."""
        return len(self.hops)

    @property
    def broken(self) -> bool:
        """Whether the chain is broken."""
        return self.status == "broken"

    @property
    def resolved(self) -> bool:
        """Whether the chain reaches a page."""
        return self.status == "resolved"

    @property
    def external(self) -> bool:
        """Whether the chain points outside the document."""
        return self.status == "external"

    @property
    def break_hop(self) -> int | None:
        """Alias for :attr:`broken_at_hop`."""
        return self.broken_at_hop

    @property
    def target_page(self) -> int | None:
        """Alias for :attr:`target_page_index`."""
        return self.target_page_index

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "id": self.id,
            "origin": self.origin.to_dict(),
            "source": self.origin.to_dict(),
            "hops": [hop.to_dict() for hop in self.hops],
            "hop_count": self.hop_count,
            "status": self.status,
            "resolved": self.resolved,
            "broken": self.broken,
            "external": self.external,
            "target_page_index": self.target_page_index,
            "broken_at_hop": self.broken_at_hop,
            "break_reason": self.break_reason,
            "ambiguous": self.ambiguous,
        }


@dataclass(frozen=True)
class DuplicateNameGroup(_MappingView):
    """All registrations which share one named destination."""

    name: str
    entries: tuple[NamedDestinationEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "name": self.name,
            "entries": [entry.to_dict() for entry in self.entries],
            "sources": [entry.source.to_dict() for entry in self.entries],
        }


@dataclass
class NavigationReport(_MappingView):
    """Result of a read-only navigation inspection."""

    pages: int
    named_destinations: list[NamedDestinationEntry] = field(default_factory=list)
    chains: list[NavigationChain] = field(default_factory=list)
    findings: list[NavigationFinding] = field(default_factory=list)

    def __call__(self) -> NavigationReport:
        """Allow a report to be used as a callable accessor as well."""
        return self

    @property
    def destinations(self) -> list[NamedDestinationEntry]:
        """Alias for :attr:`named_destinations`."""
        return self.named_destinations

    @property
    def issues(self) -> list[NavigationFinding]:
        """Alias for :attr:`findings`."""
        return self.findings

    @property
    def direct_references(self) -> list[NavigationFinding]:
        """Direct (inline destination array) references with provenance."""
        return [finding for finding in self.findings if finding.kind == "direct_reference"]

    @property
    def duplicate_names(self) -> list[NavigationFinding]:
        """Named destination registrations which repeat an earlier name."""
        return [finding for finding in self.findings if finding.kind == "duplicate_name"]

    @property
    def duplicate_name_groups(self) -> list[DuplicateNameGroup]:
        """All duplicate names grouped with every registration and source."""
        grouped: dict[str, list[NamedDestinationEntry]] = defaultdict(list)
        for entry in self.named_destinations:
            if entry.duplicate:
                grouped[entry.name].append(entry)
        return [DuplicateNameGroup(name=name, entries=tuple(entries)) for name, entries in grouped.items()]

    @property
    def missing_targets(self) -> list[NavigationFinding]:
        """References whose destination cannot be resolved inside the PDF."""
        return [finding for finding in self.findings if finding.kind == "missing_target"]

    @property
    def external_references(self) -> list[NavigationFinding]:
        """External targets which were recorded but deliberately not opened."""
        return [finding for finding in self.findings if finding.kind == "external_reference"]

    @property
    def unsupported_actions(self) -> list[NavigationFinding]:
        """Actions which are not local navigation and were not followed."""
        return [finding for finding in self.findings if finding.kind == "unsupported_action"]

    @property
    def broken_chains(self) -> list[NavigationChain]:
        """Chains which do not reach an internal page."""
        return [chain for chain in self.chains if chain.broken]

    @property
    def outline_chains(self) -> list[NavigationChain]:
        """Chains whose source is an outline item."""
        return [chain for chain in self.chains if chain.origin.kind == "outline"]

    @property
    def annotation_chains(self) -> list[NavigationChain]:
        """Chains whose source is a page annotation."""
        return [chain for chain in self.chains if chain.origin.kind == "annotation"]

    @property
    def named_destinations_by_name(self) -> dict[str, list[NamedDestinationEntry]]:
        """Named destination registrations grouped by their canonical name."""
        grouped: dict[str, list[NamedDestinationEntry]] = defaultdict(list)
        for entry in self.named_destinations:
            grouped[entry.name].append(entry)
        return dict(grouped)

    @property
    def ok(self) -> bool:
        """Whether no missing, malformed, or duplicate navigation evidence exists."""
        informational = {"direct_reference", "external_reference", "unsupported_action"}
        return not any(finding.kind not in informational for finding in self.findings)

    @property
    def summary(self) -> dict[str, Any]:
        """Counts which are useful for logs and reports."""
        return {
            "pages": self.pages,
            "named_destinations": len(self.named_destinations),
            "chains": len(self.chains),
            "direct_references": len(self.direct_references),
            "duplicate_names": len(self.duplicate_names),
            "missing_targets": len(self.missing_targets),
            "external_references": len(self.external_references),
            "unsupported_actions": len(self.unsupported_actions),
            "broken_chains": len(self.broken_chains),
            "ok": self.ok,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            "pages": self.pages,
            "ok": self.ok,
            "summary": self.summary,
            "named_destinations": [entry.to_dict() for entry in self.named_destinations],
            "destinations": [entry.to_dict() for entry in self.named_destinations],
            "chains": [chain.to_dict() for chain in self.chains],
            "findings": [finding.to_dict() for finding in self.findings],
            "issues": [finding.to_dict() for finding in self.findings],
            "direct_references": [finding.to_dict() for finding in self.direct_references],
            "duplicate_names": [finding.to_dict() for finding in self.duplicate_names],
            "duplicate_name_groups": [group.to_dict() for group in self.duplicate_name_groups],
            "missing_targets": [finding.to_dict() for finding in self.missing_targets],
            "external_references": [finding.to_dict() for finding in self.external_references],
            "unsupported_actions": [finding.to_dict() for finding in self.unsupported_actions],
            "broken_chains": [chain.to_dict() for chain in self.broken_chains],
        }


@dataclass
class _TargetResolution:
    page_index: int | None = None
    status: str = "ok"
    reason: str | None = None
    is_direct: bool = False
    alias_of: str | None = None


class _NavigationAnalyzer:
    def __init__(
        self,
        document: PdfDocCommon,
        *,
        max_depth: int | None = None,
        max_entries: int | None = None,
    ) -> None:
        configuration = get_configuration()
        self.document = document
        self.pages = list(document.pages)
        self.max_depth = max_depth
        self.max_entries = max_entries
        self.outline_max_depth = max_depth if max_depth is not None else configuration.outline_maximum_depth
        self.outline_max_entries = max_entries if max_entries is not None else configuration.outline_maximum_entries
        self.name_tree_max_depth = (
            max_depth if max_depth is not None else configuration.named_destinations_maximum_depth
        )
        self.name_tree_max_entries = (
            max_entries if max_entries is not None else configuration.named_destinations_maximum_entries
        )

        self.page_index_by_idnum: dict[int, int] = {}
        for index, page in enumerate(self.pages):
            reference = page.indirect_reference
            if reference is not None:
                self.page_index_by_idnum[reference.idnum] = index
        self.registry_entries: list[NamedDestinationEntry] = []
        self.registry_by_name: dict[str, list[NamedDestinationEntry]] = defaultdict(list)
        self.registry_by_raw_name: dict[str, list[NamedDestinationEntry]] = defaultdict(list)
        self.findings: list[NavigationFinding] = []
        self.chains: list[NavigationChain] = []
        self._name_tree_visited: set[int] = set()
        self._name_tree_entry_count = 0
        self._outline_entry_count = 0
        self._chain_index = 0
        self._referenced_entries: set[int] = set()

    @property
    def root(self) -> DictionaryObject | None:
        return _as_dict(self.document.root_object)

    def run(self) -> NavigationReport:
        """Collect and resolve all navigation evidence."""
        self._collect_named_destinations()
        self._index_named_destinations()
        self._resolve_named_destinations()
        self._walk_outline()
        self._walk_annotations()
        self._report_unreferenced_broken_entries()
        return NavigationReport(
            pages=len(self.pages),
            named_destinations=self.registry_entries,
            chains=self.chains,
            findings=self.findings,
        )

    def _next_chain_id(self, origin: Source) -> str:
        self._chain_index += 1
        return f"{origin.kind}:{self._chain_index}"

    def _add_finding(
        self,
        kind: str,
        message: str,
        source: Source,
        *,
        value: Any = None,
        hop_index: int | None = None,
        name: str | None = None,
        target_page_index: int | None = None,
        hop_source: Source | None = None,
        duplicate_of: Source | None = None,
        external_target: str | None = None,
        followed: bool = True,
    ) -> NavigationFinding:
        finding = NavigationFinding(
            kind=kind,
            message=message,
            source=source,
            value=value,
            hop_index=hop_index,
            name=name,
            target_page_index=target_page_index,
            hop_source=hop_source,
            duplicate_of=duplicate_of,
            external_target=external_target,
            followed=followed,
        )
        self.findings.append(finding)
        return finding

    # ------------------------------------------------------------------
    # Named destinations
    # ------------------------------------------------------------------
    def _collect_named_destinations(self) -> None:
        root = self.root
        if root is None:
            return

        if "/Dests" in root and not is_null_or_none(root["/Dests"]):
            legacy = _as_dict(root["/Dests"])
            if legacy is None:
                self._add_finding(
                    "malformed_name_tree",
                    "The catalog /Dests entry is not a dictionary.",
                    self._catalog_source("/Dests"),
                )
            else:
                self._walk_legacy_dests(legacy, ("catalog", "/Dests"))

        if "/Names" in root and not is_null_or_none(root["/Names"]):
            names = _as_dict(root["/Names"])
            if names is None:
                self._add_finding(
                    "malformed_name_tree",
                    "The catalog /Names entry is not a dictionary.",
                    self._catalog_source("/Names"),
                )
                return
            if "/Dests" not in names or is_null_or_none(names["/Dests"]):
                return
            tree = _as_dict(names["/Dests"])
            if tree is None:
                self._add_finding(
                    "malformed_name_tree",
                    "The /Names /Dests entry is not a dictionary.",
                    self._catalog_source("/Names/Dests"),
                )
                return
            self._walk_name_tree(tree, ("catalog", "/Names", "/Dests"), depth=0)

    def _catalog_source(self, path: str) -> Source:
        return Source(
            kind="name_tree",
            label=path,
            registry="catalog",
            object_id=_object_id(self.document.root_object),
        )

    def _walk_legacy_dests(
        self,
        node: DictionaryObject,
        path: tuple[int | str, ...],
    ) -> None:
        for key, raw_value in node.items():
            if self._name_tree_entry_count >= self.name_tree_max_entries:
                self._add_finding(
                    "limit_reached",
                    "Maximum named destination entry count reached.",
                    Source(
                        kind="name_tree",
                        label=self._path_label(path),
                        name_tree_path=path,
                        registry="catalog_dests",
                        object_id=_object_id(node),
                    ),
                )
                return
            self._name_tree_entry_count += 1
            self._add_registry_entry(
                key,
                raw_value,
                (*path, str(key)),
                registry="catalog_dests",
                node=node,
            )

    def _walk_name_tree(
        self,
        node: DictionaryObject,
        path: tuple[int | str, ...],
        *,
        depth: int,
    ) -> None:
        node_id = id(node)
        if node_id in self._name_tree_visited:
            self._add_finding(
                "cycle",
                "Detected a cycle in the named destination tree.",
                Source(
                    kind="name_tree",
                    label=self._path_label(path),
                    name_tree_path=path,
                    registry="name_tree",
                    object_id=_object_id(node),
                ),
            )
            return
        if depth > self.name_tree_max_depth:
            self._add_finding(
                "limit_reached",
                "Maximum named destination tree depth reached.",
                Source(
                    kind="name_tree",
                    label=self._path_label(path),
                    name_tree_path=path,
                    registry="name_tree",
                    object_id=_object_id(node),
                ),
            )
            return
        self._name_tree_visited.add(node_id)

        found_container = False
        if "/Kids" in node:
            found_container = True
            kids = _as_object(node["/Kids"])
            if not isinstance(kids, ArrayObject):
                self._add_finding(
                    "malformed_name_tree",
                    "The /Kids entry of a named destination node is not an array.",
                    Source(
                        kind="name_tree",
                        label=self._path_label((*path, "Kids")),
                        name_tree_path=(*path, "Kids"),
                        registry="name_tree",
                        object_id=_object_id(node),
                    ),
                )
            else:
                for index, kid in enumerate(kids):
                    kid_node = _as_dict(kid)
                    if kid_node is None:
                        self._add_finding(
                            "malformed_name_tree",
                            "A named destination /Kids entry is not a dictionary.",
                            Source(
                                kind="name_tree",
                                label=self._path_label((*path, "Kids", index)),
                                name_tree_path=(*path, "Kids", index),
                                registry="name_tree",
                                object_id=_object_id(kid),
                            ),
                        )
                        continue
                    self._walk_name_tree(
                        kid_node,
                        (*path, "Kids", index),
                        depth=depth + 1,
                    )

        if "/Names" in node:
            found_container = True
            pairs = _as_object(node["/Names"])
            if not isinstance(pairs, ArrayObject):
                self._add_finding(
                    "malformed_name_tree",
                    "The /Names entry of a named destination node is not an array.",
                    Source(
                        kind="name_tree",
                        label=self._path_label((*path, "Names")),
                        name_tree_path=(*path, "Names"),
                        registry="name_tree",
                        object_id=_object_id(node),
                    ),
                )
            else:
                if len(pairs) % 2:
                    self._add_finding(
                        "malformed_name_tree",
                        "The /Names array has an unmatched key.",
                        Source(
                            kind="name_tree",
                            label=self._path_label((*path, "Names")),
                            name_tree_path=(*path, "Names"),
                            registry="name_tree",
                            object_id=_object_id(node),
                        ),
                    )
                for index in range(0, len(pairs) - 1, 2):
                    if self._name_tree_entry_count >= self.name_tree_max_entries:
                        self._add_finding(
                            "limit_reached",
                            "Maximum named destination entry count reached.",
                            Source(
                                kind="name_tree",
                                label=self._path_label(path),
                                name_tree_path=path,
                                registry="name_tree",
                                object_id=_object_id(node),
                            ),
                        )
                        return
                    self._name_tree_entry_count += 1
                    key = _as_object(pairs[index])
                    value = pairs[index + 1]
                    if not isinstance(key, (str, bytes, NameObject)):
                        self._add_finding(
                            "malformed_name_tree",
                            "A named destination key is not a string or name.",
                            Source(
                                kind="name_tree",
                                label=self._path_label((*path, "Names", index)),
                                name_tree_path=(*path, "Names", index),
                                registry="name_tree",
                                object_id=_object_id(node),
                            ),
                        )
                        continue
                    self._add_registry_entry(
                        key,
                        value,
                        (*path, "Names", index),
                        registry="name_tree",
                        node=node,
                    )

        if not found_container:
            # Some producers place the key/value pairs directly in the node
            # instead of wrapping them in a /Names array. Treat such a node as
            # a flat registry rather than losing all of its evidence.
            for key, value in node.items():
                if str(key) in {"/Kids", "/Names"}:
                    continue
                if self._name_tree_entry_count >= self.name_tree_max_entries:
                    self._add_finding(
                        "limit_reached",
                        "Maximum named destination entry count reached.",
                        Source(
                            kind="name_tree",
                            label=self._path_label(path),
                            name_tree_path=path,
                            registry="name_tree",
                            object_id=_object_id(node),
                        ),
                    )
                    break
                self._name_tree_entry_count += 1
                self._add_registry_entry(
                    key,
                    value,
                    (*path, str(key)),
                    registry="name_tree",
                    node=node,
                )

        self._name_tree_visited.remove(node_id)

    def _add_registry_entry(
        self,
        key: Any,
        raw_value: Any,
        path: tuple[int | str, ...],
        *,
        registry: str,
        node: DictionaryObject,
    ) -> None:
        raw_name = _decode_name(key)
        name = _canonical_name(key)
        source = Source(
            kind="named_destination",
            label=self._path_label(path),
            name_tree_path=path,
            registry=registry,
            key=name,
            object_id=_object_id(node),
        )
        value = _as_object(raw_value)
        entry = NamedDestinationEntry(
            name=name,
            raw_name=raw_name,
            source=source,
            value=value,
            value_object_id=_object_id(raw_value),
        )
        self.registry_entries.append(entry)

    def _index_named_destinations(self) -> None:
        grouped: dict[str, list[NamedDestinationEntry]] = defaultdict(list)
        for entry in self.registry_entries:
            grouped[entry.name].append(entry)
            self.registry_by_name[entry.name].append(entry)
            if entry.raw_name is not None:
                self.registry_by_raw_name[entry.raw_name].append(entry)

        for name, entries in grouped.items():
            if len(entries) < 2:
                continue
            first = entries[0]
            for entry in entries:
                entry.duplicate = True
            for entry in entries[1:]:
                self._add_finding(
                    "duplicate_name",
                    f"Named destination {name!r} is registered more than once.",
                    entry.source,
                    name=name,
                    duplicate_of=first.source,
                )

    def _resolve_named_destinations(self) -> None:
        for entry in self.registry_entries:
            resolution = self._resolve_destination_value(entry.value, seen_names={entry.name})
            entry.page_index = resolution.page_index
            entry.status = resolution.status
            entry.reason = resolution.reason
            entry.is_direct = resolution.is_direct
            entry.alias_of = resolution.alias_of

    def _lookup_destination(self, raw_name: Any) -> list[NamedDestinationEntry]:
        canonical = _canonical_name(raw_name)
        raw = _decode_name(raw_name)
        candidates = self.registry_by_name.get(canonical)
        if candidates:
            return candidates
        candidates = self.registry_by_raw_name.get(raw)
        if candidates:
            return candidates
        candidates = self.registry_by_name.get(raw)
        if candidates:
            return candidates
        if raw.startswith("/"):
            return self.registry_by_name.get(raw[1:], [])
        return self.registry_by_name.get(f"/{raw}", [])

    def _resolve_destination_value(
        self,
        value: Any,
        *,
        seen_names: set[str],
    ) -> _TargetResolution:
        value = _as_object(value)
        if is_null_or_none(value):
            return _TargetResolution(status="missing_target", reason="Destination is null or missing.")
        if isinstance(value, DictionaryObject):
            if "/D" not in value:
                return _TargetResolution(
                    status="malformed_destination",
                    reason="Destination dictionary does not contain /D.",
                )
            return self._resolve_destination_value(value["/D"], seen_names=seen_names)
        if isinstance(value, ArrayObject):
            page_index = self._page_index(value)
            if page_index is None:
                return _TargetResolution(
                    status="missing_target",
                    reason="The destination page is not part of the page tree.",
                    is_direct=True,
                )
            return _TargetResolution(page_index=page_index, status="ok", is_direct=True)
        if isinstance(value, (str, bytes, NameObject, TextStringObject)):
            name = _canonical_name(value)
            if name in seen_names:
                return _TargetResolution(
                    status="malformed_destination",
                    reason=f"Named destination alias cycle detected at {name!r}.",
                    alias_of=name,
                )
            entries = self._lookup_destination(value)
            if not entries:
                return _TargetResolution(
                    status="missing_target",
                    reason=f"Named destination {name!r} is not registered.",
                    alias_of=name,
                )
            entry = entries[0]
            nested = self._resolve_destination_value(
                entry.value,
                seen_names=seen_names | {name},
            )
            nested.alias_of = name
            return nested
        return _TargetResolution(
            status="malformed_destination",
            reason=f"Unsupported destination value: {type(value).__name__}.",
        )

    def _page_index(self, destination: ArrayObject) -> int | None:  # noqa: PLR0911
        if len(destination) < 1:
            return None
        page = _as_object(destination[0])
        if is_null_or_none(page):
            return None
        if isinstance(page, NumberObject):
            page_number = int(page)
            if page_number in self.page_index_by_idnum:
                return self.page_index_by_idnum[page_number]
            if 0 <= page_number < len(self.pages):
                return page_number
            return None
        if isinstance(page, int):
            if page in self.page_index_by_idnum:
                return self.page_index_by_idnum[page]
            if 0 <= page < len(self.pages):
                return page
            return None
        if hasattr(page, "indirect_reference"):
            reference = page.indirect_reference
            if reference is not None and reference.idnum in self.page_index_by_idnum:
                return self.page_index_by_idnum[reference.idnum]
        reference = _object_id(page)
        if reference is not None:
            return self.page_index_by_idnum.get(reference[0])
        return None

    # ------------------------------------------------------------------
    # Outline
    # ------------------------------------------------------------------
    def _walk_outline(self) -> None:
        root = self.root
        if root is None or "/Outlines" not in root or is_null_or_none(root["/Outlines"]):
            return
        outlines = _as_dict(root["/Outlines"])
        if outlines is None:
            self._add_finding(
                "malformed_outline",
                "The catalog /Outlines entry is not a dictionary.",
                self._catalog_source("/Outlines"),
            )
            return
        if "/First" not in outlines:
            return
        self._walk_outline_siblings(
            outlines["/First"],
            parent_path=(),
            depth=0,
            ancestors=set(),
        )

    def _walk_outline_siblings(
        self,
        first: Any,
        *,
        parent_path: tuple[int, ...],
        depth: int,
        ancestors: set[int],
    ) -> None:
        if depth > self.outline_max_depth:
            self._add_finding(
                "limit_reached",
                "Maximum outline depth reached.",
                Source(
                    kind="outline",
                    label=self._outline_label(parent_path),
                    outline_path=parent_path,
                ),
            )
            return

        node = _as_dict(first)
        index = 0
        seen_siblings: set[int] = set()
        while node is not None:
            if self._outline_entry_count >= self.outline_max_entries:
                self._add_finding(
                    "limit_reached",
                    "Maximum outline entry count reached.",
                    Source(
                        kind="outline",
                        label=self._outline_label((*parent_path, index)),
                        outline_path=(*parent_path, index),
                    ),
                )
                return
            self._outline_entry_count += 1

            node_id = id(node)
            path = (*parent_path, index)
            source = self._outline_source(node, path)
            if node_id in ancestors or node_id in seen_siblings:
                self._add_finding(
                    "cycle",
                    "Detected a cycle in the outline structure.",
                    source,
                )
                return
            seen_siblings.add(node_id)

            self._analyze_navigation_item(node, source)

            if "/First" in node:
                self._walk_outline_siblings(
                    node["/First"],
                    parent_path=path,
                    depth=depth + 1,
                    ancestors=ancestors | {node_id},
                )

            next_node = node.get("/Next")
            node = _as_dict(next_node)
            index += 1

    def _outline_source(self, node: DictionaryObject, path: tuple[int, ...]) -> Source:
        title_value = node.get("/Title")
        title = _decode_name(title_value) if title_value is not None else ""
        return Source(
            kind="outline",
            label=self._outline_label(path),
            outline_path=path,
            title=title,
            object_id=_object_id(node),
        )

    @staticmethod
    def _outline_label(path: tuple[int, ...]) -> str:
        if not path:
            return "outline"
        return "outline[" + "][".join(str(index) for index in path) + "]"

    # ------------------------------------------------------------------
    # Page annotations
    # ------------------------------------------------------------------
    def _walk_annotations(self) -> None:
        for page_index, page in enumerate(self.pages):
            annotations = page.annotations
            if annotations is None:
                continue
            for annotation_index, raw_annotation in enumerate(annotations):
                annotation = _as_dict(raw_annotation)
                if annotation is None:
                    self._add_finding(
                        "malformed_annotation",
                        "An annotation entry is not a dictionary.",
                        Source(
                            kind="annotation",
                            label=f"page[{page_index}].annotation[{annotation_index}]",
                            page_index=page_index,
                            annotation_index=annotation_index,
                            object_id=_object_id(raw_annotation),
                        ),
                    )
                    continue
                subtype = _decode_name(annotation.get("/Subtype", ""))
                if subtype != "/Link" and "/Dest" not in annotation and "/A" not in annotation:
                    continue
                source = Source(
                    kind="annotation",
                    label=f"page[{page_index}].annotation[{annotation_index}]",
                    page_index=page_index,
                    annotation_index=annotation_index,
                    title=subtype or None,
                    object_id=_object_id(annotation),
                )
                if "/Dest" not in annotation and "/A" not in annotation:
                    self._add_broken_chain(
                        source,
                        hop_index=1,
                        message="The link annotation has no destination or action.",
                        kind="missing_target",
                    )
                else:
                    self._analyze_navigation_item(annotation, source)

    # ------------------------------------------------------------------
    # Chain construction
    # ------------------------------------------------------------------
    def _analyze_navigation_item(self, item: DictionaryObject, source: Source) -> None:
        if "/Dest" in item:
            destination = item["/Dest"]
            if is_null_or_none(destination):
                self._add_broken_chain(
                    source,
                    hop_index=1,
                    message="The /Dest entry is null.",
                    kind="missing_target",
                )
            else:
                self._build_destination_chain(source, destination)
            return

        if "/A" not in item:
            return

        action = _as_dict(item["/A"])
        if action is None:
            self._add_broken_chain(
                source,
                hop_index=1,
                message="The /A entry is not an action dictionary.",
            )
            return

        action_type = _decode_name(action.get("/S", ""))
        if action_type in {"/GoTo", ""}:
            if "/D" not in action or is_null_or_none(action["/D"]):
                self._add_broken_chain(
                    source,
                    hop_index=1,
                    message="The GoTo action does not contain a usable /D entry.",
                    kind="missing_target",
                )
                return
            self._build_destination_chain(source, action["/D"])
            return

        self._build_external_chain(source, action, action_type)

    def _add_broken_chain(
        self,
        source: Source,
        *,
        hop_index: int,
        message: str,
        kind: str = "malformed_destination",
    ) -> NavigationChain:
        hop = NavigationHop(
            index=hop_index,
            kind="source",
            status="missing",
            source=source,
            message=message,
        )
        chain = NavigationChain(
            id=self._next_chain_id(source),
            origin=source,
            hops=[hop],
            status="broken",
            broken_at_hop=hop_index,
            break_reason=message,
        )
        self.chains.append(chain)
        self._add_finding(
            kind,
            message,
            source,
            hop_index=hop_index,
        )
        return chain

    def _build_external_chain(
        self,
        source: Source,
        action: DictionaryObject,
        action_type: str,
    ) -> None:
        external_target = self._external_target(action, action_type)
        is_external_reference = action_type in _EXTERNAL_ACTIONS
        finding_kind = "external_reference" if is_external_reference else "unsupported_action"
        description = action_type or "unknown action"
        message = (
            f"{description} target {external_target!r} was recorded without opening it."
            if external_target is not None
            else f"{description} was recorded without being followed."
        )
        hop = NavigationHop(
            index=1,
            kind="external" if is_external_reference else "unsupported",
            status="external",
            source=source,
            value=action,
            name=action_type or None,
            message=message,
            followed=False,
        )
        chain = NavigationChain(
            id=self._next_chain_id(source),
            origin=source,
            hops=[hop],
            status="external",
            break_reason=message,
        )
        self.chains.append(chain)
        self._add_finding(
            finding_kind,
            message,
            source,
            hop_index=1,
            name=action_type or None,
            external_target=external_target,
            followed=False,
        )

    @staticmethod
    def _external_target(action: DictionaryObject, action_type: str) -> str | None:
        if action_type == "/URI":
            value = action.get("/URI")
            return _decode_name(value) if value is not None else None
        for key in ("/F", "/UF", "/N"):
            if key not in action:
                continue
            value = _as_object(action[key])
            if isinstance(value, DictionaryObject):
                for file_key in ("/UF", "/F", "/DOS", "/Mac", "/Unix"):
                    if file_key in value:
                        return _decode_name(value[file_key])
            return _decode_name(value)
        return None

    def _build_destination_chain(self, source: Source, destination: Any) -> NavigationChain:
        destination = _as_object(destination)
        if isinstance(destination, DictionaryObject) and "/D" in destination:
            destination = _as_object(destination["/D"])

        chain = NavigationChain(
            id=self._next_chain_id(source),
            origin=source,
        )

        if isinstance(destination, ArrayObject):
            direct_finding = self._add_finding(
                "direct_reference",
                "The destination is a direct array reference.",
                source,
                value=destination,
                hop_index=1,
            )
            page_index = self._page_index(destination)
            direct_finding.target_page_index = page_index
            if page_index is None:
                message = "The direct destination does not point to a page in this PDF."
                chain.hops.append(
                    NavigationHop(
                        index=1,
                        kind="direct",
                        status="missing",
                        source=source,
                        value=destination,
                        message=message,
                    )
                )
                chain.status = "broken"
                chain.broken_at_hop = 1
                chain.break_reason = message
                self._add_finding(
                    "missing_target",
                    message,
                    source,
                    hop_index=1,
                    target_page_index=None,
                )
            else:
                chain.hops.append(
                    NavigationHop(
                        index=1,
                        kind="direct",
                        status="ok",
                        source=source,
                        value=destination,
                        target_page_index=page_index,
                    )
                )
                chain.target_page_index = page_index
            self.chains.append(chain)
            return chain

        if isinstance(destination, (str, bytes, NameObject, TextStringObject)):
            name = _canonical_name(destination)
            entries = self._lookup_destination(destination)
            chain.ambiguous = len(entries) > 1
            chain.hops.append(
                NavigationHop(
                    index=1,
                    kind="named",
                    status="ok",
                    source=source,
                    value=destination,
                    name=name,
                )
            )
            if not entries:
                message = f"Named destination {name!r} is not registered."
                chain.hops.append(
                    NavigationHop(
                        index=2,
                        kind="registry",
                        status="missing",
                        source=source,
                        value=destination,
                        name=name,
                        message=message,
                    )
                )
                chain.status = "broken"
                chain.broken_at_hop = 2
                chain.break_reason = message
                self._add_finding(
                    "missing_target",
                    message,
                    source,
                    hop_index=2,
                    name=name,
                )
            else:
                entry = entries[0]
                self._referenced_entries.add(id(entry))
                status = "ok" if entry.status == "ok" else "missing"
                message = entry.reason
                chain.hops.append(
                    NavigationHop(
                        index=2,
                        kind="registry",
                        status=status,
                        source=entry.source,
                        value=entry.value,
                        name=name,
                        target_page_index=entry.page_index,
                        message=message,
                    )
                )
                if status == "ok":
                    chain.target_page_index = entry.page_index
                else:
                    chain.status = "broken"
                    chain.broken_at_hop = 2
                    chain.break_reason = message or "The named destination target is missing."
                    self._add_finding(
                        "missing_target",
                        chain.break_reason,
                        source,
                        hop_index=2,
                        name=name,
                        hop_source=entry.source,
                    )
            self.chains.append(chain)
            return chain

        message = f"Unsupported destination value: {type(destination).__name__}."
        chain.hops.append(
            NavigationHop(
                index=1,
                kind="source",
                status="missing",
                source=source,
                value=destination,
                message=message,
            )
        )
        chain.status = "broken"
        chain.broken_at_hop = 1
        chain.break_reason = message
        self.chains.append(chain)
        self._add_finding("malformed_destination", message, source, hop_index=1)
        return chain

    def _report_unreferenced_broken_entries(self) -> None:
        for entry in self.registry_entries:
            if id(entry) in self._referenced_entries:
                continue
            if entry.status == "ok":
                continue
            self._add_finding(
                "missing_target",
                entry.reason or "The named destination target is missing.",
                entry.source,
                name=entry.name,
                target_page_index=entry.page_index,
            )

    @staticmethod
    def _path_label(path: tuple[int | str, ...]) -> str:
        if not path:
            return "name-tree"
        return "name-tree[" + "][".join(str(part) for part in path) + "]"


def _coerce_document(
    document: PdfDocCommon | str | Path | bytes | bytearray | BinaryIO,
) -> tuple[PdfDocCommon, bool]:
    if hasattr(document, "root_object") and hasattr(document, "pages"):
        return document, False  # type: ignore[return-value]

    from ._reader import PdfReader  # noqa: PLC0415

    if isinstance(document, (str, Path)):
        return PdfReader(document), True
    if isinstance(document, (bytes, bytearray)):
        return PdfReader(BytesIO(bytes(document))), True
    return PdfReader(document), False


def analyze_navigation(
    document: PdfDocCommon | str | Path | bytes | bytearray | BinaryIO,
    *,
    max_depth: int | None = None,
    max_entries: int | None = None,
) -> NavigationReport:
    """
    Inspect navigation evidence without following external targets.

    Args:
        document: A reader/writer-like object, a path, bytes, or a binary
            stream. Paths and streams are only used to read the supplied PDF;
            external files referenced by its actions are never opened.
        max_depth: Optional override for outline and name-tree depth limits.
        max_entries: Optional override for outline and name-tree entry limits.

    Returns:
        A :class:`NavigationReport` containing named destinations, resolution
        chains, and findings with their in-document provenance.
    """
    doc, owns_document = _coerce_document(document)
    try:
        return _NavigationAnalyzer(
            doc,
            max_depth=max_depth,
            max_entries=max_entries,
        ).run()
    finally:
        if owns_document:
            close = getattr(doc, "close", None)
            if callable(close):
                close()


inspect_navigation = analyze_navigation
collect_navigation_evidence = analyze_navigation
navigation_forensics = analyze_navigation
audit_navigation = analyze_navigation


class NavigationForensics:
    """Small convenience wrapper around :func:`analyze_navigation`."""

    def __init__(
        self,
        document: PdfDocCommon | str | Path | bytes | bytearray | BinaryIO,
        *,
        max_depth: int | None = None,
        max_entries: int | None = None,
    ) -> None:
        self.document = document
        self.max_depth = max_depth
        self.max_entries = max_entries
        self._report: NavigationReport | None = None

    @property
    def report(self) -> NavigationReport:
        """Run the inspection lazily and return its report."""
        if self._report is None:
            self._report = self.run()
        return self._report

    def run(self) -> NavigationReport:
        """Run the inspection and cache the report."""
        report = analyze_navigation(
            self.document,
            max_depth=self.max_depth,
            max_entries=self.max_entries,
        )
        self._report = report
        return report

    def analyze(self) -> NavigationReport:
        """Alias for :meth:`run`."""
        return self.run()

    def to_dict(self) -> dict[str, Any]:
        """Return the report as a JSON-friendly dictionary."""
        return self.report.to_dict()
