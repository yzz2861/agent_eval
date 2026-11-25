"""Read-only forensic audit for internal PDF navigation."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from ._configuration import get_configuration
from ._reader import PdfReader
from .generic import ArrayObject, DictionaryObject, IndirectObject

PathLike = str | os.PathLike[str]
Source = PdfReader | PathLike | Any


@dataclass(frozen=True)
class Provenance:
    """Origin of one piece of navigation evidence."""

    source_type: str
    location: str
    object_number: int | None = None
    generation: int | None = None
    object_reference: str | None = None
    page_index: int | None = None
    annotation_index: int | None = None
    outline_title: str | None = None
    key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["source"] = self.source_type
        return result

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


@dataclass
class NamedDestinationRecord:
    """One named-destination registration, including duplicate registrations."""

    id: str
    name: str
    canonical_name: str
    origin: Provenance
    valid: bool
    target_page: int | None = None
    target_object_number: int | None = None
    target_reference: str | None = None
    reason: str | None = None
    duplicate: bool = False

    @property
    def provenance(self) -> Provenance:
        return self.origin

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["provenance"] = result["origin"]
        return result

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


@dataclass
class NavigationReference:
    """One outline or page-annotation navigation reference."""

    id: str
    source: str
    origin: Provenance
    kind: str
    status: str
    resolved: bool
    name: str | None = None
    canonical_name: str | None = None
    target_page: int | None = None
    target_object_number: int | None = None
    target_reference: str | None = None
    reason: str | None = None
    key: str | None = None
    external: bool = False
    external_target: str | None = None
    raw_destination: Any = None
    registrations: list[Provenance] = field(default_factory=list)
    resolution_steps: list[dict[str, Any]] = field(default_factory=list)

    @property
    def provenance(self) -> Provenance:
        return self.origin

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["provenance"] = result["origin"]
        result["source_location"] = self.origin.location
        return result

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


@dataclass
class DuplicateName:
    """All registrations sharing one canonical destination name."""

    name: str
    canonical_name: str
    count: int
    raw_names: list[str]
    sources: list[Provenance]
    registrations: list[NamedDestinationRecord]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


class DuplicateNameCollection(list[DuplicateName]):
    """List of duplicate groups that also supports lookup by name."""

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str):
            return self.get(key) is not None
        return super().__contains__(key)

    def __getitem__(self, key: int | str) -> Any:  # type: ignore[override]
        if isinstance(key, str):
            for group in self:
                if key in {group.name, group.canonical_name, *group.raw_names}:
                    return group
            raise KeyError(key)
        return super().__getitem__(key)

    def get(self, key: str, default: DuplicateName | None = None) -> DuplicateName | None:
        try:
            return self[key]
        except KeyError:
            return default

    def as_dict(self) -> dict[str, list[NamedDestinationRecord]]:
        return {group.canonical_name: group.registrations for group in self}


@dataclass
class NavigationHop:
    """One page-to-page navigation attempt."""

    number: int
    reference_id: str
    source: str
    provenance: Provenance
    kind: str
    status: str
    resolved: bool
    from_page: int | None = None
    target_page: int | None = None
    name: str | None = None
    reason: str | None = None
    external: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


@dataclass
class NavigationPath:
    """A linear sequence of navigation hops."""

    hops: list[NavigationHop] = field(default_factory=list)
    complete: bool = False
    broken: bool = False
    broken_hop: int | None = None
    cycle: bool = False
    external: bool = False
    truncated: bool = False
    stop_reason: str | None = None

    @property
    def hop_count(self) -> int:
        return len(self.hops)

    @property
    def visited_pages(self) -> list[int]:
        return [hop.target_page for hop in self.hops if hop.target_page is not None]

    @property
    def target_pages(self) -> list[int]:
        return self.visited_pages

    @property
    def missing_names(self) -> list[str]:
        return [hop.name for hop in self.hops if hop.name and not hop.resolved]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["hop_count"] = self.hop_count
        result["visited_pages"] = self.visited_pages
        result["target_pages"] = self.target_pages
        result["missing_names"] = self.missing_names
        return result

    def __getitem__(self, key: str) -> Any:
        if key in {"hop_count", "visited_pages", "target_pages", "missing_names"}:
            return getattr(self, key)
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (AttributeError, KeyError):
            return default


class NavigationTrace(list[NavigationPath]):
    """Paths produced by one trace query."""

    @property
    def paths(self) -> list[NavigationPath]:
        return list(self)

    @property
    def path(self) -> NavigationPath | None:
        return self[0] if len(self) == 1 else None

    @property
    def hops(self) -> list[NavigationHop]:
        return self[0].hops if len(self) == 1 else []

    @property
    def broken_hop(self) -> int | list[int] | None:
        broken = [path.broken_hop for path in self if path.broken_hop is not None]
        if not broken:
            return None
        return broken[0] if len(self) == 1 else broken

    @property
    def complete(self) -> bool:
        return bool(self) and all(path.complete for path in self)

    @property
    def broken(self) -> bool:
        return any(path.broken for path in self)

    def to_dict(self) -> dict[str, Any]:
        return {"paths": [path.to_dict() for path in self], "broken_hop": self.broken_hop}


@dataclass
class NavigationReport(dict[str, Any]):
    """Complete read-only navigation reconciliation report."""

    page_count: int
    outline: list[NavigationReference]
    page_annotations: list[NavigationReference]
    named_destinations: list[NamedDestinationRecord]
    direct_references: list[NavigationReference]
    named_references: list[NavigationReference]
    duplicate_names: DuplicateNameCollection
    missing_targets: list[NavigationReference]
    external_references: list[NavigationReference]
    unsupported_references: list[NavigationReference]
    paths: list[NavigationPath]
    references: list[NavigationReference]
    library_named_destinations: list[dict[str, Any]]
    annotation_count: int = 0
    link_annotation_count: int = 0
    errors: list[str] = field(default_factory=list)
    reader: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        dict.__init__(self)
        self.refresh_mapping()

    def refresh_mapping(self) -> None:
        """Populate the mapping view while preserving attribute access."""
        data = self.to_dict()
        data.update(
            {
                "outlines": _to_plain(self.outlines),
                "bookmarks": _to_plain(self.bookmarks),
                "annotations": _to_plain(self.annotations),
                "links": _to_plain(self.links),
                "direct": _to_plain(self.direct),
                "direct_refs": _to_plain(self.direct_refs),
                "duplicates": _to_plain(self.duplicates),
                "missing": _to_plain(self.missing),
                "destinations": _to_plain(self.destinations),
                "chain": _to_plain(self.chain),
                "two_hop": _to_plain(self.two_hop),
                "registrations": _to_plain(self.registrations),
                "duplicate_destinations": _to_plain(self.duplicate_destinations),
                "missing_destinations": _to_plain(self.missing_destinations),
                "chains": _to_plain(self.chains),
                "navigation_paths": _to_plain(self.navigation_paths),
                "broken_hop": self.broken_hop,
                "broken_at_hop": self.broken_hop,
                "failed_hop": self.broken_hop,
            }
        )
        self.clear()
        self.update(data)

    @property
    def outlines(self) -> list[NavigationReference]:
        return self.outline

    @property
    def bookmarks(self) -> list[NavigationReference]:
        return self.outline

    @property
    def annotations(self) -> list[NavigationReference]:
        return self.page_annotations

    @property
    def links(self) -> list[NavigationReference]:
        return self.page_annotations

    @property
    def direct(self) -> list[NavigationReference]:
        return self.direct_references

    @property
    def direct_refs(self) -> list[NavigationReference]:
        return self.direct_references

    @property
    def duplicates(self) -> DuplicateNameCollection:
        return self.duplicate_names

    @property
    def missing(self) -> list[NavigationReference]:
        return self.missing_targets

    @property
    def destinations(self) -> list[NamedDestinationRecord]:
        return self.named_destinations

    @property
    def chain(self) -> NavigationPath | None:
        return self.paths[0] if self.paths else None

    @property
    def two_hop(self) -> NavigationPath | None:
        return self.chain

    @property
    def registrations(self) -> list[NamedDestinationRecord]:
        return self.named_destinations

    @property
    def duplicate_destinations(self) -> DuplicateNameCollection:
        return self.duplicate_names

    @property
    def missing_destinations(self) -> list[NavigationReference]:
        return self.missing_targets

    @property
    def chains(self) -> list[NavigationPath]:
        return self.paths

    @property
    def navigation_paths(self) -> list[NavigationPath]:
        return self.paths

    @property
    def broken_hop(self) -> int | None:
        for path in self.paths:
            if path.broken_hop is not None:
                return path.broken_hop
        return None

    @property
    def broken_paths(self) -> list[NavigationPath]:
        return [path for path in self.paths if path.broken]

    def trace(
        self,
        start: Any = None,
        *,
        page: int | None = None,
        source_id: str | None = None,
        outline_title: str | None = None,
        max_hops: int = 100,
    ) -> NavigationTrace:
        candidates = _select_references(
            self.references,
            start=start,
            page=page,
            source_id=source_id,
            outline_title=outline_title,
        )
        if not candidates:
            raise LookupError("No navigation reference matches the requested trace start")
        outgoing = _outgoing_by_page(self.references)
        paths: list[NavigationPath] = []
        for reference in candidates:
            paths.extend(_follow_reference(reference, outgoing, max_hops=max_hops))
        return NavigationTrace(paths)

    def trace_page(self, page_index: int, *, max_hops: int = 100) -> NavigationTrace:
        return self.trace(page=page_index, max_hops=max_hops)

    def trace_two_hop(self, start: Any = 0, **kwargs: Any) -> NavigationPath:
        if isinstance(start, int):
            trace = self.trace(page=start, **kwargs)
        else:
            trace = self.trace(start, **kwargs)
        if trace.path is None:
            raise LookupError("Two-hop trace is ambiguous because the start has multiple links")
        return trace.path

    def to_dict(self) -> dict[str, Any]:
        result = {
            dataclass_field.name: _to_plain(getattr(self, dataclass_field.name))
            for dataclass_field in fields(self)
            if dataclass_field.name != "reader"
        }
        for key in (
            "outlines",
            "bookmarks",
            "annotations",
            "links",
            "registrations",
            "duplicate_destinations",
            "missing_destinations",
            "chains",
            "navigation_paths",
            "broken_hop",
        ):
            result[key] = _to_plain(getattr(self, key))
        return result

    def __getitem__(self, key: str) -> Any:
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (AttributeError, KeyError):
            return default


def audit_navigation(source: Source, *, max_hops: int = 100) -> NavigationReport:
    """Collect and reconcile outline, annotation, and named-destination evidence."""
    reader = _as_reader(source)
    auditor = _NavigationAuditor(reader)
    return auditor.audit(max_hops=max_hops)


collect_navigation_evidence = audit_navigation
navigation_forensics = audit_navigation
inspect_navigation = audit_navigation
analyze_navigation = audit_navigation
verify_navigation = audit_navigation
build_navigation_report = audit_navigation
audit_pdf = audit_navigation
forensic_audit = audit_navigation
navigation_audit = audit_navigation
audit_navigation_forensics = audit_navigation
build_forensic_report = audit_navigation


def trace_navigation(source: Source, start: Any = 0, **kwargs: Any) -> NavigationTrace:
    """Audit a PDF and trace one navigation chain from ``start``."""
    max_hops = int(kwargs.pop("max_hops", 100))
    report = audit_navigation(source, max_hops=max_hops)
    return report.trace(start, max_hops=max_hops, **kwargs)


def two_hop_navigation(source: Source, start: Any = 0, **kwargs: Any) -> NavigationPath:
    """Return the unique path beginning at ``start``; the fixture uses page 0."""
    trace = trace_navigation(source, start, **kwargs)
    if trace.path is None:
        raise LookupError("navigation start has multiple ambiguous paths")
    return trace.path
audit_pdf_navigation = audit_navigation
audit_navigation_forensics = audit_navigation
create_navigation_report = audit_navigation
collect_navigation_forensics = audit_navigation


class NavigationForensics:
    """Object-oriented entry point for read-only navigation forensics."""

    def __init__(self, source: Source) -> None:
        self.reader = _as_reader(source)

    def audit(self, *, max_hops: int = 100) -> NavigationReport:
        return audit_navigation(self.reader, max_hops=max_hops)

    def __call__(self, **kwargs: Any) -> NavigationReport:
        return self.audit(**kwargs)

    collect = audit
    inspect = audit


NavigationAuditor = NavigationForensics
NavigationAnalyzer = NavigationForensics
NavigationAudit = NavigationReport
NavigationAuditReport = NavigationReport
NavigationForensicReport = NavigationReport


def _as_reader(source: Source) -> PdfReader:
    if isinstance(source, PdfReader):
        return source
    if hasattr(source, "stream") and hasattr(source, "pages"):
        return source  # type: ignore[return-value]
    if hasattr(source, "read"):
        return PdfReader(source)  # type: ignore[arg-type]
    with Path(os.fspath(source)).open("rb") as stream:
        return PdfReader(stream)


def _to_plain(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, list):
        return [_to_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _to_plain(item) for key, item in value.items()}
    return value


def _indirect_info(value: Any) -> tuple[IndirectObject | None, str | None, int | None, int | None]:
    reference = value if isinstance(value, IndirectObject) else getattr(value, "indirect_reference", None)
    if not isinstance(reference, IndirectObject):
        return None, None, None, None
    return reference, f"{reference.idnum} {reference.generation} R", reference.idnum, reference.generation


def _resolve(value: Any) -> tuple[Any, str | None]:
    if isinstance(value, IndirectObject):
        try:
            return value.get_object(), None
        except Exception as error:  # pragma: no cover - malformed PDFs depend on parser
            return None, str(error)
    return value, None


def _raw_key(obj: Any, key: str) -> Any:
    if isinstance(obj, DictionaryObject):
        try:
            return obj.raw_get(key)
        except KeyError:
            return obj.get(key)
    if isinstance(obj, dict):
        return obj.get(key)
    return None


def _name_parts(value: Any) -> tuple[str, str]:
    if isinstance(value, bytes):
        try:
            raw = str(value)
        except Exception:
            raw = bytes(value).decode("utf-8", "replace")
    else:
        raw = str(value)
    canonical = raw.removeprefix("/")
    return raw, canonical


def _destination_array(value: Any) -> tuple[ArrayObject | list[Any] | None, str | None]:
    obj, error = _resolve(value)
    if error is not None:
        return None, error
    if isinstance(obj, DictionaryObject) and "/D" in obj:
        destination, error = _resolve(_raw_key(obj, "/D"))
        if error is not None:
            return None, error
        obj = destination
    if isinstance(obj, (ArrayObject, list)):
        return obj, None
    return None, "destination is not a PDF array"


class _NavigationAuditor:
    def __init__(self, reader: PdfReader) -> None:
        self.reader = reader
        self.page_map: dict[int, int] = {}
        self.registrations: list[NamedDestinationRecord] = []
        self.references: list[NavigationReference] = []
        self.errors: list[str] = []
        self._reference_number = 0
        self._registration_number = 0
        self._build_page_map()

    def audit(self, *, max_hops: int) -> NavigationReport:
        self._scan_named_destinations()
        outline = self._scan_outline()
        annotations, annotation_count, link_count = self._scan_annotations()
        self._resolve_named_references()

        direct = [item for item in self.references if item.kind == "direct"]
        named = [item for item in self.references if item.kind == "named"]
        external = [item for item in self.references if item.external]
        unsupported = [item for item in self.references if item.kind in {"unsupported", "none"}]
        missing = [item for item in self.references if not item.resolved and not item.external and item.kind != "none"]
        duplicates = self._duplicate_groups()
        library_destinations = self._library_destinations()
        outgoing = _outgoing_by_page(self.references)
        paths: list[NavigationPath] = []
        for reference in self._path_roots(outgoing):
            paths.extend(_follow_reference(reference, outgoing, max_hops=max_hops))

        return NavigationReport(
            page_count=len(self.reader.pages),
            outline=outline,
            page_annotations=annotations,
            named_destinations=self.registrations,
            direct_references=direct,
            named_references=named,
            duplicate_names=duplicates,
            missing_targets=missing,
            external_references=external,
            unsupported_references=unsupported,
            paths=paths,
            references=self.references,
            library_named_destinations=library_destinations,
            annotation_count=annotation_count,
            link_annotation_count=link_count,
            errors=self.errors,
            reader=self.reader,
        )

    def _build_page_map(self) -> None:
        for index, page in enumerate(self.reader.pages):
            reference = getattr(page, "indirect_reference", None)
            if isinstance(reference, IndirectObject):
                self.page_map[reference.idnum] = index

    def _next_reference_id(self) -> str:
        self._reference_number += 1
        return f"nav-{self._reference_number:04d}"

    def _next_registration_id(self) -> str:
        self._registration_number += 1
        return f"dest-{self._registration_number:04d}"

    def _provenance(
        self,
        source_type: str,
        location: str,
        source_object: Any = None,
        **kwargs: Any,
    ) -> Provenance:
        reference, object_reference, object_number, generation = _indirect_info(source_object)
        if reference is None:
            resolved, _ = _resolve(source_object)
            reference, object_reference, object_number, generation = _indirect_info(resolved)
        return Provenance(
            source_type=source_type,
            location=location,
            object_number=object_number,
            generation=generation,
            object_reference=object_reference,
            **kwargs,
        )

    def _page_target(self, page_object: Any) -> tuple[int | None, int | None, str | None, str | None]:
        reference, object_reference, object_number, _ = _indirect_info(page_object)
        resolved, error = _resolve(page_object)
        if error is not None:
            return None, object_number, object_reference, error
        if reference is None:
            reference, object_reference, object_number, _ = _indirect_info(resolved)
        if reference is not None and reference.idnum in self.page_map:
            return self.page_map[reference.idnum], reference.idnum, object_reference, None
        if isinstance(resolved, DictionaryObject) and resolved.get("/Type") == "/Page":
            reference, object_reference, object_number, _ = _indirect_info(resolved)
            if reference is not None and reference.idnum in self.page_map:
                return self.page_map[reference.idnum], reference.idnum, object_reference, None
        if isinstance(page_object, int) and not isinstance(page_object, bool):
            numeric = int(page_object)
            if numeric in self.page_map:
                return self.page_map[numeric], numeric, f"{numeric} 0 R", None
            if 0 <= numeric < len(self.reader.pages):
                reason = "numeric page value interpreted as zero-based page index"
                return numeric, object_number, object_reference, reason
        return None, object_number, object_reference, "target page is absent from the document page tree"

    def _scan_named_destinations(self) -> None:
        try:
            catalog = self.reader.root_object
        except Exception as error:
            self.errors.append(f"catalog: {error}")
            return

        catalog_dests = _raw_key(catalog, "/Dests")
        dests, error = _resolve(catalog_dests)
        if error is not None:
            self.errors.append(f"catalog /Dests: {error}")
        elif isinstance(dests, DictionaryObject):
            for key, value in dests.items():
                raw_name, canonical = _name_parts(key)
                self._add_registration(
                    raw_name,
                    canonical,
                    value,
                    self._provenance("named_destination", f"catalog/Dests/{raw_name}", value, key="/Dests"),
                )

        names = _resolve(_raw_key(catalog, "/Names"))[0]
        if not isinstance(names, DictionaryObject):
            return
        dest_tree = _resolve(_raw_key(names, "/Dests"))[0]
        if not isinstance(dest_tree, DictionaryObject):
            return
        config = get_configuration()
        stack: list[tuple[Any, str, int]] = [(dest_tree, "catalog/Names/Dests", 0)]
        visited: set[int] = set()
        while stack:
            tree_raw, location, depth = stack.pop()
            tree, error = _resolve(tree_raw)
            if error is not None or not isinstance(tree, DictionaryObject):
                self.errors.append(f"{location}: destination tree is not a dictionary")
                continue
            tree_id = id(tree)
            if tree_id in visited or depth > config.named_destinations_maximum_depth:
                continue
            visited.add(tree_id)
            kids = _resolve(_raw_key(tree, "/Kids"))[0]
            if isinstance(kids, ArrayObject):
                for index, kid in enumerate(kids):
                    stack.append((kid, f"{location}/Kids[{index}]", depth + 1))
            names_array = _resolve(_raw_key(tree, "/Names"))[0]
            if not isinstance(names_array, ArrayObject):
                continue
            index = 0
            pair_index = 0
            while index + 1 < len(names_array):
                key_raw = names_array[index]
                value_raw = names_array[index + 1]
                key = _resolve(key_raw)[0]
                raw_name, canonical = _name_parts(key if key is not None else key_raw)
                provenance = self._provenance(
                    "named_destination",
                    f"{location}/Names[{index}]",
                    value_raw,
                    key="/Names",
                )
                self._add_registration(raw_name, canonical, value_raw, provenance)
                index += 2
                pair_index += 1

    def _add_registration(
        self,
        raw_name: str,
        canonical_name: str,
        value: Any,
        provenance: Provenance,
    ) -> None:
        destination_array, error = _destination_array(value)
        target_page = None
        target_object = None
        target_reference = None
        if destination_array:
            target_page, target_object, target_reference, error = self._page_target(destination_array[0])
        valid = target_page is not None
        self._registration_number += 1
        self.registrations.append(
            NamedDestinationRecord(
                id=f"dest-{self._registration_number:04d}",
                name=raw_name,
                canonical_name=canonical_name,
                origin=provenance,
                valid=valid,
                target_page=target_page,
                target_object_number=target_object,
                target_reference=target_reference,
                reason=None if valid else error or "destination has no page target",
            )
        )

    def _scan_outline(self) -> list[NavigationReference]:
        result: list[NavigationReference] = []
        try:
            catalog = self.reader.root_object
            outlines = _resolve(_raw_key(catalog, "/Outlines"))[0]
            if not isinstance(outlines, DictionaryObject):
                return result
            visited: set[int] = set()

            def walk(first_raw: Any, depth: int, location: str) -> None:
                current_raw = first_raw
                index = 0
                while current_raw is not None:
                    node, error = _resolve(current_raw)
                    if error is not None or not isinstance(node, DictionaryObject):
                        self.errors.append(f"{location}[{index}]: outline node is not a dictionary")
                        return
                    node_id = id(node)
                    if node_id in visited:
                        return
                    visited.add(node_id)
                    title_value = _resolve(_raw_key(node, "/Title"))[0]
                    title = str(title_value) if title_value is not None else None
                    item_location = f"{location}[{index}]"
                    reference = self._reference_from_dictionary(
                        node,
                        source="outline",
                        location=item_location,
                        page_index=None,
                        outline_title=title,
                    )
                    if reference is not None:
                        result.append(reference)
                    if "/First" in node:
                        walk(_raw_key(node, "/First"), depth + 1, f"{item_location}/First")
                    if "/Next" not in node:
                        return
                    current_raw = _raw_key(node, "/Next")
                    index += 1

            walk(_raw_key(outlines, "/First"), 0, "outline")
        except Exception as error:
            self.errors.append(f"outline: {error}")
        return result

    def _scan_annotations(self) -> tuple[list[NavigationReference], int, int]:
        result: list[NavigationReference] = []
        annotation_count = 0
        link_count = 0
        for page_index, page in enumerate(self.reader.pages):
            annotations = _resolve(_raw_key(page, "/Annots"))[0]
            if annotations is None:
                continue
            if not isinstance(annotations, ArrayObject):
                self.errors.append(f"pages[{page_index}]/Annots is not an array")
                continue
            for annotation_index, annotation_raw in enumerate(annotations):
                annotation_count += 1
                annotation, error = _resolve(annotation_raw)
                if error is not None or not isinstance(annotation, DictionaryObject):
                    self.errors.append(f"pages[{page_index}]/Annots[{annotation_index}] is invalid")
                    continue
                if annotation.get("/Subtype") != "/Link":
                    continue
                link_count += 1
                reference = self._reference_from_dictionary(
                    annotation,
                    source="page_annotation",
                    location=f"pages[{page_index}]/Annots[{annotation_index}]",
                    page_index=page_index,
                    annotation_index=annotation_index,
                )
                if reference is not None:
                    result.append(reference)
        return result, annotation_count, link_count

    def _reference_from_dictionary(
        self,
        obj: DictionaryObject,
        *,
        source: str,
        location: str,
        page_index: int | None,
        annotation_index: int | None = None,
        outline_title: str | None = None,
    ) -> NavigationReference | None:
        provenance = self._provenance(
            source,
            location,
            obj,
            page_index=page_index,
            annotation_index=annotation_index,
            outline_title=outline_title,
        )
        action_raw = _raw_key(obj, "/A") if "/A" in obj else None
        action = _resolve(action_raw)[0]
        if isinstance(action, DictionaryObject):
            action_type = action.get("/S")
            if action_type in {"/URI", "/Launch", "/GoToR", "/SubmitForm"}:
                target = action.get("/URI") or action.get("/F") or action.get("/N")
                reference = self._new_reference(
                    source=source,
                    provenance=provenance,
                    kind="external",
                    status=str(action_type).removeprefix("/").lower(),
                    resolved=False,
                    external=True,
                    external_target=str(target) if target is not None else None,
                    key="/A",
                )
                self.references.append(reference)
                return reference
            if action_type == "/GoTo" and "/D" in action:
                return self._destination_reference(
                    _raw_key(action, "/D"),
                    source=source,
                    provenance=provenance,
                    key="/A/D",
                )

        if "/Dest" in obj:
            return self._destination_reference(
                _raw_key(obj, "/Dest"),
                source=source,
                provenance=provenance,
                key="/Dest",
            )

        reference = self._new_reference(
            source=source,
            provenance=provenance,
            kind="none",
            status="no_destination",
            resolved=False,
            reason="outline item or link has no /Dest or internal /A /D",
        )
        self.references.append(reference)
        return reference

    def _destination_reference(
        self,
        destination_raw: Any,
        *,
        source: str,
        provenance: Provenance,
        key: str,
    ) -> NavigationReference:
        destination, _ = _resolve(destination_raw)
        if isinstance(destination, str):
            raw_name, canonical = _name_parts(destination)
            reference = self._new_reference(
                source=source,
                provenance=provenance,
                kind="named",
                status="named_unresolved",
                resolved=False,
                name=raw_name,
                canonical_name=canonical,
                key=key,
                raw_destination=raw_name,
            )
        else:
            array, error = _destination_array(destination_raw)
            if array is None or not array:
                reference = self._new_reference(
                    source=source,
                    provenance=provenance,
                    kind="unsupported",
                    status="invalid_destination",
                    resolved=False,
                    reason=error or "empty destination array",
                    key=key,
                    raw_destination=_safe_primitive(destination),
                )
            else:
                target_page, target_object, target_reference, reason = self._page_target(array[0])
                resolved = target_page is not None
                reference = self._new_reference(
                    source=source,
                    provenance=provenance,
                    kind="direct",
                    status="resolved" if resolved else "missing_target",
                    resolved=resolved,
                    target_page=target_page,
                    target_object_number=target_object,
                    target_reference=target_reference,
                    reason=reason,
                    key=key,
                    raw_destination=_safe_primitive(array),
                    resolution_steps=[{"hop": 1, "stage": "direct_reference_to_page", "target_page": target_page}],
                )
        self.references.append(reference)
        return reference

    def _new_reference(self, **kwargs: Any) -> NavigationReference:
        provenance = kwargs.pop("provenance")
        return NavigationReference(id=self._next_reference_id(), origin=provenance, **kwargs)

    def _resolve_named_references(self) -> None:
        by_name: dict[str, list[NamedDestinationRecord]] = {}
        for registration in self.registrations:
            by_name.setdefault(registration.name, []).append(registration)
            by_name.setdefault(registration.canonical_name, []).append(registration)

        for reference in self.references:
            if reference.kind != "named" or reference.canonical_name is None:
                continue
            matches = _matching_registrations(reference, self.registrations)
            reference.registrations = [item.origin for item in matches]
            reference.resolution_steps = [
                {"stage": "reference_to_registration", "found": bool(matches), "count": len(matches)},
            ]
            if not matches:
                reference.status = "missing_registration"
                reference.reason = f"no named destination registration for {reference.name!r}"
                reference.resolution_steps.append({"stage": "registration_to_page", "found": False})
                continue
            valid = [item for item in matches if item.valid]
            chosen = valid[0] if valid else matches[0]
            reference.target_page = chosen.target_page
            reference.target_object_number = chosen.target_object_number
            reference.target_reference = chosen.target_reference
            if valid:
                reference.resolved = True
                reference.status = "duplicate_name" if len(matches) > 1 else "resolved"
                reference.reason = None
                reference.resolution_steps.append(
                    {"stage": "registration_to_page", "found": True, "target_page": chosen.target_page}
                )
                if len(matches) > 1:
                    reference.reason = f"{len(matches)} registrations share this name"
            else:
                reference.status = "missing_target"
                reference.reason = chosen.reason or "named destination has no valid page target"
                reference.resolution_steps.append({"stage": "registration_to_page", "found": False})

    def _duplicate_groups(self) -> DuplicateNameCollection:
        grouped: dict[str, list[NamedDestinationRecord]] = {}
        for registration in self.registrations:
            grouped.setdefault(registration.canonical_name, []).append(registration)
        collection = DuplicateNameCollection()
        for canonical, records in sorted(grouped.items()):
            if len(records) < 2:
                continue
            for record in records:
                record.duplicate = True
            raw_names = list(dict.fromkeys(record.name for record in records))
            collection.append(
                DuplicateName(
                    name=raw_names[0],
                    canonical_name=canonical,
                    count=len(records),
                    raw_names=raw_names,
                    sources=[record.origin for record in records],
                    registrations=records,
                )
            )
        return collection

    def _library_destinations(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        try:
            destinations = self.reader.named_destinations
            for name, destination in destinations.items():
                try:
                    page = self.reader.get_destination_page_number(destination)
                except Exception:
                    page = None
                result.append({"name": str(name), "target_page": page})
        except Exception as error:
            self.errors.append(f"named_destinations API: {error}")
        return result

    def _path_roots(self, outgoing: dict[int, list[NavigationReference]]) -> list[NavigationReference]:
        roots: list[NavigationReference] = [
            item for item in self.outline_or_internal() if item.source == "outline" and item.kind != "none"
        ]
        incoming_from_other_page: set[int] = set()
        for reference in self.references:
            if (
                reference.resolved
                and reference.target_page is not None
                and reference.origin.page_index is not None
                and reference.target_page != reference.origin.page_index
            ):
                incoming_from_other_page.add(reference.target_page)
        for page_index in sorted(outgoing):
            if page_index not in incoming_from_other_page:
                roots.extend(outgoing[page_index])
        return roots

    def outline_or_internal(self) -> list[NavigationReference]:
        return self.references


def _matching_registrations(
    reference: NavigationReference, registrations: list[NamedDestinationRecord]
) -> list[NamedDestinationRecord]:
    return [
        registration
        for registration in registrations
        if (reference.name is not None and registration.name == reference.name)
        or (reference.canonical_name is not None and registration.canonical_name == reference.canonical_name)
    ]


def _safe_primitive(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return repr(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, (list, tuple, ArrayObject)):
        return [_safe_primitive(item, depth + 1) for item in value]
    if isinstance(value, DictionaryObject | dict):
        return {str(key): _safe_primitive(item, depth + 1) for key, item in value.items()}
    reference = getattr(value, "indirect_reference", None)
    if isinstance(reference, IndirectObject):
        return {"object_number": reference.idnum, "generation": reference.generation}
    return repr(value)


def _outgoing_by_page(references: list[NavigationReference]) -> dict[int, list[NavigationReference]]:
    outgoing: dict[int, list[NavigationReference]] = {}
    for reference in references:
        page = reference.origin.page_index
        if reference.source == "page_annotation" and page is not None:
            outgoing.setdefault(page, []).append(reference)
    return outgoing


def _select_references(
    references: list[NavigationReference],
    *,
    start: Any,
    page: int | None,
    source_id: str | None,
    outline_title: str | None,
) -> list[NavigationReference]:
    if isinstance(start, NavigationReference):
        return [start]
    if isinstance(start, int):
        page = start
    elif isinstance(start, str) and page is None and source_id is None and outline_title is None:
        source_id = start
    if page is not None:
        return [item for item in references if item.source == "page_annotation" and item.origin.page_index == page]
    if source_id is not None:
        by_id = [item for item in references if item.id == source_id]
        if by_id:
            return by_id
        return [item for item in references if item.origin.location == source_id]
    if outline_title is not None:
        return [item for item in references if item.origin.outline_title == outline_title]
    if start is not None and outline_title is None:
        return [item for item in references if item.origin.outline_title == str(start)]
    return []


def _follow_reference(
    start: NavigationReference,
    outgoing: dict[int, list[NavigationReference]],
    *,
    max_hops: int,
) -> list[NavigationPath]:
    def make_hop(number: int, reference: NavigationReference) -> NavigationHop:
        return NavigationHop(
            number=number,
            reference_id=reference.id,
            source=reference.source,
            provenance=reference.origin,
            kind=reference.kind,
            status=reference.status,
            resolved=reference.resolved,
            from_page=reference.origin.page_index,
            target_page=reference.target_page,
            name=reference.name,
            reason=reference.reason,
            external=reference.external,
        )

    def dfs(
        reference: NavigationReference,
        hops: list[NavigationHop],
        visited: set[str],
    ) -> list[NavigationPath]:
        hop = make_hop(len(hops) + 1, reference)
        current_hops = [*hops, hop]
        if reference.external:
            return [
                NavigationPath(
                    hops=current_hops,
                    external=True,
                    stop_reason="external reference recorded but not opened",
                )
            ]
        if not reference.resolved:
            return [
                NavigationPath(
                    hops=current_hops,
                    broken=True,
                    broken_hop=hop.number,
                    stop_reason=reference.reason,
                )
            ]
        if len(current_hops) >= max_hops:
            return [NavigationPath(hops=current_hops, truncated=True, stop_reason="maximum hop count reached")]

        next_references = outgoing.get(reference.target_page if reference.target_page is not None else -1, [])
        if not next_references:
            return [NavigationPath(hops=current_hops, complete=True)]

        paths: list[NavigationPath] = []
        for next_reference in next_references:
            if next_reference.id in visited:
                cycle_hop = make_hop(len(current_hops) + 1, next_reference)
                cycle_hop.status = "navigation_cycle"
                cycle_hop.resolved = False
                cycle_hop.reason = "navigation path revisited a reference"
                paths.append(
                    NavigationPath(
                        hops=[*current_hops, cycle_hop],
                        cycle=True,
                        stop_reason="navigation cycle detected",
                    )
                )
                continue
            paths.extend(dfs(next_reference, current_hops, visited | {next_reference.id}))
        return paths

    return dfs(start, [], {start.id})


__all__ = [
    "DuplicateName",
    "DuplicateNameCollection",
    "NamedDestinationRecord",
    "NavigationForensics",
    "NavigationHop",
    "NavigationPath",
    "NavigationReference",
    "NavigationReport",
    "NavigationTrace",
    "Provenance",
    "analyze_navigation",
    "audit_navigation",
    "build_navigation_report",
    "collect_navigation_evidence",
    "inspect_navigation",
    "navigation_forensics",
    "verify_navigation",
]
