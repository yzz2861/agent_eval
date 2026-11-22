"""
Preview delivery checks for restricted, single-page handouts.

When a document review backend exposes a single PDF page to a restricted
visitor, it has to know exactly which internal objects the page genuinely
needs.  Page-tree inheritance (for example a ``/Resources`` dictionary living
on a parent ``/Pages`` node) and references that escape the document through
external files make the answer non obvious.

This module performs a *static* analysis only:

* it walks the objects reachable from the approved page (including inherited
  page attributes) and records the closed set of internal indirect objects
  required to render it;
* it detects references to external material (external file specifications,
  external streams, remote goto actions ...) without ever opening or reading
  that material;
* anything that cannot be confirmed as a fully self-contained internal
  dependency is reported as a manual-review item instead of being guessed.

The module never performs network or file-system access.  In particular,
stream data referenced through ``/F`` and the targets of remote actions are
detected but never fetched.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, cast

from .constants import FileSpecificationDictionaryEntries as FS_ENTRY
from .constants import PageAttributes as PG
from .errors import PyPdfError
from .generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NullObject,
    PdfObject,
    StreamObject,
    is_null_or_none,
)

if TYPE_CHECKING:
    from ._page import PageObject
    from ._reader import PdfReader

__all__ = [
    "PreviewIssueCode",
    "PreviewIssue",
    "PreviewDeliveryReport",
    "PreviewDeliveryError",
    "check_page_delivery",
    "build_page_preview",
]

#: Page attributes that may be inherited from ancestor /Pages nodes and that
#: therefore have to be resolved through the inheritance walk.
INHERITED_PAGE_KEYS = (
    PG.RESOURCES,
    PG.MEDIABOX,
    PG.CROPBOX,
    PG.BLEEDBOX,
    PG.TRIMBOX,
    PG.ARTBOX,
    PG.ROTATE,
)

#: Keys that point at other pages or at the page tree rather than at rendering
#: dependencies.  They must not pull unrelated pages into the delivery set.
PAGE_TREE_KEYS = ("/Parent", "/Kids", "/First", "/Last", "/Next", "/Prev")

#: Page-only entries that are not needed to render the page for a restricted
#: visitor and that would otherwise pull in document level trees.
PAGE_EXCLUDED_KEYS = (
    "/StructParents",
    "/Metadata",
    "/PieceInfo",
    "/OutputIntents",
    "/Thumb",
    "/B",
    "/VP",
    "/PresSteps",
    "/SeparationInfo",
    "/DPart",
    "/ID",
)

#: Action / annotation entries that carry an external file specification.
REMOTE_FILE_KEYS = (
    FS_ENTRY.F,
    FS_ENTRY.UF,
    FS_ENTRY.DOS,
    FS_ENTRY.Mac,
    FS_ENTRY.Unix,
    "/File",
)


class PreviewIssueCode(str, Enum):
    """Reason a delivery item cannot be confirmed automatically."""

    #: A stream declares its data through ``/F`` (an external file).  The data
    #: is never read and therefore cannot be delivered as an internal object.
    EXTERNAL_STREAM = "external_stream"

    #: A file specification dictionary points at an external file.
    EXTERNAL_FILE_SPECIFICATION = "external_file_specification"

    #: An action targets another document (for example /Launch, /URI,
    #: /GoToR / /GoToE).
    REMOTE_ACTION = "remote_action"

    #: An indirect reference cannot be resolved inside the source document.
    UNRESOLVABLE_REFERENCE = "unresolvable_reference"


@dataclass(frozen=True)
class PreviewIssue:
    """A single item that requires manual review before delivery."""

    code: PreviewIssueCode
    #: Human readable description of what could not be confirmed.
    detail: str
    #: ``(idnum, generation)`` of the object carrying the issue, when known.
    object_ref: tuple[int, int] | None = None
    #: Key within the object that introduced the issue, when relevant.
    key: str | None = None


@dataclass
class PreviewDeliveryReport:
    """
    Outcome of a single-page delivery check.

    Attributes:
        page_number: Zero-based index of the approved page in the reader.
        deliverable_objects: Closed set of ``(idnum, generation)`` pairs for
            the internal indirect objects the page genuinely needs.
        issues: Items that cannot be confirmed automatically.  As long as
            ``issues`` is non empty the result must be treated as
            *pending manual review* rather than delivered blindly.
    """

    page_number: int
    deliverable_objects: set[tuple[int, int]] = field(default_factory=set)
    issues: list[PreviewIssue] = field(default_factory=list)

    @property
    def is_deliverable(self) -> bool:
        """``True`` only when no manual-review item was found."""
        return not self.issues

    @property
    def requires_manual_review(self) -> bool:
        """Inverse of :attr:`is_deliverable`."""
        return bool(self.issues)


class PreviewDeliveryError(PyPdfError):
    """
    Raised when a page cannot be delivered without manual review.

    The attached PreviewDeliveryReport lists every item that could not be
    confirmed as a self-contained internal dependency.  The caller is
    expected to route the page to a human instead of exporting it.
    """

    def __init__(self, report: "PreviewDeliveryReport") -> None:
        self.report = report
        codes = ", ".join(sorted({issue.code.value for issue in report.issues}))
        super().__init__(
            f"page {report.page_number} requires manual review "
            f"({len(report.issues)} issue(s): {codes})"
        )


def _raw_inherited(page: "PageObject", key: str) -> object | None:
    """Return the raw value of an inheritable key, without dereferencing.

    Walking the /Parent chain manually keeps an IndirectObject identity so the
    dependency set can record the exact object the page inherits.
    """
    current: object = page
    seen: set[int] = set()
    while isinstance(current, DictionaryObject):
        if id(current) in seen:
            return None
        seen.add(id(current))
        if key in dict.keys(current):
            return dict.__getitem__(current, key)
        parent = current.raw_get("/Parent") if "/Parent" in current else None
        if not isinstance(parent, IndirectObject):
            return None
        current = parent.get_object()
    return None


def _iter_page_chain(page: "PageObject"):
    """Yield the page then each ancestor /Pages node (resolved objects)."""
    current: object = page
    seen: set[int] = set()
    while isinstance(current, DictionaryObject):
        if id(current) in seen:
            return
        seen.add(id(current))
        yield current
        if "/Parent" not in current:
            return
        parent = current.raw_get("/Parent")
        if not isinstance(parent, IndirectObject):
            return
        current = parent.get_object()


def _collect_inherited_resources(page: "PageObject") -> list[object]:
    """Return the raw /Resources values along the whole inheritance chain.

    A page may define its own /Resources while also inheriting another one.
    Per the PDF specification the dictionaries are combined, so every level
    contributes.  Raw (possibly indirect) values are returned bottom-up, the
    page's own resources first.
    """
    collected: list[object] = []
    for node in _iter_page_chain(page):
        if PG.RESOURCES in dict.keys(node):
            collected.append(dict.__getitem__(node, PG.RESOURCES))
    return collected


def _clone_into(target: DictionaryObject, source_raw: object, writer: object) -> None:
    """Deep-merge one raw resources level into *target*.

    Nested dictionaries are merged recursively; every other value (including
    indirect references to fonts, images or XObjects) is cloned as a whole so
    a resource shared by several pages keeps mapping to a single cloned object.
    """
    source = source_raw.get_object() if isinstance(source_raw, IndirectObject) else source_raw
    if not isinstance(source, DictionaryObject):
        return
    for raw_key, raw_value in dict.items(source):
        value = raw_value.get_object() if isinstance(raw_value, IndirectObject) else raw_value
        if isinstance(value, DictionaryObject) and raw_key in dict.keys(target):
            existing = target.raw_get(raw_key)
            existing = existing.get_object() if isinstance(existing, IndirectObject) else existing
            if isinstance(existing, DictionaryObject):
                _clone_into(existing, raw_value, writer)
                continue
        target[NameObject(str(raw_key))] = (
            raw_value.clone(writer)
            if isinstance(raw_value, IndirectObject)
            else value.clone(writer) if isinstance(value, (DictionaryObject, ArrayObject))
            else cast("PdfObject", value)
        )


def _ref_key(ref: IndirectObject) -> tuple[int, int]:
    return ref.idnum, ref.generation


def _describe_ref(obj: DictionaryObject | StreamObject) -> str:
    ref = getattr(obj, "indirect_reference", None)
    if ref is not None:
        return f"object {ref.idnum} {ref.generation} R"
    return f"direct {obj.__class__.__name__}"


def check_page_delivery(
    reader: "PdfReader",
    page_number: int,
) -> PreviewDeliveryReport:
    """
    Compute the exact internal dependencies of one page.

    The check is purely static: it resolves indirect objects that are already
    available in *reader* but never opens external files, never follows remote
    targets and never performs any network access.

    Args:
        reader: Source document.
        page_number: Zero-based index of the page approved for delivery.

    Returns:
        A :class:`PreviewDeliveryReport` listing the closed set of internal
        objects the page needs and every item that needs manual review.

    Raises:
        IndexError: If *page_number* is out of range.
    """
    page = reader.pages[page_number]
    report = PreviewDeliveryReport(page_number=page_number)

    visited: set[tuple[int, int]] = set()
    # Queue of (object to walk, is it the approved page itself).
    queue: deque[tuple[object, bool]] = deque([(page, True)])

    def add_issue(
        code: PreviewIssueCode,
        detail: str,
        owner: object | None = None,
        key: str | None = None,
    ) -> None:
        object_ref = None
        if isinstance(owner, (DictionaryObject, StreamObject)):
            ref = getattr(owner, "indirect_reference", None)
            if ref is not None:
                object_ref = _ref_key(ref)
        report.issues.append(PreviewIssue(code, detail, object_ref, key))

    def queue_value(value: object, *, is_page_root: bool = False) -> None:
        if isinstance(value, IndirectObject):
            key = _ref_key(value)
            if key in visited:
                return
            resolved = value.get_object()
            if resolved is None or is_null_or_none(resolved):
                add_issue(
                    PreviewIssueCode.UNRESOLVABLE_REFERENCE,
                    f"reference {value.idnum} {value.generation} R cannot be "
                    "resolved inside the document",
                )
                return
            visited.add(key)
            report.deliverable_objects.add(key)
            queue.append((resolved, is_page_root))
        elif isinstance(value, (DictionaryObject, ArrayObject)):
            # Direct nested containers still have to be traversed even though
            # they are not part of the indirect object set.
            queue.append((value, is_page_root))

    # The page itself is an indirect object in every well formed document.
    if page.indirect_reference is not None:
        root_key = _ref_key(page.indirect_reference)
        visited.add(root_key)
        report.deliverable_objects.add(root_key)

    while queue:
        current, is_page_root = queue.popleft()

        if isinstance(current, ArrayObject):
            for item in current:
                queue_value(item)
            continue

        if not isinstance(current, DictionaryObject):
            continue

        # A stream that keeps its data in an external file cannot be delivered
        # from the internal object store.  Detect it without reading the file.
        if isinstance(current, StreamObject) and any(
            key in current for key in (FS_ENTRY.F, FS_ENTRY.UF)
        ):
            add_issue(
                PreviewIssueCode.EXTERNAL_STREAM,
                f"stream {_describe_ref(current)} stores its data in an "
                "external file (/F) which is never read",
                current,
                FS_ENTRY.F,
            )

        type_name = current.get("/Type")
        if isinstance(type_name, NullObject):
            type_name = None

        # File specification dictionaries are always a boundary: they name
        # material that is not embedded as an ordinary rendering dependency.
        if type_name == "/Filespec" or any(
            key in current for key in REMOTE_FILE_KEYS
        ):
            named = current.get(FS_ENTRY.UF) or current.get(FS_ENTRY.F)
            target = f" {named!r}" if named is not None else ""
            add_issue(
                PreviewIssueCode.EXTERNAL_FILE_SPECIFICATION,
                f"file specification {_describe_ref(current)} names external "
                f"material{target} that is not read",
                current,
            )

        action_type = current.get("/S")
        if action_type in (
            "/Launch",
            "/URI",
            "/GoToR",
            "/GoToE",
            "/SubmitForm",
            "/ImportData",
        ):
            add_issue(
                PreviewIssueCode.REMOTE_ACTION,
                f"action {_describe_ref(current)} of type {action_type} "
                "reaches outside the document",
                current,
                "/S",
            )

        # dict iteration on purpose: DictionaryObject.__getitem__ would
        # transparently resolve indirect references, but the raw value is
        # needed to register them as distinct deliverable objects.
        for raw_key, raw_value in dict.items(current):
            key = str(raw_key)

            if key in PAGE_TREE_KEYS or (is_page_root and key in PAGE_EXCLUDED_KEYS):
                continue

            # On the approved page, inheritable attributes must be taken from
            # the resolved (possibly inherited) value instead of the raw one.
            if is_page_root and key == PG.RESOURCES:
                # Resources are merged across the whole inheritance chain.
                for resource_raw in _collect_inherited_resources(page):
                    queue_value(resource_raw, is_page_root=False)
                continue

            if is_page_root and key in INHERITED_PAGE_KEYS:
                inherited_raw = _raw_inherited(page, key)
                if inherited_raw is None or is_null_or_none(inherited_raw):
                    continue
                queue_value(inherited_raw, is_page_root=False)
                continue

            if isinstance(raw_value, IndirectObject):
                queue_value(raw_value)
            elif isinstance(raw_value, (DictionaryObject, ArrayObject)):
                queue_value(raw_value)

    return report


def build_page_preview(
    reader: "PdfReader",
    page_number: int,
) -> tuple["PdfWriter", PreviewDeliveryReport]:
    """
    Build a self-contained single-page handout for an approved page.

    The delivery check runs first.  When it finds anything that cannot be
    confirmed automatically, :class:`PreviewDeliveryError` is raised and no
    output document is produced: the caller must route the result through
    manual review instead of shipping material that might embed an external
    dependency.

    On success a fresh :class:`~pypdf.PdfWriter` is returned containing only
    the approved page and the closed set of internal objects it needs.
    Inherited page attributes (resources, boxes, rotation ...) are materialised
    onto the cloned page, page-tree links are cut, and no external file or
    remote target is ever opened.

    Args:
        reader: Source document.
        page_number: Zero-based index of the page approved for delivery.

    Returns:
        A ``(writer, report)`` tuple.  The writer holds the single deliverable
        page and the report describes the exact object set that was kept.

    Raises:
        PreviewDeliveryError: If the check reports manual-review items.
        IndexError: If *page_number* is out of range.
    """
    report = check_page_delivery(reader, page_number)
    if report.requires_manual_review:
        raise PreviewDeliveryError(report)

    # Imported lazily to avoid a circular import between the two modules.
    from ._writer import PdfWriter  # noqa: PLC0415

    source_page = reader.pages[page_number]
    writer = PdfWriter()

    excluded = ["/Parent", "/Annots", "/AA", "/AF", *PAGE_EXCLUDED_KEYS]
    cloned_page = cast(
        "PageObject",
        source_page.clone(writer, force_duplicate=True, ignore_fields=excluded)
        .get_object(),
    )

    # Build a single self-contained /Resources dictionary combining the page's
    # own resources with every inherited level.  Shared resources keep mapping
    # to one cloned object because IndirectObject.clone deduplicates per writer.
    merged_resources = DictionaryObject()
    for resource_raw in _collect_inherited_resources(source_page):
        _clone_into(merged_resources, resource_raw, writer)
    if dict.keys(merged_resources):
        cloned_page[NameObject(PG.RESOURCES)] = writer._add_object(merged_resources)

    # Materialise the remaining inheritable attributes (boxes, rotation ...)
    # the page does not define on its own.
    for inherited_key in INHERITED_PAGE_KEYS:
        if inherited_key == PG.RESOURCES:
            continue
        if inherited_key in dict.keys(source_page):
            continue
        inherited_raw = _raw_inherited(source_page, inherited_key)
        if inherited_raw is None or is_null_or_none(inherited_raw):
            continue
        cloned_page[NameObject(inherited_key)] = (
            inherited_raw.clone(writer)
            if isinstance(inherited_raw, IndirectObject)
            else cast("PdfObject", inherited_raw)
        )

    writer.add_page(cloned_page)
    return writer, report
