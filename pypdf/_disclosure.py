"""
Offline reconciliation of annotation disclosure statements.

An archive center keeps two read-only excerpts of the same PDF document:

* the *internal* excerpt may review annotation positions (``/Rect``),
* the *external* excerpt is only approved to disclose the annotation
  category (``/Subtype``) and the relative page number.

This module binds three things together so the two excerpts can be
checked offline against the same source document:

* the page label (what a viewer shows as "the page number"),
* the actual object an annotation belongs to (its indirect reference),
* the approved disclosure scope.

Annotations that cannot be tied to a single page of the document are
skipped instead of being disclosed:

* annotations whose page relationship cannot be explained (for example
  a ``/P`` entry pointing at a different page, or an entry that does not
  resolve to an annotation dictionary at all), and
* instances attached to a shared object, i.e. an annotation object that
  is referenced from more than one ``/Annots`` array.

The annotation text (``/Contents``) is never read, so public artifacts
produced from the external scope cannot leak the actual annotation body.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ._doc_common import PdfDocCommon
from .constants import AnnotationDictionaryAttributes as ADA
from .constants import PageAttributes as PG
from .generic import DictionaryObject, IndirectObject


class DisclosureScope(Enum):
    """The disclosure scope an excerpt is approved for."""

    #: Positions of annotations may be reviewed.
    INTERNAL = "internal"
    #: Only the annotation category and the relative page number
    #: may be disclosed.
    EXTERNAL = "external"


class SkipReason(Enum):
    """Why an annotation instance was not disclosed."""

    #: The annotation cannot be tied to the page it was found on.
    UNEXPLAINABLE_PAGE_RELATION = "unexplainable_page_relation"
    #: The annotation object is shared between several ``/Annots`` arrays.
    SHARED_OBJECT = "shared_object"


@dataclass(frozen=True, order=True)
class AnnotationObjectRef:
    """A stable reference to the actual object an annotation belongs to."""

    idnum: int
    generation: int


@dataclass(frozen=True)
class AnnotationStatement:
    """
    A single disclosure statement about one annotation instance.

    ``rect`` is only populated for the internal scope; the external
    scope never carries positions or the annotation text.
    """

    scope: DisclosureScope
    page_label: str
    relative_page: int
    category: str | None
    source: AnnotationObjectRef
    rect: tuple[float, ...] | None = None


@dataclass(frozen=True)
class SkippedAnnotation:
    """An annotation instance that was not disclosed, with the reason."""

    reason: SkipReason
    page_label: str
    relative_page: int
    category: str | None
    source: AnnotationObjectRef | None


@dataclass
class DisclosureReport:
    """The statements collected from one read-only excerpt."""

    scope: DisclosureScope
    statements: list[AnnotationStatement] = field(default_factory=list)
    skipped: list[SkippedAnnotation] = field(default_factory=list)

    def public_artifact(self) -> list[dict[str, Any]]:
        """
        Return the disclosable view of this report.

        The artifact only contains the fields approved for the report's
        scope. It never contains the annotation text, and positions are
        only present for the internal scope.
        """
        artifact = []
        for statement in self.statements:
            record: dict[str, Any] = {
                "page_label": statement.page_label,
                "relative_page": statement.relative_page,
                "category": statement.category,
                "source": {
                    "idnum": statement.source.idnum,
                    "generation": statement.source.generation,
                },
            }
            if self.scope is DisclosureScope.INTERNAL:
                record["rect"] = (
                    list(statement.rect) if statement.rect is not None else None
                )
            artifact.append(record)
        return artifact


@dataclass(frozen=True)
class StatementBinding:
    """Two statements, one per excerpt, tied to the same source object."""

    source: AnnotationObjectRef
    internal: AnnotationStatement
    external: AnnotationStatement

    @property
    def agrees(self) -> bool:
        """Whether both statements describe the source identically."""
        return (
            self.internal.page_label,
            self.internal.relative_page,
            self.internal.category,
        ) == (
            self.external.page_label,
            self.external.relative_page,
            self.external.category,
        )


@dataclass
class ReconciliationResult:
    """The outcome of reconciling an internal and an external report."""

    bindings: list[StatementBinding] = field(default_factory=list)
    unmatched_internal: list[AnnotationStatement] = field(default_factory=list)
    unmatched_external: list[AnnotationStatement] = field(default_factory=list)

    @property
    def mismatches(self) -> list[StatementBinding]:
        """Bindings where the two statements disagree on the disclosed fields."""
        return [binding for binding in self.bindings if not binding.agrees]

    @property
    def is_consistent(self) -> bool:
        """Whether every statement is bound to the same source on both sides."""
        return (
            not self.unmatched_internal
            and not self.unmatched_external
            and not self.mismatches
        )


def _annotation_category(annot: DictionaryObject) -> str | None:
    subtype = annot.get(ADA.Subtype)
    return str(subtype) if subtype is not None else None


def _annotation_rect(annot: DictionaryObject) -> tuple[float, ...] | None:
    rect = annot.get(ADA.Rect)
    if rect is None:
        return None
    return tuple(float(value) for value in rect)


def _page_relation_is_explainable(annot: DictionaryObject, page: Any) -> bool:
    """
    Check that the annotation's ``/P`` entry, if present, points back to
    the page the annotation was discovered on.
    """
    page_ref = annot.get(ADA.P)
    if page_ref is None:
        return True
    if not isinstance(page_ref, IndirectObject):
        return False
    own_ref = page.indirect_reference
    return (
        own_ref is not None
        and page_ref.idnum == own_ref.idnum
        and page_ref.generation == own_ref.generation
    )


def collect_annotation_statements(
    reader: PdfDocCommon, scope: DisclosureScope
) -> DisclosureReport:
    """
    Walk the page tree of ``reader`` and collect disclosure statements.

    Args:
        reader: The source document to take the read-only excerpt from.
        scope: The approved disclosure scope of the excerpt.

    Returns:
        A report with one statement per disclosable annotation instance
        and the list of skipped instances.
    """
    report = DisclosureReport(scope=scope)
    labels = reader.page_labels

    # First pass: find every annotation instance and where it appears.
    occurrences: dict[AnnotationObjectRef, list[tuple[int, DictionaryObject]]] = {}
    pages = list(reader.pages)
    for page_index, page in enumerate(pages):
        annots = page.get(PG.ANNOTS) or []
        for entry in annots:
            label = labels[page_index]
            relative_page = page_index + 1
            if not isinstance(entry, IndirectObject):
                report.skipped.append(
                    SkippedAnnotation(
                        reason=SkipReason.UNEXPLAINABLE_PAGE_RELATION,
                        page_label=label,
                        relative_page=relative_page,
                        category=None,
                        source=None,
                    )
                )
                continue
            annot = entry.get_object()
            if not isinstance(annot, DictionaryObject):
                report.skipped.append(
                    SkippedAnnotation(
                        reason=SkipReason.UNEXPLAINABLE_PAGE_RELATION,
                        page_label=label,
                        relative_page=relative_page,
                        category=None,
                        source=AnnotationObjectRef(entry.idnum, entry.generation),
                    )
                )
                continue
            ref = AnnotationObjectRef(entry.idnum, entry.generation)
            occurrences.setdefault(ref, []).append((page_index, annot))

    # Second pass: disclose or skip each instance.
    for ref, instances in occurrences.items():
        if len(instances) > 1:
            # The object is shared: skip every instance attached to it.
            for page_index, annot in instances:
                report.skipped.append(
                    SkippedAnnotation(
                        reason=SkipReason.SHARED_OBJECT,
                        page_label=labels[page_index],
                        relative_page=page_index + 1,
                        category=_annotation_category(annot),
                        source=ref,
                    )
                )
            continue
        page_index, annot = instances[0]
        label = labels[page_index]
        relative_page = page_index + 1
        category = _annotation_category(annot)
        if not _page_relation_is_explainable(annot, pages[page_index]):
            report.skipped.append(
                SkippedAnnotation(
                    reason=SkipReason.UNEXPLAINABLE_PAGE_RELATION,
                    page_label=label,
                    relative_page=relative_page,
                    category=category,
                    source=ref,
                )
            )
            continue
        rect = _annotation_rect(annot) if scope is DisclosureScope.INTERNAL else None
        report.statements.append(
            AnnotationStatement(
                scope=scope,
                page_label=label,
                relative_page=relative_page,
                category=category,
                source=ref,
                rect=rect,
            )
        )
    return report


def reconcile_statements(
    internal: DisclosureReport, external: DisclosureReport
) -> ReconciliationResult:
    """
    Reconcile an internal and an external report taken from the same document.

    Every statement is bound to the actual annotation object it stems from,
    so a statement in one excerpt can be traced back to its source through
    the matching statement in the other excerpt.
    """
    if internal.scope is not DisclosureScope.INTERNAL:
        raise ValueError("internal report must use DisclosureScope.INTERNAL")
    if external.scope is not DisclosureScope.EXTERNAL:
        raise ValueError("external report must use DisclosureScope.EXTERNAL")

    internal_by_source = {stmt.source: stmt for stmt in internal.statements}
    external_by_source = {stmt.source: stmt for stmt in external.statements}

    result = ReconciliationResult()
    for source in sorted(internal_by_source.keys() & external_by_source.keys()):
        result.bindings.append(
            StatementBinding(
                source=source,
                internal=internal_by_source[source],
                external=external_by_source[source],
            )
        )
    for source in sorted(internal_by_source.keys() - external_by_source.keys()):
        result.unmatched_internal.append(internal_by_source[source])
    for source in sorted(external_by_source.keys() - internal_by_source.keys()):
        result.unmatched_external.append(external_by_source[source])
    return result
