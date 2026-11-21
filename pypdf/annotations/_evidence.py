"""Read-only, page-queryable annotation evidence index.

This module builds an evidence index over the annotations of a document
without modifying it. It is meant for review/audit hand-offs where the
annotations on a *dossier* (a set of covered pages) have to be accounted
for:

- **Entities**: one record per annotation object. Identity is based on
  the indirect reference ``(idnum, generation)`` for indirect objects and
  on the in-page position for annotations embedded directly in ``/Annots``.
  It is never derived from the text contents alone, so an annotation whose
  reference was copied to another page stays the same entity, while two
  independently added annotations with identical text stay distinct.
- **Reply relations**: one record per annotation carrying ``/IRT``.
  Replies whose target is not part of the covered pages keep a
  *missing evidence* note that states on which page the original lives
  (located by scanning the whole document, read-only).
- **Page references**: the actual entries of each covered page's
  ``/Annots`` array, preserving position and indirect reference numbers.
"""

from dataclasses import dataclass

from .._protocols import PdfReaderProtocol
from ..generic import DictionaryObject, IndirectObject

EntityKey = tuple
"""Identity key of an annotation entity.

``("indirect", idnum, generation)`` for indirect objects,
``("direct", page, position)`` for annotations embedded in ``/Annots``.
"""


@dataclass(frozen=True)
class AnnotationEntity:
    """One annotation object, independent of how many pages reference it."""

    key: EntityKey
    subtype: str | None
    contents: str | None
    title: str | None
    name: str | None
    pages: tuple[int, ...]
    indirect: bool
    idnum: int | None
    generation: int | None

    def describe(self) -> str:
        """Human-readable identity of the entity (never text-only)."""
        if self.indirect:
            ref = f"{self.idnum} {self.generation} R"
        else:
            ref = f"direct annotation at page {self.key[1]}, position {self.key[2]}"
        label = self.subtype or "annotation"
        return f"{label} ({ref}) on page(s) {list(self.pages)}"


@dataclass(frozen=True)
class PageAnnotationReference:
    """One actual entry of a page's ``/Annots`` array."""

    page: int
    position: int
    entity_key: EntityKey
    indirect: bool
    idnum: int | None
    generation: int | None


@dataclass(frozen=True)
class MissingEvidenceNote:
    """Records that a reply's original is not covered by the dossier."""

    reply_key: EntityKey
    reply_pages: tuple[int, ...]
    target_reference: EntityKey | None
    target_pages: tuple[int, ...]
    reason: str


@dataclass(frozen=True)
class ReplyRelation:
    """One ``/IRT`` reply relationship."""

    source_key: EntityKey
    source_pages: tuple[int, ...]
    reply_type: str
    target_reference: EntityKey | None
    target_key: EntityKey | None
    missing: MissingEvidenceNote | None


@dataclass(frozen=True)
class PageEvidence:
    """Everything the index knows about one covered page."""

    page: int
    references: tuple[PageAnnotationReference, ...]
    entities: tuple[AnnotationEntity, ...]
    replies: tuple[ReplyRelation, ...]


@dataclass(frozen=True)
class AnnotationEvidenceReport:
    """Summary separating copied annotations from same-text duplicates."""

    covered_pages: tuple[int, ...]
    copied_to_other_pages: tuple[AnnotationEntity, ...]
    same_text_independent: tuple[tuple[AnnotationEntity, ...], ...]
    missing_evidence: tuple[MissingEvidenceNote, ...]

    def to_text(self) -> str:
        """Render the report as human-readable text."""
        lines = [
            "Annotation evidence report",
            f"Covered pages: {list(self.covered_pages)}",
            "",
            "Copied to another page (same object referenced from several pages):",
        ]
        if self.copied_to_other_pages:
            lines.extend(f"- {entity.describe()}" for entity in self.copied_to_other_pages)
        else:
            lines.append("- none")
        lines.append("")
        lines.append("Independent same-text annotations (distinct objects with identical contents):")
        if self.same_text_independent:
            for group in self.same_text_independent:
                contents = group[0].contents
                members = "; ".join(entity.describe() for entity in group)
                lines.append(f"- {contents!r}: {members}")
        else:
            lines.append("- none")
        lines.append("")
        lines.append("Missing evidence (reply originals outside the dossier):")
        if self.missing_evidence:
            lines.extend(f"- {note.reason}" for note in self.missing_evidence)
        else:
            lines.append("- none")
        return "\n".join(lines)


def _entity_key_for(page: int, position: int, entry: object) -> EntityKey | None:
    if isinstance(entry, IndirectObject):
        return ("indirect", entry.idnum, entry.generation)
    if isinstance(entry, DictionaryObject):
        return ("direct", page, position)
    return None


def _page_annots(page_obj: DictionaryObject) -> list:
    annots = page_obj.get("/Annots")
    if isinstance(annots, IndirectObject):
        annots = annots.get_object()
    if annots is None:
        return []
    return list(annots)


class AnnotationEvidenceIndex:
    """
    Read-only evidence index over a reader's annotations.

    Args:
        reader: The reader (or writer) to index. It is never modified.
        pages: 0-based page numbers covered by the dossier.
            ``None`` covers the whole document.
    """

    def __init__(
        self,
        reader: PdfReaderProtocol,
        pages: list[int] | tuple[int, ...] | None = None,
    ) -> None:
        total = len(reader.pages)
        if pages is None:
            covered = tuple(range(total))
        else:
            covered = tuple(sorted(set(pages)))
        for page_number in covered:
            if not 0 <= page_number < total:
                raise IndexError(f"page {page_number} is out of range for {total} pages")
        self._covered_pages = covered

        objects: dict[EntityKey, DictionaryObject] = {}
        entity_pages: dict[EntityKey, list[int]] = {}
        references: dict[int, list[PageAnnotationReference]] = {page: [] for page in covered}

        for page_number in covered:
            page_obj = reader.pages[page_number]
            for position, entry in enumerate(_page_annots(page_obj)):
                key = _entity_key_for(page_number, position, entry)
                if key is None:
                    continue
                obj = entry.get_object() if isinstance(entry, IndirectObject) else entry
                if not isinstance(obj, DictionaryObject):
                    continue
                objects.setdefault(key, obj)
                entity_pages.setdefault(key, [])
                if page_number not in entity_pages[key]:
                    entity_pages[key].append(page_number)
                references[page_number].append(
                    PageAnnotationReference(
                        page=page_number,
                        position=position,
                        entity_key=key,
                        indirect=isinstance(entry, IndirectObject),
                        idnum=(entry.idnum if isinstance(entry, IndirectObject) else None),
                        generation=(entry.generation if isinstance(entry, IndirectObject) else None),
                    )
                )

        entities: dict[EntityKey, AnnotationEntity] = {}
        for key, obj in objects.items():
            entities[key] = AnnotationEntity(
                key=key,
                subtype=obj.get("/Subtype"),
                contents=obj.get("/Contents"),
                title=obj.get("/T"),
                name=obj.get("/NM"),
                pages=tuple(sorted(entity_pages[key])),
                indirect=key[0] == "indirect",
                idnum=key[1] if key[0] == "indirect" else None,
                generation=key[2] if key[0] == "indirect" else None,
            )

        replies: list[ReplyRelation] = []
        for key, obj in objects.items():
            irt = obj.get("/IRT")
            if irt is None:
                continue
            reply_type = obj.get("/RT", "/R")
            reply_type = reply_type.removeprefix("/")
            target_reference: EntityKey | None = None
            target_key: EntityKey | None = None
            if isinstance(irt, IndirectObject):
                target_reference = ("indirect", irt.idnum, irt.generation)
                if target_reference in entities:
                    target_key = target_reference
            elif isinstance(irt, DictionaryObject):
                for candidate_key, candidate_obj in objects.items():
                    if candidate_obj is irt or candidate_obj == irt:
                        target_key = candidate_key
                        break
            missing = None
            if target_key is None:
                missing = self._missing_evidence(
                    reader=reader,
                    entities=entities,
                    reply_key=key,
                    reply_pages=entities[key].pages,
                    target_reference=target_reference,
                )
            replies.append(
                ReplyRelation(
                    source_key=key,
                    source_pages=entities[key].pages,
                    reply_type=reply_type,
                    target_reference=target_reference,
                    target_key=target_key,
                    missing=missing,
                )
            )

        self._entities = entities
        self._references = references
        self._replies = tuple(replies)

    def _missing_evidence(
        self,
        reader: PdfReaderProtocol,
        entities: dict[EntityKey, AnnotationEntity],
        reply_key: EntityKey,
        reply_pages: tuple[int, ...],
        target_reference: EntityKey | None,
    ) -> MissingEvidenceNote:
        target_pages: tuple[int, ...] = ()
        if target_reference is not None:
            found = []
            for page_number in range(len(reader.pages)):
                for entry in _page_annots(reader.pages[page_number]):
                    if _entity_key_for(page_number, 0, entry) == target_reference:
                        found.append(page_number)
                        break
            target_pages = tuple(found)
        reply_desc = entities[reply_key].describe()
        if target_reference is None:
            reason = f"Reply {reply_desc} refers to an inline original that is not part of the covered pages"
        elif target_pages:
            missing = [p for p in target_pages if p not in self._covered_pages]
            reason = (
                f"Reply {reply_desc} is missing its original "
                f"{target_reference[1]} {target_reference[2]} R: "
                f"it lives on page(s) {missing} which are not covered "
                "by this dossier"
            )
        else:
            reason = (
                f"Reply {reply_desc} refers to original "
                f"{target_reference[1]} {target_reference[2]} R which is not "
                "present in any page's /Annots of the document"
            )
        return MissingEvidenceNote(
            reply_key=reply_key,
            reply_pages=reply_pages,
            target_reference=target_reference,
            target_pages=target_pages,
            reason=reason,
        )

    @property
    def covered_pages(self) -> tuple[int, ...]:
        """0-based page numbers covered by this dossier."""
        return self._covered_pages

    @property
    def entities(self) -> tuple[AnnotationEntity, ...]:
        """All annotation entities on covered pages."""
        return tuple(self._entities.values())

    @property
    def replies(self) -> tuple[ReplyRelation, ...]:
        """All reply relations found on covered pages."""
        return self._replies

    def entity(self, key: EntityKey) -> AnnotationEntity:
        """Look up one entity by its identity key."""
        return self._entities[key]

    def page(self, page_number: int) -> PageEvidence:
        """Return the evidence recorded for one covered page."""
        if page_number not in self._covered_pages:
            raise IndexError(f"page {page_number} is not covered by this dossier")
        references = tuple(self._references[page_number])
        entities = tuple(self._entities[ref.entity_key] for ref in references)
        replies = tuple(reply for reply in self._replies if page_number in reply.source_pages)
        return PageEvidence(
            page=page_number,
            references=references,
            entities=entities,
            replies=replies,
        )

    def report(self) -> AnnotationEvidenceReport:
        """Build the summary report for the covered dossier."""
        copied = tuple(
            sorted(
                (e for e in self._entities.values() if len(e.pages) > 1),
                key=lambda e: e.pages,
            )
        )
        by_text: dict[str, list[AnnotationEntity]] = {}
        for entity in self._entities.values():
            if entity.contents:
                by_text.setdefault(entity.contents, []).append(entity)
        same_text = tuple(tuple(sorted(group, key=lambda e: e.pages)) for group in by_text.values() if len(group) > 1)
        missing = tuple(reply.missing for reply in self._replies if reply.missing is not None)
        return AnnotationEvidenceReport(
            covered_pages=self._covered_pages,
            copied_to_other_pages=copied,
            same_text_independent=same_text,
            missing_evidence=missing,
        )
