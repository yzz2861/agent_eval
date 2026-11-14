"""
Read-only enumeration and policy handling of active PDF content.

The scanner walks the parsed object graph of a :class:`PdfReader<pypdf.PdfReader>`
(or a :class:`PdfWriter<pypdf.PdfWriter>`) and reports active content such as
document/page/field trigger actions, JavaScript, launch and submit-form actions,
rich media and embedded files.

Design guarantees:

* No action is ever executed. The scanner only reads dictionaries and arrays.
* No network or external file access is triggered. URI, Launch and embedded
  file targets are reported as data, never resolved.
* All traversal is bounded by an :class:`AuditBudget`, protecting against
  corrupt dictionaries, recursive action chains, repeated objects and very
  large script strings.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import Enum, unique
from typing import TYPE_CHECKING, Any

from .._utils import logger_warning
from ..errors import ActiveContentError, AuditBudgetExceededError
from ..generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NullObject,
    StreamObject,
)

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:

    class StrEnum(str, Enum):
        def __str__(self) -> str:
            return str(self.value)


if TYPE_CHECKING:
    from collections.abc import Iterator

    from .._doc_common import PdfDocCommon

PdfObjectType = Any


# Action subtypes (the /S entry of an action dictionary) that are considered
# active content. Navigation actions such as /GoTo and /URI are intentionally
# excluded so that ordinary links do not get reported.
ACTIVE_ACTION_TYPES: frozenset[str] = frozenset(
    {
        "JavaScript",
        "Launch",
        "SubmitForm",
        "ImportData",
        "ResetForm",
        "RichMediaExecute",
        "Sound",
        "Movie",
        "Rendition",
        "Thread",
        "Trans",
        "Hide",
        "SetOCGState",
        "GoTo3DView",
    }
)

# Trigger event keys allowed in the catalog /AA dictionary (PDF 2.0 table 45).
CATALOG_AA_TRIGGERS: frozenset[str] = frozenset({"/WC", "/WS", "/DS", "/WP", "/DP"})

# Trigger event keys allowed in a page /AA dictionary (table 191).
PAGE_AA_TRIGGERS: frozenset[str] = frozenset({"/O", "/C"})

# Trigger event keys allowed in a form field /AA dictionary (table 8.71).
FIELD_AA_TRIGGERS: frozenset[str] = frozenset({"/K", "/F", "/V", "/C", "/E", "/X", "/D", "/U", "/Fo", "/Bl"})

# Trigger event keys allowed on an annotation dictionary.
ANNOTATION_AA_TRIGGERS: frozenset[str] = frozenset({"/E", "/X", "/D", "/U", "/Fo", "/Bl"})

# Additional action keys defined directly on annotations.
ANNOTATION_ACTION_KEYS: frozenset[str] = frozenset({"/A", "/PA", "/PC"})

_ASSOCIATED_FILES_KEY = "/AF"


@unique
class ActiveContentKind(StrEnum):
    """High-level category of a reported active-content entry."""

    OPEN_ACTION = "open_action"
    ADDITIONAL_ACTION = "additional_action"
    JAVASCRIPT = "javascript"
    LAUNCH = "launch"
    SUBMIT_FORM = "submit_form"
    RICH_MEDIA = "rich_media"
    EMBEDDED_FILE = "embedded_file"
    FIELD_ACTION = "field_action"
    OTHER_ACTION = "other_action"


@unique
class ActiveContentLocation(StrEnum):
    """Where an active-content entry was found."""

    CATALOG_OPEN_ACTION = "catalog/open_action"
    CATALOG_AA = "catalog/aa"
    PAGE_AA = "page/aa"
    ANNOTATION_ACTION = "annotation/action"
    ANNOTATION_AA = "annotation/aa"
    FIELD_AA = "field/aa"
    NAME_TREE_JAVASCRIPT = "name_tree/javascript"
    NAME_TREE_EMBEDDED_FILE = "name_tree/embedded_file"
    ASSOCIATED_FILE = "associated_file"
    RICH_MEDIA_ANNOTATION = "annotation/rich_media"


@unique
class ActiveContentPolicy(StrEnum):
    """What the scanner should do when it encounters active content."""

    REPORT = "report"
    """Only report the detected entries; the document is left untouched."""
    REJECT = "reject"
    """Raise :class:`ActiveContentError` as soon as active content is found."""
    PURGE = "purge"
    """Remove the detected active content from the mutable document object."""


@dataclass(frozen=True)
class AuditBudget:
    """
    Bounds for an active-content audit.

    Every limit protects against a specific denial-of-service shape: object
    and depth limits stop recursive action chains and corrupt dictionaries,
    the visited limit stops repeated objects from being re-walked, and the
    script limits cap how much of a (potentially huge) script string is read
    and reported.
    """

    max_objects: int = 200_000
    """Maximum number of dictionaries/arrays resolved during the whole audit."""
    max_depth: int = 256
    """Maximum nesting depth while following references and action chains."""
    max_visited: int = 200_000
    """Maximum number of distinct indirect objects kept in the cycle guard."""
    max_entries: int = 10_000
    """Maximum number of active-content entries reported."""
    max_script_length: int = 10_000
    """Maximum number of script characters read into a preview."""
    max_script_bytes: int = 50_000
    """Maximum number of script bytes decoded for a preview."""


@dataclass(frozen=True)
class ActiveContentEntry:
    """
    A single piece of active content found in a document.

    All attributes use plain, JSON-serialisable types so that the report can
    be handed straight to a logging or serialisation layer.
    """

    kind: str
    """One of :class:`ActiveContentKind` (the value is a plain string)."""
    location: str
    """One of :class:`ActiveContentLocation` (the value is a plain string)."""
    action_type: str | None
    """Action subtype name without the leading slash, e.g. ``JavaScript``."""
    trigger: str | None
    """Trigger key that fires the entry, e.g. ``/O`` or ``/K``."""
    object_number: int | None
    """Indirect object number of the entry itself, or ``None`` if direct."""
    generation: int
    """Generation number paired with :attr:`object_number`."""
    page_number: int | None
    """Zero-based page number when the entry belongs to a page."""
    field_name: str | None
    """Fully qualified form field name when the entry belongs to a field."""
    reference_chain: tuple[str, ...]
    """Human-readable path from the document catalog to the entry."""
    script_preview: str | None = None
    """Bounded preview of a JavaScript script; ``None`` for other entries."""
    script_truncated: bool = False
    """Whether :attr:`script_preview` was cut off by the script budget."""
    script_length: int = 0
    """Total length of the script in characters before truncation."""
    target: str | None = None
    """Declared Launch/SubmitForm target, reported without resolving it."""

    def to_dict(self) -> dict[str, Any]:
        """Return a stable, JSON-serialisable representation of the entry."""
        return {
            "kind": str(self.kind),
            "location": str(self.location),
            "action_type": self.action_type,
            "trigger": self.trigger,
            "object_number": self.object_number,
            "generation": self.generation,
            "page_number": self.page_number,
            "field_name": self.field_name,
            "reference_chain": list(self.reference_chain),
            "script_preview": self.script_preview,
            "script_truncated": self.script_truncated,
            "script_length": self.script_length,
            "target": self.target,
        }


@dataclass
class ActiveContentReport:
    """Result of an active-content audit."""

    policy: str
    entries: list[ActiveContentEntry] = field(default_factory=list)
    purged: bool = False
    duplicates_seen: int = 0
    malformed_seen: int = 0
    truncated_scripts: int = 0

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[ActiveContentEntry]:
        return iter(self.entries)

    @property
    def has_active_content(self) -> bool:
        """Whether at least one active-content entry was detected."""
        return bool(self.entries)

    @property
    def kinds(self) -> tuple[str, ...]:
        """Sorted tuple of the distinct entry kinds in this report."""
        return tuple(sorted({str(entry.kind) for entry in self.entries}))

    def to_dict(self) -> dict[str, Any]:
        """Return a stable, JSON-serialisable representation of the report."""
        return {
            "policy": str(self.policy),
            "has_active_content": self.has_active_content,
            "purged": self.purged,
            "duplicates_seen": self.duplicates_seen,
            "malformed_seen": self.malformed_seen,
            "truncated_scripts": self.truncated_scripts,
            "entries": [entry.to_dict() for entry in self.entries],
        }


def _ref_key(obj: PdfObjectType) -> tuple[str, int, int] | None:
    """Stable identity key for a (possibly indirect) PDF object."""
    reference = getattr(obj, "indirect_reference", None)
    if isinstance(reference, IndirectObject):
        return ("indirect", reference.idnum, reference.generation)
    return None


def _object_number(obj: Any) -> tuple[int | None, int]:
    reference = getattr(obj, "indirect_reference", None)
    if isinstance(reference, IndirectObject):
        return reference.idnum, reference.generation
    return None, 0


def _safe_get_object(value: Any) -> Any:
    """Resolve an indirect reference without raising on malformed input."""
    if value is None or not hasattr(value, "get_object"):
        return value
    try:
        return value.get_object()
    except Exception as exc:
        logger_warning(
            "Active content audit could not resolve an object: %(error)s",
            source=__name__,
            error=exc,
        )
        return None


def _action_subtype(action: DictionaryObject) -> str | None:
    subtype = action.get("/S")
    if subtype is None:
        return None
    return str(subtype).lstrip("/") or None


def _kind_for_action(subtype: str | None) -> str:
    if subtype == "JavaScript":
        return ActiveContentKind.JAVASCRIPT
    if subtype == "Launch":
        return ActiveContentKind.LAUNCH
    if subtype == "SubmitForm":
        return ActiveContentKind.SUBMIT_FORM
    if subtype in {"RichMediaExecute", "Rendition", "Movie", "Sound", "GoTo3DView"}:
        return ActiveContentKind.RICH_MEDIA
    return ActiveContentKind.OTHER_ACTION


class ActiveContentScanner:
    """
    Read-only scanner for active PDF content.

    Args:
        pdf: A :class:`PdfReader<pypdf.PdfReader>` or
            :class:`PdfWriter<pypdf.PdfWriter>` to audit.
        policy: Whether to only report, reject or purge active content.
        budget: Explicit traversal budgets. Defaults are sufficient for
            ordinary documents and keep malformed files bounded.

    The scanner performs no I/O beyond the objects that pypdf already parsed;
    it never executes JavaScript, never launches a program and never performs
    a network request.
    """

    def __init__(
        self,
        pdf: PdfDocCommon,
        *,
        policy: ActiveContentPolicy | str = ActiveContentPolicy.REPORT,
        budget: AuditBudget | None = None,
    ) -> None:
        self._pdf = pdf
        self._policy = ActiveContentPolicy(str(policy))
        self._budget = budget if budget is not None else AuditBudget()
        self._report = ActiveContentReport(policy=str(self._policy))
        self._visited: set[tuple[str, int, int]] = set()
        # Traversal guard scoped to a single root walk. Unlike the global
        # visited statistics, it does not suppress an object reached through
        # another trigger (e.g. the same action on /O and /C).
        self._walk_visited: set[tuple[str, int, int]] | None = None
        self._seen_entries: set[tuple[str, ...]] = set()
        self._reported_objects: dict[tuple[str, int, int], int] = {}
        self._objects_seen = 0
        # Roots scheduled for removal when the policy is PURGE. Each item is
        # the mutable container dictionary plus the key to delete.
        self._purge_targets: list[tuple[DictionaryObject, str]] = []
        self._aa_owners: dict[int, DictionaryObject] = {}
        self._field_pages: dict[int, int | None] = {}

    # -- Public API -------------------------------------------------------

    def scan(self) -> ActiveContentReport:
        """
        Enumerate the active content of the document.

        Returns:
            An :class:`ActiveContentReport`. With the ``REJECT`` policy an
            :class:`ActiveContentError` is raised instead when active content
            exists; with ``PURGE`` the document is mutated and the returned
            report describes what was removed.
        """
        catalog = self._resolve_catalog()
        if catalog is not None:
            self._scan_catalog(catalog)
            self._scan_pages()
            self._scan_form_fields(catalog)

        if self._policy is ActiveContentPolicy.REJECT and self._report.has_active_content:
            raise ActiveContentError(
                "Active content was detected and the active policy is 'reject'.",
                report=self._report,
            )

        if self._policy is ActiveContentPolicy.PURGE and self._report.has_active_content:
            self._purge()
            self._report.purged = True

        return self._report

    # -- Budget / traversal plumbing -------------------------------------

    def _resolve_catalog(self) -> DictionaryObject | None:
        try:
            catalog = self._pdf.root_object
        except Exception as exc:
            logger_warning(
                "Active content audit could not read the catalog: %(error)s",
                source=__name__,
                error=exc,
            )
            self._report.malformed_seen += 1
            return None
        catalog = _safe_get_object(catalog)
        if not isinstance(catalog, DictionaryObject):
            self._report.malformed_seen += 1
            return None
        return catalog

    def _enter_object(self, obj: Any, depth: int) -> bool:
        """Register an object against the budgets and cycle guard."""
        if depth > self._budget.max_depth:
            raise AuditBudgetExceededError(
                f"Active content audit exceeded the maximum nesting depth of {self._budget.max_depth}."
            )
        self._objects_seen += 1
        if self._objects_seen > self._budget.max_objects:
            raise AuditBudgetExceededError(
                f"Active content audit exceeded the object budget of {self._budget.max_objects}."
            )
        key = _ref_key(obj)
        if key is not None:
            guard = self._walk_visited if self._walk_visited is not None else self._visited
            if key in guard:
                self._report.duplicates_seen += 1
                return False
            if len(self._visited) >= self._budget.max_visited:
                raise AuditBudgetExceededError(
                    f"Active content audit exceeded the visited-object budget of {self._budget.max_visited}."
                )
            guard.add(key)
            self._visited.add(key)
        return True

    def _record(self, entry: ActiveContentEntry) -> bool:
        """Add an entry unless an identical one was already reported."""
        dedup_key = (
            str(entry.kind),
            str(entry.location),
            entry.trigger or "",
            str(entry.object_number),
            entry.field_name or "",
            entry.reference_chain[-1] if entry.reference_chain else "",
        )
        if dedup_key in self._seen_entries:
            self._report.duplicates_seen += 1
            return False
        self._seen_entries.add(dedup_key)
        if entry.object_number is not None:
            object_key = ("indirect", entry.object_number, entry.generation)
            if object_key in self._reported_objects:
                self._report.duplicates_seen += 1
            self._reported_objects[object_key] = self._reported_objects.get(object_key, 0) + 1
        if len(self._report.entries) >= self._budget.max_entries:
            raise AuditBudgetExceededError(
                f"Active content audit exceeded the entry budget of {self._budget.max_entries}."
            )
        self._report.entries.append(entry)
        return True

    # -- Catalog level ----------------------------------------------------

    def _scan_catalog(self, catalog: DictionaryObject) -> None:
        # /OpenAction may either be an action dictionary or a destination
        # array (plain navigation). Only the dictionary form is active.
        open_action = _safe_get_object(catalog.get("/OpenAction"))
        if isinstance(open_action, DictionaryObject):
            self._walk_action_container(
                open_action,
                location=ActiveContentLocation.CATALOG_OPEN_ACTION,
                chain=("/Catalog", "/OpenAction"),
                trigger=None,
                page_number=None,
                field_name=None,
                root_container=catalog,
                root_key="/OpenAction",
                default_kind=ActiveContentKind.OPEN_ACTION,
                force_purge_root=True,
            )
        elif open_action is not None and not isinstance(open_action, NullObject):
            # An array OpenAction is a simple destination, not active content.
            pass

        self._scan_additional_actions(
            catalog,
            allowed=CATALOG_AA_TRIGGERS,
            location=ActiveContentLocation.CATALOG_AA,
            chain=("/Catalog", "/AA"),
            page_number=None,
            field_name=None,
        )

        names = _safe_get_object(catalog.get("/Names"))
        if isinstance(names, DictionaryObject):
            self._scan_javascript_name_tree(names)
            self._scan_embedded_file_name_tree(names)

        self._scan_associated_files(catalog, chain=("/Catalog", "/AF"))

    def _scan_javascript_name_tree(self, names: DictionaryObject) -> None:
        container = _safe_get_object(names.get("/JavaScript"))
        if not isinstance(container, DictionaryObject):
            if container is not None and not isinstance(container, NullObject):
                self._report.malformed_seen += 1
            return
        for leaf_path, value in self._iter_name_tree(container, chain=("/Catalog", "/Names", "/JavaScript")):
            action = _safe_get_object(value)
            if not isinstance(action, DictionaryObject):
                if action is not None and not isinstance(action, NullObject):
                    self._report.malformed_seen += 1
                continue
            self._walk_action_container(
                action,
                location=ActiveContentLocation.NAME_TREE_JAVASCRIPT,
                chain=(*leaf_path, "[value]"),
                trigger=None,
                page_number=None,
                field_name=None,
                root_container=None,
                root_key=None,
                default_kind=ActiveContentKind.JAVASCRIPT,
                force_purge_root=True,
            )

    def _iter_name_tree(self, node: DictionaryObject, *, chain: tuple[str, ...]) -> list[tuple[tuple[str, ...], Any]]:
        """Flatten a PDF name tree with a cycle guard and depth budget."""
        results: list[tuple[tuple[str, ...], Any]] = []
        stack: list[tuple[DictionaryObject, tuple[str, ...], int]] = [(node, chain, 0)]
        while stack:
            current, current_chain, depth = stack.pop()
            if depth > self._budget.max_depth:
                raise AuditBudgetExceededError(
                    f"Active content audit exceeded the maximum name tree depth of {self._budget.max_depth}."
                )
            if not self._enter_object(current, depth):
                continue
            if not isinstance(current, DictionaryObject):
                self._report.malformed_seen += 1
                continue
            leaf_names = _safe_get_object(current.get("/Names"))
            if isinstance(leaf_names, ArrayObject):
                results.extend(
                    (
                        (*current_chain, "/Names", f"[{index}]"),
                        leaf_names[index],
                    )
                    for index in range(1, len(leaf_names), 2)
                )
            elif leaf_names is not None and not isinstance(leaf_names, NullObject):
                self._report.malformed_seen += 1
            kids = _safe_get_object(current.get("/Kids"))
            if isinstance(kids, ArrayObject):
                for index, kid in enumerate(kids):
                    kid_obj = _safe_get_object(kid)
                    if isinstance(kid_obj, DictionaryObject):
                        stack.append((kid_obj, (*current_chain, "/Kids", f"[{index}]"), depth + 1))
                    elif kid_obj is not None and not isinstance(kid_obj, NullObject):
                        self._report.malformed_seen += 1
            elif kids is not None and not isinstance(kids, NullObject):
                self._report.malformed_seen += 1
        return results

    # -- Action dictionaries ---------------------------------------------

    def _scan_additional_actions(
        self,
        container: DictionaryObject,
        *,
        allowed: frozenset[str],
        location: ActiveContentLocation,
        chain: tuple[str, ...],
        page_number: int | None,
        field_name: str | None,
    ) -> None:
        aa = _safe_get_object(container.get("/AA"))
        if aa is None or isinstance(aa, NullObject):
            return
        if not isinstance(aa, DictionaryObject):
            self._report.malformed_seen += 1
            return
        if not self._enter_object(aa, len(chain)):
            return
        for trigger, value in aa.items():
            trigger_name = str(trigger)
            if trigger_name not in allowed:
                continue
            action_root = _safe_get_object(value)
            if isinstance(action_root, NullObject) or action_root is None:
                continue
            if not isinstance(action_root, DictionaryObject):
                if isinstance(value, ArrayObject):
                    # A trigger may hold an array of actions.
                    if any(
                        _action_subtype(candidate) in ACTIVE_ACTION_TYPES
                        for candidate in (_safe_get_object(item) for item in value)
                        if isinstance(candidate, DictionaryObject)
                    ):
                        self._register_aa_owner(container)
                    self._walk_action_array(
                        value,
                        location=location,
                        chain=(*chain, trigger_name),
                        trigger=trigger_name,
                        page_number=page_number,
                        field_name=field_name,
                        root_container=aa,
                        root_key=trigger_name,
                        default_kind=ActiveContentKind.ADDITIONAL_ACTION,
                        report_inactive=False,
                    )
                else:
                    self._report.malformed_seen += 1
                continue
            if _action_subtype(action_root) in ACTIVE_ACTION_TYPES:
                self._register_aa_owner(container)
            self._walk_action_container(
                action_root,
                location=location,
                chain=(*chain, trigger_name),
                trigger=trigger_name,
                page_number=page_number,
                field_name=field_name,
                root_container=aa,
                root_key=trigger_name,
                default_kind=ActiveContentKind.ADDITIONAL_ACTION,
                report_inactive=False,
            )

    def _walk_action_array(
        self,
        array: ArrayObject,
        *,
        location: ActiveContentLocation,
        chain: tuple[str, ...],
        trigger: str | None,
        page_number: int | None,
        field_name: str | None,
        root_container: DictionaryObject | None,
        root_key: str | None,
        default_kind: str,
        force_purge_root: bool = False,
        report_inactive: bool = True,
    ) -> None:
        for index, item in enumerate(array):
            action = _safe_get_object(item)
            if isinstance(action, DictionaryObject):
                self._walk_action_container(
                    action,
                    location=location,
                    chain=(*chain, f"[{index}]"),
                    trigger=trigger,
                    page_number=page_number,
                    field_name=field_name,
                    root_container=root_container,
                    root_key=root_key,
                    default_kind=default_kind,
                    force_purge_root=force_purge_root,
                    report_inactive=report_inactive,
                )
            elif action is not None and not isinstance(action, NullObject):
                self._report.malformed_seen += 1

    # -- Form fields ------------------------------------------------------

    def _scan_form_fields(self, catalog: DictionaryObject) -> None:
        acroform = _safe_get_object(catalog.get("/AcroForm"))
        if acroform is None or isinstance(acroform, NullObject):
            return
        if not isinstance(acroform, DictionaryObject):
            self._report.malformed_seen += 1
            return
        fields = _safe_get_object(acroform.get("/Fields"))
        if fields is None or isinstance(fields, NullObject):
            return
        if not isinstance(fields, ArrayObject):
            self._report.malformed_seen += 1
            return
        for index, field_ref in enumerate(fields):
            field = _safe_get_object(field_ref)
            if isinstance(field, DictionaryObject):
                self._walk_field(
                    field,
                    parent_name=None,
                    chain=("/Catalog", "/AcroForm", "/Fields", f"[{index}]"),
                    depth=1,
                )
            elif field is not None and not isinstance(field, NullObject):
                self._report.malformed_seen += 1

    def _walk_field(
        self,
        field: DictionaryObject,
        *,
        parent_name: str | None,
        chain: tuple[str, ...],
        depth: int,
    ) -> None:
        if depth > self._budget.max_depth:
            raise AuditBudgetExceededError(
                f"Active content audit exceeded the maximum field depth of {self._budget.max_depth}."
            )
        if not self._enter_object(field, depth):
            return
        name_part = self._stringify(field.get("/T"))
        full_name = f"{parent_name}.{name_part}" if parent_name and name_part else (name_part or parent_name)
        page_number = self._field_page_number(field)
        # Fields may carry a plain /A action in addition to trigger events.
        field_action = _safe_get_object(field.get("/A"))
        if isinstance(field_action, DictionaryObject):
            subtype = _action_subtype(field_action)
            if subtype in ACTIVE_ACTION_TYPES:
                self._walk_action_container(
                    field_action,
                    location=ActiveContentLocation.FIELD_AA,
                    chain=(*chain, "/A"),
                    trigger="/A",
                    page_number=page_number,
                    field_name=full_name,
                    root_container=field,
                    root_key="/A",
                    default_kind=ActiveContentKind.FIELD_ACTION,
                    report_inactive=False,
                )
        elif isinstance(field_action, ArrayObject):
            self._walk_action_array(
                field_action,
                location=ActiveContentLocation.FIELD_AA,
                chain=(*chain, "/A"),
                trigger="/A",
                page_number=page_number,
                field_name=full_name,
                root_container=field,
                root_key="/A",
                default_kind=ActiveContentKind.FIELD_ACTION,
                report_inactive=False,
            )
        elif field_action is not None and not isinstance(field_action, NullObject):
            self._report.malformed_seen += 1
        self._scan_additional_actions(
            field,
            allowed=FIELD_AA_TRIGGERS,
            location=ActiveContentLocation.FIELD_AA,
            chain=(*chain, "/AA"),
            page_number=page_number,
            field_name=full_name,
        )
        kids = _safe_get_object(field.get("/Kids"))
        if isinstance(kids, ArrayObject):
            for index, kid_ref in enumerate(kids):
                kid = _safe_get_object(kid_ref)
                if isinstance(kid, DictionaryObject):
                    self._walk_field(
                        kid,
                        parent_name=full_name,
                        chain=(*chain, "/Kids", f"[{index}]"),
                        depth=depth + 1,
                    )
                elif kid is not None and not isinstance(kid, NullObject):
                    self._report.malformed_seen += 1
        elif kids is not None and not isinstance(kids, NullObject):
            self._report.malformed_seen += 1

    def _field_page_number(self, field: DictionaryObject) -> int | None:
        reference = field.indirect_reference
        if reference is None:
            return None
        key = (reference.idnum, reference.generation)
        if key in self._field_pages:
            return self._field_pages[key]
        try:
            page_number = self._pdf._get_page_number_by_indirect(reference)
        except Exception:
            page_number = None
        if page_number is None:
            # Widget annotations reference their page through /P.
            page_ref = _safe_get_object(field.get("/P"))
            if isinstance(page_ref, DictionaryObject) and page_ref.indirect_reference is not None:
                try:
                    page_number = self._pdf._get_page_number_by_indirect(page_ref.indirect_reference)
                except Exception:
                    page_number = None
        self._field_pages[key] = page_number
        return page_number

    # -- Embedded files ---------------------------------------------------

    def _scan_embedded_file_name_tree(self, names: DictionaryObject) -> None:
        container = _safe_get_object(names.get("/EmbeddedFiles"))
        if not isinstance(container, DictionaryObject):
            if container is not None and not isinstance(container, NullObject):
                self._report.malformed_seen += 1
            return
        for leaf_path, value in self._iter_name_tree(container, chain=("/Catalog", "/Names", "/EmbeddedFiles")):
            spec = _safe_get_object(value)
            if not isinstance(spec, DictionaryObject):
                if spec is not None and not isinstance(spec, NullObject):
                    self._report.malformed_seen += 1
                continue
            self._record_embedded_file(
                spec,
                location=ActiveContentLocation.NAME_TREE_EMBEDDED_FILE,
                chain=(*leaf_path, "[value]"),
                page_number=None,
            )

    def _scan_associated_files(
        self,
        container: DictionaryObject,
        *,
        chain: tuple[str, ...],
        page_number: int | None = None,
    ) -> None:
        files = _safe_get_object(container.get(_ASSOCIATED_FILES_KEY))
        if not isinstance(files, ArrayObject):
            if files is not None and not isinstance(files, NullObject):
                self._report.malformed_seen += 1
            return
        for index, file_ref in enumerate(files):
            spec = _safe_get_object(file_ref)
            if isinstance(spec, DictionaryObject):
                self._record_embedded_file(
                    spec,
                    location=ActiveContentLocation.ASSOCIATED_FILE,
                    chain=(*chain, f"[{index}]"),
                    page_number=page_number,
                )
            elif spec is not None and not isinstance(spec, NullObject):
                self._report.malformed_seen += 1

    def _record_embedded_file(
        self,
        spec: DictionaryObject,
        *,
        location: ActiveContentLocation,
        chain: tuple[str, ...],
        page_number: int | None,
    ) -> None:
        has_stream = self._has_embedded_stream(spec)
        if not has_stream:
            return
        object_number, generation = _object_number(spec)
        self._record(
            ActiveContentEntry(
                kind=ActiveContentKind.EMBEDDED_FILE,
                location=str(location),
                action_type=None,
                trigger=None,
                object_number=object_number,
                generation=generation,
                page_number=page_number,
                field_name=None,
                reference_chain=chain,
                target=self._stringify(spec.get("/F")) or self._stringify(spec.get("/UF")),
            )
        )

    def _has_embedded_stream(self, spec: DictionaryObject) -> bool:
        embedded = _safe_get_object(spec.get("/EF"))
        if isinstance(embedded, DictionaryObject):
            for key in ("/F", "/UF", "/DOS", "/Mac", "/Unix"):
                stream = _safe_get_object(embedded.get(key))
                if isinstance(stream, StreamObject):
                    return True
        # Associated files may reference the stream directly through /F.
        return isinstance(_safe_get_object(spec.get("/F")), StreamObject)

    # -- Purge policy -----------------------------------------------------

    def _schedule_purge(self, container: DictionaryObject, key: str) -> None:
        if self._policy is ActiveContentPolicy.PURGE:
            self._purge_targets.append((container, key))

    def _register_aa_owner(self, owner: DictionaryObject) -> None:
        self._aa_owners.setdefault(id(owner), owner)

    def _purge(self) -> None:
        # Remove trigger/action roots collected while walking action graphs.
        for container, key in self._purge_targets:
            try:
                if key in container:
                    del container[NameObject(key)]
            except Exception as exc:
                logger_warning(
                    "Active content purge failed for %(key)s: %(error)s",
                    source=__name__,
                    key=key,
                    error=exc,
                )
                self._report.malformed_seen += 1

        # Empty /AA containers are inert but confusing to leave behind.
        for aa_container in self._aa_owners.values():
            aa_dict = aa_container.get("/AA")
            if isinstance(aa_dict, DictionaryObject) and not aa_dict:
                try:
                    del aa_container[NameObject("/AA")]
                except Exception:
                    pass

        catalog = self._resolve_catalog()
        if catalog is not None:
            self._purge_catalog(catalog)
            self._purge_pages()

    def _purge_catalog(self, catalog: DictionaryObject) -> None:
        # The JavaScript name tree only exists to hold document-level scripts.
        names = _safe_get_object(catalog.get("/Names"))
        if isinstance(names, DictionaryObject):
            if "/JavaScript" in names:
                del names[NameObject("/JavaScript")]
            if "/EmbeddedFiles" in names:
                del names[NameObject("/EmbeddedFiles")]
            if not names:
                del catalog[NameObject("/Names")]
        if "/AF" in catalog:
            del catalog[NameObject("/AF")]

    def _purge_pages(self) -> None:
        try:
            pages = list(self._pdf.pages)
        except Exception:
            return
        for page in pages:
            if not isinstance(page, DictionaryObject):
                continue
            if "/AF" in page:
                del page[NameObject("/AF")]
            annotations = _safe_get_object(page.get("/Annots"))
            if not isinstance(annotations, ArrayObject):
                continue
            survivors = ArrayObject()
            changed = False
            for annotation_ref in annotations:
                annotation = _safe_get_object(annotation_ref)
                if isinstance(annotation, DictionaryObject) and str(annotation.get("/Subtype", "")) == "/RichMedia":
                    changed = True
                    continue
                survivors.append(annotation_ref)
            if changed:
                page[NameObject("/Annots")] = survivors

    def _walk_action_container(
        self,
        action: DictionaryObject,
        *,
        location: ActiveContentLocation,
        chain: tuple[str, ...],
        trigger: str | None,
        page_number: int | None,
        field_name: str | None,
        root_container: DictionaryObject | None,
        root_key: str | None,
        default_kind: str,
        force_purge_root: bool = False,
        report_inactive: bool = True,
    ) -> None:
        """Walk an action dictionary and every reachable /Next action."""
        previous_guard = self._walk_visited
        self._walk_visited = set()
        stack: list[tuple[DictionaryObject, tuple[str, ...], int]] = [(action, chain, len(chain))]
        try:
            while stack:
                current, current_chain, depth = stack.pop()
                if depth > self._budget.max_depth:
                    raise AuditBudgetExceededError(
                        f"Active content audit exceeded the maximum action chain depth of {self._budget.max_depth}."
                    )
                if not self._enter_object(current, depth):
                    continue
                if not isinstance(current, DictionaryObject):
                    self._report.malformed_seen += 1
                    continue
                subtype = _action_subtype(current)
                if not report_inactive and subtype not in ACTIVE_ACTION_TYPES:
                    # Navigation actions reached from a trigger/annotation are
                    # ordinary behaviour and must not be reported or purged.
                    next_value = _safe_get_object(current.get("/Next"))
                    if isinstance(next_value, DictionaryObject):
                        stack.append((next_value, (*current_chain, "/Next"), depth + 1))
                    elif isinstance(next_value, ArrayObject):
                        for index in range(len(next_value) - 1, -1, -1):
                            item = _safe_get_object(next_value[index])
                            if isinstance(item, DictionaryObject):
                                stack.append(
                                    (
                                        item,
                                        (*current_chain, "/Next", f"[{index}]"),
                                        depth + 1,
                                    )
                                )
                    continue
                self._report_action(
                    current,
                    subtype=subtype,
                    location=location,
                    chain=current_chain,
                    trigger=trigger,
                    page_number=page_number,
                    field_name=field_name,
                    default_kind=default_kind,
                )
                if (
                    root_container is not None
                    and root_key is not None
                    and (force_purge_root or subtype in ACTIVE_ACTION_TYPES)
                ):
                    # Only the first action of a trigger is the removable root;
                    # /Next entries live inside the action graph itself.
                    self._schedule_purge(root_container, root_key)
                    root_container = None
                next_value = _safe_get_object(current.get("/Next"))
                if isinstance(next_value, DictionaryObject):
                    stack.append((next_value, (*current_chain, "/Next"), depth + 1))
                elif isinstance(next_value, ArrayObject):
                    for index in range(len(next_value) - 1, -1, -1):
                        item = _safe_get_object(next_value[index])
                        if isinstance(item, DictionaryObject):
                            stack.append(
                                (
                                    item,
                                    (*current_chain, "/Next", f"[{index}]"),
                                    depth + 1,
                                )
                            )
                        elif item is not None and not isinstance(item, NullObject):
                            self._report.malformed_seen += 1
                elif next_value is not None and not isinstance(next_value, NullObject):
                    self._report.malformed_seen += 1
        finally:
            self._walk_visited = previous_guard

    def _report_action(
        self,
        action: DictionaryObject,
        *,
        subtype: str | None,
        location: ActiveContentLocation,
        chain: tuple[str, ...],
        trigger: str | None,
        page_number: int | None,
        field_name: str | None,
        default_kind: str,
    ) -> None:
        is_active = subtype in ACTIVE_ACTION_TYPES
        kind = _kind_for_action(subtype) if is_active else default_kind
        object_number, generation = _object_number(action)
        script_preview = None
        script_truncated = False
        script_length = 0
        target = None
        if subtype == "JavaScript":
            script_preview, script_truncated, script_length = self._read_script(action)
        elif subtype in {"Launch", "SubmitForm", "ImportData"}:
            target = self._read_action_target(action, subtype)
        entry = ActiveContentEntry(
            kind=kind,
            location=str(location),
            action_type=subtype,
            trigger=trigger,
            object_number=object_number,
            generation=generation,
            page_number=page_number,
            field_name=field_name,
            reference_chain=chain,
            script_preview=script_preview,
            script_truncated=script_truncated,
            script_length=script_length,
            target=target,
        )
        if self._record(entry) and script_truncated:
            self._report.truncated_scripts += 1

    def _read_script(self, action: DictionaryObject) -> tuple[str | None, bool, int]:
        raw = _safe_get_object(action.get("/JS"))
        if raw is None:
            return None, False, 0
        if isinstance(raw, StreamObject):
            # Never decode a whole stream: read only the bounded raw byte prefix.
            data = raw.get_data() if hasattr(raw, "get_data") else b""
            if isinstance(data, str):
                data = data.encode("utf-8", errors="replace")
            data = data[: self._budget.max_script_bytes]
            text = data.decode("utf-8", errors="replace")
            return self._truncate_script(text, True)
        text = str(raw)
        return self._truncate_script(text, len(text) > self._budget.max_script_length)

    def _truncate_script(self, text: str, already_truncated: bool) -> tuple[str, bool, int]:
        total_length = len(text)
        if total_length > self._budget.max_script_length:
            return text[: self._budget.max_script_length], True, total_length
        return text, already_truncated, total_length

    def _read_action_target(self, action: DictionaryObject, subtype: str) -> str | None:
        # The target is reported as inert data; it is never opened or resolved.
        if subtype == "Launch":
            spec = _safe_get_object(action.get("/F")) or action.get("/Win") or action.get("/Unix") or action.get("/Mac")
            if isinstance(spec, DictionaryObject):
                return self._stringify(spec.get("/F"))
            return self._stringify(spec)
        if subtype in {"SubmitForm", "ImportData"}:
            urls = _safe_get_object(action.get("/F"))
            if isinstance(urls, ArrayObject):
                parts = [self._stringify(item) for item in urls]
                return ";".join(part for part in parts if part)
            return self._stringify(urls)
        return None

    @staticmethod
    def _stringify(value: Any) -> str | None:
        value = _safe_get_object(value) if isinstance(value, IndirectObject) else value
        if value is None or isinstance(value, NullObject):
            return None
        return str(value)

    # -- Pages and annotations -------------------------------------------

    def _scan_pages(self) -> None:
        try:
            pages = list(self._pdf.pages)
        except Exception as exc:
            logger_warning(
                "Active content audit could not read the page tree: %(error)s",
                source=__name__,
                error=exc,
            )
            self._report.malformed_seen += 1
            return
        for page_number, page in enumerate(pages):
            if not isinstance(page, DictionaryObject):
                self._report.malformed_seen += 1
                continue
            page_chain = ("/Catalog", "/Pages", f"[{page_number}]")
            self._scan_additional_actions(
                page,
                allowed=PAGE_AA_TRIGGERS,
                location=ActiveContentLocation.PAGE_AA,
                chain=(*page_chain, "/AA"),
                page_number=page_number,
                field_name=None,
            )
            self._scan_associated_files(page, chain=(*page_chain, "/AF"), page_number=page_number)
            self._scan_annotations(page, page_number, page_chain)

    def _scan_annotations(self, page: DictionaryObject, page_number: int, page_chain: tuple[str, ...]) -> None:
        annotations = _safe_get_object(page.get("/Annots"))
        if annotations is None or isinstance(annotations, NullObject):
            return
        if not isinstance(annotations, ArrayObject):
            self._report.malformed_seen += 1
            return
        for index, annotation_ref in enumerate(annotations):
            annotation = _safe_get_object(annotation_ref)
            if not isinstance(annotation, DictionaryObject):
                if annotation is not None and not isinstance(annotation, NullObject):
                    self._report.malformed_seen += 1
                continue
            annot_chain = (*page_chain, "/Annots", f"[{index}]")
            self._scan_one_annotation(annotation, page_number, annot_chain)

    def _scan_one_annotation(
        self,
        annotation: DictionaryObject,
        page_number: int,
        annot_chain: tuple[str, ...],
    ) -> None:
        subtype = str(annotation.get("/Subtype", ""))
        if subtype == "/RichMedia":
            object_number, generation = _object_number(annotation)
            self._record(
                ActiveContentEntry(
                    kind=ActiveContentKind.RICH_MEDIA,
                    location=ActiveContentLocation.RICH_MEDIA_ANNOTATION,
                    action_type="RichMedia",
                    trigger=None,
                    object_number=object_number,
                    generation=generation,
                    page_number=page_number,
                    field_name=None,
                    reference_chain=annot_chain,
                )
            )
        # Explicit action dictionaries. A plain /Link with a /URI or /GoTo
        # action is ordinary navigation and must not be flagged.
        for key in ANNOTATION_ACTION_KEYS:
            value = _safe_get_object(annotation.get(key))
            if isinstance(value, DictionaryObject):
                self._scan_annotation_action(
                    value,
                    annotation=annotation,
                    action_key=key,
                    page_number=page_number,
                    chain=(*annot_chain, key),
                )
            elif isinstance(value, ArrayObject):
                for array_index, item in enumerate(value):
                    item_obj = _safe_get_object(item)
                    if isinstance(item_obj, DictionaryObject):
                        self._scan_annotation_action(
                            item_obj,
                            annotation=annotation,
                            action_key=key,
                            page_number=page_number,
                            chain=(*annot_chain, key, f"[{array_index}]"),
                        )
            elif value is not None and not isinstance(value, NullObject):
                self._report.malformed_seen += 1
        self._scan_annotation_aa(annotation, page_number, annot_chain)
        if subtype == "/FileAttachment":
            spec = _safe_get_object(annotation.get("/FS"))
            if isinstance(spec, DictionaryObject) and self._has_embedded_stream(spec):
                self._record_embedded_file(
                    spec,
                    location=ActiveContentLocation.ASSOCIATED_FILE,
                    chain=(*annot_chain, "/FS"),
                    page_number=page_number,
                )

    def _scan_annotation_action(
        self,
        action: DictionaryObject,
        *,
        annotation: DictionaryObject,
        action_key: str,
        page_number: int,
        chain: tuple[str, ...],
    ) -> None:
        subtype = _action_subtype(action)
        if subtype not in ACTIVE_ACTION_TYPES:
            # /GoTo, /URI and friends are ordinary link behaviour.
            return
        self._walk_action_container(
            action,
            location=ActiveContentLocation.ANNOTATION_ACTION,
            chain=chain,
            trigger=None,
            page_number=page_number,
            field_name=None,
            root_container=annotation,
            root_key=action_key,
            default_kind=ActiveContentKind.OTHER_ACTION,
        )

    def _scan_annotation_aa(
        self,
        annotation: DictionaryObject,
        page_number: int,
        annot_chain: tuple[str, ...],
    ) -> None:
        aa = _safe_get_object(annotation.get("/AA"))
        if not isinstance(aa, DictionaryObject):
            if aa is not None and not isinstance(aa, NullObject):
                self._report.malformed_seen += 1
            return
        if not self._enter_object(aa, len(annot_chain)):
            return
        for trigger, value in aa.items():
            trigger_name = str(trigger)
            if trigger_name not in ANNOTATION_AA_TRIGGERS:
                continue
            action = _safe_get_object(value)
            if isinstance(action, DictionaryObject):
                subtype = _action_subtype(action)
                if subtype not in ACTIVE_ACTION_TYPES:
                    continue
                self._register_aa_owner(annotation)
                self._walk_action_container(
                    action,
                    location=ActiveContentLocation.ANNOTATION_AA,
                    chain=(*annot_chain, "/AA", trigger_name),
                    trigger=trigger_name,
                    page_number=page_number,
                    field_name=None,
                    root_container=aa,
                    root_key=trigger_name,
                    default_kind=ActiveContentKind.OTHER_ACTION,
                )
            elif isinstance(value, ArrayObject):
                if any(
                    _action_subtype(candidate) in ACTIVE_ACTION_TYPES
                    for candidate in (_safe_get_object(item) for item in value)
                    if isinstance(candidate, DictionaryObject)
                ):
                    self._register_aa_owner(annotation)
                self._walk_action_array(
                    value,
                    location=ActiveContentLocation.ANNOTATION_AA,
                    chain=(*annot_chain, "/AA", trigger_name),
                    trigger=trigger_name,
                    page_number=page_number,
                    field_name=None,
                    root_container=aa,
                    root_key=trigger_name,
                    default_kind=ActiveContentKind.OTHER_ACTION,
                )
            elif action is not None and not isinstance(action, NullObject):
                self._report.malformed_seen += 1


def audit_active_content(
    pdf: PdfDocCommon,
    *,
    policy: ActiveContentPolicy | str = ActiveContentPolicy.REPORT,
    budget: AuditBudget | None = None,
) -> ActiveContentReport:
    """
    Audit a PDF document for active content.

    This is a thin convenience wrapper around :class:`ActiveContentScanner`.

    Args:
        pdf: The reader (or writer) to inspect.
        policy: ``report`` (default), ``reject`` or ``purge``.
        budget: Optional explicit :class:`AuditBudget`.

    Returns:
        The :class:`ActiveContentReport` produced by the scan.
    """
    return ActiveContentScanner(pdf, policy=policy, budget=budget).scan()
