# Copyright (c) 2006, Mathieu Fenniak
# Copyright (c) 2007, Ashish Kulkarni <kulkarni.ashish@gmail.com>
# Copyright (c) 2024, Pubpub-ZZ
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# * The name of the author may not be used to endorse or promote products
# derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import struct
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import (
    Any,
    NamedTuple,
    cast,
)

from ._configuration import get_configuration
from ._encryption import Encryption
from ._page import PageObject, _VirtualList
from ._page_labels import index2labels
from ._utils import (
    _TraversalState,
    deprecation_no_replacement,
    logger_warning,
    parse_iso8824_date,
)
from .constants import (
    AnnotationDictionaryAttributes as AA,
)
from .constants import CatalogAttributes as CA
from .constants import (
    CheckboxRadioButtonAttributes,
    Core,
    GoToActionArguments,
    PagesAttributes,
    UserAccessPermissions,
)
from .constants import DocumentInformationAttributes as DI
from .constants import FieldDictionaryAttributes as FA
from .constants import (
    InteractiveFormDictEntries as IF,
)
from .constants import PageAttributes as PG
from .errors import LimitReachedError, PdfReadError, PyPdfError
from .generic import (
    ArrayObject,
    BooleanObject,
    ByteStringObject,
    Destination,
    DictionaryObject,
    Field,
    Fit,
    FloatObject,
    IndirectObject,
    NameObject,
    NullObject,
    PdfObject,
    StreamObject,
    TextStringObject,
    TreeObject,
    ViewerPreferences,
    create_string_object,
    is_null_or_none,
)
from .generic._files import EmbeddedFile
from .types import OutlineType, PagemodeType
from .xmp import XmpInformation


def convert_to_int(d: bytes, size: int) -> int | tuple[Any, ...]:
    if size > 8:
        raise PdfReadError("Invalid size in convert_to_int")
    d = b"\x00\x00\x00\x00\x00\x00\x00\x00" + d
    d = d[-8:]
    return cast(int, struct.unpack(">Q", d)[0])


# Attributes a page inherits from its ancestors in the page tree.
_INHERITABLE_PAGE_ATTRIBUTES = (
    NameObject(PG.RESOURCES),
    NameObject(PG.MEDIABOX),
    NameObject(PG.CROPBOX),
    NameObject(PG.ROTATE),
)


class _PageTreeItem(NamedTuple):
    """A page tree node waiting to be flattened by :meth:`PdfDocCommon._flatten`."""

    node: DictionaryObject
    #: Inherited attributes. Shared read-only between the kids of one node.
    inherit: dict[str, Any]
    indirect_reference: IndirectObject | None
    depth: int


#: A ``/Pages`` node currently being walked: the node - carrying the attributes its
#: kids inherit - and the part of its ``/Kids`` which has not been reached yet.
_PageTreeFrame = tuple[_PageTreeItem, Iterator[PdfObject]]

_UNSET = object()


class _DisplayStateAccess:
    """Provide mapping-style access to the immutable display-state results."""

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def get(self, key: str, default: Any = None) -> Any:
        """Return a result entry or *default* when it does not exist."""
        return getattr(self, key, default)

    def keys(self) -> tuple[str, ...]:
        """Return the available result entry names."""
        return tuple(self.__dataclass_fields__)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class WidgetDisplayState(_DisplayStateAccess):
    """
    The structurally determinable display state of one widget annotation.

    A field can have several widgets, for example when the same checkbox is
    placed on multiple pages. Each widget is reported separately, because the
    PDF stores the visible state on the widget (``/AS``), not on the field.
    """

    page_number: int | None
    """Zero-based page number, or ``None`` when no page can be associated."""

    widget: IndirectObject | None
    """Indirect reference to the widget annotation, when available."""

    state: str | tuple[str, ...] | None
    """
    Button: the active ``/AS`` name (for example ``/Yes`` or ``/Off``).

    Choice: the display value(s) selected by ``/V`` and/or ``/I``.

    ``None`` when the display state cannot be established from the structure.
    """

    determined: bool
    """Whether :attr:`state` can be established without rendering the page."""

    reason: str | None = None
    """Why the display state could not be determined (or a structural warning)."""

    object_reference: IndirectObject | None = None
    """Reference to the object that supports or blocks the conclusion."""

    is_selected: bool | None = None
    """Button selection derived from ``/AS``; ``None`` for choice/unknown states."""

    selected_values: tuple[str, ...] = ()
    """Choice values selected by the widget's inherited field value."""

    selected_indices: tuple[int, ...] = ()
    """Choice indices selected by ``/I``."""

    source: str = "unknown"
    """``appearance_state``, ``field_value`` or ``unknown``."""

    appearance_present: bool | None = None
    """Whether an ``/AP`` normal appearance is present."""

    needs_appearance_regeneration: bool = False
    """Whether ``/NeedAppearances`` may make a reader regenerate the appearance."""

    page_confirmed: bool = True
    """Whether the widget was found in the page's ``/Annots`` array."""

    declared_page_number: int | None = None
    """Page from the widget's ``/P`` entry, if it differs from the observed page."""

    @property
    def page(self) -> int | None:
        """Alias for :attr:`page_number`."""
        return self.page_number

    @property
    def display_state(self) -> str | tuple[str, ...] | None:
        """Alias for :attr:`state`."""
        return self.state

    @property
    def widget_reference(self) -> IndirectObject | None:
        """Alias for :attr:`widget`."""
        return self.widget


@dataclass(frozen=True)
class FieldDisplayState(_DisplayStateAccess):
    """
    Read-only structural display information for one form field.

    The field value is reported exactly once on this object. Per-page visual
    states are reported in :attr:`widgets`, so repeated widgets do not duplicate
    the saved field value.
    """

    name: str
    """Qualified field name."""

    field_type: str | None
    """Inherited field type (``/Btn``, ``/Ch``, ...), if available."""

    value: Any | None
    """The field's inherited ``/V`` value, reported once."""

    widgets: tuple[WidgetDisplayState, ...]
    """Display state for each widget occurrence, in page order."""

    determined: bool
    """Whether the complete display state can be established structurally."""

    reason: str | None = None
    """Why the field-level display state could not be determined."""

    field_reference: IndirectObject | None = None
    """Indirect reference to the field dictionary, when available."""

    object_reference: IndirectObject | None = None
    """Reference supporting a field-level conclusion."""

    selected_values: tuple[str, ...] = ()
    """Choice values selected by the field's inherited value."""

    selected_indices: tuple[int, ...] = ()
    """Choice indices selected by the field's ``/I`` entry."""

    needs_appearance_regeneration: bool = False
    """Whether the document requests appearance regeneration."""

    @property
    def states(self) -> tuple[WidgetDisplayState, ...]:
        """Alias for :attr:`widgets`."""
        return self.widgets

    @property
    def display_states(self) -> tuple[WidgetDisplayState, ...]:
        """Alias for :attr:`widgets`."""
        return self.widgets

    @property
    def pages(self) -> tuple[int | None, ...]:
        """Page numbers covered by the widget states."""
        return tuple(state.page_number for state in self.widgets)

    @property
    def state(self) -> str | tuple[str, ...] | None:
        """The state of the only widget, or ``None`` for a multi-widget field."""
        return self.widgets[0].state if len(self.widgets) == 1 else None

    @property
    def page_number(self) -> int | None:
        """The page of the only widget occurrence, if there is exactly one."""
        return self.widgets[0].page_number if len(self.widgets) == 1 else None

    @property
    def widget(self) -> IndirectObject | None:
        """The widget reference when exactly one occurrence is selected."""
        return self.widgets[0].widget if len(self.widgets) == 1 else None


class DocumentInformation(DictionaryObject):
    """
    A class representing the basic document metadata provided in a PDF File.
    This class is accessible through
    :py:class:`PdfReader.metadata<pypdf.PdfReader.metadata>`.

    All text properties of the document metadata have
    *two* properties, e.g. author and author_raw. The non-raw property will
    always return a ``TextStringObject``, making it ideal for a case where the
    metadata is being displayed. The raw property can sometimes return a
    ``ByteStringObject``, if pypdf was unable to decode the string's text
    encoding; this requires additional safety in the caller and therefore is not
    as commonly accessed.
    """

    def __init__(self) -> None:
        DictionaryObject.__init__(self)

    def _get_text(self, key: str) -> str | None:
        retval = self.get(key, None)
        if isinstance(retval, TextStringObject):
            return retval
        if isinstance(retval, ByteStringObject):
            return str(retval)
        return None

    @property
    def title(self) -> str | None:
        """
        Read-only property accessing the document's title.

        Returns a ``TextStringObject`` or ``None`` if the title is not
        specified.
        """
        return (
            self._get_text(DI.TITLE) or self.get(DI.TITLE).get_object()  # type: ignore[union-attr]
            if self.get(DI.TITLE)
            else None
        )

    @property
    def title_raw(self) -> str | None:
        """The "raw" version of title; can return a ``ByteStringObject``."""
        return self.get(DI.TITLE)

    @property
    def author(self) -> str | None:
        """
        Read-only property accessing the document's author.

        Returns a ``TextStringObject`` or ``None`` if the author is not
        specified.
        """
        return self._get_text(DI.AUTHOR)

    @property
    def author_raw(self) -> str | None:
        """The "raw" version of author; can return a ``ByteStringObject``."""
        return self.get(DI.AUTHOR)

    @property
    def subject(self) -> str | None:
        """
        Read-only property accessing the document's subject.

        Returns a ``TextStringObject`` or ``None`` if the subject is not
        specified.
        """
        return self._get_text(DI.SUBJECT)

    @property
    def subject_raw(self) -> str | None:
        """The "raw" version of subject; can return a ``ByteStringObject``."""
        return self.get(DI.SUBJECT)

    @property
    def creator(self) -> str | None:
        """
        Read-only property accessing the document's creator.

        If the document was converted to PDF from another format, this is the
        name of the application (e.g. OpenOffice) that created the original
        document from which it was converted. Returns a ``TextStringObject`` or
        ``None`` if the creator is not specified.
        """
        return self._get_text(DI.CREATOR)

    @property
    def creator_raw(self) -> str | None:
        """The "raw" version of creator; can return a ``ByteStringObject``."""
        return self.get(DI.CREATOR)

    @property
    def producer(self) -> str | None:
        """
        Read-only property accessing the document's producer.

        If the document was converted to PDF from another format, this is the
        name of the application (for example, macOS Quartz) that converted it to
        PDF. Returns a ``TextStringObject`` or ``None`` if the producer is not
        specified.
        """
        return self._get_text(DI.PRODUCER)

    @property
    def producer_raw(self) -> str | None:
        """The "raw" version of producer; can return a ``ByteStringObject``."""
        return self.get(DI.PRODUCER)

    @property
    def creation_date(self) -> datetime | None:
        """Read-only property accessing the document's creation date."""
        return parse_iso8824_date(self._get_text(DI.CREATION_DATE))

    @property
    def creation_date_raw(self) -> str | None:
        """
        The "raw" version of creation date; can return a ``ByteStringObject``.

        Typically in the format ``D:YYYYMMDDhhmmss[+Z-]hh'mm`` where the suffix
        is the offset from UTC.
        """
        return self.get(DI.CREATION_DATE)

    @property
    def modification_date(self) -> datetime | None:
        """
        Read-only property accessing the document's modification date.

        The date and time the document was most recently modified.
        """
        return parse_iso8824_date(self._get_text(DI.MOD_DATE))

    @property
    def modification_date_raw(self) -> str | None:
        """
        The "raw" version of modification date; can return a
        ``ByteStringObject``.

        Typically, in the format ``D:YYYYMMDDhhmmss[+Z-]hh'mm`` where the suffix
        is the offset from UTC.
        """
        return self.get(DI.MOD_DATE)

    @property
    def keywords(self) -> str | None:
        """
        Read-only property accessing the document's keywords.

        Returns a ``TextStringObject`` or ``None`` if keywords are not
        specified.
        """
        return self._get_text(DI.KEYWORDS)

    @property
    def keywords_raw(self) -> str | None:
        """The "raw" version of keywords; can return a ``ByteStringObject``."""
        return self.get(DI.KEYWORDS)


class PdfDocCommon(ABC):
    """
    Common functions from PdfWriter and PdfReader objects.

    This root class is strongly abstracted.
    """

    strict: bool = False  # default

    flattened_pages: list[PageObject] | None = None

    _encryption: Encryption | None = None

    _readonly: bool = False

    @property
    @abstractmethod
    def root_object(self) -> DictionaryObject:
        ...  # pragma: no cover

    @property
    @abstractmethod
    def pdf_header(self) -> str:
        ...  # pragma: no cover

    @abstractmethod
    def get_object(
        self, indirect_reference: int | IndirectObject
    ) -> PdfObject | None:
        ...  # pragma: no cover

    @abstractmethod
    def _replace_object(self, indirect_reference: IndirectObject, obj: PdfObject) -> PdfObject:
        ...  # pragma: no cover

    @property
    @abstractmethod
    def _info(self) -> DictionaryObject | None:
        ...  # pragma: no cover

    @property
    def metadata(self) -> DocumentInformation | None:
        """
        Retrieve the PDF file's document information dictionary, if it exists.

        Note that some PDF files use metadata streams instead of document
        information dictionaries, and these metadata streams will not be
        accessed by this function.
        """
        retval = DocumentInformation()
        if self._info is None:
            return None
        retval.update(self._info)
        return retval

    @property
    @abstractmethod
    def xmp_metadata(self) -> XmpInformation | None:
        ...  # pragma: no cover

    @property
    def viewer_preferences(self) -> ViewerPreferences | None:
        """Returns the existing ViewerPreferences as an overloaded dictionary."""
        o = self.root_object.get(CA.VIEWER_PREFERENCES, None)
        if o is None:
            return None
        o = o.get_object()
        if not isinstance(o, DictionaryObject):
            logger_warning(
                "Viewer preferences are not a dictionary: %(preferences)s",
                source=__name__,
                preferences=o,
            )
            return None
        if not isinstance(o, ViewerPreferences):
            o = ViewerPreferences(o)
            if hasattr(o, "indirect_reference") and o.indirect_reference is not None:
                self._replace_object(o.indirect_reference, o)
            else:
                self.root_object[NameObject(CA.VIEWER_PREFERENCES)] = o
        return o

    def get_num_pages(self) -> int:
        """
        Calculate the number of pages in this PDF file.

        Returns:
            The number of pages of the parsed PDF file.

        Raises:
            PdfReadError: If restrictions prevent this action.

        """
        # The page tree cannot be walked while the document is still encrypted;
        # the PDF file's page count is used in this case. Once the document has
        # been decrypted (or if it is not encrypted at all), the flattened page
        # tree is used instead, as the /Count value might be wrong.
        encryption = self._encryption
        if self.is_encrypted and (encryption is None or not encryption.is_decrypted()):
            return self.root_object["/Pages"]["/Count"]  # type: ignore[no-any-return, index]
        if self.flattened_pages is None:
            self._flatten(self._readonly)
        assert self.flattened_pages is not None
        return len(self.flattened_pages)

    def get_page(self, page_number: int) -> PageObject:
        """
        Retrieve a page by number from this PDF file.
        Most of the time ``.pages[page_number]`` is preferred.

        Args:
            page_number: The page number to retrieve
                (pages begin at zero)

        Returns:
            A :class:`PageObject<pypdf._page.PageObject>` instance.

        """
        if self.flattened_pages is None:
            self._flatten(self._readonly)
        assert self.flattened_pages is not None, "mypy"
        return self.flattened_pages[page_number]

    def _get_page_in_node(
        self,
        page_number: int,
    ) -> tuple[DictionaryObject, int]:
        """
        Retrieve the node and position within the /Kids containing the page.
        If page_number is greater than the number of pages, it returns the top node, -1.
        """
        top = cast(DictionaryObject, self.root_object["/Pages"])
        visited: set[int] = set()

        def recursive_call(
            _node: DictionaryObject, mi: int
        ) -> tuple[PdfObject | None, int]:
            _node_id = id(_node)
            if _node_id in visited:
                raise LimitReachedError("Detected cycle in /Pages hierarchy when retrieving page.")
            visited.add(_node_id)
            ma = cast(int, _node.get("/Count", 1))  # default 1 for /Page types
            if _node.get("/Type") == "/Page":
                if page_number == mi:
                    return _node, -1
                return None, mi + 1
            if (page_number - mi) >= ma:  # not in nodes below
                if _node == top:
                    return top, -1
                return None, mi + ma
            for _idx, kid in enumerate(cast(ArrayObject, _node["/Kids"])):
                kid = cast(DictionaryObject, kid.get_object())
                n, i = recursive_call(kid, mi)
                if n is not None:  # page has just been found ...
                    if i < 0:  # ... just below!
                        return _node, _idx
                    # ... at lower levels
                    return n, i
                mi = i
            raise PyPdfError("Unexpectedly cannot find the node.")

        node, idx = recursive_call(top, 0)
        assert isinstance(node, DictionaryObject), "mypy"
        return node, idx

    @property
    def named_destinations(self) -> dict[str, Destination]:
        """A read-only dictionary which maps names to destinations."""
        return self._get_named_destinations()

    def get_named_dest_root(self) -> ArrayObject:
        named_dest = ArrayObject()
        if CA.NAMES in self.root_object and isinstance(
            self.root_object[CA.NAMES], DictionaryObject
        ):
            names = cast(DictionaryObject, self.root_object[CA.NAMES])
            if CA.DESTS in names and isinstance(names[CA.DESTS], DictionaryObject):
                # §3.6.3 Name Dictionary (PDF spec 1.7)
                dests = cast(DictionaryObject, names[CA.DESTS])
                if CA.NAMES in dests:
                    # §7.9.6, entries in a name tree node dictionary
                    named_dest = cast(ArrayObject, dests[CA.NAMES])
                else:
                    named_dest = ArrayObject()
                    dests[NameObject(CA.NAMES)] = named_dest
            elif hasattr(self, "_add_object"):
                dests = DictionaryObject()
                dests_ref = self._add_object(dests)
                names[NameObject(CA.DESTS)] = dests_ref
                dests[NameObject(CA.NAMES)] = named_dest

        elif hasattr(self, "_add_object"):
            names = DictionaryObject()
            names_ref = self._add_object(names)
            self.root_object[NameObject(CA.NAMES)] = names_ref
            dests = DictionaryObject()
            dests_ref = self._add_object(dests)
            names[NameObject(CA.DESTS)] = dests_ref
            dests[NameObject(CA.NAMES)] = named_dest

        return named_dest

    ## common
    def _get_named_destinations(
        self,
        *,
        tree: DictionaryObject | None = None,
        retval: dict[str, Destination] | None = None,
        visited: set[int] | None = None,
        depth: int = 0,
        traversal_state: _TraversalState | None = None,
    ) -> dict[str, Destination]:
        """
        Retrieve the named destinations present in the document.

        Args:
            tree: The current tree.
            retval: The previously retrieved destinations for nested calls.
            visited: Already known/visited objects.
            depth: Current name tree nesting depth.
            traversal_state: Shared visitor counters.

        Returns:
            A dictionary which maps names to destinations.

        """
        if traversal_state is None:
            traversal_state = _TraversalState()

        if visited is None:
            visited = set()
        if retval is None:
            retval = {}
            catalog = self.root_object

            # get the name tree
            candidate: PdfObject | None = None
            if CA.DESTS in catalog:
                candidate = catalog[CA.DESTS].get_object()
            elif CA.NAMES in catalog:
                names = catalog[CA.NAMES].get_object()
                if isinstance(names, DictionaryObject) and CA.DESTS in names:
                    candidate = names[CA.DESTS].get_object()
            if candidate is not None and not isinstance(candidate, DictionaryObject):
                logger_warning(
                    "Destination tree is not a dictionary: %(tree)s",
                    source=__name__,
                    tree=candidate,
                )
                return retval
            if candidate is not None:
                tree = candidate

        if is_null_or_none(tree):
            return retval
        assert tree is not None, "mypy"

        configuration = get_configuration()
        if depth > configuration.named_destinations_maximum_depth:
            raise LimitReachedError(
                f"Maximum named destination depth exceeded: "
                f"{depth} > {configuration.named_destinations_maximum_depth}."
            )

        tree_id = id(tree)
        if tree_id in visited:
            logger_warning("Detected cycle in destination tree.", source=__name__)
            return retval
        visited.add(tree_id)

        traversal_state.entry_count += 1
        if traversal_state.entry_count > configuration.named_destinations_maximum_entries:
            raise LimitReachedError(
                f"Maximum named destination entry limit exceeded: "
                f"{traversal_state.entry_count} > {configuration.named_destinations_maximum_entries}."
            )

        if PagesAttributes.KIDS in tree:
            kids = tree[PagesAttributes.KIDS].get_object()
            if not isinstance(kids, ArrayObject):
                logger_warning(
                    "Destination tree kids are not an array: %(kids)s",
                    source=__name__,
                    kids=kids,
                )
                return retval
            # recurse down the tree
            for kid in kids:
                self._get_named_destinations(
                    tree=kid.get_object(),
                    retval=retval,
                    visited=visited,
                    depth=depth + 1,
                    traversal_state=traversal_state,
                )
        # §7.9.6, entries in a name tree node dictionary
        elif CA.NAMES in tree:  # /Kids and /Names are exclusives (§7.9.6)
            names = tree[CA.NAMES].get_object()
            if not isinstance(names, ArrayObject):
                logger_warning(
                    "Destination tree names are not an array: %(names)s",
                    source=__name__,
                    names=names,
                )
                return retval
            i = 0
            while i < len(names):
                key = names[i].get_object()
                i += 1
                if not isinstance(key, (bytes, str)):
                    continue
                try:
                    value = names[i].get_object()
                except IndexError:
                    break
                i += 1
                if isinstance(value, DictionaryObject):
                    if "/D" in value:
                        value = value["/D"]
                    else:
                        continue
                dest = self._build_destination(key, value)
                if dest is not None:
                    retval[cast(str, dest["/Title"])] = dest
                    # Remain backwards-compatible.
                    retval[str(key)] = dest
        else:  # case where /Dests is in the document's catalog dictionary (PDF 1.7 specs, §2 about PDF 1.1)
            for k__, v__ in tree.items():
                val = v__.get_object()
                if isinstance(val, DictionaryObject):
                    if "/D" in val:
                        val = val["/D"].get_object()
                    else:
                        continue
                dest = self._build_destination(k__, val)
                if dest is not None:
                    retval[k__] = dest
        return retval

    # A select group of relevant field attributes. For the complete list,
    # see §12.3.2 of the PDF 1.7 or PDF 2.0 specification.

    def get_fields(
        self,
        tree: DictionaryObject | None = None,
        retval: dict[Any, Any] | None = None,
        fileobj: Any | None = None,
        stack: Any = _UNSET,
        *,
        _visited: set[int] | None = None,
        _depth: int = 0,
        _traversal_state: _TraversalState | None = None,
    ) -> dict[str, Any] | None:
        """
        Extract field data if this PDF contains interactive form fields.

        The *tree*, *retval*, *visited*, *depth* parameters are for internal use.

        Args:
            tree: Current object to parse.
            retval: In-progress list of fields.
            fileobj: A file object (usually a text file) to write
                a report to on all interactive form fields found.
            stack: The stack to use. Deprecated.
            _visited: Set of already visited IDs. Callers should usually omit this.
            _depth: The current field depth.
            _traversal_state: The current traversal state.

        Returns:
            A dictionary where each key is a field name, and each
            value is a :class:`Field<pypdf.generic.Field>` object. By
            default, the mapping name is used for keys.
            ``None`` if form data could not be located.

        """
        if stack is not _UNSET:
            deprecation_no_replacement(name="stack", removed_in="7.0.0")

        configuration = get_configuration()
        if _depth >= configuration.form_fields_maximum_depth:
            raise LimitReachedError("Reached maximum allowed form field depth.")
        if _traversal_state is None:
            _traversal_state = _TraversalState()

        def _check_field_limit(_increment: int) -> None:
            _traversal_state.entry_count += _increment
            if _traversal_state.entry_count > configuration.form_fields_maximum_entries:
                raise LimitReachedError("Exceeded maximum number of fields allowed.")

        field_attributes = FA.attributes_dict()
        field_attributes.update(CheckboxRadioButtonAttributes.attributes_dict())
        if retval is None:
            retval = {}
            catalog = self.root_object
            _visited = set()
            # get the AcroForm tree
            if CA.ACRO_FORM in catalog:
                entry = catalog[CA.ACRO_FORM]
                acro_form = None if entry is None else entry.get_object()
                if acro_form is not None and not isinstance(
                    acro_form, DictionaryObject
                ):
                    logger_warning(
                        "AcroForm is not a dictionary: %(acro_form)s",
                        source=__name__,
                        acro_form=acro_form,
                    )
                    return None
                tree = acro_form
            else:
                return None
        if tree is None:
            return retval
        assert _visited is not None
        if "/Fields" in tree:
            fields = tree["/Fields"].get_object()
            if not isinstance(fields, ArrayObject):
                logger_warning(
                    "AcroForm /Fields is not an array: %(fields)s",
                    source=__name__,
                    fields=fields,
                )
                return retval
            _check_field_limit(len(fields))
            for f in fields:
                field = f.get_object()
                self._build_field(
                    field=field, retval=retval, fileobj=fileobj, field_attributes=field_attributes,
                    visited=_visited, depth=_depth, traversal_state=_traversal_state,
                )
        elif any(attr in tree for attr in field_attributes):
            # Tree is a field
            _check_field_limit(1)
            self._build_field(
                field=tree, retval=retval, fileobj=fileobj, field_attributes=field_attributes,
                visited=_visited, depth=_depth, traversal_state=_traversal_state,
            )
        return retval

    def _get_qualified_field_name(
            self,
            *,
            parent: DictionaryObject,
            visited: set[int] | None = None
    ) -> str:
        if visited is None:
            visited = set()
        parent_id = id(parent)
        if parent_id in visited:
            raise LimitReachedError("Detected cycle in /Parent hierarchy when retrieving qualified field name.")
        visited.add(parent_id)

        if "/TM" in parent:
            return cast(str, parent["/TM"])
        if "/Parent" in parent:
            return (
                self._get_qualified_field_name(
                    parent=cast(DictionaryObject, parent["/Parent"]),
                    visited=visited,
                )
                + "."
                + cast(str, parent.get("/T", ""))
            )
        return cast(str, parent.get("/T", ""))

    @staticmethod
    def _normal_appearance(appearance: Any) -> DictionaryObject:
        """Return the /N normal-appearance sub-dictionary of an /AP entry."""
        appearance = appearance.get_object()
        if not isinstance(appearance, DictionaryObject):
            raise PdfReadError(f"Expected appearance dictionary, got {appearance!r}")
        normal = appearance.get("/N")
        if normal is not None:
            normal = normal.get_object()
        if not isinstance(normal, DictionaryObject):
            raise PdfReadError(f"Expected /N appearance dictionary, got {normal!r}")
        return normal

    def _build_field(
        self,
        *,
        field: TreeObject | DictionaryObject,
        retval: dict[Any, Any],
        fileobj: Any,
        field_attributes: Any,
        visited: set[int],
        depth: int,
        traversal_state: _TraversalState,
    ) -> None:
        if not isinstance(field, DictionaryObject):
            logger_warning(
                "Form field is not a dictionary: %(field)s",
                source=__name__,
                field=field,
            )
            return
        if all(attr not in field for attr in ("/T", "/TM")):
            return
        key = self._get_qualified_field_name(parent=field)
        if fileobj:
            self._write_field(fileobj, field, field_attributes)
            fileobj.write("\n")
        retval[key] = Field(field)
        obj = retval[key].indirect_reference.get_object()  # to get the full object
        if obj.get(FA.FT, "") == "/Ch" and obj.get(NameObject(FA.Opt)):
            retval[key][NameObject("/_States_")] = obj[NameObject(FA.Opt)]
        if obj.get(FA.FT, "") == "/Btn" and "/AP" in obj:
            #  Checkbox
            normal = self._normal_appearance(obj["/AP"])
            retval[key][NameObject("/_States_")] = ArrayObject(list(normal.keys()))
            if "/Off" not in retval[key]["/_States_"]:
                retval[key][NameObject("/_States_")].append(NameObject("/Off"))
        elif obj.get(FA.FT, "") == "/Btn" and obj.get(FA.Ff, 0) & FA.FfBits.Radio != 0:
            states: list[str] = []
            retval[key][NameObject("/_States_")] = ArrayObject(states)
            for k in obj.get(FA.Kids, {}):
                k = k.get_object()
                if "/AP" not in k:
                    raise PdfReadError(f"Button field kid missing /AP: {k!r}")
                normal = self._normal_appearance(k["/AP"])
                for s in list(normal.keys()):
                    if s not in states:
                        states.append(s)
                retval[key][NameObject("/_States_")] = ArrayObject(states)
            if (
                obj.get(FA.Ff, 0) & FA.FfBits.NoToggleToOff != 0
                and "/Off" in retval[key]["/_States_"]
            ):
                del retval[key]["/_States_"][retval[key]["/_States_"].index("/Off")]
        # at last for order
        self._check_kids(
            tree=field, retval=retval, fileobj=fileobj, visited=visited, depth=depth, traversal_state=traversal_state
        )

    def _check_kids(
        self,
        *,
        tree: TreeObject | DictionaryObject,
        retval: Any,
        fileobj: Any,
        visited: set[int],
        depth: int,
        traversal_state: _TraversalState,
    ) -> None:
        tree_id = id(tree)
        if tree_id in visited:
            logger_warning(
                "%(field_name)s already parsed",
                source=__name__,
                field_name=self._get_qualified_field_name(parent=tree),
            )
            return
        visited.add(tree_id)
        if PagesAttributes.KIDS in tree:
            # recurse down the tree
            for kid in tree[PagesAttributes.KIDS]:  # type: ignore[attr-defined]
                kid = kid.get_object()
                self.get_fields(
                    tree=kid, retval=retval, fileobj=fileobj,
                    _visited=visited, _depth=depth + 1, _traversal_state=traversal_state
                )

    def _write_field(self, fileobj: Any, field: Any, field_attributes: Any) -> None:
        field_attributes_tuple = FA.attributes()
        field_attributes_tuple = (
            field_attributes_tuple + CheckboxRadioButtonAttributes.attributes()
        )

        for attr in field_attributes_tuple:
            if attr in (
                FA.Kids,
                FA.AA,
            ):
                continue
            attr_name = field_attributes[attr]
            try:
                if attr == FA.FT:
                    # Make the field type value clearer
                    types = {
                        "/Btn": "Button",
                        "/Tx": "Text",
                        "/Ch": "Choice",
                        "/Sig": "Signature",
                    }
                    if field[attr] in types:
                        fileobj.write(f"{attr_name}: {types[field[attr]]}\n")
                elif attr == FA.Parent:
                    # Let's just write the name of the parent
                    try:
                        name = field[attr][FA.TM]
                    except KeyError:
                        name = field[attr][FA.T]
                    fileobj.write(f"{attr_name}: {name}\n")
                else:
                    fileobj.write(f"{attr_name}: {field[attr]}\n")
            except KeyError:
                # Field attribute is N/A or unknown, so don't write anything
                pass

    def get_form_text_fields(self, full_qualified_name: bool = False) -> dict[str, Any]:
        """
        Retrieve form fields from the document with textual data.

        Args:
            full_qualified_name: to get full name

        Returns:
            A dictionary. The key is the name of the form field,
            the value is the content of the field.

            If the document contains multiple form fields with the same name, the
            second and following will get the suffix .2, .3, ...

        """

        def indexed_key(k: str, fields: dict[Any, Any]) -> str:
            if k not in fields:
                return k
            return (
                k
                + "."
                + str(sum(1 for kk in fields if kk.startswith(k + ".")) + 2)
            )

        # Retrieve document form fields
        form_fields = self.get_fields()
        if form_fields is None:
            return {}
        ff = {}
        for field, value in form_fields.items():
            if value.get("/FT") == "/Tx":
                if full_qualified_name:
                    ff[field] = value.get("/V")
                else:
                    ff[indexed_key(cast(str, value.get("/T", field)), ff)] = value.get("/V")
        return ff

    def get_pages_showing_field(
        self, field: Field | PdfObject | IndirectObject
    ) -> list[PageObject]:
        """
        Provides list of pages where the field is called.

        Args:
            field: Field Object, PdfObject or IndirectObject referencing a Field

        Returns:
            List of pages:
                - Empty list:
                    The field has no widgets attached
                    (either hidden field or ancestor field).
                - Single page list:
                    Page where the widget is present
                    (most common).
                - Multi-page list:
                    Field with multiple kids widgets
                    (example: radio buttons, field repeated on multiple pages).

        """
        try:
            # to cope with all types
            field = cast(DictionaryObject, field.indirect_reference.get_object())  # type: ignore[union-attr]
        except Exception as exc:
            raise ValueError("Field type is invalid") from exc
        if is_null_or_none(field.get_inherited(key="/FT", default=None)):
            raise ValueError("Field is not valid")
        ret = []
        if field.get("/Subtype", "") == "/Widget":
            if "/P" in field:
                ret = [field["/P"].get_object()]
            else:
                ret = [
                    p
                    for p in self.pages
                    if field.indirect_reference in p.get("/Annots", "")
                ]
        else:
            kids = field.get("/Kids", ())
            for k in kids:
                k = k.get_object()
                if (k.get("/Subtype", "") == "/Widget") and ("/T" not in k):
                    # Kid that is just a widget, not a field:
                    if "/P" in k:
                        ret += [k["/P"].get_object()]
                    else:
                        ret += [
                            p
                            for p in self.pages
                            if k.indirect_reference in p.get("/Annots", "")
                        ]
        return [
            x
            if isinstance(x, PageObject)
            else (self.pages[self._get_page_number_by_indirect(x.indirect_reference)])  # type: ignore[index, union-attr]
            for x in ret
        ]

    @staticmethod
    def _display_resolve(obj: Any) -> Any:
        """Resolve indirect objects without changing the underlying document."""
        return obj.get_object() if isinstance(obj, IndirectObject) else obj

    @staticmethod
    def _display_is_true(obj: Any) -> bool:
        """Interpret PDF boolean-like values without relying on truthiness."""
        obj = obj.get_object() if isinstance(obj, IndirectObject) else obj
        if is_null_or_none(obj):
            return False
        return bool(getattr(obj, "value", obj))

    def _get_display_acro_form(self) -> DictionaryObject | None:
        """Return the AcroForm dictionary, if any, without validating all fields."""
        entry = self.root_object.get(CA.ACRO_FORM)
        if is_null_or_none(entry):
            return None
        acro_form = self._display_resolve(entry)
        return acro_form if isinstance(acro_form, DictionaryObject) else None

    def _get_display_inherited(
        self,
        obj: DictionaryObject,
        key: str,
        field: DictionaryObject,
        default: Any = None,
    ) -> Any:
        """Read an inheritable field entry, tolerating broken Parent chains."""
        try:
            value = obj.get_inherited(key, _UNSET)
        except Exception:
            value = _UNSET
        if value is not _UNSET:
            return value
        if obj is field:
            return default
        try:
            return field.get_inherited(key, default)
        except Exception:
            return default

    def _display_field_name(self, field: DictionaryObject) -> str:
        """Get the qualified name without failing on a malformed hierarchy."""
        try:
            return self._get_qualified_field_name(parent=field)
        except Exception:
            return str(field.get(FA.TM, field.get(FA.T, "")))

    def _iter_display_fields(
        self, acro_form: DictionaryObject
    ) -> Iterator[tuple[str, DictionaryObject]]:
        """Walk named fields in the AcroForm tree without building Field copies."""
        fields = self._display_resolve(acro_form.get(IF.Fields))
        if not isinstance(fields, ArrayObject):
            return
        maximum_depth = get_configuration().form_fields_maximum_depth
        visited: set[int] = set()

        def walk(obj: Any, depth: int) -> Iterator[tuple[str, DictionaryObject]]:
            obj = self._display_resolve(obj)
            if not isinstance(obj, DictionaryObject) or depth > maximum_depth:
                return
            obj_id = id(obj)
            if obj_id in visited:
                return
            visited.add(obj_id)
            if FA.T in obj or FA.TM in obj:
                yield self._display_field_name(obj), obj
            kids = self._display_resolve(obj.get(FA.Kids))
            if isinstance(kids, ArrayObject):
                for kid in kids:
                    yield from walk(kid, depth + 1)

        for field in fields:
            yield from walk(field, 0)

    @staticmethod
    def _is_display_widget(obj: DictionaryObject) -> bool:
        """Check whether an object can act as a widget annotation."""
        if obj.get(AA.Subtype) == "/Widget":
            return True
        if AA.AP not in obj:
            return False
        return AA.Rect in obj or AA.P in obj or not obj.get(FA.Kids)

    def _collect_display_widgets(
        self, field: DictionaryObject
    ) -> list[DictionaryObject]:
        """Collect the field itself and all descendant widgets."""
        widgets: list[DictionaryObject] = []
        visited: set[int] = set()

        def walk(obj: Any) -> None:
            obj = self._display_resolve(obj)
            if not isinstance(obj, DictionaryObject):
                return
            obj_id = id(obj)
            if obj_id in visited:
                return
            visited.add(obj_id)
            if self._is_display_widget(obj):
                widgets.append(obj)
            kids = self._display_resolve(obj.get(FA.Kids))
            if isinstance(kids, ArrayObject):
                for kid in kids:
                    walk(kid)

        walk(field)
        return widgets

    @staticmethod
    def _same_display_object(first: Any, second: Any) -> bool:
        """Compare PDF objects by identity/reference only, never by value."""
        if first is second:
            return True
        first_ref = first if isinstance(first, IndirectObject) else getattr(first, "indirect_reference", None)
        second_ref = second if isinstance(second, IndirectObject) else getattr(second, "indirect_reference", None)
        return first_ref is not None and first_ref == second_ref

    def _get_display_declared_page(self, widget: DictionaryObject) -> int | None:
        """Resolve the optional /P page of a widget."""
        declared = widget.get(AA.P)
        if is_null_or_none(declared):
            return None
        if isinstance(declared, IndirectObject):
            return self._get_page_number_by_indirect(declared)
        for page_number, page in enumerate(self.pages):
            if self._same_display_object(page, declared):
                return page_number
        return None

    def _get_display_page_occurrences(
        self, widget: DictionaryObject
    ) -> list[tuple[int | None, bool, int | None]]:
        """
        Locate a widget in page /Annots arrays.

        Returns:
            Tuples of ``(page_number, page_confirmed, declared_page_number)``.
            A widget can occur on several pages. If it is not listed in any
            /Annots array, its /P page is returned as an unconfirmed fallback.
        """
        occurrences: list[tuple[int | None, bool, int | None]] = []
        declared_page = self._get_display_declared_page(widget)
        for page_number, page in enumerate(self.pages):
            annotations = self._display_resolve(page.get(PG.ANNOTS))
            if not isinstance(annotations, ArrayObject):
                continue
            for annotation in annotations:
                if self._same_display_object(annotation, widget) or self._same_display_object(
                    self._display_resolve(annotation), widget
                ):
                    occurrences.append((page_number, True, declared_page))
                    break
        if not occurrences:
            occurrences.append((declared_page, False, declared_page))
        return occurrences

    @staticmethod
    def _display_page_filter_value(page: int | PageObject | None) -> int | None:
        """Normalize a page filter to a zero-based page number."""
        if page is None:
            return None
        if isinstance(page, bool):
            raise ValueError("page must be a page number or PageObject")
        if isinstance(page, int):
            return page
        if isinstance(page, PageObject):
            page_number = page.page_number
            if page_number is None:
                raise ValueError("PageObject is not attached to a document")
            return page_number
        raise ValueError("page must be a page number or PageObject")

    def _get_display_field_object(
        self, field: str | Field | PdfObject | IndirectObject
    ) -> DictionaryObject:
        """Resolve a public field argument to its dictionary in the PDF."""
        if isinstance(field, str):
            acro_form = self._get_display_acro_form()
            if acro_form is not None:
                for name, candidate in self._iter_display_fields(acro_form):
                    if name == field:
                        return candidate
            raise ValueError(f"Field not found: {field}")
        obj = self._display_resolve(field)
        if isinstance(obj, Field) and obj.indirect_reference is not None:
            obj = self._display_resolve(obj.indirect_reference)
        if isinstance(obj, DictionaryObject) and obj.get(AA.Subtype) == "/Widget":
            has_field_entries = any(key in obj for key in (FA.T, FA.TM, FA.Kids, FA.FT))
            if FA.Parent in obj and not has_field_entries:
                parent = self._display_resolve(obj[FA.Parent])
                if isinstance(parent, DictionaryObject):
                    obj = parent
        if not isinstance(obj, DictionaryObject):
            raise ValueError("Field type is invalid")
        return obj

    def _resolve_button_widget_state(
        self,
        widget: DictionaryObject,
        field: DictionaryObject,
        page_number: int | None,
        page_confirmed: bool,
        declared_page_number: int | None,
        needs_appearance_regeneration: bool,
    ) -> WidgetDisplayState:
        """Derive a button's visible state from /AS and the matching /AP stream."""
        widget_ref = widget.indirect_reference or field.indirect_reference
        field_flags = int(self._get_display_inherited(widget, FA.Ff, field, 0) or 0)

        if field_flags & FA.FfBits.Pushbutton:
            return WidgetDisplayState(
                page_number=page_number,
                widget=widget_ref,
                state=None,
                determined=False,
                reason="Pushbutton widgets do not have a persistent selected state.",
                object_reference=widget_ref,
                source="unknown",
                needs_appearance_regeneration=needs_appearance_regeneration,
                page_confirmed=page_confirmed,
                declared_page_number=declared_page_number,
            )

        appearance = self._get_display_inherited(widget, AA.AP, field)
        appearance_obj = self._display_resolve(appearance)
        if not isinstance(appearance_obj, DictionaryObject):
            reason = "Widget has no /AP appearance dictionary."
            if needs_appearance_regeneration:
                reason += " /NeedAppearances is set, so the appearance may need to be regenerated."
            return WidgetDisplayState(
                page_number=page_number,
                widget=widget_ref,
                state=None,
                determined=False,
                reason=reason,
                object_reference=widget_ref,
                source="unknown",
                appearance_present=False,
                needs_appearance_regeneration=needs_appearance_regeneration,
                page_confirmed=page_confirmed,
                declared_page_number=declared_page_number,
            )

        normal = self._display_resolve(appearance_obj.get("/N"))
        if not isinstance(normal, DictionaryObject) or isinstance(normal, StreamObject):
            return WidgetDisplayState(
                page_number=page_number,
                widget=widget_ref,
                state=None,
                determined=False,
                reason="Normal appearance is not a multi-state dictionary; /AS cannot be confirmed.",
                object_reference=widget_ref,
                source="unknown",
                appearance_present=normal is not None,
                needs_appearance_regeneration=needs_appearance_regeneration,
                page_confirmed=page_confirmed,
                declared_page_number=declared_page_number,
            )

        state_entry = widget.get(AA.AS)
        if is_null_or_none(state_entry):
            return WidgetDisplayState(
                page_number=page_number,
                widget=widget_ref,
                state=None,
                determined=False,
                reason="Widget has no /AS appearance state.",
                object_reference=widget_ref,
                source="unknown",
                appearance_present=True,
                needs_appearance_regeneration=needs_appearance_regeneration,
                page_confirmed=page_confirmed,
                declared_page_number=declared_page_number,
            )

        active_state = str(self._display_resolve(state_entry))
        available_states = {str(key) for key in normal}
        if active_state not in available_states and active_state != "/Off":
            return WidgetDisplayState(
                page_number=page_number,
                widget=widget_ref,
                state=active_state,
                determined=False,
                reason=f"/AS {active_state!r} has no matching /AP /N appearance stream.",
                object_reference=widget_ref,
                is_selected=None,
                source="appearance_state",
                appearance_present=True,
                needs_appearance_regeneration=needs_appearance_regeneration,
                page_confirmed=page_confirmed,
                declared_page_number=declared_page_number,
            )

        return WidgetDisplayState(
            page_number=page_number,
            widget=widget_ref,
            state=active_state,
            determined=True,
            object_reference=widget_ref,
            is_selected=active_state != "/Off",
            source="appearance_state",
            appearance_present=True,
            needs_appearance_regeneration=needs_appearance_regeneration,
            page_confirmed=page_confirmed,
            declared_page_number=declared_page_number,
        )

    @staticmethod
    def _display_options(value: Any) -> list[tuple[str, str]]:
        """Normalize /Opt entries to ``(export_value, display_value)`` pairs."""
        if not isinstance(value, ArrayObject):
            return []
        options: list[tuple[str, str]] = []
        for entry in value:
            if isinstance(entry, IndirectObject):
                entry = entry.get_object()
            if isinstance(entry, (ArrayObject, list)) and len(entry) >= 2:
                export = entry[0].get_object() if isinstance(entry[0], IndirectObject) else entry[0]
                display = entry[1].get_object() if isinstance(entry[1], IndirectObject) else entry[1]
                options.append((str(export), str(display)))
            else:
                text = str(entry)
                options.append((text, text))
        return options

    @staticmethod
    def _display_value_list(value: Any) -> list[str]:
        """Normalize a /V entry to a list of strings."""
        if is_null_or_none(value):
            return []
        if isinstance(value, IndirectObject):
            value = value.get_object()
        if isinstance(value, (ArrayObject, list)):
            values: list[str] = []
            for entry in value:
                if isinstance(entry, IndirectObject):
                    entry = entry.get_object()
                if not is_null_or_none(entry):
                    values.append(str(entry))
            return values
        if value == "":
            return []
        return [str(value)]

    def _display_appearance_present(
        self, widget: DictionaryObject, field: DictionaryObject
    ) -> bool:
        """Return whether the widget has an inherited normal appearance."""
        appearance = self._display_resolve(self._get_display_inherited(widget, AA.AP, field))
        if not isinstance(appearance, DictionaryObject):
            return False
        return self._display_resolve(appearance.get("/N")) is not None

    def _resolve_choice_state(
        self,
        widget: DictionaryObject,
        field: DictionaryObject,
        page_number: int | None,
        page_confirmed: bool,
        declared_page_number: int | None,
        needs_appearance_regeneration: bool,
    ) -> WidgetDisplayState:
        """Derive selected choice values from the inherited /V, /I and /Opt."""
        widget_ref = widget.indirect_reference or field.indirect_reference
        value = self._get_display_inherited(widget, FA.V, field)
        indices_entry = self._get_display_inherited(widget, "/I", field)
        options = self._display_options(self._get_display_inherited(widget, FA.Opt, field))
        values = self._display_value_list(value)

        indices: list[int] = []
        if not is_null_or_none(indices_entry):
            indices_obj = self._display_resolve(indices_entry)
            if isinstance(indices_obj, (ArrayObject, list)):
                for index in indices_obj:
                    index = self._display_resolve(index)
                    try:
                        indices.append(int(index))
                    except (TypeError, ValueError):
                        return WidgetDisplayState(
                            page_number=page_number,
                            widget=widget_ref,
                            state=None,
                            determined=False,
                            reason="The /I entry contains a non-numeric index.",
                            object_reference=widget_ref,
                            source="unknown",
                            needs_appearance_regeneration=needs_appearance_regeneration,
                            page_confirmed=page_confirmed,
                            declared_page_number=declared_page_number,
                        )
            else:
                return WidgetDisplayState(
                    page_number=page_number,
                    widget=widget_ref,
                    state=None,
                    determined=False,
                    reason="The /I entry is not an array.",
                    object_reference=widget_ref,
                    source="unknown",
                    needs_appearance_regeneration=needs_appearance_regeneration,
                    page_confirmed=page_confirmed,
                    declared_page_number=declared_page_number,
                )

        selected_values = list(values)
        if indices:
            if any(index < 0 or index >= len(options) for index in indices):
                return WidgetDisplayState(
                    page_number=page_number,
                    widget=widget_ref,
                    state=None,
                    determined=False,
                    reason="The /I entry references an index outside /Opt.",
                    object_reference=widget_ref,
                    source="unknown",
                    needs_appearance_regeneration=needs_appearance_regeneration,
                    page_confirmed=page_confirmed,
                    declared_page_number=declared_page_number,
                )
            indexed_values = [options[index][0] for index in indices]
            if selected_values:
                if selected_values != indexed_values:
                    return WidgetDisplayState(
                        page_number=page_number,
                        widget=widget_ref,
                        state=None,
                        determined=False,
                        reason="The /V and /I entries select different options.",
                        object_reference=widget_ref,
                        source="unknown",
                        needs_appearance_regeneration=needs_appearance_regeneration,
                        page_confirmed=page_confirmed,
                        declared_page_number=declared_page_number,
                    )
            else:
                selected_values = indexed_values

        export_to_display = dict(options)
        labels = [export_to_display.get(item, item) for item in selected_values]
        if not indices:
            if options:
                indices = [
                    position
                    for position, (export, _display) in enumerate(options)
                    if export in selected_values
                ]
            else:
                indices = []
        field_flags = int(self._get_display_inherited(widget, FA.Ff, field, 0) or 0)
        if not labels:
            state: str | tuple[str, ...] = ()
        elif len(labels) == 1 and not (field_flags & FA.FfBits.MultiSelect):
            state = labels[0]
        else:
            state = tuple(labels)

        return WidgetDisplayState(
            page_number=page_number,
            widget=widget_ref,
            state=state,
            determined=True,
            object_reference=widget_ref,
            selected_values=tuple(selected_values),
            selected_indices=tuple(indices),
            source="field_value",
            appearance_present=self._display_appearance_present(widget, field),
            needs_appearance_regeneration=needs_appearance_regeneration,
            page_confirmed=page_confirmed,
            declared_page_number=declared_page_number,
        )

    def _build_display_state(
        self, field: DictionaryObject, page_filter: int | None
    ) -> FieldDisplayState:
        """Build a :class:`FieldDisplayState` for one field."""
        acro_form = self._get_display_acro_form()
        needs_appearance_regeneration = (
            self._display_is_true(acro_form.get(IF.NeedAppearances))
            if acro_form is not None
            else False
        )
        field_type_raw = self._get_display_inherited(field, FA.FT, field)
        field_type = str(field_type_raw) if field_type_raw is not None else None
        field_name = self._display_field_name(field)
        value_raw = self._get_display_inherited(field, FA.V, field)
        field_value = self._display_resolve(value_raw)
        selected_values: tuple[str, ...] = ()
        selected_indices: tuple[int, ...] = ()
        field_ref = field.indirect_reference

        if field_type not in ("/Btn", "/Ch"):
            return FieldDisplayState(
                name=field_name,
                field_type=field_type,
                value=field_value,
                widgets=(),
                determined=False,
                reason=f"Unsupported field type {field_type!r}; only /Btn and /Ch are audited.",
                field_reference=field_ref,
                object_reference=field_ref,
                needs_appearance_regeneration=needs_appearance_regeneration,
            )

        if field_type == "/Ch":
            field_selection = self._resolve_choice_state(
                field, field, None, False, None, needs_appearance_regeneration
            )
            if field_selection.determined:
                selected_values = field_selection.selected_values
                selected_indices = field_selection.selected_indices

        widgets = self._collect_display_widgets(field)
        states: list[WidgetDisplayState] = []
        for widget in widgets:
            if field_type == "/Btn":
                for page_number, page_confirmed, declared_page in self._get_display_page_occurrences(widget):
                    states.append(
                        self._resolve_button_widget_state(
                            widget,
                            field,
                            page_number,
                            page_confirmed,
                            declared_page,
                            needs_appearance_regeneration,
                        )
                    )
            else:
                for page_number, page_confirmed, declared_page in self._get_display_page_occurrences(widget):
                    state = self._resolve_choice_state(
                        widget,
                        field,
                        page_number,
                        page_confirmed,
                        declared_page,
                        needs_appearance_regeneration,
                    )
                    states.append(state)

        if page_filter is not None:
            states = [state for state in states if state.page_number == page_filter]

        if not states:
            reason = (
                "No widget annotation is attached to this field."
                if page_filter is None
                else f"No widget annotation for this field was found on page {page_filter}."
            )
            return FieldDisplayState(
                name=field_name,
                field_type=field_type,
                value=field_value,
                widgets=(),
                determined=False,
                reason=reason,
                field_reference=field_ref,
                object_reference=field_ref,
                selected_values=selected_values,
                selected_indices=selected_indices,
                needs_appearance_regeneration=needs_appearance_regeneration,
            )

        determined = all(state.determined for state in states)
        if determined:
            reason = None
        else:
            reasons = []
            for state in states:
                if not state.determined and state.reason and state.reason not in reasons:
                    reasons.append(state.reason)
            reason = reasons[0] if len(reasons) == 1 else "One or more widget display states cannot be determined."
        object_reference = field_ref
        if not determined:
            object_reference = next(
                (
                    state.object_reference
                    for state in states
                    if not state.determined and state.object_reference is not None
                ),
                field_ref,
            )
        return FieldDisplayState(
            name=field_name,
            field_type=field_type,
            value=field_value,
            widgets=tuple(states),
            determined=determined,
            reason=reason,
            field_reference=field_ref,
            object_reference=object_reference,
            selected_values=selected_values,
            selected_indices=selected_indices,
            needs_appearance_regeneration=needs_appearance_regeneration,
        )

    def get_field_display_state(
        self,
        field: str | Field | PdfObject | IndirectObject,
        page: int | PageObject | None = None,
    ) -> FieldDisplayState:
        """
        Report the structurally confirmable display state of a form field.

        This is a read-only check. It does not render the document, run
        appearance-generation code or execute document actions.

        For button fields the visible state comes from each widget's ``/AS``
        entry and the matching ``/AP /N`` appearance stream. Consequently a
        field with several widgets can have different visible states on
        different pages even though it has a single ``/V`` value. For choice
        fields the selected option is derived from the inherited ``/V``,
        ``/I`` and ``/Opt`` entries.

        Args:
            field: a field name, a :class:`Field`, a field dictionary or an
                indirect reference to one. Widget annotations are accepted and
                resolved to their parent field when necessary.
            page: an optional zero-based page number or :class:`PageObject`.
                Only widget occurrences on that page are returned. The field
                value is still reported exactly once.

        Returns:
            A :class:`FieldDisplayState`. Elements whose display cannot be
            confirmed from the PDF structure have ``determined=False``, a
            ``reason`` and an ``object_reference`` pointing at the relevant
            widget/field object.

        Raises:
            ValueError: If *field* cannot be resolved to a field dictionary.
        """
        page_filter = self._display_page_filter_value(page)
        field_obj = self._get_display_field_object(field)
        return self._build_display_state(field_obj, page_filter)

    def get_form_field_display_states(
        self, page: int | PageObject | None = None
    ) -> dict[str, FieldDisplayState]:
        """
        Report display states for all button and choice fields in the document.

        This is the document-wide counterpart of
        :meth:`get_field_display_state`. When *page* is given, only fields with
        a widget occurrence on that page are returned and their ``widgets``
        tuples are restricted to that page.
        """
        page_filter = self._display_page_filter_value(page)
        acro_form = self._get_display_acro_form()
        if acro_form is None:
            return {}
        result: dict[str, FieldDisplayState] = {}
        for name, field in self._iter_display_fields(acro_form):
            try:
                state = self._build_display_state(field, page_filter)
            except Exception as exc:
                field_ref = field.indirect_reference
                state = FieldDisplayState(
                    name=name,
                    field_type=None,
                    value=None,
                    widgets=(),
                    determined=False,
                    reason=f"Could not inspect field: {exc}",
                    field_reference=field_ref,
                    object_reference=field_ref,
                )
            if state.field_type not in ("/Btn", "/Ch"):
                continue
            if page_filter is not None and not state.widgets:
                continue
            result[name] = state
        return result

    def get_field_display_states(
        self, page: int | PageObject | None = None
    ) -> dict[str, FieldDisplayState]:
        """Alias for :meth:`get_form_field_display_states`."""
        return self.get_form_field_display_states(page=page)

    def get_form_field_display_state(
        self,
        field: str | Field | PdfObject | IndirectObject,
        page: int | PageObject | None = None,
    ) -> FieldDisplayState:
        """Alias for :meth:`get_field_display_state`."""
        return self.get_field_display_state(field=field, page=page)

    def get_field_state(
        self,
        field: str | Field | PdfObject | IndirectObject,
        page: int | PageObject | None = None,
    ) -> FieldDisplayState:
        """Alias for :meth:`get_field_display_state`."""
        return self.get_field_display_state(field=field, page=page)

    def get_field_states(
        self, page: int | PageObject | None = None
    ) -> dict[str, FieldDisplayState]:
        """Alias for :meth:`get_form_field_display_states`."""
        return self.get_form_field_display_states(page=page)

    @property
    def open_destination(
        self,
    ) -> Destination | TextStringObject | ByteStringObject | None:
        """
        Property to access the opening destination (``/OpenAction`` entry in
        the PDF catalog). It returns ``None`` if the entry does not exist
        or is not set.

        Raises:
            Exception: If a destination is invalid.

        """
        if "/OpenAction" not in self.root_object:
            return None
        oa: Any = self.root_object["/OpenAction"]
        if isinstance(oa, bytes):  # pragma: no cover
            oa = oa.decode()
        if isinstance(oa, str):
            return create_string_object(oa)
        if isinstance(oa, ArrayObject):
            try:
                page, typ, *array = oa
                fit = Fit(typ, tuple(array))
                return Destination("OpenAction", page, fit)
            except Exception as exc:
                raise Exception(f"Invalid Destination {oa}: {exc}") from exc
        else:
            return None

    @open_destination.setter
    def open_destination(self, dest: str | Destination | PageObject | None) -> None:
        raise NotImplementedError("No setter for open_destination")

    @property
    def outline(self) -> OutlineType:
        """
        Read-only property for the outline present in the document
        (i.e., a collection of 'outline items' which are also known as
        'bookmarks').
        """
        return self._get_outline()

    def _get_outline(
        self,
        *,
        node: DictionaryObject | None = None,
        outline: Any | None = None,
        visited: set[int] | None = None,
        depth: int = 0,
        traversal_state: _TraversalState | None = None
    ) -> OutlineType:
        if traversal_state is None:
            traversal_state = _TraversalState()

        if outline is None:
            outline = []
            catalog = self.root_object

            # get the outline dictionary and named destinations
            if Core.OUTLINES in catalog:
                lines = catalog[Core.OUTLINES]

                # A reference to an object which is missing or free in the xref table
                # resolves to None.
                if is_null_or_none(lines):
                    return outline

                if not isinstance(lines, DictionaryObject):
                    logger_warning(
                        "Outlines are not a dictionary: %(lines)s",
                        source=__name__,
                        lines=lines,
                    )
                    return outline

                # §12.3.3 Document outline, entries in the outline dictionary
                if "/First" in lines:
                    node = cast(DictionaryObject, lines["/First"])
            self._named_destinations = self._get_named_destinations()

        if node is None:
            return outline

        configuration = get_configuration()
        if depth > configuration.outline_maximum_depth:
            raise LimitReachedError(f"Maximum outline depth reached: {depth} > {configuration.outline_maximum_depth}.")

        # see if there are any more outline items
        if visited is None:
            visited = set()
        while True:
            node_id = id(node)
            if node_id in visited:
                logger_warning("Detected cycle in outline structure for %(node)s", source=__name__, node=node)
                break
            visited.add(node_id)
            traversal_state.entry_count += 1
            if traversal_state.entry_count > configuration.outline_maximum_entries:
                raise LimitReachedError(
                    f"Maximum outline entry limit reached: "
                    f"{traversal_state.entry_count} > {configuration.outline_maximum_entries}."
                )

            if not isinstance(node, DictionaryObject):
                logger_warning(
                    "Outline node is not a dictionary: %(node)s",
                    source=__name__,
                    node=node,
                )
                break

            outline_obj = self._build_outline_item(node)
            if outline_obj:
                outline.append(outline_obj)

            # check for sub-outline
            if "/First" in node:
                sub_outline: list[Any] = []
                # Pass a copy to allow multiple outer entries to reference the same inner one.
                inner_visited = visited.copy()
                self._get_outline(
                    node=cast(DictionaryObject, node["/First"]),
                    outline=sub_outline,
                    visited=inner_visited,
                    depth=depth + 1,
                    traversal_state=traversal_state,
                )
                if sub_outline:
                    outline.append(sub_outline)

            if "/Next" not in node:
                break
            node = cast(DictionaryObject, node["/Next"])

        return outline

    @property
    def threads(self) -> ArrayObject | None:
        """
        Read-only property for the list of threads.

        See §12.4.3 from the PDF 1.7 or 2.0 specification.

        It is an array of dictionaries with "/F" (the first bead in the thread)
        and "/I" (a thread information dictionary containing information about
        the thread, such as its title, author, and creation date) properties or
        None if there are no articles.

        Since PDF 2.0 it can also contain an indirect reference to a metadata
        stream containing information about the thread, such as its title,
        author, and creation date.
        """
        catalog = self.root_object
        if Core.THREADS in catalog:
            return cast("ArrayObject", catalog[Core.THREADS])
        return None

    @abstractmethod
    def _get_page_number_by_indirect(
        self, indirect_reference: int | NullObject | IndirectObject | None
    ) -> int | None:
        ...  # pragma: no cover

    def get_page_number(self, page: PageObject) -> int | None:
        """
        Retrieve page number of a given PageObject.

        Args:
            page: The page to get page number. Should be
                an instance of :class:`PageObject<pypdf._page.PageObject>`

        Returns:
            The page number or None if page is not found

        """
        return self._get_page_number_by_indirect(page.indirect_reference)

    def get_destination_page_number(self, destination: Destination) -> int | None:
        """
        Retrieve page number of a given Destination object.

        Args:
            destination: The destination to get page number.

        Returns:
            The page number or None if page is not found

        """
        return self._get_page_number_by_indirect(destination.page)

    def _build_destination(
        self,
        title: str | bytes,
        array: ArrayObject | None,
    ) -> Destination:
        page, typ = None, None
        # A valid destination is an array of at least a page and a fit type.
        # Anything else (a name, a bare number, a NullObject, None, ...) cannot
        # be unpacked below, so treat it as a missing destination.
        if not isinstance(array, ArrayObject) or len(array) < 2:
            page = NullObject()
            return Destination(title, page, Fit.fit())
        page, typ, *fit_args = array
        try:
            return Destination(title, page, Fit(fit_type=typ, fit_args=fit_args))
        except PdfReadError:
            logger_warning(
                "Unknown destination: %(title)r %(fit_args)s",
                source=__name__,
                title=title,
                fit_args=fit_args,
            )
            if self.strict:
                raise
            # create a link to first Page
            tmp = self.pages[0].indirect_reference
            indirect_reference = NullObject() if tmp is None else tmp
            return Destination(title, indirect_reference, Fit.fit())

    def _build_outline_item(self, node: DictionaryObject) -> Destination | None:
        dest, title, outline_item = None, None, None

        # title required for valid outline
        # §12.3.3, entries in an outline item dictionary
        if "/Title" in node:
            title = cast("str", node["/Title"])
        else:
            if self.strict:
                raise PdfReadError(f"Outline Entry Missing /Title attribute: {node!r}")
            title = ""

        if "/A" in node:
            # Action, PDF 1.7 and PDF 2.0 §12.6 (only type GoTo supported)
            action = cast(DictionaryObject, node["/A"])
            if GoToActionArguments.S in action:
                action_type = cast(NameObject, action[GoToActionArguments.S])
                if action_type == "/GoTo":
                    if GoToActionArguments.D in action:
                        dest = action[GoToActionArguments.D]
                    elif self.strict:
                        raise PdfReadError(f"Outline Action Missing /D attribute: {node!r}")
            elif self.strict:
                raise PdfReadError(f"Outline Action Missing /S attribute: {node!r}")
        elif "/Dest" in node:
            # Destination, PDF 1.7 and PDF 2.0 §12.3.2
            dest = node["/Dest"]
            # if array was referenced in another object, will be a dict w/ key "/D"
            if isinstance(dest, DictionaryObject) and "/D" in dest:
                dest = dest["/D"]

        if isinstance(dest, ArrayObject):
            outline_item = self._build_destination(title, dest)
        elif isinstance(dest, str):
            # named destination, addresses NameObject Issue #193
            # TODO: Keep named destination instead of replacing it?
            try:
                outline_item = self._build_destination(
                    title, self._named_destinations[dest].dest_array
                )
            except KeyError:
                # named destination not found in Name Dict
                outline_item = self._build_destination(title, None)
        elif dest is None:
            # outline item not required to have destination or action
            # PDFv1.7 Table 153
            outline_item = self._build_destination(title, dest)
        else:
            if self.strict:
                raise PdfReadError(f"Unexpected destination {dest!r}")
            logger_warning(
                "Removed unexpected destination %(dest)r from destination",
                source=__name__,
                dest=dest,
            )
            outline_item = self._build_destination(title, None)

        # if outline item created, add color, format, and child count if present
        if outline_item:
            if "/C" in node:
                # Color of outline item font in (R, G, B) with values ranging 0.0-1.0
                color = node["/C"]
                if isinstance(color, list):
                    outline_item[NameObject("/C")] = ArrayObject(FloatObject(c) for c in color)
                else:
                    logger_warning(
                        "Ignoring non-array outline color %(color)r",
                        source=__name__,
                        color=color,
                    )
            if "/F" in node:
                # specifies style characteristics bold and/or italic
                # with 1=italic, 2=bold, 3=both
                outline_item[NameObject("/F")] = node["/F"]
            if "/Count" in node:
                # absolute value = num. visible children
                # with positive = open/unfolded, negative = closed/folded
                outline_item[NameObject("/Count")] = node["/Count"]
            #  if count is 0 we will consider it as open (to have available is_open)
            outline_item[NameObject("/%is_open%")] = BooleanObject(
                node.get("/Count", 0) >= 0
            )
        outline_item.node = node
        try:
            outline_item.indirect_reference = node.indirect_reference
        except AttributeError:
            pass
        return outline_item

    @property
    def pages(self) -> Sequence[PageObject]:
        """
        Property that emulates a list of :class:`PageObject<pypdf._page.PageObject>`.
        This property allows to get a page or a range of pages.

        The returned object supports indexing, slicing, ``len()``, iteration and
        (for PdfWriter) ``del``, but it is not a :class:`list` - pages are looked
        up on demand rather than materialized up front, so list-only operations
        such as ``append()`` or concatenation with ``+`` are not available.

        Note:
            For PdfWriter only: Provides the capability to remove a page/range of
            page from the list (using the del operator). Remember: Only the page
            entry is removed, as the objects beneath can be used elsewhere. A
            solution to completely remove them - if they are not used anywhere - is
            to write to a buffer/temporary file and then load it into a new
            PdfWriter.

        """
        return _VirtualList(self.get_num_pages, self.get_page)

    @property
    def page_labels(self) -> list[str]:
        """
        A list of labels for the pages in this document.

        This property is read-only. The labels are in the order that the pages
        appear in the document.
        """
        return index2labels(self, len(self.pages))

    @property
    def page_layout(self) -> str | None:
        """
        Get the page layout currently being used.

        .. list-table:: Valid ``layout`` values
           :widths: 50 200

           * - /NoLayout
             - Layout explicitly not specified
           * - /SinglePage
             - Show one page at a time
           * - /OneColumn
             - Show one column at a time
           * - /TwoColumnLeft
             - Show pages in two columns, odd-numbered pages on the left
           * - /TwoColumnRight
             - Show pages in two columns, odd-numbered pages on the right
           * - /TwoPageLeft
             - Show two pages at a time, odd-numbered pages on the left
           * - /TwoPageRight
             - Show two pages at a time, odd-numbered pages on the right
        """
        try:
            return cast(NameObject, self.root_object[CA.PAGE_LAYOUT])
        except KeyError:
            return None

    @property
    def page_mode(self) -> PagemodeType | None:
        """
        Get the page mode currently being used.

        .. list-table:: Valid ``mode`` values
           :widths: 50 200

           * - /UseNone
             - Do not show outline or thumbnails panels
           * - /UseOutlines
             - Show outline (aka bookmarks) panel
           * - /UseThumbs
             - Show page thumbnails panel
           * - /FullScreen
             - Fullscreen view
           * - /UseOC
             - Show Optional Content Group (OCG) panel
           * - /UseAttachments
             - Show attachments panel
        """
        try:
            return self.root_object["/PageMode"]  # type: ignore[return-value]
        except KeyError:
            return None

    def _flatten(self, list_only: bool = False) -> None:
        """
        Process the document pages to ease searching.

        Attributes of a page may inherit from ancestor nodes
        in the page tree. Flattening means moving
        any inheritance data into descendant nodes,
        effectively removing the inheritance dependency.
        The result is stored in ``self.flattened_pages``.

        Note: It is distinct from another use of "flattening" applied to PDFs.
        Flattening a PDF also means combining all the contents into one single layer
        and making the file less editable.

        The page tree is walked with an explicit stack instead of recursion, so the
        traversal is bound by ``Configuration.page_tree_maximum_depth`` and
        ``Configuration.page_tree_maximum_entries`` only, not by the interpreter
        recursion limit.

        Args:
            list_only: If True, the page's own entries are not copied into the
                generated :class:`PageObject`. Attributes inherited from ancestor
                nodes are applied either way. Note that a page reached through an
                indirect reference is already populated by :class:`PageObject`
                itself, so this only has an effect for ``/Kids`` entries that are
                inline dictionaries.

        """
        configuration = get_configuration()
        self.flattened_pages = None
        pages = self.root_object.get("/Pages", NullObject()).get_object()
        if not isinstance(pages, DictionaryObject):
            raise PdfReadError("Invalid object in /Pages")

        flattened_pages: list[PageObject] = []
        traversal_state = _TraversalState()
        remaining_page_entries = _TraversalState(entry_count=configuration.page_tree_maximum_page_entries)
        # id() values of the nodes on the path from the root to the current node.
        # Detects multi-hop cycles such as A→B→C→A that the single-parent check misses.
        ancestor_ids: set[int] = set()
        # The /Pages nodes of that path whose /Kids are not exhausted yet.
        stack: list[_PageTreeFrame] = []
        item: _PageTreeItem | None = _PageTreeItem(
            node=pages, inherit={}, indirect_reference=None, depth=0
        )
        while item is not None:
            if item.depth > configuration.page_tree_maximum_depth:
                raise LimitReachedError(
                    f"Maximum page tree depth reached: {item.depth} > {configuration.page_tree_maximum_depth}."
                )

            # Get the current node_type
            node = item.node
            if PagesAttributes.TYPE in node:
                node_type = cast(str, node[PagesAttributes.TYPE])
            # if the page tree node has no /Type, consider as a page if /Kids is also missing
            elif PagesAttributes.KIDS not in node:
                # Without /Type, only accept it as a page if it carries a structural page key.
                if self.strict and not any(key in node for key in (PG.CONTENTS, PG.MEDIABOX, PG.PARENT)):
                    raise PdfReadError(f"Non-page object reached through /Kids: {node!r}")
                node_type = "/Page"
            else:
                node_type = "/Pages"

            # Flatten that type of node
            if node_type == "/Pages":
                ancestor_ids.add(id(node))
                stack.append(self._enter_page_tree_node(item))
            elif node_type == "/Page":
                flattened_pages.append(
                    self._flatten_leaf_page(
                        item=item, list_only=list_only, remaining_page_entries=remaining_page_entries
                    )
                )

            item = self._pop_next_page_tree_kid(stack, ancestor_ids, traversal_state)

        # Assigned only here, so that a failed traversal does not leave a partial page list behind.
        self.flattened_pages = flattened_pages

    def _enter_page_tree_node(self, item: _PageTreeItem) -> _PageTreeFrame:
        """
        Start walking an intermediate ``/Pages`` node: propagate its inheritable
        attributes and pair it with an iterator over its ``/Kids``.
        """
        pages = item.node
        # Copied before being modified, as the kids of the enclosing node share it.
        inherit = dict(item.inherit)
        for attr in _INHERITABLE_PAGE_ATTRIBUTES:
            if attr in pages:
                inherit[attr] = pages[attr]

        kids = pages.get(PagesAttributes.KIDS, ArrayObject()).get_object()
        if isinstance(kids, NullObject):
            kids = ArrayObject()
        elif not isinstance(kids, ArrayObject):
            raise PdfReadError(f"Expected /Kids to be an array, got {type(kids).__name__}.")

        return item._replace(inherit=inherit), iter(kids)

    def _pop_next_page_tree_kid(
        self,
        stack: list[_PageTreeFrame],
        ancestor_ids: set[int],
        traversal_state: _TraversalState,
    ) -> _PageTreeItem | None:
        """
        Return the next page tree node to flatten, leaving the ``/Pages`` nodes whose
        ``/Kids`` are exhausted, or ``None`` when the traversal is complete.

        Cyclic references and the configured page-tree entry limit are enforced here.
        """
        configuration = get_configuration()
        while stack:
            parent, kids = stack[-1]
            pages_reference = getattr(parent.node, "indirect_reference", object())
            for page in kids:
                if getattr(page, "indirect_reference", object()) == pages_reference:
                    raise PdfReadError("Detected cyclic page references.")

                obj = page.get_object()
                if not isinstance(obj, DictionaryObject):
                    if not is_null_or_none(obj):
                        logger_warning(
                            "Ignoring page tree entry that is not a dictionary: %(entry)s",
                            source=__name__,
                            entry=obj,
                        )
                    # damaged file may have invalid child in /Pages
                    continue
                if not obj:
                    # An empty dictionary would otherwise be read as a blank page.
                    continue
                if id(obj) in ancestor_ids:
                    raise PdfReadError("Detected cyclic page references.")
                traversal_state.entry_count += 1
                if traversal_state.entry_count > configuration.page_tree_maximum_entries:
                    raise LimitReachedError(
                        "Maximum page tree entry limit reached: "
                        f"{traversal_state.entry_count} > {configuration.page_tree_maximum_entries}."
                    )
                return _PageTreeItem(
                    node=obj,
                    inherit=parent.inherit,
                    indirect_reference=page if isinstance(page, IndirectObject) else None,
                    depth=parent.depth + 1,
                )
            stack.pop()
            ancestor_ids.discard(id(parent.node))
        return None

    def _flatten_leaf_page(
            self, *, item: _PageTreeItem, list_only: bool, remaining_page_entries: _TraversalState
    ) -> PageObject:
        """
        Build the :class:`PageObject` for a leaf ``/Page`` node.

        ``list_only`` suppresses copying the page's own entries; the inherited
        attributes are applied regardless. When the node has an indirect reference,
        :class:`PageObject` has already copied those entries in its constructor,
        so the flag only matters for inline ``/Kids`` dictionaries.
        """
        node = item.node

        # Indirect PageObjects are populated by the constructor even when
        # list_only=True. Inline dictionaries are copied only when list_only=False.
        entry_count = (
            len(node)
            if item.indirect_reference is not None or not list_only
            else 0
        )

        # Inherited attributes are inserted only when missing from the page.
        entry_count += sum(
            attribute not in node for attribute in item.inherit
        )

        remaining_page_entries.entry_count -= entry_count
        if remaining_page_entries.entry_count < 0:
            raise LimitReachedError("Maximum page tree page entry limit exceeded!")

        page = PageObject(self, item.indirect_reference)
        if not list_only:
            page.update(node)
        for attribute, value in item.inherit.items():
            # If the page has its own value, it does not inherit the parent's value.
            if attribute not in page:
                page[attribute] = value

        return page

    def remove_page(
        self,
        page: int | PageObject | IndirectObject,
        clean: bool = False,
    ) -> None:
        """
        Remove page from pages list.

        Args:
            page:
                * :class:`int`: Page number to be removed.
                * :class:`~pypdf._page.PageObject`: page to be removed. If the page appears many times
                  only the first one will be removed.
                * :class:`~pypdf.generic.IndirectObject`: Reference to page to be removed.

            clean: replace PageObject with NullObject to prevent annotations
                or destinations to reference a detached page.

        """
        if self.flattened_pages is None:
            self._flatten(self._readonly)
        assert self.flattened_pages is not None
        if isinstance(page, IndirectObject):
            p = page.get_object()
            if not isinstance(p, PageObject):
                logger_warning("IndirectObject is not referencing a page", source=__name__)
                return
            page = p

        if not isinstance(page, int):
            try:
                page = self.flattened_pages.index(page)
            except ValueError:
                logger_warning("Cannot find page in pages", source=__name__)
                return
        if not (0 <= page < len(self.flattened_pages)):
            logger_warning("Page number is out of range", source=__name__)
            return

        ind = self.pages[page].indirect_reference
        # `pages` is typed as a Sequence because it is not a list, but the
        # concrete _VirtualList does implement deletion.
        del cast(_VirtualList, self.pages)[page]
        if clean and ind is not None:
            self._replace_object(ind, NullObject())

    def _get_indirect_object(self, num: int, gen: int) -> PdfObject | None:
        """
        Used to ease development.

        This is equivalent to generic.IndirectObject(num,gen,self).get_object()

        Args:
            num: The object number of the indirect object.
            gen: The generation number of the indirect object.

        Returns:
            A PdfObject

        """
        return IndirectObject(num, gen, self).get_object()

    @property
    def user_access_permissions(self) -> UserAccessPermissions | None:
        """
        Get the user access permissions for encrypted documents.
        Returns None if not encrypted.

        .. warning::

            For AES-256 encrypted documents (R=5/R=6), the returned
            permissions are derived from the ``/P`` field, which is
            only trustworthy if the ``/Perms`` integrity check passed.
            Check :attr:`are_permissions_valid` to verify.
        """
        if self._encryption is None:
            return None
        return UserAccessPermissions(self._encryption.P)

    @property
    def are_permissions_valid(self) -> bool | None:
        """
        Whether the ``/Perms`` integrity check passed for this document.

        For AES-256 encrypted documents (R=5/R=6), the ``/Perms`` field
        is an encrypted copy of the permissions that can be verified
        independently. Returns ``False`` if this check fails (the ``/P``
        permissions may have been tampered with).

        Returns ``None`` if the document is not encrypted or has not yet
        been decrypted via :meth:`decrypt()<pypdf.PdfReader.decrypt>`.
        Returns ``True`` for non-AES-256 encryption (no ``/Perms`` to check).
        """
        if self._encryption is None:
            return None
        if not self._encryption.is_decrypted():
            return None
        return self._encryption._are_permissions_valid

    @property
    @abstractmethod
    def is_encrypted(self) -> bool:
        """
        Read-only boolean property showing whether this PDF file is encrypted.

        Note that this property, if true, will remain true even after the
        :meth:`decrypt()<pypdf.PdfReader.decrypt>` method is called.
        """
        ...  # pragma: no cover

    @property
    def xfa(self) -> dict[str, bytes] | None:

        catalog = self.root_object

        if "/AcroForm" not in catalog or not catalog["/AcroForm"]:
            return None

        tree = cast(TreeObject, catalog["/AcroForm"])
        retval: dict[str, bytes] = {}

        if "/XFA" not in tree:
            return retval

        fields = tree["/XFA"].get_object()
        if not isinstance(fields, ArrayObject):
            logger_warning(
                "XFA entry is not an array: %(fields)s",
                source=__name__,
                fields=fields,
            )
            return retval

        accumulated_length = 0
        decoding_work_maximum_length = get_configuration().xfa_decoding_work_maximum_length

        field_iterator = iter(fields)
        for field in field_iterator:
            tag = field
            field = next(field_iterator, None)
            if is_null_or_none(field):
                continue
            assert field is not None, "mypy"

            field = cast(StreamObject | None, field.get_object())
            if is_null_or_none(field):
                continue
            assert field is not None, "mypy"

            decoded_data = field.get_data()
            accumulated_length += len(decoded_data)

            if accumulated_length > decoding_work_maximum_length:
                raise LimitReachedError(
                    "XFA decoding exceeded the maximum accumulated "
                    f"decoding work of {decoding_work_maximum_length} bytes."
                )

            retval[tag] = decoded_data
        return retval

    @property
    def attachments(self) -> Mapping[str, list[bytes]]:
        """Mapping of attachment filenames to their content."""
        entries: dict[str, list[EmbeddedFile]] = {}

        for entry in self.attachment_list:
            for name in entry._names:
                entries.setdefault(name, []).append(entry)

        return LazyDict(
            {
                name: (self._get_attachment_contents, attachment_entries)
                for name, attachment_entries in entries.items()
            }
        )

    @classmethod
    def _get_attachment_contents(cls, entries: list[EmbeddedFile]) -> list[bytes]:
        return [entry.content for entry in entries]

    @property
    def attachment_list(self) -> Iterator[EmbeddedFile]:
        """Iterable of attachment objects."""
        yield from EmbeddedFile._load(self.root_object, strict=self.strict)

    @abstractmethod
    def _repr_mimebundle_(
        self,
        include: Iterable[str] | None = None,
        exclude: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """
        Integration into Jupyter Notebooks.

        This method returns a dictionary that maps a mime-type to its
        representation.

        .. seealso::

            https://ipython.readthedocs.io/en/stable/config/integrating.html
        """
        ...  # pragma: no cover


class LazyDict(Mapping[Any, Any]):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._raw_dict = dict(*args, **kwargs)

    def __getitem__(self, key: str) -> Any:
        func, arg = self._raw_dict.__getitem__(key)
        return func(arg)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._raw_dict)

    def __len__(self) -> int:
        return len(self._raw_dict)

    def __str__(self) -> str:
        return f"LazyDict(keys={list(self.keys())})"
