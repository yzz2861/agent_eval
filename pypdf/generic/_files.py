from __future__ import annotations

import bisect
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from typing import TYPE_CHECKING, Any, cast

from pypdf._utils import format_iso8824_date, logger_warning, parse_iso8824_date
from pypdf.constants import CatalogAttributes as CA
from pypdf.constants import FileSpecificationDictionaryEntries
from pypdf.constants import PageAttributes as PG
from pypdf.errors import PdfReadError, PyPdfError
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DecodedStreamObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    NullObject,
    NumberObject,
    StreamObject,
    TextStringObject,
    is_null_or_none,
)

if TYPE_CHECKING:
    import datetime
    from collections.abc import Iterable, Iterator

    from pypdf._writer import PdfWriter


class EmbeddedFile:
    """
    Container holding the information on an embedded file.

    Attributes are evaluated lazily if possible.

    Further information on embedded files can be found in section 7.11 of the PDF 2.0 specification.
    """
    def __init__(self, name: str, pdf_object: DictionaryObject, parent: ArrayObject | None = None) -> None:
        """
        Args:
            name: The (primary) name as provided in the name tree.
            pdf_object: The corresponding PDF object to allow retrieving further data.
            parent: The parent list.
        """
        self._name = name
        self.pdf_object = pdf_object
        self._parent = parent

    @property
    def name(self) -> str:
        """
        The (primary) name of the embedded file as provided in the name tree.

        .. warning::

            This value can contain arbitrary characters. Please make sure to sanitize it before
            using it to write the file content to the disk for example.
        """
        return self._name

    @classmethod
    def _create_new(cls, writer: PdfWriter, name: str, content: str | bytes) -> EmbeddedFile:
        """
        Create a new embedded file and add it to the PdfWriter.

        Args:
            writer: The PdfWriter instance to add the embedded file to.
            name: The filename to display.
            content: The data in the file.

        Returns:
            EmbeddedFile instance for the newly created embedded file.
        """
        # Convert string content to bytes if needed
        if isinstance(content, str):
            content = content.encode("latin-1")

        # Create the file entry (the actual embedded file stream)
        file_entry = DecodedStreamObject()
        file_entry.set_data(content)
        file_entry.update({NameObject(PG.TYPE): NameObject("/EmbeddedFile")})

        # Create the /EF entry
        ef_entry = DictionaryObject()
        ef_entry.update({NameObject("/F"): writer._add_object(file_entry)})

        # Create the filespec dictionary
        from pypdf.generic import create_string_object  # noqa: PLC0415
        filespec = DictionaryObject()
        filespec_reference = writer._add_object(filespec)
        name_object = cast(TextStringObject, create_string_object(name))
        filespec.update(
            {
                NameObject(PG.TYPE): NameObject("/Filespec"),
                NameObject(FileSpecificationDictionaryEntries.F): name_object,
                NameObject(FileSpecificationDictionaryEntries.EF): ef_entry,
            }
        )

        # Add the name and filespec to the names array.
        # We use the inverse order for insertion, as this allows us to re-use the
        # same index.
        names_array = cls._get_names_array(writer)
        insertion_index = cls._get_insertion_index(names_array, name_object)
        names_array.insert(insertion_index, filespec_reference)
        names_array.insert(insertion_index, name_object)

        # Return an EmbeddedFile instance
        return cls(name=name, pdf_object=filespec, parent=names_array)

    @classmethod
    def _get_names_array(cls, writer: PdfWriter) -> ArrayObject:
        """Get the names array for embedded files, possibly creating and flattening it."""
        if CA.NAMES not in writer.root_object:
            # Add the /Names entry to the catalog.
            writer.root_object[NameObject(CA.NAMES)] = writer._add_object(DictionaryObject())

        names_dict = cast(DictionaryObject, writer.root_object[CA.NAMES])
        if "/EmbeddedFiles" not in names_dict:
            # We do not yet have an entry for embedded files. Create and return it.
            names = ArrayObject()
            embedded_files_names_dictionary = DictionaryObject(
                {NameObject(CA.NAMES): names}
            )
            names_dict[NameObject("/EmbeddedFiles")] = writer._add_object(embedded_files_names_dictionary)
            return names

        # We have an existing embedded files entry.
        embedded_files_names_tree = cast(DictionaryObject, names_dict["/EmbeddedFiles"])
        if "/Names" in embedded_files_names_tree:
            # Simple case: We already have a flat list.
            return cast(ArrayObject, embedded_files_names_tree[NameObject(CA.NAMES)])
        if "/Kids" not in embedded_files_names_tree:
            # Invalid case: This is no name tree.
            raise PdfReadError("Got neither Names nor Kids in embedded files tree.")

        # Complex case: Convert a /Kids-based name tree to a /Names-based one.
        # /Name-based ones are much easier to handle and allow us to simplify the
        # actual insertion logic by only having to consider one case.
        names = ArrayObject()
        kids = cast(ArrayObject, embedded_files_names_tree["/Kids"].get_object())
        embedded_files_names_dictionary = DictionaryObject(
            {NameObject(CA.NAMES): names}
        )
        names_dict[NameObject("/EmbeddedFiles")] = writer._add_object(embedded_files_names_dictionary)
        for kid in kids:
            # Write the flattened file entries. As we do not change the actual files,
            # this should not have any impact on references to them.
            # There might be further (nested) kids here.
            # Wait for an example before evaluating an implementation.
            for name in kid.get_object().get("/Names", []):
                names.append(name)
        return names

    @classmethod
    def _get_insertion_index(cls, names_array: ArrayObject, name: str) -> int:
        keys = [names_array[i].encode("utf-8") for i in range(0, len(names_array), 2)]
        name_bytes = name.encode("utf-8")

        start = bisect.bisect_left(keys, name_bytes)
        end = bisect.bisect_right(keys, name_bytes)

        if start != end:
            return end * 2
        if start == 0:
            return 0
        if start == (key_count := len(keys)):
            return key_count * 2
        return end * 2

    @property
    def alternative_name(self) -> str | None:
        """
        Retrieve the alternative name (as per the file specification dictionary).

        .. warning::

            This value can contain arbitrary characters. Please make sure to sanitize it before
            using it to write the file content to the disk for example.
        """
        for key in [FileSpecificationDictionaryEntries.UF, FileSpecificationDictionaryEntries.F]:
            # PDF 2.0 reference, table 43:
            #   > A PDF reader shall use the value of the UF key, when present, instead of the F key.
            if key in self.pdf_object:
                value = self.pdf_object[key].get_object()
                if not is_null_or_none(value):
                    return cast(str, value)
        return None

    @alternative_name.setter
    def alternative_name(self, value: TextStringObject | None) -> None:
        """Set the alternative name (as per the file specification dictionary)."""
        if value is None:
            if FileSpecificationDictionaryEntries.UF in self.pdf_object:
                self.pdf_object[NameObject(FileSpecificationDictionaryEntries.UF)] = NullObject()
            if FileSpecificationDictionaryEntries.F in self.pdf_object:
                self.pdf_object[NameObject(FileSpecificationDictionaryEntries.F)] = NullObject()
        else:
            self.pdf_object[NameObject(FileSpecificationDictionaryEntries.UF)] = value
            self.pdf_object[NameObject(FileSpecificationDictionaryEntries.F)] = value

    @property
    def description(self) -> str | None:
        """Retrieve the description."""
        value = self.pdf_object.get(FileSpecificationDictionaryEntries.DESC)
        if is_null_or_none(value):
            return None
        return value

    @description.setter
    def description(self, value: TextStringObject | None) -> None:
        """Set the description."""
        if value is None:
            self.pdf_object[NameObject(FileSpecificationDictionaryEntries.DESC)] = NullObject()
        else:
            self.pdf_object[NameObject(FileSpecificationDictionaryEntries.DESC)] = value

    @property
    def associated_file_relationship(self) -> str:
        """Retrieve the relationship of the referring document to this embedded file."""
        return cast(
            NameObject,
            self.pdf_object.get("/AFRelationship", NameObject("/Unspecified")),
        )

    @associated_file_relationship.setter
    def associated_file_relationship(self, value: NameObject) -> None:
        """Set the relationship of the referring document to this embedded file."""
        self.pdf_object[NameObject("/AFRelationship")] = value

    @property
    def _embedded_file(self) -> StreamObject:
        """Retrieve the actual embedded file stream."""
        if "/EF" not in self.pdf_object:
            raise PdfReadError(f"/EF entry not found: {self.pdf_object}")
        ef = cast(DictionaryObject, self.pdf_object["/EF"])
        for key in [FileSpecificationDictionaryEntries.UF, FileSpecificationDictionaryEntries.F]:
            if key in ef:
                return cast(StreamObject, ef[key].get_object())
        raise PdfReadError(f"No /(U)F key found in file dictionary: {ef}")

    @property
    def _params(self) -> DictionaryObject:
        """Retrieve the file-specific parameters."""
        return cast(DictionaryObject, self._embedded_file.get("/Params", DictionaryObject()).get_object())

    @cached_property
    def _ensure_params(self) -> DictionaryObject:
        """Ensure the /Params dictionary exists and return it."""
        embedded_file = self._embedded_file
        if "/Params" not in embedded_file:
            embedded_file[NameObject("/Params")] = DictionaryObject()
        return cast(DictionaryObject, embedded_file["/Params"])

    @property
    def subtype(self) -> str | None:
        """Retrieve the subtype. This is a MIME media type, prefixed by a slash."""
        value = self._embedded_file.get("/Subtype")
        if is_null_or_none(value):
            return None
        return value

    @subtype.setter
    def subtype(self, value: NameObject | None) -> None:
        """Set the subtype. This should be a MIME media type, prefixed by a slash."""
        embedded_file = self._embedded_file
        if value is None:
            embedded_file[NameObject("/Subtype")] = NullObject()
        else:
            embedded_file[NameObject("/Subtype")] = value

    @property
    def content(self) -> bytes:
        """Retrieve the actual file content."""
        return self._embedded_file.get_data()

    @content.setter
    def content(self, value: str | bytes) -> None:
        """Set the file content."""
        if isinstance(value, str):
            value = value.encode("latin-1")
        self._embedded_file.set_data(value)

    @property
    def size(self) -> int | None:
        """Retrieve the size of the uncompressed file in bytes."""
        value = self._params.get("/Size")
        if is_null_or_none(value):
            return None
        return value

    @size.setter
    def size(self, value: NumberObject | None) -> None:
        """Set the size of the uncompressed file in bytes."""
        params = self._ensure_params
        if value is None:
            params[NameObject("/Size")] = NullObject()
        else:
            params[NameObject("/Size")] = value

    @property
    def creation_date(self) -> datetime.datetime | None:
        """Retrieve the file creation datetime."""
        return parse_iso8824_date(self._params.get("/CreationDate"))

    @creation_date.setter
    def creation_date(self, value: datetime.datetime | None) -> None:
        """Set the file creation datetime."""
        params = self._ensure_params
        if value is None:
            params[NameObject("/CreationDate")] = NullObject()
        else:
            date_str = format_iso8824_date(value)
            params[NameObject("/CreationDate")] = TextStringObject(date_str)

    @property
    def modification_date(self) -> datetime.datetime | None:
        """Retrieve the datetime of the last file modification."""
        return parse_iso8824_date(self._params.get("/ModDate"))

    @modification_date.setter
    def modification_date(self, value: datetime.datetime | None) -> None:
        """Set the datetime of the last file modification."""
        params = self._ensure_params
        if value is None:
            params[NameObject("/ModDate")] = NullObject()
        else:
            date_str = format_iso8824_date(value)
            params[NameObject("/ModDate")] = TextStringObject(date_str)

    @property
    def checksum(self) -> bytes | None:
        """Retrieve the MD5 checksum of the (uncompressed) file."""
        value = self._params.get("/CheckSum")
        if is_null_or_none(value):
            return None
        return value

    @checksum.setter
    def checksum(self, value: ByteStringObject | None) -> None:
        """Set the MD5 checksum of the (uncompressed) file."""
        params = self._ensure_params
        if value is None:
            params[NameObject("/CheckSum")] = NullObject()
        else:
            params[NameObject("/CheckSum")] = value

    @property
    def _names(self) -> Iterator[str]:
        yield self.name
        if self.alternative_name is not None and self.alternative_name != self.name:
            yield self.alternative_name

    def delete(self) -> None:
        """Delete the file from the document."""
        if not self._parent:
            raise PyPdfError("Parent required to delete file from document.")
        if self.pdf_object in self._parent:
            index = self._parent.index(self.pdf_object)
        elif (
                (indirect_reference := getattr(self.pdf_object, "indirect_reference", None)) is not None
                and indirect_reference in self._parent
        ):
            index = self._parent.index(indirect_reference)
        else:
            raise PyPdfError("File not found in parent object.")
        self._parent.pop(index)  # Reference.
        self._parent.pop(index - 1)  # Name.
        self.pdf_object = DictionaryObject()  # Invalidate.

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"

    @staticmethod
    def _report_malformed(message: str, strict: bool) -> None:
        """Raise an exception in strict mode, warn otherwise."""
        if strict:
            raise PdfReadError(message)
        logger_warning(message, source=__name__)

    @classmethod
    def _load_from_names(cls, names: ArrayObject, strict: bool = False) -> Iterator[EmbeddedFile]:
        """
        Convert the given name tree into class instances.

        Args:
            names: The name tree to load the data from.
            strict: Whether to raise an exception on a file specification that is not a dictionary
                instead of issuing a warning and skipping it.

        Returns:
            Iterable of class instances for the files found.
        """
        # This is a name tree of the format [name_1, reference_1, name_2, reference_2, ...]
        for i, name in enumerate(names):
            if not isinstance(name, str):
                # Skip plain strings and retrieve them as `direct_name` by index.
                file_dictionary = name.get_object()
                if isinstance(file_dictionary, NullObject):
                    # A null value is equivalent to an omitted entry.
                    continue
                if not isinstance(file_dictionary, DictionaryObject):
                    cls._report_malformed(
                        f"Embedded file specification is not a dictionary: {file_dictionary}", strict=strict
                    )
                    continue
                direct_name = names[i - 1].get_object()
                yield EmbeddedFile(name=direct_name, pdf_object=file_dictionary, parent=names)

    @classmethod
    def _load(cls, catalog: DictionaryObject, strict: bool = False) -> Iterator[EmbeddedFile]:
        """
        Load the embedded files for the given document catalog.

        This method and its signature are considered internal API and thus not exposed publicly for now.

        Args:
            catalog: The document catalog to load from.
            strict: Whether to raise an exception on malformed name trees
                instead of issuing a warning and skipping them.

        Returns:
            Iterable of class instances for the files found.
        """
        if "/Names" not in catalog:
            return
        names = catalog["/Names"]
        if isinstance(names, NullObject):
            # A null value is equivalent to an omitted entry.
            return
        if not isinstance(names, DictionaryObject):
            cls._report_malformed(f"Names tree is not a dictionary: {names}", strict=strict)
            return
        if "/EmbeddedFiles" not in names:
            return
        container = names["/EmbeddedFiles"]
        if isinstance(container, NullObject):
            return
        if not isinstance(container, DictionaryObject):
            cls._report_malformed(f"Embedded files entry is not a dictionary: {container}", strict=strict)
            return

        if "/Kids" in container:
            kids = container["/Kids"].get_object()
            if isinstance(kids, NullObject):
                kids = ArrayObject()
            elif not isinstance(kids, ArrayObject):
                cls._report_malformed(f"Embedded files /Kids is not an array: {kids}", strict=strict)
                return
            for kid in kids:
                # There might be further (nested) kids here.
                # Wait for an example before evaluating an implementation.
                kid = kid.get_object()
                if not isinstance(kid, DictionaryObject):
                    cls._report_malformed(f"Embedded files kid is not a dictionary: {kid}", strict=strict)
                    continue
                if "/Names" not in kid:
                    continue
                kid_names = kid["/Names"].get_object()
                if isinstance(kid_names, NullObject):
                    continue
                if not isinstance(kid_names, ArrayObject):
                    cls._report_malformed(f"Embedded files name list is not an array: {kid_names}", strict=strict)
                    continue
                yield from cls._load_from_names(kid_names, strict=strict)
        if "/Names" in container:
            container_names = container["/Names"].get_object()
            if isinstance(container_names, NullObject):
                return
            if not isinstance(container_names, ArrayObject):
                cls._report_malformed(f"Embedded files name list is not an array: {container_names}", strict=strict)
                return
            yield from cls._load_from_names(container_names, strict=strict)


class AttachmentSource(str, Enum):
    """The location within a document at which an attachment is referenced."""

    DOCUMENT_NAME_TREE = "document-name-tree"
    """The document's embedded files name tree (catalog ``/Names`` entry)."""
    DOCUMENT_ASSOCIATED_FILE = "document-associated-file"
    """The catalog ``/AF`` array (associated files, PDF 2.0)."""
    PAGE_ASSOCIATED_FILE = "page-associated-file"
    """A page's ``/AF`` array (associated files, PDF 2.0)."""
    ANNOTATION = "annotation"
    """An annotation's ``/FS`` entry (e.g. a FileAttachment annotation)."""


class AttachmentFlag(str, Enum):
    """A noteworthy property of an attachment record."""

    NAME_CONFLICT = "name-conflict"
    """The same name is used by records with different content."""
    EXTERNAL_FILESPEC = "external-filespec"
    """The file specification has no ``/EF`` entry; the file is not embedded."""
    BROKEN_REFERENCE = "broken-reference"
    """A reference could not be resolved to a file specification or stream."""


@dataclass(frozen=True)
class ObjectIdentity:
    """
    The identity of a PDF object within one reader session.

    Indirect objects are identified by their object and generation number,
    direct objects by their in-memory identity. Two references denote the
    same object if and only if their identities are equal.
    """

    indirect: tuple[int, int] | None = None
    """Object and generation number for indirect objects, ``None`` otherwise."""
    direct: int | None = None
    """In-memory identity for direct objects, ``None`` otherwise."""

    @classmethod
    def of(cls, obj: Any) -> ObjectIdentity:
        """Determine the identity of the given (possibly indirect) object."""
        if obj is None:
            return cls()
        if isinstance(obj, IndirectObject):
            return cls(indirect=(obj.idnum, obj.generation))
        indirect_reference = getattr(obj, "indirect_reference", None)
        if indirect_reference is not None:
            return cls(indirect=(indirect_reference.idnum, indirect_reference.generation))
        return cls(direct=id(obj))

    def __str__(self) -> str:
        if self.indirect is not None:
            return f"{self.indirect[0]} {self.indirect[1]} R"
        if self.direct is not None:
            return f"direct object 0x{self.direct:x}"
        return "unresolvable object"


@dataclass(frozen=True)
class AttachmentReference:
    """A single location at which an attachment is referenced."""

    source: AttachmentSource
    """Where in the document the reference was found."""
    name: str | None
    """The name used at this location, if any could be determined."""
    filespec: ObjectIdentity
    """The identity of the referenced file specification dictionary."""
    page_index: int | None = None
    """The 0-based page index for page-level and annotation references."""


@dataclass
class AttachmentRecord:
    """
    All references to one embedded file stream (or one unresolvable reference target).

    References from different sources that resolve to the same embedded file
    stream are grouped into a single record, so no relationship is lost when
    the same content is reachable through several names or locations.
    """

    stream: ObjectIdentity | None
    """The identity of the embedded file stream, ``None`` for external or broken references."""
    names: tuple[str, ...]
    """All names under which this record is referenced, sorted."""
    references: tuple[AttachmentReference, ...]
    """All locations at which this record is referenced."""
    flags: frozenset[AttachmentFlag] = frozenset()

    @property
    def filespecs(self) -> tuple[ObjectIdentity, ...]:
        """The identities of all file specification dictionaries referencing this record."""
        seen: dict[ObjectIdentity, None] = {}
        for reference in self.references:
            seen.setdefault(reference.filespec)
        return tuple(seen)

    @property
    def has_name_conflict(self) -> bool:
        """Whether any of this record's names is also used by a different record."""
        return AttachmentFlag.NAME_CONFLICT in self.flags

    @property
    def is_external(self) -> bool:
        """Whether this record describes a file that is not embedded in the document."""
        return AttachmentFlag.EXTERNAL_FILESPEC in self.flags

    @property
    def is_broken(self) -> bool:
        """Whether any reference of this record could not be fully resolved."""
        return AttachmentFlag.BROKEN_REFERENCE in self.flags

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} names={list(self.names)!r} "
            f"stream={self.stream} flags={sorted(self.flags)!r}>"
        )


@dataclass
class _RecordBuilder:
    """Mutable accumulator for an AttachmentRecord while scanning."""

    stream: ObjectIdentity | None = None
    names: set[str] = field(default_factory=set)
    references: list[AttachmentReference] = field(default_factory=list)
    flags: set[AttachmentFlag] = field(default_factory=set)


class AttachmentInventory(Sequence[AttachmentRecord]):
    """
    Read-only inventory of all attachment references in a document.

    The inventory collects references from the document's embedded files name
    tree, the catalog and page ``/AF`` arrays, and annotation ``/FS`` entries.
    References resolving to the same embedded file stream are grouped into a
    single :class:`AttachmentRecord`, identified by object identity.

    The inventory is purely informational: it never decodes stream content
    and never writes any attachment data to disk.
    """

    def __init__(self, records: Iterable[AttachmentRecord]) -> None:
        self._records = list(records)

    def __len__(self) -> int:
        return len(self._records)

    def __getitem__(self, index: int) -> AttachmentRecord:
        return self._records[index]

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} records={len(self._records)}>"

    def find_by_name(self, name: str) -> list[AttachmentRecord]:
        """Return all records referenced under the given name."""
        return [record for record in self._records if name in record.names]

    def find_by_stream(self, stream: ObjectIdentity) -> AttachmentRecord | None:
        """Return the record for the given embedded stream identity, if any."""
        for record in self._records:
            if record.stream is not None and record.stream == stream:
                return record
        return None

    @staticmethod
    def _filespec_display_name(filespec: DictionaryObject) -> str | None:
        """Retrieve the display name of a file specification dictionary."""
        for key in (FileSpecificationDictionaryEntries.UF, FileSpecificationDictionaryEntries.F):
            value = filespec.get(key)
            if is_null_or_none(value):
                continue
            value = value.get_object()
            if isinstance(value, str):
                return str(value)
        return None

    @staticmethod
    def _resolve_stream(filespec: DictionaryObject) -> tuple[Any, AttachmentFlag | None]:
        """
        Resolve the embedded file stream of a file specification dictionary.

        Returns the (unresolved) stream object and ``None`` on success, or
        ``None`` and the applicable flag otherwise.
        """
        ef = filespec.get("/EF")
        if ef is None:
            return None, AttachmentFlag.EXTERNAL_FILESPEC
        ef = ef.get_object()
        if not isinstance(ef, DictionaryObject):
            return None, AttachmentFlag.BROKEN_REFERENCE
        for key in (
            FileSpecificationDictionaryEntries.UF,
            FileSpecificationDictionaryEntries.F,
            FileSpecificationDictionaryEntries.DOS,
            FileSpecificationDictionaryEntries.Mac,
            FileSpecificationDictionaryEntries.Unix,
        ):
            value = ef.get(key)
            if is_null_or_none(value):
                continue
            if isinstance(value.get_object(), StreamObject):
                return value, None
            return None, AttachmentFlag.BROKEN_REFERENCE
        return None, AttachmentFlag.BROKEN_REFERENCE

    @classmethod
    def _iter_name_tree_entries(cls, catalog: DictionaryObject) -> Iterator[tuple[str | None, Any]]:
        """
        Yield ``(name, value)`` pairs from the embedded files name tree.

        Unlike :meth:`EmbeddedFile._load`, malformed entries are yielded as
        well (with a ``None`` name or a non-dictionary value) so that they can
        be flagged as broken references.
        """
        names_dict = catalog.get("/Names")
        if is_null_or_none(names_dict):
            return
        names_dict = names_dict.get_object()
        if not isinstance(names_dict, DictionaryObject):
            return
        container = names_dict.get("/EmbeddedFiles")
        if is_null_or_none(container):
            return
        container = container.get_object()
        if not isinstance(container, DictionaryObject):
            return

        name_arrays: list[Any] = []
        kids = container.get("/Kids")
        if not is_null_or_none(kids):
            kids = kids.get_object()
            if isinstance(kids, ArrayObject):
                for kid in kids:
                    kid = kid.get_object()
                    if isinstance(kid, DictionaryObject) and "/Names" in kid:
                        name_arrays.append(kid["/Names"])
        if "/Names" in container:
            name_arrays.append(container["/Names"])

        for name_array in name_arrays:
            name_array = name_array.get_object()
            if not isinstance(name_array, ArrayObject):
                continue
            for i in range(0, len(name_array), 2):
                name_object = name_array[i].get_object()
                name = str(name_object) if isinstance(name_object, str) else None
                value = name_array[i + 1] if i + 1 < len(name_array) else None
                yield name, value

    @classmethod
    def _iter_af_entries(cls, dictionary: DictionaryObject) -> Iterator[Any]:
        """Yield the file specifications of an ``/AF`` array."""
        af = dictionary.get("/AF")
        if is_null_or_none(af):
            return
        af = af.get_object()
        if not isinstance(af, ArrayObject):
            return
        yield from af

    @classmethod
    def _collect_references(
        cls, catalog: DictionaryObject, pages: Iterable[DictionaryObject]
    ) -> list[tuple[AttachmentSource, str | None, int | None, Any]]:
        """Collect raw ``(source, name, page_index, value)`` references."""
        raw: list[tuple[AttachmentSource, str | None, int | None, Any]] = []
        for name, value in cls._iter_name_tree_entries(catalog):
            raw.append((AttachmentSource.DOCUMENT_NAME_TREE, name, None, value))
        for value in cls._iter_af_entries(catalog):
            raw.append((AttachmentSource.DOCUMENT_ASSOCIATED_FILE, None, None, value))
        for page_index, page in enumerate(pages):
            for value in cls._iter_af_entries(page):
                raw.append((AttachmentSource.PAGE_ASSOCIATED_FILE, None, page_index, value))
            annots = page.get("/Annots")
            if is_null_or_none(annots):
                continue
            annots = annots.get_object()
            if not isinstance(annots, ArrayObject):
                continue
            for annot in annots:
                annot = annot.get_object()
                if isinstance(annot, DictionaryObject) and "/FS" in annot:
                    raw.append((AttachmentSource.ANNOTATION, None, page_index, annot["/FS"]))
        return raw

    @classmethod
    def _build(
        cls, catalog: DictionaryObject, pages: Iterable[DictionaryObject]
    ) -> AttachmentInventory:
        """
        Build the inventory from a document catalog and its pages.

        This method and its signature are considered internal API and thus not exposed publicly for now.
        """
        builders: dict[Any, _RecordBuilder] = {}
        for source, name, page_index, value in cls._collect_references(catalog, pages):
            filespec = value.get_object() if value is not None else None
            filespec_identity = ObjectIdentity.of(value)
            flags: set[AttachmentFlag] = set()
            stream_identity: ObjectIdentity | None = None
            if name is None and source == AttachmentSource.DOCUMENT_NAME_TREE:
                flags.add(AttachmentFlag.BROKEN_REFERENCE)
            if not isinstance(filespec, DictionaryObject):
                flags.add(AttachmentFlag.BROKEN_REFERENCE)
            else:
                if name is None:
                    name = cls._filespec_display_name(filespec)
                stream_value, flag = cls._resolve_stream(filespec)
                if flag is not None:
                    flags.add(flag)
                if stream_value is not None:
                    stream_identity = ObjectIdentity.of(stream_value)

            if stream_identity is not None:
                key: Any = ("stream", stream_identity)
            elif filespec is not None:
                key = ("filespec", filespec_identity)
            else:
                key = ("unresolvable", len(builders))
            builder = builders.setdefault(key, _RecordBuilder())
            if stream_identity is not None:
                builder.stream = stream_identity
            if name is not None:
                builder.names.add(name)
            builder.flags.update(flags)
            builder.references.append(
                AttachmentReference(
                    source=source,
                    name=name,
                    filespec=filespec_identity,
                    page_index=page_index,
                )
            )

        # Flag name conflicts: a name used by more than one record.
        records_by_name: dict[str, set[Any]] = {}
        for key, builder in builders.items():
            for name in builder.names:
                records_by_name.setdefault(name, set()).add(key)
        for name, keys in records_by_name.items():
            if len(keys) > 1:
                for key in keys:
                    builders[key].flags.add(AttachmentFlag.NAME_CONFLICT)

        return cls(
            AttachmentRecord(
                stream=builder.stream,
                names=tuple(sorted(builder.names)),
                references=tuple(builder.references),
                flags=frozenset(builder.flags),
            )
            for builder in builders.values()
        )
