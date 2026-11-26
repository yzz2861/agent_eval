from __future__ import annotations

import bisect
from functools import cached_property
from typing import TYPE_CHECKING, cast

from pypdf._utils import format_iso8824_date, logger_warning, parse_iso8824_date
from pypdf.constants import AFRelationship, FileSpecificationDictionaryEntries
from pypdf.constants import CatalogAttributes as CA
from pypdf.constants import PageAttributes as PG
from pypdf.errors import PdfReadError, PyPdfError
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DecodedStreamObject,
    DictionaryObject,
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
    def __init__(
        self,
        name: str,
        pdf_object: DictionaryObject,
        parent: ArrayObject | None = None,
        *,
        is_name_tree_entry: bool = True,
        page_indexes: Iterable[int] | None = None,
    ) -> None:
        """
        Args:
            name: The (primary) name as provided in the name tree.
            pdf_object: The corresponding PDF object to allow retrieving further data.
            parent: The parent list.
            is_name_tree_entry: Whether ``parent`` is a name tree entry list.
            page_indexes: Zero-based indexes of pages this file is associated with.
        """
        self._name = name
        self.pdf_object = pdf_object
        self._parent = parent
        self._parents: list[tuple[ArrayObject, bool]] = []
        self._page_indexes: set[int] = set(page_indexes or ())
        self._is_associated = False
        if parent is not None:
            self._parents.append((parent, is_name_tree_entry))

    @property
    def name(self) -> str:
        """
        The (primary) name of the embedded file as provided in the name tree.

        .. warning::

            This value can contain arbitrary characters. Please make sure to sanitize it before
            using it to write the file content to the disk for example.
        """
        return self._name

    @property
    def is_embedded(self) -> bool:
        """Whether the file specification contains an embedded file stream."""
        return "/EF" in self.pdf_object and not is_null_or_none(self.pdf_object["/EF"])

    @property
    def is_associated(self) -> bool:
        """Whether this file is referenced by an ``/AF`` array."""
        return self._is_associated

    @property
    def page_indexes(self) -> list[int]:
        """Zero-based indexes of the pages this file is associated with."""
        return sorted(self._page_indexes)

    @property
    def pages(self) -> list[int]:
        """Zero-based page numbers this file is associated with."""
        return self.page_indexes

    @property
    def associated_page_indexes(self) -> list[int]:
        """Alias for :attr:`page_indexes`."""
        return self.page_indexes

    @property
    def associated_pages(self) -> list[int]:
        """Alias for :attr:`page_indexes`."""
        return self.page_indexes

    @property
    def page_numbers(self) -> list[int]:
        """Alias for :attr:`page_indexes`."""
        return self.page_indexes

    @classmethod
    def _create_new(cls, writer: PdfWriter, name: str, content: str | bytes | None) -> EmbeddedFile:
        """
        Create a new embedded file and add it to the PdfWriter.

        Args:
            writer: The PdfWriter instance to add the embedded file to.
            name: The filename to display.
            content: The data in the file. If ``None``, only an external file
                specification is created.

        Returns:
            EmbeddedFile instance for the newly created embedded file.
        """
        ef_entry: DictionaryObject | None = None
        if content is not None:
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
        filespec.update({
            NameObject(PG.TYPE): NameObject("/Filespec"),
            NameObject(FileSpecificationDictionaryEntries.F): name_object,
        })

        if ef_entry is not None:
            filespec[NameObject(FileSpecificationDictionaryEntries.EF)] = ef_entry

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
        value = self.pdf_object.get(
            NameObject("/AFRelationship"), NameObject(AFRelationship.UNSPECIFIED)
        )
        value = value.get_object() if hasattr(value, "get_object") else value
        if is_null_or_none(value):
            return AFRelationship.UNSPECIFIED
        return cast(str, value)

    @associated_file_relationship.setter
    def associated_file_relationship(self, value: NameObject) -> None:
        """Set the relationship of the referring document to this embedded file."""
        self.pdf_object[NameObject("/AFRelationship")] = value

    @property
    def relationship(self) -> str:
        """Alias for :attr:`associated_file_relationship`."""
        return self.associated_file_relationship

    @relationship.setter
    def relationship(self, value: NameObject) -> None:
        self.associated_file_relationship = value

    @property
    def af_relationship(self) -> str:
        """Alias for :attr:`associated_file_relationship`."""
        return self.associated_file_relationship

    @af_relationship.setter
    def af_relationship(self, value: NameObject) -> None:
        self.associated_file_relationship = value

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
        if not self.is_embedded:
            return DictionaryObject()
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
        if not self.is_embedded:
            return None
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
        """Delete the file from the document.

        This also removes references from all associated-file (``/AF``)
        arrays the file has been discovered in.
        """
        if not self._parents and not self._parent:
            raise PyPdfError("Parent required to delete file from document.")

        parents = list(self._parents)
        if not parents and self._parent is not None:
            parents.append((self._parent, True))

        deleted = False
        for parent, is_name_tree_entry in parents:
            index = self._find_index(parent)
            if index is None:
                continue
            if is_name_tree_entry:
                parent.pop(index)  # Reference.
                parent.pop(index - 1)  # Name.
            else:
                parent.pop(index)
            deleted = True

        if not deleted:
            raise PyPdfError("File not found in parent object.")
        self.pdf_object = DictionaryObject()  # Invalidate.
        self._parents.clear()

    def _find_index(self, parent: ArrayObject) -> int | None:
        """Find the index of this file specification within an array."""
        if self.pdf_object in parent:
            return parent.index(self.pdf_object)
        indirect_reference = getattr(self.pdf_object, "indirect_reference", None)
        if indirect_reference is not None and indirect_reference in parent:
            return parent.index(indirect_reference)
        return None

    def _add_parent(self, parent: ArrayObject, *, is_name_tree_entry: bool) -> None:
        """Register another array referencing this file specification."""
        for known_parent, _ in self._parents:
            if known_parent is parent:
                return
        self._parents.append((parent, is_name_tree_entry))

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
                yield EmbeddedFile(
                    name=direct_name,
                    pdf_object=file_dictionary,
                    parent=names,
                    is_name_tree_entry=True,
                )

    @staticmethod
    def _file_specification_key(file_specification: DictionaryObject) -> tuple[object, ...]:
        """Return a stable key identifying a file specification object."""
        indirect_reference = getattr(file_specification, "indirect_reference", None)
        if indirect_reference is not None:
            try:
                return (
                    "indirect",
                    id(indirect_reference.pdf),
                    indirect_reference.idnum,
                    indirect_reference.generation,
                )
            except AttributeError:  # pragma: no cover - defensive for custom objects
                return ("indirect", id(indirect_reference))
        return ("direct", id(file_specification))

    @staticmethod
    def _name_from_file_specification(file_specification: DictionaryObject) -> str:
        """Retrieve the best available name from a file specification."""
        for key in (FileSpecificationDictionaryEntries.UF, FileSpecificationDictionaryEntries.F):
            value = file_specification.get(NameObject(key))
            if is_null_or_none(value):
                continue
            value = value.get_object() if hasattr(value, "get_object") else value
            if is_null_or_none(value):
                continue
            return str(value)
        return ""

    @classmethod
    def _load_from_associated_files(
        cls,
        associated_files: object,
        strict: bool = False,
        page_index: int | None = None,
    ) -> Iterator[EmbeddedFile]:
        """Load the file specifications from an ``/AF`` array."""
        array = associated_files.get_object() if hasattr(associated_files, "get_object") else associated_files
        if isinstance(array, NullObject):
            return
        if not isinstance(array, ArrayObject):
            cls._report_malformed(
                f"Associated files entry is not an array: {array}", strict=strict
            )
            return

        for entry in array:
            file_specification = entry.get_object() if hasattr(entry, "get_object") else entry
            if isinstance(file_specification, NullObject):
                continue
            if not isinstance(file_specification, DictionaryObject):
                cls._report_malformed(
                    "Associated file specification is not a dictionary: "
                    f"{file_specification}",
                    strict=strict,
                )
                continue
            attachment = cls(
                name=cls._name_from_file_specification(file_specification),
                pdf_object=file_specification,
                parent=array,
                is_name_tree_entry=False,
                page_indexes=() if page_index is None else (page_index,),
            )
            attachment._is_associated = True
            yield attachment

    @classmethod
    def _load_from_af(
        cls,
        associated_files: object,
        strict: bool = False,
        page_index: int | None = None,
    ) -> Iterator[EmbeddedFile]:
        """Alias for :meth:`_load_from_associated_files`."""
        yield from cls._load_from_associated_files(
            associated_files, strict=strict, page_index=page_index
        )

    @classmethod
    def _iter_pages(cls, catalog: DictionaryObject) -> Iterator[tuple[int, DictionaryObject]]:
        """Iterate over the pages of a document in document order."""
        pages = catalog.get(NameObject(CA.PAGES))
        if is_null_or_none(pages):
            return
        pages = pages.get_object() if hasattr(pages, "get_object") else pages
        if not isinstance(pages, DictionaryObject):
            return

        stack = [pages]
        seen: set[tuple[object, ...]] = set()
        page_index = 0
        while stack:
            node = stack.pop()
            key = cls._file_specification_key(node)
            if key in seen:
                continue
            seen.add(key)

            kids = node.get(NameObject("/Kids"))
            kids = kids.get_object() if hasattr(kids, "get_object") else kids
            if isinstance(kids, ArrayObject):
                for kid in reversed(kids):
                    kid = kid.get_object() if hasattr(kid, "get_object") else kid
                    if isinstance(kid, DictionaryObject):
                        stack.append(kid)
                continue

            node_type = node.get(NameObject(PG.TYPE))
            if node_type == "/Page" or (node_type is None and "/Kids" not in node):
                yield page_index, node
                page_index += 1

    @classmethod
    def _load_from_name_tree(cls, catalog: DictionaryObject, strict: bool = False) -> Iterator[EmbeddedFile]:
        """Load embedded files from the ``/EmbeddedFiles`` name tree."""
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

        yield from cls._load_from_name_tree_node(container, strict=strict)

    @classmethod
    def _load_from_name_tree_node(
        cls, node: DictionaryObject, strict: bool = False
    ) -> Iterator[EmbeddedFile]:
        """Recursively load a name tree node."""
        if "/Kids" in node:
            kids = node["/Kids"].get_object()
            if isinstance(kids, NullObject):
                kids = ArrayObject()
            elif not isinstance(kids, ArrayObject):
                cls._report_malformed(f"Embedded files /Kids is not an array: {kids}", strict=strict)
                return
            for kid in kids:
                kid = kid.get_object()
                if not isinstance(kid, DictionaryObject):
                    cls._report_malformed(f"Embedded files kid is not a dictionary: {kid}", strict=strict)
                    continue
                yield from cls._load_from_name_tree_node(kid, strict=strict)
        if "/Names" in node:
            names = node["/Names"].get_object()
            if isinstance(names, NullObject):
                return
            if not isinstance(names, ArrayObject):
                cls._report_malformed(f"Embedded files name list is not an array: {names}", strict=strict)
                return
            yield from cls._load_from_names(names, strict=strict)
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
        loaded: dict[tuple[object, ...], list[EmbeddedFile]] = {}
        attachments: list[EmbeddedFile] = []

        for attachment in cls._load_from_name_tree(catalog, strict=strict):
            key = cls._file_specification_key(attachment.pdf_object)
            loaded.setdefault(key, []).append(attachment)
            attachments.append(attachment)

        document_entries: list[tuple[object, int | None]] = [
            (catalog.get(NameObject(CA.AF)), None),
        ]
        for page_index, page in cls._iter_pages(catalog):
            document_entries.append((page.get(NameObject(PG.AF)), page_index))

        for associated_files, page_index in document_entries:
            if is_null_or_none(associated_files):
                continue
            parent_array = (
                associated_files.get_object()
                if hasattr(associated_files, "get_object")
                else associated_files
            )
            for attachment in cls._load_from_associated_files(
                associated_files, strict=strict, page_index=page_index
            ):
                key = cls._file_specification_key(attachment.pdf_object)
                existing_entries = loaded.get(key)
                if existing_entries is None:
                    loaded[key] = [attachment]
                    attachments.append(attachment)
                    continue

                for existing in existing_entries:
                    existing._is_associated = True
                    existing._page_indexes.update(attachment._page_indexes)
                    if isinstance(parent_array, ArrayObject):
                        existing._add_parent(parent_array, is_name_tree_entry=False)

        yield from attachments


AssociatedFile = EmbeddedFile
__all__ = ["AssociatedFile", "EmbeddedFile"]
