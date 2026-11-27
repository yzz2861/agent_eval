from __future__ import annotations

from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from dissect.database.bsd.c_db import c_db

if TYPE_CHECKING:
    from collections.abc import Iterator


DBT = tuple[
    c_db.HOFFPAGE | c_db.HKEYDATA | c_db.HEAPHDR | c_db.BKEYDATA | c_db.BOVERFLOW | c_db.BINTERNAL | c_db.RINTERNAL,
    bytes,
]
"""An internal page entry structure + data (loosely related to Data-Base Thang)."""


class DBEntry(NamedTuple):
    """A record in a Berkeley DB, including the page it was read from."""

    key: bytes | int | None
    data: bytes | None
    page: int | None = None
    index: int | None = None
    flags: int = 0
    deleted: bool = False


class DB:
    """Berkeley DB.

    Args:
        fh: File-like object containing the Berkeley DB data.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.fh.seek(0)

        meta = c_db.DBMETA(self.fh)
        self.fh.seek(0)

        if meta.magic == c_db.DB_BTREEMAGIC and meta.type == c_db.P_BTREEMETA:
            self.meta = c_db.BTMETA(self.fh)
        elif meta.magic == c_db.DB_HASHMAGIC and meta.type == c_db.P_HASHMETA:
            self.meta = c_db.HMETA(self.fh)
        else:
            raise NotImplementedError(f"Unsupported DB type: {meta.magic:#x} {meta.type}")

        self.page_size = self.meta.dbmeta.pagesize

        page_overhead = len(c_db.PAGE)
        if self.meta.dbmeta.flags & c_db.DB_AM_ENCRYPT:
            page_overhead += len(c_db.PG_CRYPTO)
        elif self.meta.dbmeta.flags & c_db.DB_AM_CHKSUM:
            page_overhead += len(c_db.PG_CHKSUM)
        self._page_overhead = page_overhead

        self.page = lru_cache(128)(self.page)

        # Pages that could not be read, or that were referenced but absent. Keeping
        # track of these allows callers to distinguish a missing record from a
        # record that is genuinely not present in the database.
        self.missing_pages: set[int] = set()

    @property
    def is_btree(self) -> bool:
        """Return whether the database of a ``DB_BTREE`` type."""
        return self.meta.dbmeta.magic == c_db.DB_BTREEMAGIC

    @property
    def is_recno(self) -> bool:
        """Return whether the database is a ``DB_RECNO`` type."""
        return self.is_btree and (self.meta.dbmeta.flags & c_db.BTM_RECNO) != 0

    @property
    def is_hash(self) -> bool:
        """Return whether the database is a ``DB_HASH`` type."""
        return self.meta.dbmeta.magic == c_db.DB_HASHMAGIC

    def page(self, pgno: int) -> Page:
        """Get a single page by page number.

        Args:
            pgno: Page number to retrieve.
        """
        return Page(self, pgno)

    def entries(self, include_deleted: bool = True) -> Iterator[DBEntry]:
        """Iterate over all records, including their page and deletion state.

        Args:
            include_deleted: Include entries that have the Berkeley DB ``B_DELETE``
                flag set. These keys are not part of the current logical index, but
                they can still be useful for forensic purposes.
        """
        self.page.cache_clear()
        self.missing_pages.clear()

        it = self._iter_db_entries()

        if (self.is_btree and not self.is_recno) or self.is_hash:
            # Hash and Btree leaf entries are stored as key/data pairs.
            while True:
                try:
                    page, index, key_dbt, key, _ = next(it)
                    _, _, data_dbt, data, _ = next(it)
                except StopIteration:
                    break

                key_flags = getattr(key_dbt, "type", 0)
                data_flags = getattr(data_dbt, "type", 0)
                flags = key_flags | data_flags
                deleted = bool(flags & c_db.B_DELETE)

                if self.is_btree and data_flags & ~c_db.B_DELETE == c_db.B_DUPLICATE:
                    # Off-page duplicate values: the key is stored once and the data
                    # item points to a chain of P_LDUP pages. Expand the values while
                    # keeping the original key and page provenance.
                    for value, value_deleted in duplicate_values(self, data_dbt.pgno, data_dbt.tlen):
                        if (deleted or value_deleted) and not include_deleted:
                            continue
                        yield DBEntry(
                            bytes(key),
                            value,
                            page,
                            index,
                            flags | (c_db.B_DELETE if value_deleted else 0),
                            deleted or value_deleted,
                        )
                    continue

                if deleted and not include_deleted:
                    continue

                yield DBEntry(bytes(key), bytes(data), page, index, flags, deleted)
        elif self.is_recno:
            for page, index, dbt, data, recno in it:
                # The recno comes from the P_IRECNO subtree counts, so gaps left by
                # missing pages or deleted entries do not renumber later records.
                flags = getattr(dbt, "type", 0)
                deleted = bool(flags & c_db.B_DELETE)
                if deleted and not include_deleted:
                    continue
                yield DBEntry(recno, bytes(data), page, index, flags, deleted)

    def records(self, include_deleted: bool = False) -> Iterator[tuple[bytes | int, bytes]]:
        """Iterate over all logical records in the database.

        Args:
            include_deleted: Include entries that have the Berkeley DB ``B_DELETE``
                flag set. Retained keys from a previous version are normally excluded.
        """
        for entry in self.entries(include_deleted=include_deleted):
            yield entry.key, entry.data

    def _iter_db_entries(self) -> Iterator[tuple[int, int, DBT[0], bytes, int | None]]:
        seen: set[int] = set()
        if self.is_btree:
            yield from self._walk_btree_entries(self.meta.root, seen, 1 if self.is_recno else None)
        elif self.is_hash:
            for i in range(self.meta.max_bucket + 1):
                yield from self._walk_hash_entries(BUCKET_TO_PAGE(self, i), seen)
        else:
            raise NotImplementedError("Unsupported DB type")

    def _walk_btree_entries(
        self, pgno: int, seen: set[int], recno: int | None = None
    ) -> Iterator[tuple[int, int, DBT[0], bytes, int | None]]:
        if pgno in seen or not self._page_is_valid(self.page(pgno)):
            return

        seen.add(pgno)
        page = self.page(pgno)

        if page.header.type in (c_db.P_IBTREE, c_db.P_IRECNO):
            for entry, _ in page.entries():
                yield from self._walk_btree_entries(entry.pgno, seen, recno)
                if recno is not None:
                    recno += entry.nrecs
        elif page.header.type in (c_db.P_LBTREE, c_db.P_LRECNO):
            for index, (entry, data) in enumerate(page.entries()):
                yield page.pgno, index, entry, data, recno
                if recno is not None:
                    recno += 1

    def _walk_hash_entries(self, pgno: int, seen: set[int]) -> Iterator[tuple[int, int, DBT[0], bytes, int | None]]:
        if pgno in seen or not self._page_is_valid(self.page(pgno)):
            return

        seen.add(pgno)
        page = self.page(pgno)

        for index, (entry, data) in enumerate(page.entries()):
            yield page.pgno, index, entry, data, None

        if page.header.next_pgno:
            yield from self._walk_hash_entries(page.header.next_pgno, seen)

    def _page_is_valid(self, page: Page) -> bool:
        if not page.is_valid:
            self.missing_pages.add(page.pgno)
            return False
        return True

    def _iter_db(self) -> Iterator[DBT]:
        if self.is_btree:
            yield from self._iter_btree()
        elif self.is_hash:
            yield from self._iter_hash()
        else:
            raise NotImplementedError("Unsupported DB type")

    def _iter_btree(self) -> Iterator[DBT]:
        yield from self._walk_btree(self.meta.root)

    def _walk_btree(self, pgno: int) -> Iterator[DBT]:
        page = self.page(pgno)
        if page.header.type in (c_db.P_IBTREE, c_db.P_IRECNO):
            # Internal page
            for entry, _ in page.entries():
                yield from self._walk_btree(entry.pgno)
        elif page.header.type in (c_db.P_LBTREE, c_db.P_LRECNO):
            # Leaf page
            yield from page.entries()

    def _iter_hash(self) -> Iterator[DBT]:
        for i in range(self.meta.max_bucket + 1):
            pgno = BUCKET_TO_PAGE(self, i)
            yield from self._walk_hash(pgno)

    def _walk_hash(self, pgno: int) -> Iterator[DBT]:
        page = self.page(pgno)
        yield from page.entries()

        if page.header.next_pgno:
            yield from self._walk_hash(page.header.next_pgno)


class Page:
    """A single page in a Berkeley DB.

    Args:
        db: The parent ``DB`` instance.
        pgno: The page number to load.
    """

    def __init__(self, db: DB, pgno: int):
        self.db = db
        self.pgno = pgno
        self.offset = pgno * self.db.page_size

    @cached_property
    def raw(self) -> bytes:
        """Raw page data."""
        self.db.fh.seek(self.offset)
        return self.db.fh.read(self.db.page_size)

    @cached_property
    def data(self) -> memoryview:
        """Page data, excluding any overhead (headers)."""
        return memoryview(self.raw)[self.db._page_overhead :]

    @cached_property
    def header(self) -> c_db.PAGE:
        """Page header."""
        return c_db.PAGE(self.raw)

    @property
    def is_valid(self) -> bool:
        """Whether this page exists and has a usable header."""
        return len(self.raw) == self.db.page_size and self.header.type != c_db.P_INVALID

    @property
    def valid(self) -> bool:
        """Whether this page exists and has a usable header."""
        return self.is_valid

    @property
    def missing(self) -> bool:
        """Whether this page is absent or unreadable."""
        return not self.is_valid

    @property
    def type(self) -> int:
        """Page type."""
        return self.header.type

    @cached_property
    def lookup(self) -> list[int]:
        """List of offsets to entries in the page."""
        if self.type in (
            c_db.P_LBTREE,
            c_db.P_IBTREE,
            c_db.P_LRECNO,
            c_db.P_IRECNO,
            c_db.P_LDUP,
            c_db.P_HASH,
            c_db.P_HASH_UNSORTED,
        ):
            return c_db.uint16[self.header.entries](self.data)
        return []

    def entry(self, index: int) -> DBT:
        """Get a single entry by index. Type depends on page type.

        Also returns the associated data (DBT, Data-Base Thang, or key/data buffer) if applicable.

        References:
            - ``__db_ret``

        Args:
            index: Index of the entry to retrieve.
        """
        if index >= len(self.lookup):
            raise IndexError("Index out of range")

        buf = memoryview(self.raw)[self.lookup[index] :]
        # These are the types that can be DBTs
        if self.header.type in (c_db.P_HASH_UNSORTED, c_db.P_HASH):
            if buf[0] & ~c_db.B_DELETE == c_db.H_OFFPAGE:
                entry = c_db.HOFFPAGE(buf)
                return entry, overflow_data(self.db, entry.pgno, entry.tlen)

            next_offset = self.db.page_size if index == 0 else self.lookup[index - 1]
            data_length = (next_offset - self.lookup[index]) - len(c_db.HKEYDATA)

            return c_db.HKEYDATA(buf), buf[len(c_db.HKEYDATA) : len(c_db.HKEYDATA) + data_length]

        if self.header.type == c_db.P_HEAP:
            entry = c_db.HEAPHDR(buf)
            if entry.flags & (c_db.HEAP_RECSPLIT | c_db.HEAP_RECFIRST):
                raise NotImplementedError("Heap split records not implemented")
            return entry, buf[len(c_db.HEAPHDR) : len(c_db.HEAPHDR) + entry.size]

        if self.header.type in (c_db.P_LBTREE, c_db.P_LDUP, c_db.P_LRECNO):
            entry = c_db.BKEYDATA(buf)
            entry_type = entry.type & ~c_db.B_DELETE
            if entry_type == c_db.B_OVERFLOW:
                entry = c_db.BOVERFLOW(buf)
                return entry, overflow_data(self.db, entry.pgno, entry.tlen)
            if entry_type == c_db.B_DUPLICATE:
                entry = c_db.BOVERFLOW(buf)
                return entry, b""

            return entry, buf[len(c_db.BKEYDATA) : len(c_db.BKEYDATA) + entry.len]

        # These are more internal types, but we still want to parse them
        if self.header.type == c_db.P_IBTREE:
            entry = c_db.BINTERNAL(buf)
            return entry, buf[len(c_db.BINTERNAL) : len(c_db.BINTERNAL) + entry.len]

        if self.header.type == c_db.P_IRECNO:
            return c_db.RINTERNAL(buf), b""

        raise NotImplementedError(f"Page type not implemented: {self.header.type}")

    def entries(self) -> Iterator[DBT]:
        """Iterate over all entries in the page."""
        if not self.header.entries:
            raise TypeError("Page doesn't have iterable entries")

        for idx in range(self.header.entries):
            yield self.entry(idx)


def overflow_data(db: DB, pgno: int, size: int) -> bytes:
    """Get off-page data.

    References:
        - ``__db_goff``

    Args:
        db: The parent ``DB`` instance.
        pgno: The starting page number of the overflow data.
        size: The total size of the overflow data to read.
    """
    result = []
    while size > 0 and pgno != c_db.PGNO_INVALID:
        page = db.page(pgno)
        if not page.is_valid:
            db.missing_pages.add(pgno)
            break
        if page.type != c_db.P_OVERFLOW:
            db.missing_pages.add(pgno)
            break

        read_size = min(size, page.header.hf_offset)
        result.append(page.data[:read_size])
        size -= read_size

        pgno = page.header.next_pgno

    return b"".join(result)


def duplicate_values(db: DB, pgno: int, size: int) -> Iterator[tuple[bytes, bool]]:
    """Get the values from an off-page duplicate chain.

    Args:
        db: The parent ``DB`` instance.
        pgno: The first duplicate leaf page.
        size: The total size of the duplicate values.
    """
    seen: set[int] = set()
    while pgno != c_db.PGNO_INVALID and pgno not in seen:
        seen.add(pgno)
        page = db.page(pgno)
        if not page.is_valid or page.type != c_db.P_LDUP:
            db.missing_pages.add(pgno)
            break

        for entry, data in page.entries():
            value_deleted = bool(getattr(entry, "type", 0) & c_db.B_DELETE)
            yield data, value_deleted
            size -= len(data)

        pgno = page.header.next_pgno


def _db_log2(num: int) -> int:
    i = 0
    limit = 1
    while limit < num:
        i += 1
        limit = limit << 1

    return i


def BS_TO_PAGE(bucket: int, spares: list[int]) -> int:
    return bucket + spares[_db_log2(bucket + 1)]


def BUCKET_TO_PAGE(db: DB, bucket: int) -> int:
    return BS_TO_PAGE(bucket, db.meta.spares)
