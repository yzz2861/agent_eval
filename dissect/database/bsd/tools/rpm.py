# References:
# - https://rpm.org/docs/
from __future__ import annotations

import argparse
import posixpath
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, NamedTuple

from dissect.database.bsd import db
from dissect.database.bsd.tools.c_rpm import c_rpm

if TYPE_CHECKING:
    from collections.abc import Iterator


TYPE_SIZE_MAP = {
    c_rpm.rpmTagType.RPM_NULL_TYPE: 0,
    c_rpm.rpmTagType.RPM_CHAR_TYPE: 1,
    c_rpm.rpmTagType.RPM_INT8_TYPE: 2,
    c_rpm.rpmTagType.RPM_INT16_TYPE: 2,
    c_rpm.rpmTagType.RPM_INT32_TYPE: 4,
    c_rpm.rpmTagType.RPM_INT64_TYPE: 8,
    c_rpm.rpmTagType.RPM_STRING_TYPE: -1,
    c_rpm.rpmTagType.RPM_BIN_TYPE: 1,
    c_rpm.rpmTagType.RPM_STRING_ARRAY_TYPE: -1,
    c_rpm.rpmTagType.RPM_I18NSTRING_TYPE: -1,
}


TYPE_PARSERS = {
    c_rpm.rpmTagType.RPM_NULL_TYPE: lambda _: None,
    c_rpm.rpmTagType.RPM_CHAR_TYPE: c_rpm.char,
    c_rpm.rpmTagType.RPM_INT8_TYPE: c_rpm.uint8,
    c_rpm.rpmTagType.RPM_INT16_TYPE: c_rpm.uint16,
    c_rpm.rpmTagType.RPM_INT32_TYPE: c_rpm.uint32,
    c_rpm.rpmTagType.RPM_INT64_TYPE: c_rpm.uint64,
    c_rpm.rpmTagType.RPM_STRING_TYPE: lambda v: v.split(b"\x00")[0].decode(),
    c_rpm.rpmTagType.RPM_BIN_TYPE: lambda v: v,
    c_rpm.rpmTagType.RPM_STRING_ARRAY_TYPE: lambda v, c: [s.decode() for s in v.split(b"\x00")[:c]],
    c_rpm.rpmTagType.RPM_I18NSTRING_TYPE: lambda v: v.split(b"\x00")[0].decode(),
}

ARRAY_TYPES = (
    c_rpm.rpmTagType.RPM_CHAR_TYPE,
    c_rpm.rpmTagType.RPM_INT8_TYPE,
    c_rpm.rpmTagType.RPM_INT16_TYPE,
    c_rpm.rpmTagType.RPM_INT32_TYPE,
    c_rpm.rpmTagType.RPM_INT64_TYPE,
)


class PackageEntry(NamedTuple):
    path: str
    size: int
    mode: int
    mtime: int
    user: str
    group: str
    digest: bytes


class File(PackageEntry):
    pass


class Directory(PackageEntry):
    pass


class Package:
    """RPM Package.

    Args:
        buf: Bytes containing the RPM Package header blob.
    """

    def __init__(self, buf: bytes, record: int | None = None):
        self.blob = HeaderBlob(buf)
        self.record = record

    @property
    def recno(self) -> int | None:
        """The database record number this package was read from."""
        return self.record

    @property
    def record_id(self) -> int | None:
        """The database record number this package was read from."""
        return self.record

    def __repr__(self) -> str:
        return f"<Package name={self.name!r} version={self.version!r} release={self.release!r}>"

    def __iter__(self) -> Iterator[File | Directory]:
        return self.entries()

    @property
    def name(self) -> str:
        """Package name."""
        return self.blob.value(c_rpm.rpmTag.RPMTAG_NAME)

    @property
    def version(self) -> str:
        """Package version."""
        return self.blob.value(c_rpm.rpmTag.RPMTAG_VERSION)

    @property
    def release(self) -> str:
        """Package release."""
        return self.blob.value(c_rpm.rpmTag.RPMTAG_RELEASE)

    @property
    def summary(self) -> str:
        """Package summary."""
        return self.blob.value(c_rpm.rpmTag.RPMTAG_SUMMARY)

    @property
    def description(self) -> str:
        """Package description."""
        return self.blob.value(c_rpm.rpmTag.RPMTAG_DESCRIPTION)

    def entries(self) -> Iterator[File | Directory]:
        """Iterate over all files and directories in the package."""
        if c_rpm.rpmTag.RPMTAG_FILESIZES not in self.blob:
            return

        sizes = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILESIZES))
        modes = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILEMODES))
        mtimes = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILEMTIMES))
        users = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILEUSERNAME))
        groups = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILEGROUPNAME))
        digests = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILEDIGESTS))

        basenames = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_BASENAMES))
        dirnames = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_DIRNAMES))
        dirindex = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_DIRINDEXES))

        for i, name in enumerate(basenames):
            dirname = dirnames[dirindex[i]]
            klass = Directory if stat.S_ISDIR(modes[i]) else File
            yield klass(
                posixpath.join(dirname, name),
                sizes[i],
                modes[i],
                mtimes[i],
                users[i],
                groups[i],
                digests[i],
            )


def _as_list(value: Any) -> list[Any]:
    return [value] if not isinstance(value, list) else value


class HeaderBlob:
    """RPM Header Blob.

    Args:
        buf: Bytes containing the RPM Header Blob.
    """

    def __init__(self, buf: bytes):
        self.buf = buf
        self.header = c_rpm.header_intro(self.buf)

        # sizeof(il) + sizeof(dl) + (il * sizeof(pe)) + dl
        self.pvlen = 4 + 4 + (self.header.index_length * len(c_rpm.entryInfo)) + self.header.data_length
        self.data_start = 4 + 4 + (self.header.index_length * len(c_rpm.entryInfo))
        self.data_end = self.data_start + self.header.data_length

        self.tag_map = {e.tag: idx for idx, e in enumerate(self.header.entries)}

    def __contains__(self, tag: c_rpm.rpmTag) -> bool:
        return tag.value in self.tag_map

    def entry(self, idx: int) -> tuple[c_rpm.rpmTag, int | str | bytes | list[int] | list[str] | None]:
        """Get the ``(tag, value)`` for the given index."""
        entry = self.header.entries[idx]

        tag = c_rpm.rpmTag(entry.tag)
        type = c_rpm.rpmTagType(entry.type)

        type_size = TYPE_SIZE_MAP[type]
        if type_size == -1:
            next_entry = self.header.entries[idx + 1] if idx + 1 < self.header.index_length else None
            data_size = (next_entry.offset if next_entry else len(self.buf)) - entry.offset
        else:
            data_size = entry.count * type_size

        data = self.buf[self.data_start + entry.offset : self.data_start + entry.offset + data_size]

        parser = TYPE_PARSERS[type]
        if type in ARRAY_TYPES and entry.count > 1:
            parser = parser[entry.count]

        value = parser(data, entry.count) if type == c_rpm.rpmTagType.RPM_STRING_ARRAY_TYPE else parser(data)
        return tag, value

    def entries(self) -> Iterator[tuple[c_rpm.rpmTag, int | str | bytes | list[int] | list[str] | None]]:
        """Iterate over all ``(tag, value)`` entries in the header."""
        for idx in range(self.header.index_length):
            yield self.entry(idx)

    def value(self, tag: c_rpm.rpmTag) -> int | str | bytes | list[int] | list[str] | None:
        """Get the value for the given tag."""
        if (idx := self.tag_map.get(tag.value)) is None:
            raise IndexError(f"Tag not found: {tag}")
        return self.entry(idx)[1]


class PackageRecord(NamedTuple):
    """A package and the database record number it was read from."""

    record: int
    package: Package


@dataclass(frozen=True)
class NameEntry:
    """A key in the RPMDB ``Name`` index.

    The value of a ``Name`` index entry is a record number in the main ``Packages``
    database. An entry can still be present on a page after it was logically deleted,
    in which case ``deleted`` is set. Such entries are historical claims and are kept
    around for provenance instead of being treated as current records.
    """

    name: str
    record: int | None
    raw: bytes
    deleted: bool = False
    page: int | None = None
    index: int | None = None
    reason: str | None = None

    @property
    def claim(self) -> NameEntry:
        return self

    @property
    def retained(self) -> bool:
        return self.deleted

    @property
    def record_id(self) -> int | None:
        return self.record

    def __iter__(self) -> Iterator[str | int | None]:
        yield self.name
        yield self.record


@dataclass(frozen=True)
class PackageClaim:
    """A single claim about a package, with its database origin."""

    name: str
    version: str | None
    release: str | None
    record: int | None
    source: str
    deleted: bool = False
    stale: bool = False
    reason: str | None = None
    package: Package | None = None
    page: int | None = None
    index: int | None = None

    @property
    def kind(self) -> str:
        return "index" if self.source == "Name" else "record"

    @property
    def retained(self) -> bool:
        return self.deleted

    @property
    def recno(self) -> int | None:
        return self.record

    @property
    def record_id(self) -> int | None:
        return self.record


@dataclass(frozen=True)
class PackageStatus:
    """The reconciled state of an RPM package.

    ``version`` is only set when it was confirmed from a main ``Packages`` record.
    An index claim by itself is not enough. If the live index points at a record
    that is missing or cannot be decoded, the status is unknown instead of silently
    falling back to a stale value.
    """

    name: str
    version: str | None = None
    release: str | None = None
    record: int | None = None
    source: str = "unknown"
    proven: bool = False
    claims: tuple[PackageClaim, ...] = ()
    conflicts: tuple[PackageClaim, ...] = ()
    missing: tuple[int | None, ...] = ()
    missing_pages: tuple[int, ...] = ()
    reason: str | None = None
    package: Package | None = None

    @property
    def unknown(self) -> bool:
        return not self.proven

    @property
    def current_version(self) -> str | None:
        return self.version

    @property
    def confirmed_version(self) -> str | None:
        return self.version

    @property
    def version_known(self) -> bool:
        return self.version is not None

    @property
    def is_unknown(self) -> bool:
        return self.unknown

    @property
    def is_proven(self) -> bool:
        return self.proven

    @property
    def index_claims(self) -> tuple[PackageClaim, ...]:
        return tuple(claim for claim in self.claims if claim.source == "Name")

    @property
    def record_claims(self) -> tuple[PackageClaim, ...]:
        return tuple(claim for claim in self.claims if claim.source == "Packages")

    @property
    def stale(self) -> tuple[PackageClaim, ...]:
        return tuple(claim for claim in self.claims if claim.stale)

    @property
    def retained(self) -> tuple[PackageClaim, ...]:
        return tuple(claim for claim in self.claims if claim.retained)

    @property
    def history(self) -> tuple[PackageClaim, ...]:
        return self.conflicts

    @property
    def historical_conflicts(self) -> tuple[PackageClaim, ...]:
        return self.conflicts

    @property
    def retained_old_keys(self) -> tuple[PackageClaim, ...]:
        return self.retained

    @property
    def confirmation(self) -> PackageClaim | None:
        for claim in self.record_claims:
            if claim.record == self.record and not claim.stale:
                return claim
        return None

    @property
    def provenance(self) -> tuple[PackageClaim, ...]:
        return self.claims

    def entries(self) -> Iterator[File | Directory]:
        """Iterate over the files of the confirmed package, if any."""
        if self.package is None:
            return
        yield from self.package.entries()

    def __iter__(self) -> Iterator[File | Directory]:
        return self.entries()

    def __getattr__(self, name: str) -> Any:
        package = object.__getattribute__(self, "package")
        if package is not None:
            return getattr(package, name)
        raise AttributeError(name)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "release": self.release,
            "record": self.record,
            "source": self.source,
            "proven": self.proven,
            "unknown": self.unknown,
            "reason": self.reason,
            "claims": [
                {
                    "name": claim.name,
                    "version": claim.version,
                    "release": claim.release,
                    "record": claim.record,
                    "source": claim.source,
                    "deleted": claim.deleted,
                    "stale": claim.stale,
                    "reason": claim.reason,
                }
                for claim in self.claims
            ],
        }


class NameIndex:
    """RPMDB ``Name`` index.

    Args:
        fh: File-like object containing the RPMDB ``Name`` database (a Berkeley DB).
        byteorder: Byte order of the four-byte record numbers. Use ``auto`` to infer it
            from the available record numbers in the main ``Packages`` database.
        record_ids: Optional record numbers present in the main database, used for
            byte-order detection.
    """

    def __init__(
        self,
        fh: BinaryIO,
        *,
        byteorder: str = "auto",
        record_ids: set[int] | None = None,
    ):
        self.db = db.DB(fh)
        self.record_ids = set(record_ids) if record_ids is not None else None
        self._byteorder = byteorder
        self._detected_byteorder: str | None = None

    def __iter__(self) -> Iterator[NameEntry]:
        return self.entries()

    @property
    def byteorder(self) -> str:
        """Byte order used to decode record numbers."""
        if self._byteorder != "auto":
            return self._byteorder
        if self._detected_byteorder is None:
            self._detected_byteorder = self._detect_byteorder()
        return self._detected_byteorder

    def _detect_byteorder(self) -> str:
        values = [entry.data for entry in self._raw() if entry.data is not None and len(entry.data) == 4]
        if not values:
            return "little"

        if self.record_ids:
            scored = []
            for order in ("big", "little"):
                decoded = [int.from_bytes(value, order) for value in values]
                score = sum(1 for value in decoded if value in self.record_ids)
                scored.append((score, -max(decoded), order))
            return max(scored)[2]

        # Without the main database, prefer the interpretation that produces the
        # smallest plausible record numbers. Most RPM databases use host byte order.
        big_max = max(int.from_bytes(value, "big") for value in values)
        little_max = max(int.from_bytes(value, "little") for value in values)
        return "big" if big_max <= little_max else "little"

    def _raw(self) -> list[db.DBEntry]:
        return list(self.db.entries(include_deleted=True))

    def entries(self, name: str | None = None, *, include_deleted: bool = True) -> Iterator[NameEntry]:
        """Iterate over index claims, optionally filtered by package name."""
        byteorder = self.byteorder
        for entry in self._raw():
            if isinstance(entry.key, int) or entry.key is None:
                continue

            try:
                key = entry.key.decode()
            except UnicodeDecodeError:
                key = entry.key.decode(errors="replace")

            if name is not None and key != name:
                continue
            if entry.deleted and not include_deleted:
                continue

            raw = entry.data or b""
            record = int.from_bytes(raw, byteorder) if len(raw) == 4 else None
            reason = None
            if record is None:
                reason = "invalid-record-number"
            elif record == 0:
                record = None
                reason = "invalid-record-number"

            yield NameEntry(
                name=key,
                record=record,
                raw=raw,
                deleted=entry.deleted,
                page=entry.page,
                index=entry.index,
                reason=reason,
            )

    def claims(self, name: str | None = None, *, include_deleted: bool = True) -> Iterator[NameEntry]:
        return self.entries(name, include_deleted=include_deleted)

    def records(self, name: str | None = None, *, include_deleted: bool = True) -> Iterator[tuple[str, int | None]]:
        """Iterate over ``(name, record)`` pairs."""
        for entry in self.entries(name, include_deleted=include_deleted):
            yield entry.name, entry.record

    def items(self, name: str | None = None, *, include_deleted: bool = True) -> Iterator[tuple[str, int | None]]:
        return self.records(name, include_deleted=include_deleted)

    def lookup(self, name: str, *, include_deleted: bool = True) -> list[NameEntry]:
        return list(self.entries(name, include_deleted=include_deleted))

    def get(self, name: str, *, include_deleted: bool = True) -> list[NameEntry]:
        return self.lookup(name, include_deleted=include_deleted)


class Packages:
    """RPMDB Packages database.

    Args:
        fh: File-like object containing the RPMDB Packages database (a Berkeley DB).
        name_fh: Optional file-like object containing the RPMDB Name index.
    """

    def __init__(
        self,
        fh: BinaryIO,
        name_fh: BinaryIO | None = None,
        *,
        names: BinaryIO | None = None,
        name_db: BinaryIO | None = None,
        byteorder: str = "auto",
    ):
        self.db = db.DB(fh)
        self._name_fh = name_fh if name_fh is not None else names if names is not None else name_db
        self._byteorder = byteorder
        self._name_index: NameIndex | None = None

    def __iter__(self) -> Iterator[Package]:
        return self.entries()

    @property
    def name_index(self) -> NameIndex | None:
        """The optional ``Name`` index database."""
        if self._name_index is None and self._name_fh is not None:
            self._name_index = NameIndex(
                self._name_fh,
                byteorder=self._byteorder,
                record_ids=self.record_ids(),
            )
        return self._name_index

    @property
    def names(self) -> NameIndex | None:
        return self.name_index

    @property
    def name_db(self) -> NameIndex | None:
        return self.name_index

    def record_ids(self) -> set[int]:
        """Return the record numbers present in the main database."""
        return {entry.key for entry in self.db.entries(include_deleted=True) if isinstance(entry.key, int)}

    def raw_records(
        self, *, include_deleted: bool = True
    ) -> Iterator[tuple[int, bytes | None, bool, int | None, int | None]]:
        """Iterate over ``(record, data, deleted, page, index)`` tuples."""
        for entry in self.db.entries(include_deleted=include_deleted):
            if not isinstance(entry.key, int):
                continue
            yield entry.key, entry.data, entry.deleted, entry.page, entry.index

    def records(self, *, include_deleted: bool = False) -> Iterator[PackageRecord]:
        """Iterate over ``(record, package)`` pairs."""
        for record, data, _, _, _ in self.raw_records(include_deleted=include_deleted):
            if data is None or len(data) <= 4:
                continue
            try:
                package = Package(data, record=record)
                if not _package_is_complete(package):
                    continue
                yield PackageRecord(record, package)
            except Exception:
                continue

    def entries(self) -> Iterator[Package]:
        """Iterate over all packages in the database."""
        for record in self.records():
            yield record.package

    def items(self, *, include_deleted: bool = False) -> Iterator[PackageRecord]:
        return self.records(include_deleted=include_deleted)

    def packages(self) -> Iterator[Package]:
        """Iterate over all packages in the database."""
        return self.entries()

    def record(self, record: int) -> Package | None:
        """Get a package by database record number."""
        for current, data, _, _, _ in self.raw_records(include_deleted=True):
            if current != record or data is None or len(data) <= 4:
                continue
            try:
                package = Package(data, record=current)
            except Exception:
                return None
            if not _package_is_complete(package):
                return None
            return package
        return None

    def status(self, name: str) -> PackageStatus:
        """Reconcile the index claims and main records for ``name``."""
        return _resolve_status(self, self.name_index, name)

    def resolve(self, name: str) -> PackageStatus:
        return self.status(name)

    def lookup(self, name: str) -> PackageStatus:
        return self.status(name)

    def get(self, name: str) -> PackageStatus:
        return self.status(name)

    def package(self, name: str) -> Package | None:
        """Return the confirmed package for ``name``, if its version is proven."""
        return self.status(name).package

    def get_package(self, name: str) -> Package | None:
        return self.package(name)

    def find_package(self, name: str) -> Package | None:
        return self.package(name)

    def __getitem__(self, key: str | int) -> PackageStatus | Package | None:
        if isinstance(key, int):
            return self.record(key)
        return self.status(key)


class PackageDatabase:
    """Combined RPMDB ``Packages`` and ``Name`` databases.

    Args:
        packages: A ``Packages`` instance, a file-like object, a file path, or a
            directory containing ``Packages`` and ``Name`` files.
        name: Optional ``Name`` index file-like object or path.
    """

    def __init__(
        self,
        packages: Packages | BinaryIO | str | Path,
        name: BinaryIO | str | Path | None = None,
        *,
        path: str | Path | None = None,
        byteorder: str = "auto",
    ):
        self._owned: list[BinaryIO] = []

        if isinstance(packages, Packages):
            self.packages = packages
        else:
            packages_fh = packages
            name_fh = name

            if isinstance(packages, (str, Path)):
                packages_path = Path(packages)
                if packages_path.is_dir():
                    packages_fh = self._open(packages_path / "Packages")
                    name_path = packages_path / "Name"
                    name_fh = self._open(name_path) if name_path.exists() else None
                else:
                    packages_fh = self._open(packages_path)

            if isinstance(name_fh, (str, Path)):
                name_fh = self._open(Path(name_fh))

            self.packages = Packages(packages_fh, name_fh, byteorder=byteorder)

        if path is not None and self.packages.name_index is None:
            index_path = Path(path) / "Name" if Path(path).is_dir() else Path(path)
            if index_path.exists():
                self.packages._name_fh = self._open(index_path)

    def _open(self, path: Path) -> BinaryIO:
        fh = path.open("rb")
        self._owned.append(fh)
        return fh

    @classmethod
    def from_directory(cls, path: str | Path, *, byteorder: str = "auto") -> PackageDatabase:
        """Open a directory containing ``Packages`` and ``Name`` databases."""
        return cls(path, byteorder=byteorder)

    @classmethod
    def from_files(
        cls,
        packages: BinaryIO,
        name: BinaryIO | None = None,
        *,
        byteorder: str = "auto",
    ) -> PackageDatabase:
        """Open explicit ``Packages`` and ``Name`` file objects."""
        return cls(packages, name, byteorder=byteorder)

    def close(self) -> None:
        for fh in self._owned:
            fh.close()
        self._owned.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def __iter__(self) -> Iterator[Package]:
        return self.packages.entries()

    @property
    def name_index(self) -> NameIndex | None:
        return self.packages.name_index

    @property
    def names(self) -> NameIndex | None:
        return self.packages.name_index

    @property
    def name_db(self) -> NameIndex | None:
        return self.packages.name_index

    def records(self, *, include_deleted: bool = False) -> Iterator[PackageRecord]:
        return self.packages.records(include_deleted=include_deleted)

    def items(self, *, include_deleted: bool = False) -> Iterator[PackageRecord]:
        return self.records(include_deleted=include_deleted)

    def entries(self) -> Iterator[Package]:
        return self.packages.entries()

    def record(self, record: int) -> Package | None:
        return self.packages.record(record)

    def status(self, name: str) -> PackageStatus:
        return self.packages.status(name)

    def resolve(self, name: str) -> PackageStatus:
        return self.status(name)

    def lookup(self, name: str) -> PackageStatus:
        return self.status(name)

    def get(self, name: str) -> PackageStatus:
        return self.status(name)

    def package(self, name: str) -> Package | None:
        """Return the confirmed package for ``name``, if its version is proven."""
        return self.status(name).package

    def get_package(self, name: str) -> Package | None:
        return self.package(name)

    def find_package(self, name: str) -> Package | None:
        return self.package(name)

    def __getitem__(self, key: str | int) -> PackageStatus | Package | None:
        if isinstance(key, int):
            return self.record(key)
        return self.status(key)

    def names_seen(self) -> set[str]:
        """Return all package names seen in either database."""
        result = set()
        for record in self.packages.records():
            if name := _package_name(record.package):
                result.add(name)
        if (index := self.name_index) is not None:
            result.update(entry.name for entry in index.entries(include_deleted=True))
        return result

    def statuses(self) -> Iterator[PackageStatus]:
        """Reconcile every package name seen in the database."""
        for name in sorted(self.names_seen()):
            yield self.status(name)

    def resolve_all(self) -> Iterator[PackageStatus]:
        return self.statuses()


def _installtime(package: Package) -> int:
    try:
        value = package.blob.value(c_rpm.rpmTag.RPMTAG_INSTALLTIME)
        return int(value)  # type: ignore[arg-type]
    except (IndexError, TypeError, ValueError):
        return 0


def _package_name(package: Package) -> str | None:
    try:
        return package.name
    except Exception:
        return None


def _package_is_complete(package: Package) -> bool:
    """Whether the decoded header bytes are fully present (no missing pages)."""
    return package.blob.data_end <= len(package.blob.buf)


def _resolve_status(packages: Packages, name_index: NameIndex | None, name: str) -> PackageStatus:
    records: dict[int, Package] = {}
    package_names: dict[int, str] = {}
    versions: dict[int, str | None] = {}
    releases: dict[int, str | None] = {}
    installtimes: dict[int, int] = {}
    deleted_records: dict[int, bool] = {}
    record_errors: dict[int, str] = {}

    for record, data, deleted, _, _ in packages.raw_records(include_deleted=True):
        deleted_records[record] = deleted
        if data is None or len(data) <= 4:
            record_errors[record] = "missing-record-data"
            continue
        try:
            package = Package(data, record=record)
            if not _package_is_complete(package):
                record_errors[record] = "truncated-record"
                continue
            package_name = package.name
            version = package.version
            release = package.release
        except Exception:
            record_errors[record] = "undecodable-record"
            continue

        records[record] = package
        package_names[record] = package_name
        versions[record] = version
        releases[record] = release
        installtimes[record] = _installtime(package)

    record_claims = [
        PackageClaim(
            name=package_names[record],
            version=versions[record],
            release=releases[record],
            record=record,
            source="Packages",
            deleted=deleted_records[record],
            stale=deleted_records[record],
            package=records[record],
        )
        for record in records
        if package_names[record] == name
    ]

    active_record_claims = [claim for claim in record_claims if not claim.deleted]
    best: PackageClaim | None = None
    if active_record_claims:
        best = max(active_record_claims, key=lambda claim: (installtimes[claim.record or 0], claim.record or 0))

    index_claims: list[PackageClaim] = []
    if name_index is not None:
        for entry in name_index.entries(name, include_deleted=True):
            package = records.get(entry.record) if entry.record is not None else None
            reason = entry.reason
            version: str | None = None
            release: str | None = None

            if entry.record is not None:
                if package is None:
                    reason = record_errors.get(entry.record, "missing-record")
                else:
                    version = versions.get(entry.record)
                    release = releases.get(entry.record)
                    if deleted_records.get(entry.record):
                        reason = "deleted-record"
                    if package_names.get(entry.record) != name:
                        reason = "name-mismatch"

            stale = entry.deleted or package is None or bool(deleted_records.get(entry.record))
            if entry.deleted and reason is None:
                reason = "retained-deleted-key"
            if package is not None and package_names.get(entry.record) != name and reason is None:
                reason = "name-mismatch"

            index_claims.append(
                PackageClaim(
                    name=name,
                    version=version,
                    release=release,
                    record=entry.record,
                    source="Name",
                    deleted=entry.deleted,
                    stale=stale,
                    reason=reason,
                    package=package,
                    page=entry.page,
                    index=entry.index,
                )
            )

    unknown_reason: str | None = None
    unresolved_live = [
        claim
        for claim in index_claims
        if not claim.deleted and (claim.package is None or claim.reason in ("name-mismatch", "deleted-record"))
    ]
    if unresolved_live:
        if best is None:
            unknown_reason = unresolved_live[0].reason or "unresolved-index-claim"
        else:
            # A live index entry pointing beyond the newest main record may describe
            # a record whose page is missing. Do not claim the older record is current.
            newer = [
                claim for claim in unresolved_live if claim.record is None or (claim.record or 0) > (best.record or 0)
            ]
            if newer:
                unknown_reason = newer[0].reason or "missing-record"

    all_claims = index_claims + record_claims
    if best is not None:
        all_claims = [
            replace(
                claim,
                stale=claim.stale or claim.record != best.record,
                reason=claim.reason if claim.reason is not None or claim.record == best.record else "superseded-record",
            )
            for claim in all_claims
        ]

    conflicts = [claim for claim in all_claims if claim.stale]
    missing = tuple(sorted({claim.record for claim in unresolved_live}, key=lambda value: (value is None, value or 0)))
    missing_pages = set(packages.db.missing_pages)
    if name_index is not None:
        missing_pages.update(name_index.db.missing_pages)

    proven = best is not None and unknown_reason is None
    return PackageStatus(
        name=name,
        version=best.version if proven and best is not None else None,
        release=best.release if proven and best is not None else None,
        record=best.record if proven and best is not None else None,
        source="Packages" if proven else "unknown",
        proven=proven,
        claims=tuple(all_claims),
        conflicts=tuple(conflicts),
        missing=missing,
        missing_pages=tuple(sorted(missing_pages)),
        reason=unknown_reason,
        package=best.package if proven and best is not None else None,
    )


# Convenience aliases for callers that prefer explicit database names.
PackageDB = PackageDatabase
RPMDatabase = PackageDatabase
RPMDB = PackageDatabase
PackageIndex = NameIndex
NameDB = NameIndex
IndexEntry = NameEntry
IndexClaim = NameEntry
PackageState = PackageStatus
PackageResolution = PackageStatus


def package_status(
    packages: Packages | BinaryIO | str | Path,
    name: str,
    names: BinaryIO | str | Path | None = None,
    *,
    byteorder: str = "auto",
) -> PackageStatus:
    """Convenience wrapper to reconcile a single package name."""
    database = PackageDatabase(packages, names, byteorder=byteorder)
    try:
        return database.status(name)
    finally:
        database.close()


resolve_package = package_status
lookup_package = package_status
get_package_status = package_status


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="input RPMDB Packages file")
    args = parser.parse_args()

    with args.input.open("rb") as fh:
        db = Packages(fh)
        for package in db.entries():
            print(package)
            for entry in package.entries():
                if isinstance(entry, File):
                    print(f"  FILE {entry.path} {entry.size} bytes")
                elif isinstance(entry, Directory):
                    print(f"  DIR  {entry.path}")
            print()

    return 0


if __name__ == "__main__":
    main()
