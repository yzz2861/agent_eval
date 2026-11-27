from __future__ import annotations

import logging
import os
import struct
from collections import OrderedDict
from dataclasses import dataclass
from itertools import groupby
from operator import itemgetter
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream, RunlistStream

from dissect.fat.c_exfat import (
    BITMAP_ENTRY,
    DIR_ENTRY_SIZE,
    EOC,
    FAT_ENTRY_SIZE,
    FILE_ENTRY,
    NO_VOLUME_LABEL_ENTRY,
    UPCASE_TABLE_ENTRY,
    VOLUME_LABEL_ENTRY,
    c_exfat,
)
from dissect.fat.exceptions import InvalidHeaderMagic

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

__all__ = [
    "EXACT_NAME_ORIGIN",
    "UPCASE_TABLE_ORIGIN",
    "ExFAT",
    "ExFATDirectory",
    "NameCandidate",
    "NameKey",
    "NameSlot",
    "NameVerification",
    "UpcaseTable",
    "name_hash",
    "utf16_text",
    "utf16_units",
]

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_EXFAT", "CRITICAL"))

UPCASE_TABLE_SIZE = 0x10000
UPCASE_TABLE_ORIGIN = "image-upcase-table"
EXACT_NAME_ORIGIN = "exact-name"


def utf16_units(name: str | bytes | Iterable[int]) -> tuple[int, ...]:
    """Return the raw UTF-16 code units for a name.

    Strings are encoded as UTF-16LE without normalising or up-casing them. Bytes are interpreted as raw
    little-endian UTF-16 data and iterables are interpreted as a sequence of 16-bit code units.
    """
    if isinstance(name, str):
        data = name.encode("utf-16-le", errors="surrogatepass")
        return tuple(struct.unpack(f"<{len(data) // 2}H", data))

    if isinstance(name, bytes):
        if len(name) % 2:
            raise ValueError("UTF-16 data must contain an even number of bytes")
        return tuple(struct.unpack(f"<{len(name) // 2}H", name))

    units = tuple(name)
    if any(not isinstance(unit, int) or not 0 <= unit <= 0xFFFF for unit in units):
        raise ValueError("UTF-16 code units must be integers in the range 0x0000-0xFFFF")
    return units


def utf16_text(units: Sequence[int]) -> str:
    """Decode raw UTF-16 code units for display without changing them."""
    if not units:
        return ""
    data = b"".join(struct.pack("<H", unit) for unit in units)
    return data.decode("utf-16-le", errors="surrogatepass")


def name_hash(units: Iterable[int]) -> int:
    """Calculate the 16-bit exFAT name hash for raw (or up-cased) UTF-16 units."""
    value = 0
    for unit in units:
        value = ((value << 7) | (value >> 25)) & 0xFFFFFFFF
        value = (value + unit) & 0xFFFFFFFF

    return (value ^ (value >> 16)) & 0xFFFF


class UpcaseTable:
    """An exFAT up-case table loaded from the image."""

    def __init__(self, entry: c_exfat.UPCASE_DIRECTORY_ENTRY, data: bytes):
        self.entry = entry
        self.data = data
        self.mapping = self._decompress(data)

    def __getattr__(self, name: str):
        # Keep access to the on-disk directory entry available through this object.
        return getattr(self.entry, name)

    def __getitem__(self, unit: int) -> int:
        return self.mapping[unit]

    def __iter__(self):
        return iter(self.mapping)

    def __len__(self) -> int:
        return len(self.mapping)

    @staticmethod
    def _decompress(data: bytes) -> tuple[int, ...]:
        """Decompress the up-case table, using identity for omitted code points."""
        mapping = list(range(UPCASE_TABLE_SIZE))
        index = 0
        offset = 0

        while offset + 2 <= len(data) and index < UPCASE_TABLE_SIZE:
            value = struct.unpack_from("<H", data, offset)[0]
            offset += 2

            if value == 0xFFFF:
                if offset + 2 > len(data):
                    break
                # 0xFFFF introduces a run of code points without an explicit mapping. Those code
                # points retain their identity mapping.
                index += struct.unpack_from("<H", data, offset)[0]
                offset += 2
            else:
                mapping[index] = value
                index += 1

        return tuple(mapping)

    def upcase(self, units: Iterable[int]) -> tuple[int, ...]:
        """Apply the image up-case table to raw UTF-16 code units."""
        return tuple(self.mapping[unit] for unit in units)


@dataclass(frozen=True)
class NameKey:
    """A name lookup key and the provenance of the rules used to create it."""

    raw_units: tuple[int, ...]
    units: tuple[int, ...]
    origin: str
    hash: int
    table_checksum: int | None = None

    @property
    def text(self) -> str:
        return utf16_text(self.raw_units)

    @property
    def key_text(self) -> str:
        return utf16_text(self.units)

    @property
    def key_source(self) -> str:
        return self.origin

    @property
    def source(self) -> str:
        return self.origin

    @property
    def provenance(self) -> str:
        return self.origin

    @property
    def hash_source(self) -> str:
        return self.origin


@dataclass(frozen=True)
class NameSlot:
    """A file entry retained from directory parsing, including its physical slot."""

    name: str
    units: tuple[int, ...]
    slot: int
    entry_slot: int
    offset: int
    file: c_exfat.FILE
    value: object

    @property
    def filename(self) -> str:
        return self.name

    @property
    def raw_utf16(self) -> tuple[int, ...]:
        return self.units


@dataclass(frozen=True)
class NameCandidate:
    """A directory entry whose name matches a verification key."""

    name: str
    units: tuple[int, ...]
    key: tuple[int, ...]
    key_origin: str
    match: str
    slot: int
    entry_slot: int
    offset: int
    file: c_exfat.FILE
    value: object
    stored_name_hash: int
    computed_name_hash: int
    hash_matches: bool

    @property
    def filename(self) -> str:
        return self.name

    @property
    def raw_utf16(self) -> tuple[int, ...]:
        return self.units


@dataclass(frozen=True)
class NameVerification:
    """Read-only result of verifying a name against a parsed exFAT directory."""

    query: NameKey
    candidates: tuple[NameCandidate, ...]

    def __iter__(self):
        return iter(self.candidates)

    def __len__(self) -> int:
        return len(self.candidates)

    def __getitem__(self, index: int) -> NameCandidate:
        return self.candidates[index]

    @property
    def matches(self) -> tuple[NameCandidate, ...]:
        return self.candidates

    @property
    def key(self) -> tuple[int, ...]:
        return self.query.units

    @property
    def key_source(self) -> str:
        return self.query.origin

    @property
    def provenance(self) -> str:
        return self.query.origin

    @property
    def slots(self) -> tuple[int, ...]:
        return tuple(candidate.slot for candidate in self.candidates)

    @property
    def exact_matches(self) -> tuple[NameCandidate, ...]:
        return tuple(candidate for candidate in self.candidates if candidate.match == "exact")


class ExFATDirectory(OrderedDict):
    """A parsed exFAT directory that retains every file entry slot.

    The dictionary interface is unchanged for existing callers. ``records`` additionally keeps entries that would
    otherwise be hidden by a duplicate dictionary key so that name verification can report all candidates and their
    original directory slots.
    """

    def __init__(self, exfat: ExFAT | None = None):
        super().__init__()
        self.exfat = exfat
        self.records: list[NameSlot] = []

    def verify_name(self, name: str | bytes | Iterable[int]) -> NameVerification:
        """Verify a name using this directory's entries and the image up-case table, if available."""
        table = self.exfat.upcase_table if self.exfat is not None else None
        return _verify_name(self._effective_records(), name, table)

    def lookup_name(self, name: str | bytes | Iterable[int]) -> NameVerification:
        """Alias for :meth:`verify_name`."""
        return self.verify_name(name)

    def name_key(self, name: str | bytes | Iterable[int]) -> NameKey:
        """Create a name key using this directory's image rules."""
        if self.exfat is None:
            raise ValueError("Directory is not associated with an exFAT image")
        return self.exfat.name_key(name)

    def archive_key(self, name: str | bytes | Iterable[int]) -> tuple[int, ...]:
        """Create a stable archive key using this directory's image rules."""
        return self.name_key(name).units

    def archive_index(self) -> OrderedDict[tuple[int, ...], tuple[NameCandidate, ...]]:
        """Group every retained entry by archive key without discarding colliding slots."""
        table = self.exfat.upcase_table if self.exfat is not None else None
        index = OrderedDict()
        for record in self._effective_records():
            result = _verify_name([record], utf16_text(record.units), table)
            if not result.candidates:
                continue
            candidate = result.candidates[0]
            index.setdefault(candidate.key, []).append(candidate)

        return OrderedDict((key, tuple(candidates)) for key, candidates in index.items())

    def _effective_records(self) -> list[NameSlot]:
        """Return child slots, including for the root dictionary wrapper that contains ``/``."""
        if self.records:
            return self.records

        root = self.get("/")
        if isinstance(root, tuple) and len(root) == 2 and isinstance(root[1], ExFATDirectory):
            return root[1].records

        return self.records


def _verify_name(
    records: Iterable[NameSlot], name: str | bytes | Iterable[int], table: UpcaseTable | None
) -> NameVerification:
    """Verify a name against retained directory slots."""
    raw_units = utf16_units(name)

    if table is not None:
        key_units = table.upcase(raw_units)
        origin = UPCASE_TABLE_ORIGIN
        table_checksum = table.upcase_checksum
    else:
        # Without the image up-case table there is no image-defined case folding. Only an exact raw UTF-16
        # comparison is safe; host Unicode rules must not be substituted for the volume's rules.
        key_units = raw_units
        origin = EXACT_NAME_ORIGIN
        table_checksum = None

    query = NameKey(
        raw_units=raw_units,
        units=key_units,
        origin=origin,
        hash=name_hash(key_units),
        table_checksum=table_checksum,
    )

    candidates = []
    for record in records:
        candidate_key = table.upcase(record.units) if table is not None else record.units
        if candidate_key != key_units:
            continue

        stored_hash = record.file.stream.filename_hash
        computed_hash = name_hash(candidate_key)
        candidates.append(
            NameCandidate(
                name=record.name,
                units=record.units,
                key=candidate_key,
                key_origin=origin,
                match="exact" if record.units == raw_units else "upcase",
                slot=record.slot,
                entry_slot=record.entry_slot,
                offset=record.offset,
                file=record.file,
                value=record.value,
                stored_name_hash=stored_hash,
                computed_name_hash=computed_hash,
                hash_matches=stored_hash == computed_hash,
            )
        )

    return NameVerification(query=query, candidates=tuple(candidates))


class ExFAT:
    def __init__(self, fh: BinaryIO):
        self.filesystem = fh
        fh.seek(0)

        self.vbr = c_exfat.EXFAT_HEADER(fh.read(512))
        self.fs_name = self.vbr.fs_name
        if self.fs_name != b"EXFAT   ":
            raise InvalidHeaderMagic("Invalid exFAT header magic")

        # These get stored as exponents
        self.sector_size = 2**self.vbr.bytes_per_sector_exp
        self.cluster_size = self.sector_size * (2**self.vbr.sectors_per_cluster_exp)

        self.fat_sector = self.vbr.fat_sector  # Almost always sector 128 (absolute)
        self.fat_sector_count = self.vbr.fat_sector_count
        self.fat_size = self.fat_sector_count * self.sector_size
        self.fat = RangeStream(fh, (self.fat_sector * self.sector_size), self.fat_size)

        self.cluster_heap_sector = self.vbr.cluster_heap_sector
        self.cluster_count = self.vbr.cluster_heap_count
        self.root_dir_cluster = self.vbr.root_dir_cluster
        self.root_dir_sector = self.cluster_to_sector(self.root_dir_cluster)
        self.root_directory = RootDirectory(fh, self.root_dir_cluster, self)
        self.files = self.root_directory.dict  # maybe linked list to be able to traverse sub directories easier?

        self.alloc_bitmap = self.root_directory.bitmap_entry
        self.upcase_entry = self.root_directory.upcase_entry
        self._upcase_table: UpcaseTable | None = None
        self._upcase_table_loaded = False
        self.volume_label = self.root_directory.volume_entry.volume_label.strip("\x00")

    @property
    def upcase_table(self) -> UpcaseTable | None:
        """The image's up-case table, or ``None`` when the image does not provide a usable table."""
        if not self._upcase_table_loaded:
            self._upcase_table = self._load_upcase_table()
            self._upcase_table_loaded = True

        return self._upcase_table

    def _load_upcase_table(self) -> UpcaseTable | None:
        entry = self.root_directory.upcase_entry
        if entry is None or entry.upcase_start_cluster < 2 or entry.upcase_length == 0:
            return None

        try:
            runlist = self._upcase_runlist(entry)
            stream = RunlistStream(self.filesystem, runlist, entry.upcase_length, self.sector_size)
            data = stream.read()
        except (EOFError, OSError, ValueError, struct.error):
            log.debug("Unable to read exFAT up-case table", exc_info=True)
            return None

        return UpcaseTable(entry, data)

    def _upcase_runlist(self, entry: c_exfat.UPCASE_DIRECTORY_ENTRY) -> list[tuple[int, int]]:
        """Read the up-case table through its FAT chain when one is present, otherwise as a contiguous run."""
        cluster_count = -(-entry.upcase_length // self.cluster_size)
        clusters = []
        current = entry.upcase_start_cluster

        for _ in range(cluster_count):
            clusters.append(current)
            self.fat.seek(current * FAT_ENTRY_SIZE)
            next_cluster = struct.unpack("<L", self.fat.read(FAT_ENTRY_SIZE))[0]

            if next_cluster in (0, EOC) or next_cluster < 2 or next_cluster >= self.cluster_count + 2:
                if len(clusters) != cluster_count:
                    clusters = []
                break
            current = next_cluster

        if len(clusters) == cluster_count:
            return self._runlist_from_clusters(clusters)

        return self.runlist(entry.upcase_start_cluster, not_fragmented=True, size=entry.upcase_length)

    def _runlist_from_clusters(self, clusters: list[int]) -> list[tuple[int, int]]:
        """Convert a list of clusters to a sector runlist."""
        sectors_per_cluster = 2**self.vbr.sectors_per_cluster_exp
        runlist = []
        for _, cluster_group in groupby(enumerate(clusters), lambda item: item[1] - item[0]):
            run = list(map(itemgetter(1), cluster_group))
            runlist.append((self.cluster_to_sector(run[0]), len(run) * sectors_per_cluster))

        return runlist

    def name_key(self, name: str | bytes | Iterable[int]) -> NameKey:
        """Create a name key from the image up-case table, or from the exact name when no table exists."""
        raw_units = utf16_units(name)
        table = self.upcase_table

        if table is not None:
            units = table.upcase(raw_units)
            origin = UPCASE_TABLE_ORIGIN
            table_checksum = table.upcase_checksum
        else:
            units = raw_units
            origin = EXACT_NAME_ORIGIN
            table_checksum = None

        return NameKey(
            raw_units=raw_units,
            units=units,
            origin=origin,
            hash=name_hash(units),
            table_checksum=table_checksum,
        )

    def lookup_key(self, name: str | bytes | Iterable[int]) -> NameKey:
        """Alias for :meth:`name_key`."""
        return self.name_key(name)

    def archive_key(self, name: str | bytes | Iterable[int]) -> tuple[int, ...]:
        """Return a stable archive key based only on this image's name rules."""
        return self.name_key(name).units

    def name_hash(self, name: str | bytes | Iterable[int]) -> int:
        """Calculate the exFAT name hash for a name using the image's lookup key."""
        return self.name_key(name).hash

    def get_directory(self, directory: str | Sequence[str] | ExFATDirectory | None = "/") -> ExFATDirectory:
        """Return a parsed directory by path or by direct object."""
        if isinstance(directory, ExFATDirectory):
            return directory

        if isinstance(directory, tuple) and len(directory) == 2 and isinstance(directory[1], ExFATDirectory):
            return directory[1]

        if isinstance(directory, (list, tuple)):
            parts = [str(part) for part in directory]
        else:
            parts = str(directory or "").strip("/").split("/")

        node = self.files["/"][1]
        for part in parts:
            if not part:
                continue
            node = node[part][1]
            if not isinstance(node, ExFATDirectory):  # pragma: no cover - defensive for externally supplied trees
                raise TypeError(f"Directory {part!r} does not retain name slots")

        return node

    def verify_name(
        self, name: str | bytes | Iterable[int], directory: str | Sequence[str] | ExFATDirectory | None = "/"
    ) -> NameVerification:
        """Verify a name against a parsed directory without modifying parser state."""
        target = self.get_directory(directory)
        return _verify_name(target._effective_records(), name, self.upcase_table)

    def archive_index(
        self, directory: str | Sequence[str] | ExFATDirectory | None = "/"
    ) -> OrderedDict[tuple[int, ...], tuple[NameCandidate, ...]]:
        """Group a directory's entries by image-defined archive key while preserving every slot."""
        return self.get_directory(directory).archive_index()

    def lookup_name(
        self, name: str | bytes | Iterable[int], directory: str | Sequence[str] | ExFATDirectory | None = "/"
    ) -> NameVerification:
        """Alias for :meth:`verify_name`."""
        return self.verify_name(name, directory)

    def check_name(
        self, name: str | bytes | Iterable[int], directory: str | Sequence[str] | ExFATDirectory | None = "/"
    ) -> NameVerification:
        """Alias for :meth:`verify_name`."""
        return self.verify_name(name, directory)

    def cluster_to_sector(self, cluster: int) -> int | None:
        """Returns the clusters' corresponding sector address.

        Args:
            cluster (int): cluster address

        Returns:
            int: corresponding sector address if available
        """
        sector = ((cluster - 2) * (2**self.vbr.sectors_per_cluster_exp)) + self.cluster_heap_sector
        return sector if sector > 0 else None

    def sector_to_cluster(self, sector: int) -> int | None:
        """Returns the sectors' corresponding cluster address.

        Args:
            sector (int): sector address

        Returns:
            int: corresponding cluster address if available
        """
        cluster = ((sector - self.cluster_to_sector(2)) // self.sector_size) + 2
        return cluster if cluster >= 2 else None

    def runlist(
        self, starting_cluster: int, not_fragmented: bool = True, size: int | None = None
    ) -> list[tuple[int, int]]:
        """Creates a RunlistStream compatible runlist from exFAT FAT structures, in sectors.

        Args:
            starting_cluster (int): First cluster of file, folder or location in question

        Returns:
            runlist: [(sector_offset, run_length_in_sectors)]
        """
        # If file is not fragmented clusters will not be present in the FAT
        cluster_chain = [starting_cluster] if not_fragmented else self.get_cluster_chain(starting_cluster)
        runlist = []
        sectors_per_cluster = 2**self.vbr.sectors_per_cluster_exp

        # TODO Graceful way to construct a runlist of non-fragmented streams spanning multiple sectors
        if size:
            run = -(-size // self.cluster_size) * sectors_per_cluster
            runlist.append((self.cluster_to_sector(cluster_chain[0]), run))
        else:
            # This is a somewhat convoluted, but short way to group successive
            # clusters together.
            # As the cluster numbers in the cluster_chain are strictly
            # incrementing, a successive range of clusters will have the same
            # delta with respect to their position in the cluster_chain, which
            # is different from any other successive range, which is what is
            # used in the groupby().
            # Example: [(3, 1), (4, 1), (6, 1)] becomes [(3, 2), (6, 1)]
            for _, cluster_group in groupby(enumerate(cluster_chain), lambda i: i[0] - i[1]):
                run = list(map(itemgetter(1), cluster_group))
                start_cluster = run[0]
                run_len = len(run) * sectors_per_cluster
                runlist.append((self.cluster_to_sector(start_cluster), run_len))

        return runlist

    def get_cluster_chain(self, starting_cluster: int) -> list[int]:
        """Reads the on disk FAT to construct the cluster chain.

        Args:
            starting_cluster (int): cluster to look-up the chain from

        Returns:
            list: Chain of clusters. Including starting_cluster
        """
        next_ = 0x00000000
        chain = []

        if starting_cluster < 2:
            return chain

        while next_ != EOC:
            self.fat.seek(starting_cluster * FAT_ENTRY_SIZE)
            next_ = struct.unpack("<L", self.fat.read(FAT_ENTRY_SIZE))[0]
            chain.append(starting_cluster)
            starting_cluster = next_

        return chain

    @staticmethod
    def _utc_timezone(timezone: int) -> dict[str, str | int]:
        """Converts a Microsoft exFAT timezone byte to its UTC timezone equivalent.

        Args:
            timezone (int): exFAT timezone byte

        Returns:
            dict: UTC name (str), UTC offset in minutes (int)
        """
        #    utc_bool -64 32 16 : 8 4 2 1
        #              ^ sign
        TIMEZONE_MINUTE_INCREMENT = 15
        utc_enabled = timezone >> 7
        signed = (timezone >> 6) & 0x11  # Check if the second bit is set

        if utc_enabled:
            if signed:
                utc_minute_offset = ((timezone & 0x3F) - 64) * TIMEZONE_MINUTE_INCREMENT
            else:
                utc_minute_offset = (timezone & 0x7F) * TIMEZONE_MINUTE_INCREMENT

            hours, minutes = divmod(utc_minute_offset, 60)
            utc_name = f"UTC{hours:+03}:{minutes:02}"

            return {"name": utc_name, "offset": utc_minute_offset}

        return {"name": "localtime", "offset": 0}


class RootDirectory:
    def __init__(self, fh: BinaryIO, location: int, exfat: ExFAT):
        self.exfat = exfat
        self.location = location
        self.size = 0
        self.root_dir = None
        self.volume_entry = None
        self.upcase_entry = None
        self.bitmap_entry = None
        self.dict = ExFATDirectory(self.exfat)
        self._parse_root_dir(fh)

    def _parse_root_dir(self, fh: BinaryIO) -> None:
        """Parses the passed fh to construct the Root directory object."""
        # Root dir is always present in FAT so we pass False to traverse the FAT table
        # thus root dir is per definition fragmented
        runlist = self.exfat.runlist(self.location, False)
        size = 0  # in bytes

        # Calculate size of rootdir from runlist since rootdir has no size attribute
        for run in runlist:
            size += run[1] * self.exfat.sector_size

        self.size = size
        self.root_dir = RunlistStream(fh, runlist, self.size, self.exfat.sector_size)
        self.dict = self._create_root_dir(self.root_dir)

    def _parse_subdir(self, entry: c_exfat.FILE) -> ExFATDirectory:
        """Parses the given sub directory file directory entry for containing files.

        Args:
            entry (FILE): Directory FILE entry

        Returns:
            ExFATDirectory: Containing files in sub directory
        """
        folder_location = entry.stream.location
        folder_size = entry.stream.data_length  # in bytes
        folder_runlist = self.exfat.runlist(folder_location, not_fragmented=entry.stream.flags.not_fragmented)

        fh = RunlistStream(self.exfat.filesystem, folder_runlist, folder_size, self.exfat.sector_size)
        return self._parse_file_entries(fh)

    @staticmethod
    def _construct_filename(fn_entries: list[c_exfat.FILENAME_DIRECTORY_ENTRY], is_dir: bool = False) -> str:
        """Assembles the filename from given file name directory entries.

        Args:
            fn_entries (list): A list of exFAT file name directory entries

        Returns:
            str: Name of file or folder stripped from trailing null values
        """
        units = []
        for fn_entry in fn_entries:
            units.extend(fn_entry.filename)

        while units and units[-1] == 0:
            units.pop()

        filename = utf16_text(units)

        return filename if not is_dir else filename + "/"

    @staticmethod
    def _filename_units(
        fn_entries: list[c_exfat.FILENAME_DIRECTORY_ENTRY], filename_length: int | None = None
    ) -> tuple[int, ...]:
        """Return the raw UTF-16 units from filename directory entries."""
        units = []
        for fn_entry in fn_entries:
            data = fn_entry.dumps()
            units.extend(struct.unpack("<15H", data[2:32]))

        if filename_length is not None:
            units = units[:filename_length]
        else:
            while units and units[-1] == 0:
                units.pop()

        return tuple(units)

    def _parse_file_entries(self, fh: BinaryIO) -> ExFATDirectory:
        """Finds and parses file entries in a given file handle (file like object).

        Args:
            fh (Stream object): Any stream object

        Returns:
            ExFATDirectory: Found and parsed file directory entries
        """
        entries = ExFATDirectory(self.exfat)

        while fh.tell() < fh.size:
            entry_offset = fh.tell()
            entry = c_exfat.FILE_DIRECTORY_ENTRY(fh.read(DIR_ENTRY_SIZE))

            if entry.entry_type == FILE_ENTRY:  # Or entry.entry_type == 0x05:
                # Entry is a file so we reuse it
                metadata = entry

                # -1 because the metadata entry includes the stream dir entry in its count
                fnentry_count = metadata.subentry_count - 1

                stream = c_exfat.STREAM_DIRECTORY_ENTRY(fh.read(DIR_ENTRY_SIZE))
                fn_entries = [c_exfat.FILENAME_DIRECTORY_ENTRY(fh.read(DIR_ENTRY_SIZE)) for _ in range(fnentry_count)]

                file_ = c_exfat.FILE(metadata=metadata, stream=stream, fn_entries=fn_entries)
                if file_.metadata.attributes.directory:
                    # A directory will have its own file entry as its first element and an ordered dict
                    # of file entry contained in it which can be accessed by their corresponding keys
                    filename = self._construct_filename(file_.fn_entries)
                    value = (file_, self._parse_subdir(file_))
                else:
                    filename = self._construct_filename(file_.fn_entries)
                    value = (file_, None)

                units = self._filename_units(file_.fn_entries, file_.stream.filename_length)
                entries.records.append(
                    NameSlot(
                        name=utf16_text(units),
                        units=units,
                        slot=len(entries.records),
                        entry_slot=entry_offset // DIR_ENTRY_SIZE,
                        offset=entry_offset,
                        file=file_,
                        value=value,
                    )
                )
                entries[filename] = value
            elif entry.entry_type == 0x00:
                # We could break early on entry_type==0x00 (end-of-directory)
                # since all following entries are expected to be 0x00 as well.
                pass
            else:
                self._non_file_entries(entry)

        return entries

    def _non_file_entries(self, entry: c_exfat.FILE_DIRECTORY_ENTRY) -> None:
        if entry.entry_type == VOLUME_LABEL_ENTRY or entry.entry_type == NO_VOLUME_LABEL_ENTRY:
            self.volume_entry = c_exfat.VOLUME_DIRECTORY_ENTRY(entry.dumps())
        elif entry.entry_type == BITMAP_ENTRY:
            self.bitmap_entry = c_exfat.BITMAP_DIRECTORY_ENTRY(entry.dumps())
        elif entry.entry_type == UPCASE_TABLE_ENTRY:
            self.upcase_entry = c_exfat.UPCASE_DIRECTORY_ENTRY(entry.dumps())

    def _create_root_dir(self, root_dir: BinaryIO) -> ExFATDirectory:
        """Since exFAT does not have a dedicated root directory entry
        one has to be constructed form available parameters during filesystem parsing.

        This is ballpark so no real forensic conclusions should be based on the information of the root entry
        """
        metadata = c_exfat.FILE_DIRECTORY_ENTRY(
            entry_type=0x85, subentry_count=2, attributes=c_exfat.ATTRIBUTES(directory=0b1)
        )

        stream = c_exfat.STREAM_DIRECTORY_ENTRY(
            entry_type=0xC0,
            flags=c_exfat.FILE_FLAGS(allocation_possible=0b0, not_fragmented=0b0),
            filename_length=1,
            location=self.location,
            data_length=self.size,
        )

        fn_entries = [
            c_exfat.FILENAME_DIRECTORY_ENTRY(
                entry_type=0xC1, flags=0x00, filename=[0x2F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            )
        ]

        root_entry = ExFATDirectory(self.exfat)
        root_entry["/"] = (
            c_exfat.FILE(metadata=metadata, stream=stream, fn_entries=fn_entries),
            self._parse_file_entries(root_dir),
        )

        return root_entry
