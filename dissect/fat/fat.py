# References:
# - https://ogris.de/fatrepair/fat.c
# - https://github.com/nathanhi/pyfatfs
# - https://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc
from __future__ import annotations

import datetime
import struct
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache, reduce
from operator import itemgetter
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream, RunlistStream
from dissect.util.ts import dostimestamp

from dissect.fat.c_fat import (
    BAD_CLUSTER,
    DATA_CLUSTER_MAX,
    DATA_CLUSTER_MIN,
    END_OF_CLUSTER_MAX,
    END_OF_CLUSTER_MIN,
    FAT12_EOC,
    FREE_CLUSTER,
    VALID_BPB_MEDIA,
    Fattype,
    c_fat,
)
from dissect.fat.exceptions import (
    BadClusterError,
    EmptyDirectoryError,
    FileNotFoundError,
    FreeClusterError,
    InvalidBPB,
    InvalidDirectoryError,
    LastEmptyDirectoryError,
    NotADirectoryError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


class FATFS:
    def __init__(self, fh: BinaryIO, encoding: str = "ibm437"):
        self.fh = fh
        self.encoding = encoding

        fh.seek(0)
        sector = fh.read(512)
        bpb_size = len(c_fat.Bpb)
        self.bpb = c_fat.Bpb(sector[:bpb_size])
        bpb16 = c_fat.Bpb16(sector[bpb_size:])
        bpb32 = c_fat.Bpb32(sector[bpb_size:])

        validate_bpb(self.bpb)

        self.fat_size = self.bpb.BPB_FATSz16 or bpb32.BPB_FATSz32
        self.total_sectors = self.bpb.BPB_TotSec16 or self.bpb.BPB_TotSec32

        # Taken from FAT32 spec
        root_dir_sectors = ((self.bpb.BPB_RootEntCnt * 32) + (self.bpb.BPB_BytsPerSec - 1)) // self.bpb.BPB_BytsPerSec
        self.first_data_sector = self.bpb.BPB_RsvdSecCnt + (self.bpb.BPB_NumFATs * self.fat_size) + root_dir_sectors

        data_sec = self.total_sectors - self.first_data_sector
        count_of_clusters = data_sec // self.bpb.BPB_SecPerClus
        if count_of_clusters < 4085:
            self.type = Fattype.FAT12
            self.bpb_ext = bpb16
        elif count_of_clusters < 65525:
            self.type = Fattype.FAT16
            self.bpb_ext = bpb16
        else:
            self.type = Fattype.FAT32
            self.bpb_ext = bpb32

        self.sector_size = self.bpb.BPB_BytsPerSec
        self.cluster_size = self.bpb.BPB_BytsPerSec * self.bpb.BPB_SecPerClus

        # FAT table layout and mirroring declarations from the BPB.
        # FAT12/16 volumes always keep all tables mirrored; FAT32 can disable
        # mirroring through BPB_ExtFlags and nominate a single active table.
        self.fat_count = self.bpb.BPB_NumFATs
        if self.type == Fattype.FAT32:
            ext_flags = self.bpb_ext.BPB_ExtFlags
            self.fat_mirroring_enabled = not bool(ext_flags & 0x0080)
            self.active_fat = ext_flags & 0x000F if not self.fat_mirroring_enabled else 0
        else:
            self.fat_mirroring_enabled = True
            self.active_fat = 0
        self.active_fat = min(self.active_fat, self.fat_count - 1)

        # FATs start after the reserved sectors, each table is fat_size sectors
        fat_offset = self.bpb.BPB_RsvdSecCnt * self.sector_size
        self.fats = [
            FAT(
                RangeStream(
                    fh,
                    fat_offset + index * self.fat_size * self.sector_size,
                    self.fat_size * self.sector_size,
                ),
                self.type,
                index=index,
            )
            for index in range(self.fat_count)
        ]
        self.fat = self.fats[self.active_fat]
        self.data_stream = RangeStream(fh, self.first_data_sector * self.sector_size, data_sec * self.sector_size)

        # volume label with stripped padding
        self.volume_label = bytes(self.bpb_ext.BS_VolLab).strip(b"\x20").decode(encoding)

        # volume serial number, hex encoded
        self.volume_id = f"{self.bpb_ext.BS_VolID:x}"

        self.root = RootDirectory(self)

    def get(self, path: str, dirent: DirectoryEntry | RootDirectory | None = None) -> DirectoryEntry | RootDirectory:
        dirent = dirent if dirent else self.root

        # Programmatically we will often use the `/` separator, so replace it with the native path separator of FAT
        # `/` is an illegal character in FAT filenames, so it's safe to replace
        parts = path.replace("/", "\\").split("\\")
        for part in parts:
            if not part:
                continue

            if dirent is self.root and part in (".", ".."):
                continue

            part_upper = part.upper()
            for child in dirent.iterdir():
                if part_upper in (child.name.upper(), child.short_name.upper()):
                    dirent = child
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return dirent

    def compare_chains(self, cluster: int, size: int | None = None) -> ChainComparison:
        """Walk a cluster chain in every FAT table and compare the results.

        Each table declared in the BPB is walked independently with
        :meth:`FAT.walk_chain`. ``size`` is the declared file size in bytes and
        is used to derive how many clusters the chain must provide; combined
        with read failures and termination markers this yields a confirmable
        common prefix and the per-table branches where the tables diverge.
        """
        expected_clusters = None
        if size is not None:
            expected_clusters = (size + self.cluster_size - 1) // self.cluster_size

        walks = [fat.walk_chain(cluster, expected_clusters) for fat in self.fats]
        return ChainComparison(
            start_cluster=cluster,
            walks=walks,
            mirroring_enabled=self.fat_mirroring_enabled,
            active_table=self.active_fat,
            size=size,
            expected_clusters=expected_clusters,
        )


def validate_bpb(bpb: c_fat.Bpb | bytes) -> None:
    if isinstance(bpb, bytes):
        bpb = c_fat.Bpb(bpb[: len(c_fat.Bpb)])

    # Detect a valid x86 JMP opcode
    if not (bpb.BS_jmpBoot[0] == 0xEB and bpb.BS_jmpBoot[2] == 0x90) and bpb.BS_jmpBoot[0] != 0xE9:
        raise InvalidBPB(f"Invalid BS_jmpBoot: {bytes(bpb.BS_jmpBoot)!r}")

    if bpb.BPB_BytsPerSec not in [2**x for x in range(9, 13)]:
        raise InvalidBPB(f"Invalid BPB_BytsPerSec: 0x{bpb.BPB_BytsPerSec:x}")

    if bpb.BPB_SecPerClus not in [2**x for x in range(8)]:
        raise InvalidBPB(f"Invalid BPB_SecPerClus: 0x{bpb.BPB_SecPerClus:x}")

    if bpb.BPB_RsvdSecCnt == 0:
        raise InvalidBPB(f"Invalid BPB_RsvdSecCnt, must not be 0: 0x{bpb.BPB_RsvdSecCnt:x}")

    if bpb.BPB_Media not in VALID_BPB_MEDIA:
        raise InvalidBPB(f"Invalid BPB_Media: 0x{bpb.BPB_Media:x}")

    if bpb.BPB_NumFATs < 1:
        raise InvalidBPB(f"Invalid BPB_NumFATs, must be at least 1: 0x{bpb.BPB_NumFATs:x}")

    root_entry_count = bpb.BPB_RootEntCnt * 32
    root_entry_count %= bpb.BPB_BytsPerSec
    if bpb.BPB_RootEntCnt != 0 and root_entry_count != 0:
        raise InvalidBPB("Root entry count does not align with bytes per sector")

    if bpb.BPB_TotSec16 == 0 and bpb.BPB_TotSec32 == 0:
        raise InvalidBPB(f"Invalid BPB_TotSec16 and BPB_TotSec32: 0x{bpb.BPB_TotSec16:x}, 0x{bpb.BPB_TotSec32:x}")


class FAT:
    def __init__(self, fh: BinaryIO, fattype: Fattype, index: int = 0):
        self.fh = fh
        self.index = index

        if fattype == Fattype.FAT12:
            self.bits_per_entry = 12
        elif fattype == Fattype.FAT16:
            self.bits_per_entry = 16
        elif fattype == Fattype.FAT32:
            self.bits_per_entry = 32
        else:
            raise TypeError("Unsupported FAT type")

        self.entry_count = int(self.fh.size // (self.bits_per_entry / 8))

        self.get = lru_cache(4096)(self.get)

    def get(self, cluster: int) -> int | None:
        if cluster >= self.entry_count:
            raise ValueError(f"Cluster exceeds FAT entry count: {cluster} >= {self.entry_count}")

        if self.bits_per_entry == 12:
            offset_in_fat = cluster + (cluster // 2)
            self.fh.seek(offset_in_fat)
            value = struct.unpack("<H", self.fh.read(2))[0]

            return value >> 4 if cluster & 1 else value & 0x0FFF

        if self.bits_per_entry == 16:
            offset_in_fat = cluster * 2
            self.fh.seek(offset_in_fat)
            return struct.unpack("<H", self.fh.read(2))[0]

        if self.bits_per_entry == 32:
            offset_in_fat = cluster * 4
            self.fh.seek(offset_in_fat)
            return struct.unpack("<I", self.fh.read(4))[0] & 0x0FFFFFFF  # FAT32 clusters are 28 bits

        raise ValueError("Unsupported FAT type")

    def chain(self, cluster: int) -> Iterator[int]:
        bits = self.bits_per_entry
        while True:
            value = self.get(cluster)

            if DATA_CLUSTER_MIN <= value <= mask(DATA_CLUSTER_MAX, bits):
                yield cluster

            # FAT12 special EOC
            if self.bits_per_entry == 12 and value == FAT12_EOC:
                yield cluster
                break

            if mask(END_OF_CLUSTER_MIN, bits) <= value <= mask(END_OF_CLUSTER_MAX, bits):
                yield cluster
                break

            if value == mask(BAD_CLUSTER, bits):
                raise BadClusterError(cluster)

            if value == FREE_CLUSTER:
                raise FreeClusterError(cluster)

            cluster = value

    def runlist(self, cluster: int) -> Iterator[tuple[int, int]]:
        """Create a runlist from a cluster chain.

        First two clusters are reserved, so substract those.
        Also combine consecutive clusters for a more efficient runlist.
        """
        chain = self.chain(cluster)

        run_start = next(chain) - 2
        run_size = 1

        for cl in chain:
            if cl == run_start + run_size:
                run_size += 1
            else:
                yield (run_start, run_size)
                run_start = cl - 2
                run_size = 1
        else:
            yield (run_start, run_size)

    def walk_chain(self, cluster: int, expected_clusters: int | None = None) -> ChainWalk:
        """Walk a cluster chain without raising, for forensic inspection.

        Unlike :meth:`chain`, unreadable or invalid entries and loops are
        reported through the returned :class:`ChainWalk` instead of raising.
        ``expected_clusters`` can be derived from a file size to check whether
        the chain is long enough for the file it should describe.
        """
        bits = self.bits_per_entry
        clusters = []
        seen = set()
        termination = ChainTermination.END_OF_CHAIN

        while True:
            if cluster in seen:
                termination = ChainTermination.CYCLE
                break
            seen.add(cluster)

            try:
                value = self.get(cluster)
            except ValueError:
                termination = ChainTermination.OUT_OF_RANGE
                break
            except (EOFError, OSError, struct.error):
                termination = ChainTermination.READ_ERROR
                break

            if value == FREE_CLUSTER:
                termination = ChainTermination.FREE_CLUSTER
                break

            if value == mask(BAD_CLUSTER, bits):
                termination = ChainTermination.BAD_CLUSTER
                break

            clusters.append(cluster)

            # FAT12 special EOC
            if self.bits_per_entry == 12 and value == FAT12_EOC:
                break

            if mask(END_OF_CLUSTER_MIN, bits) <= value <= mask(END_OF_CLUSTER_MAX, bits):
                break

            if expected_clusters is not None and len(clusters) >= expected_clusters:
                termination = ChainTermination.LENGTH_REACHED
                break

            cluster = value

        return ChainWalk(
            table=self.index,
            clusters=clusters,
            termination=termination,
            expected_clusters=expected_clusters,
        )


class ChainTermination(Enum):
    """Reason a cluster chain walk stopped."""

    END_OF_CHAIN = "end-of-chain"
    LENGTH_REACHED = "length-reached"
    FREE_CLUSTER = "free-cluster"
    BAD_CLUSTER = "bad-cluster"
    OUT_OF_RANGE = "out-of-range"
    CYCLE = "cycle"
    READ_ERROR = "read-error"


@dataclass
class ChainWalk:
    """Result of walking a cluster chain in a single FAT table."""

    table: int
    clusters: list[int]
    termination: ChainTermination
    expected_clusters: int | None = None

    @property
    def clean(self) -> bool:
        """Whether the walk ended on a valid terminator instead of an error."""
        return self.termination in (ChainTermination.END_OF_CHAIN, ChainTermination.LENGTH_REACHED)

    @property
    def length_satisfied(self) -> bool:
        """Whether the walk covers at least the clusters needed for the file size."""
        return self.expected_clusters is None or len(self.clusters) >= self.expected_clusters

    @property
    def confirmed(self) -> bool:
        """Whether the walk both terminates cleanly and satisfies the file length."""
        return self.clean and self.length_satisfied


class ChainVerdict(Enum):
    """Forensic verdict for a cross-table chain comparison."""

    CONSISTENT = "consistent"
    STALE_MIRROR = "stale-mirror"
    MIRRORED_DIVERGENCE = "mirrored-divergence"
    UNCONFIRMED = "unconfirmed"


@dataclass
class ChainComparison:
    """Forensic side-by-side view of one cluster chain across all FAT tables."""

    start_cluster: int
    walks: list[ChainWalk]
    mirroring_enabled: bool
    active_table: int
    size: int | None = None
    expected_clusters: int | None = None

    @property
    def common_prefix(self) -> list[int]:
        """Clusters all tables agree on, from the start of the chain."""
        prefix = []
        for entries in zip(*(walk.clusters for walk in self.walks), strict=False):
            first = entries[0]
            if all(entry == first for entry in entries):
                prefix.append(first)
            else:
                break
        return prefix

    @property
    def diverged(self) -> bool:
        """Whether any table walks a different chain than the others."""
        sequences = [walk.clusters for walk in self.walks]
        return any(sequence != sequences[0] for sequence in sequences[1:])

    @property
    def divergence_offset(self) -> int | None:
        """Chain position where the tables start to disagree, if they do."""
        if not self.diverged:
            return None
        return len(self.common_prefix)

    @property
    def branches(self) -> dict[int, list[int]]:
        """Remaining clusters per table after the common prefix."""
        offset = len(self.common_prefix)
        return {walk.table: walk.clusters[offset:] for walk in self.walks}

    @property
    def verdict(self) -> ChainVerdict:
        """Verdict based on the BPB mirroring declaration and the walked chains."""
        if not self.diverged:
            if all(walk.confirmed for walk in self.walks):
                return ChainVerdict.CONSISTENT
            return ChainVerdict.UNCONFIRMED
        if self.mirroring_enabled:
            return ChainVerdict.MIRRORED_DIVERGENCE
        if self.walks[self.active_table].confirmed:
            return ChainVerdict.STALE_MIRROR
        return ChainVerdict.UNCONFIRMED

    def report(self) -> str:
        """Render a human-readable summary for forensic review."""
        if self.mirroring_enabled:
            declaration = "mirroring enabled"
        else:
            declaration = f"mirroring disabled, active table {self.active_table}"
        lines = [
            f"chain start: cluster {self.start_cluster}",
            f"declaration: {len(self.walks)} tables, {declaration}",
        ]
        if self.size is not None:
            lines.append(f"file size: {self.size} bytes ({self.expected_clusters} clusters expected)")
        for walk in self.walks:
            chain = " -> ".join(map(str, walk.clusters)) or "<empty>"
            lines.append(f"table {walk.table}: {chain} [{walk.termination.value}]")
        prefix = " -> ".join(map(str, self.common_prefix)) or "<none>"
        lines.append(f"common prefix: {prefix}")
        if self.diverged:
            lines.append(f"diverges at chain position {self.divergence_offset}")
        lines.append(f"verdict: {self.verdict.value}")
        return "\n".join(lines)


class DirectoryEntry:
    def __init__(self, fs: FATFS, fh: BinaryIO, parent: DirectoryEntry | RootDirectory | None = None):
        self.fs = fs
        self.parent = parent

        self.dirent = None
        self.ldirents = []

        self.name = None
        self.short_name = None

        buf = fh.read(32)
        dirent = c_fat.Dirent(buf)

        if dirent.DIR_Name[0] == 0xE5:
            raise EmptyDirectoryError("Dirent is an empty entry")

        if dirent.DIR_Name[0] == 0x0:
            raise LastEmptyDirectoryError("Dirent is the last empty entry")

        if dirent.DIR_Attr & c_fat.ATTR_LONG_NAME_MASK == c_fat.ATTR_LONG_NAME:
            ldirent = c_fat.Ldirent(buf)
            found_last = False
            while ldirent.LDIR_Attr == c_fat.ATTR_LONG_NAME:
                self.ldirents.append(ldirent)
                if ldirent.LDIR_Ord & c_fat.LAST_LONG_ENTRY:
                    if found_last:
                        raise InvalidDirectoryError("Dirent contains multiple last-long entries")
                    found_last = True

                buf = fh.read(32)
                ldirent = c_fat.Ldirent(buf)

            self.dirent = c_fat.Dirent(buf)

            self.ldirents.sort(key=lambda e: e.LDIR_Ord & 0x3F)
            name_map = (e.LDIR_Name1 + e.LDIR_Name2 + e.LDIR_Name3 for e in self.ldirents)
            name_reduce = bytes(reduce(lambda a, b: a + b, name_map))
            self.name = c_fat.wchar[None](name_reduce + b"\x00\x00")
        else:
            self.dirent = dirent

        dir_name = bytearray(self.dirent.DIR_Name)
        if dir_name[0] == 0x05:
            dir_name[0] = 0xE5

        base = dir_name[:8].decode(self.fs.encoding).rstrip("\x00").rstrip()
        ext = dir_name[8:].decode(self.fs.encoding).rstrip("\x00").rstrip()

        self.short_name = f"{base}.{ext}" if ext else base
        if not self.name:
            self.name = self.short_name

        self._runlist = None
        self._entries = None

    def __repr__(self) -> str:
        return f"<DirectoryEntry name={self.name}>"

    @property
    def path(self) -> str:
        return "\\".join([self.parent.path if self.parent else "", self.name]).lstrip("\\")

    @property
    def size(self) -> size:
        if self.is_directory():
            return sum(map(itemgetter(1), self.dataruns())) * self.fs.cluster_size
        return self.dirent.DIR_FileSize

    @property
    def cluster(self) -> int:
        return (self.dirent.DIR_FstClusHI << 16) | self.dirent.DIR_FstClusLO

    @property
    def ctime(self) -> datetime.datetime:
        if self.dirent.DIR_CrtDate and self.dirent.DIR_CrtTime:
            return dostimestamp(
                (self.dirent.DIR_CrtDate << 16) | self.dirent.DIR_CrtTime,
                self.dirent.DIR_CrtTimeTenth,
            )
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def atime(self) -> datetime.datetime:
        if self.dirent.DIR_LstAccDate:
            return dostimestamp(self.dirent.DIR_LstAccDate << 16)
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def mtime(self) -> datetime.datetime:
        return dostimestamp((self.dirent.DIR_WrtDate << 16) | self.dirent.DIR_WrtTime)

    def is_readonly(self) -> bool:
        return bool(self.dirent.DIR_Attr & c_fat.ATTR_READ_ONLY)

    def is_hidden(self) -> bool:
        return bool(self.dirent.DIR_Attr & c_fat.ATTR_HIDDEN)

    def is_system(self) -> bool:
        return bool(self.dirent.DIR_Attr & c_fat.ATTR_SYSTEM)

    def is_volume_id(self) -> bool:
        return bool(self.dirent.DIR_Attr & c_fat.ATTR_VOLUME_ID)

    def is_directory(self) -> bool:
        return bool(self.dirent.DIR_Attr & c_fat.ATTR_DIRECTORY)

    def is_archive(self) -> bool:
        return bool(self.dirent.DIR_Attr & c_fat.ATTR_ARCHIVE)

    def iterdir(self) -> Iterator[DirectoryEntry]:
        if not self.is_directory():
            raise NotADirectoryError(self.name)

        if not self._entries:
            entries = []
            for entry in _iter_dirent(self.fs, self.open(), self):
                yield entry
                entries.append(entry)

            self._entries = entries
        else:
            yield from self._entries

    def dataruns(self) -> list[tuple[int, int]]:
        if self._runlist is None:
            self._runlist = [] if self.cluster == FREE_CLUSTER else list(self.fs.fat.runlist(self.cluster))
        return self._runlist

    def open(self) -> RunlistStream:
        return RunlistStream(self.fs.data_stream, self.dataruns(), self.size, self.fs.cluster_size)


class RootDirectory(DirectoryEntry):
    def __init__(self, fs: FATFS):
        self.fs = fs
        self.name = "\\"
        self.short_name = self.name

        self._runlist = None
        self._entries = None

    @property
    def path(self) -> str:
        return ""

    @property
    def size(self) -> int:
        if self.fs.type in (Fattype.FAT12, Fattype.FAT16):
            return self.fs.bpb.BPB_RootEntCnt * 32
        return sum(map(itemgetter(1), self.dataruns())) * self.fs.cluster_size

    @property
    def cluster(self) -> int | None:
        if self.fs.type == Fattype.FAT32:
            return self.fs.bpb_ext.BPB_RootClus
        return None

    @property
    def ctime(self) -> datetime.datetime:
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def atime(self) -> datetime.datetime:
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    @property
    def mtime(self) -> datetime.datetime:
        return datetime.datetime(1980, 1, 1)  # noqa: DTZ001

    def is_readonly(self) -> bool:
        return False

    def is_hidden(self) -> bool:
        return False

    def is_system(self) -> bool:
        return False

    def is_volume_id(self) -> bool:
        return False

    def is_directory(self) -> bool:
        return True

    def is_archive(self) -> bool:
        return False

    def iterdir(self) -> Iterator[DirectoryEntry]:
        if not self._entries:
            entries = []
            for entry in _iter_dirent(self.fs, self.open(), self):
                yield entry
                entries.append(entry)

            self._entries = entries
        else:
            yield from self._entries

    def dataruns(self) -> list[tuple[int, int]]:
        if self._runlist is None:
            self._runlist = [] if self.cluster == FREE_CLUSTER else list(self.fs.fat.runlist(self.cluster))
        return self._runlist

    def open(self) -> RangeStream | RunlistStream:
        if self.fs.type in (Fattype.FAT12, Fattype.FAT16):
            root_dir_sector = self.fs.bpb.BPB_RsvdSecCnt + (self.fs.fat_size * self.fs.bpb.BPB_NumFATs)
            offset = root_dir_sector * self.fs.sector_size
            return RangeStream(self.fs.fh, offset, self.size)
        return RunlistStream(self.fs.data_stream, self.dataruns(), self.size, self.fs.cluster_size)


def mask(v: int, bits: int) -> int:
    return v & ((1 << bits) - 1)


def _iter_dirent(
    fs: FATFS, fh: BinaryIO, parent: DirectoryEntry | RootDirectory | None = None
) -> Iterator[DirectoryEntry]:
    while True:
        try:
            yield DirectoryEntry(fs, fh, parent)
        except EmptyDirectoryError:  # noqa: PERF203
            continue
        except LastEmptyDirectoryError:
            break
        except EOFError:
            break
