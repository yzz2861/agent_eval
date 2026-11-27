from __future__ import annotations

import io
import struct

from dissect.fat.c_fat import Fattype
from dissect.fat.fat import (
    FATFS,
    ChainTermination,
    ChainVerdict,
)

SECTOR_SIZE = 512
RESERVED_SECTORS = 32
NUM_FATS = 2
FAT_SIZE_SECTORS = 512  # 65536 FAT32 entries per table
DATA_SECTORS = 65600  # keeps the cluster count above the FAT32 threshold
TOTAL_SECTORS = RESERVED_SECTORS + NUM_FATS * FAT_SIZE_SECTORS + DATA_SECTORS

EOC = 0x0FFFFFFF

FILE_CLUSTER = 5
FILE_SIZE = 1800  # 4 clusters of 512 bytes


def build_fat32_image(ext_flags: int, tables: list[dict[int, int]]) -> io.BytesIO:
    """Synthesize a minimal FAT32 card image with per-table FAT entries.

    Only the boot sector and the FAT regions are materialized; the data
    region is declared in the BPB but never read by the chain comparison.
    """
    image = bytearray((RESERVED_SECTORS + NUM_FATS * FAT_SIZE_SECTORS) * SECTOR_SIZE)

    image[0:3] = b"\xeb\x00\x90"  # BS_jmpBoot
    image[3:11] = b"MSWIN4.1"  # BS_OEMName
    struct.pack_into("<H", image, 11, SECTOR_SIZE)  # BPB_BytsPerSec
    struct.pack_into("<B", image, 13, 1)  # BPB_SecPerClus
    struct.pack_into("<H", image, 14, RESERVED_SECTORS)  # BPB_RsvdSecCnt
    struct.pack_into("<B", image, 16, NUM_FATS)  # BPB_NumFATs
    struct.pack_into("<H", image, 17, 0)  # BPB_RootEntCnt
    struct.pack_into("<B", image, 21, 0xF8)  # BPB_Media
    struct.pack_into("<I", image, 32, TOTAL_SECTORS)  # BPB_TotSec32

    struct.pack_into("<I", image, 36, FAT_SIZE_SECTORS)  # BPB_FATSz32
    struct.pack_into("<H", image, 40, ext_flags)  # BPB_ExtFlags
    struct.pack_into("<I", image, 44, 2)  # BPB_RootClus
    struct.pack_into("<H", image, 48, 1)  # BPB_FSInfo
    struct.pack_into("<H", image, 50, 6)  # BPB_BkBootSec
    struct.pack_into("<B", image, 66, 0x29)  # BS_BootSig
    image[71:82] = b"FORENSICS  "  # BS_VolLab
    image[82:90] = b"FAT32   "  # BS_FilSysType

    for table_idx, entries in enumerate(tables):
        base = (RESERVED_SECTORS + table_idx * FAT_SIZE_SECTORS) * SECTOR_SIZE
        struct.pack_into("<I", image, base, 0x0FFFFFF8)  # media descriptor
        struct.pack_into("<I", image, base + 4, EOC)  # reserved cluster 1
        struct.pack_into("<I", image, base + 8, EOC)  # root directory cluster 2
        for cluster, value in entries.items():
            struct.pack_into("<I", image, base + cluster * 4, value)

    return io.BytesIO(bytes(image))


def test_bpb_mirror_declarations() -> None:
    fs = FATFS(build_fat32_image(0x0000, [{}, {}]))

    assert fs.type == Fattype.FAT32
    assert fs.fat_count == 2
    assert fs.fat_mirroring_enabled is True
    assert fs.active_fat == 0
    assert len(fs.fats) == 2
    assert fs.fat is fs.fats[0]


def test_bpb_active_table_declaration() -> None:
    # Mirroring disabled, table 1 nominated as the active table
    fs = FATFS(build_fat32_image(0x0081, [{}, {}]))

    assert fs.fat_mirroring_enabled is False
    assert fs.active_fat == 1
    assert fs.fat is fs.fats[1]


def test_card_only_active_table_updated() -> None:
    # Card that declares an active table and only keeps that one up to date:
    # the active table holds the full chain, the stale mirror ends early.
    tables = [
        {FILE_CLUSTER: 6, 6: 7, 7: 8, 8: EOC},
        {FILE_CLUSTER: 6, 6: EOC},
    ]
    fs = FATFS(build_fat32_image(0x0080, tables))

    comparison = fs.compare_chains(FILE_CLUSTER, FILE_SIZE)

    assert comparison.expected_clusters == 4
    assert [walk.clusters for walk in comparison.walks] == [[5, 6, 7, 8], [5, 6]]
    assert comparison.walks[0].confirmed
    assert comparison.walks[1].termination == ChainTermination.END_OF_CHAIN
    assert not comparison.walks[1].length_satisfied

    assert comparison.common_prefix == [5, 6]
    assert comparison.divergence_offset == 2
    assert comparison.branches == {0: [7, 8], 1: []}
    assert comparison.verdict == ChainVerdict.STALE_MIRROR


def test_card_declares_mirror_but_diverges() -> None:
    # Card that declares mirroring but the tables fork halfway through the
    # chain: both branches are well-formed, so the divergence is suspicious.
    tables = [
        {FILE_CLUSTER: 6, 6: 7, 7: 8, 8: EOC},
        {FILE_CLUSTER: 6, 6: 9, 9: 10, 10: EOC},
    ]
    fs = FATFS(build_fat32_image(0x0000, tables))

    comparison = fs.compare_chains(FILE_CLUSTER, FILE_SIZE)

    assert all(walk.confirmed for walk in comparison.walks)
    assert comparison.common_prefix == [5, 6]
    assert comparison.divergence_offset == 2
    assert comparison.branches == {0: [7, 8], 1: [9, 10]}
    assert comparison.verdict == ChainVerdict.MIRRORED_DIVERGENCE


def test_card_consistent_mirrors() -> None:
    chain = {FILE_CLUSTER: 6, 6: 7, 7: 8, 8: EOC}
    fs = FATFS(build_fat32_image(0x0000, [dict(chain), dict(chain)]))

    comparison = fs.compare_chains(FILE_CLUSTER, FILE_SIZE)

    assert not comparison.diverged
    assert comparison.divergence_offset is None
    assert comparison.common_prefix == [5, 6, 7, 8]
    assert comparison.verdict == ChainVerdict.CONSISTENT


def test_walk_chain_termination_markers() -> None:
    tables = [
        {
            5: 0,  # runs into a free cluster
            10: 11,  # loops back on itself
            11: 10,
            20: 0x0FFFFFF7,  # runs into a bad cluster marker
        },
        {},
    ]
    fs = FATFS(build_fat32_image(0x0000, tables))
    fat = fs.fats[0]

    walk = fat.walk_chain(5)
    assert walk.clusters == []
    assert walk.termination == ChainTermination.FREE_CLUSTER
    assert not walk.clean

    walk = fat.walk_chain(10)
    assert walk.clusters == [10, 11]
    assert walk.termination == ChainTermination.CYCLE
    assert not walk.clean

    walk = fat.walk_chain(20)
    assert walk.clusters == []
    assert walk.termination == ChainTermination.BAD_CLUSTER
    assert not walk.clean


def test_comparison_report() -> None:
    tables = [
        {FILE_CLUSTER: 6, 6: 7, 7: 8, 8: EOC},
        {FILE_CLUSTER: 6, 6: 9, 9: 10, 10: EOC},
    ]
    fs = FATFS(build_fat32_image(0x0000, tables))

    report = fs.compare_chains(FILE_CLUSTER, FILE_SIZE).report()

    assert "mirroring enabled" in report
    assert "table 0: 5 -> 6 -> 7 -> 8" in report
    assert "table 1: 5 -> 6 -> 9 -> 10" in report
    assert "common prefix: 5 -> 6" in report
    assert "diverges at chain position 2" in report
    assert "verdict: mirrored-divergence" in report
