from __future__ import annotations

import struct
from typing import TYPE_CHECKING

import pytest

from dissect.fat.c_exfat import c_exfat
from dissect.fat.exfat import EXACT_NAME_ORIGIN, UPCASE_TABLE_ORIGIN, ExFAT, UpcaseTable, utf16_units
from tests._exfat_image import build_exfat_image

if TYPE_CHECKING:
    from pathlib import Path

ASCII_UPCASE = {code: code - 0x20 for code in range(ord("a"), ord("z") + 1)}


def test_compressed_upcase_runs_keep_identity_mappings() -> None:
    data = struct.pack("<HHH", 0xFFFF, 0x61, 0x41)
    entry = c_exfat.UPCASE_DIRECTORY_ENTRY(entry_type=0x82, upcase_checksum=0xE619D30D)
    table = UpcaseTable(entry, data)

    assert table.upcase((0x00, 0x60, 0x61)) == (0x00, 0x60, 0x41)


def test_split_surrogates_keep_raw_utf16_units(tmp_path: Path) -> None:
    # The high surrogate lands in the first filename entry and the low surrogate in the second.
    name = "abcdefghijklmn😀"
    image = tmp_path / "surrogate.bin"
    build_exfat_image(image, [name], upcase_mapping=ASCII_UPCASE)

    exfat = open_image(image)
    result = exfat.verify_name(name)
    assert len(result.candidates) == 1
    assert result.candidates[0].name == name
    assert result.candidates[0].units == utf16_units(name)


def open_image(path: Path) -> ExFAT:
    return ExFAT(path.open("rb"))


def test_archive_key_uses_volume_upcase_not_host_casefold(tmp_path: Path) -> None:
    image = tmp_path / "names.bin"
    build_exfat_image(image, ["ß.txt", "SS.txt"], upcase_mapping=ASCII_UPCASE)

    # Host Unicode case folding equates these names, but the image up-case table leaves U+00DF unchanged.
    assert "ß.txt".casefold() == "ss.txt".casefold()

    exfat = open_image(image)
    key = exfat.name_key("ß.txt")
    assert key.origin == UPCASE_TABLE_ORIGIN
    assert key.raw_units == utf16_units("ß.txt")
    assert key.units != exfat.name_key("SS.txt").units
    assert exfat.archive_key("ß.txt") != exfat.archive_key("SS.txt")
    archive = exfat.archive_index()
    assert set(archive) == {exfat.archive_key("ß.txt"), exfat.archive_key("SS.txt")}
    assert [candidate.name for candidate in archive[exfat.archive_key("ss.txt")]] == ["SS.txt"]


def test_name_hash_and_raw_units_are_verified_from_image(tmp_path: Path) -> None:
    image = tmp_path / "names.bin"
    hashes = build_exfat_image(image, ["ß.txt", "SS.txt"], upcase_mapping=ASCII_UPCASE)

    exfat = open_image(image)
    result = exfat.verify_name("ss.txt")

    assert result.key_source == UPCASE_TABLE_ORIGIN
    assert result.slots == (1,)
    candidate = result.candidates[0]
    assert candidate.name == "SS.txt"
    assert candidate.match == "upcase"
    assert candidate.units == utf16_units("SS.txt")
    assert candidate.stored_name_hash == hashes["SS.txt"]
    assert candidate.computed_name_hash == hashes["SS.txt"]
    assert candidate.hash_matches is True


def test_missing_upcase_table_only_matches_exact_original_name(tmp_path: Path) -> None:
    image = tmp_path / "no-upcase.bin"
    build_exfat_image(image, ["a.txt", "A.txt"], include_upcase=False)

    exfat = open_image(image)
    assert exfat.upcase_table is None
    assert exfat.name_key("a.txt").origin == EXACT_NAME_ORIGIN

    lower = exfat.verify_name("a.txt")
    upper = exfat.verify_name("A.txt")
    assert [candidate.name for candidate in lower.candidates] == ["a.txt"]
    assert [candidate.name for candidate in upper.candidates] == ["A.txt"]
    assert lower.key_source == upper.key_source == EXACT_NAME_ORIGIN


def test_upcase_collisions_keep_all_candidates_and_directory_slots(tmp_path: Path) -> None:
    image = tmp_path / "collisions.bin"
    build_exfat_image(image, ["a.txt", "A.txt", "a.txt"], upcase_mapping=ASCII_UPCASE)

    exfat = open_image(image)
    result = exfat.verify_name("A.txt")

    assert len(result.candidates) == 3
    assert result.slots == (0, 1, 2)
    assert [candidate.entry_slot for candidate in result.candidates] == [2, 5, 8]
    assert [candidate.units for candidate in result.candidates] == [
        utf16_units("a.txt"),
        utf16_units("A.txt"),
        utf16_units("a.txt"),
    ]
    assert all(candidate.hash_matches for candidate in result.candidates)
    index = exfat.archive_index()
    assert [candidate.slot for candidate in index[exfat.archive_key("a.txt")]] == [0, 1, 2]

    # The dictionary view keeps its historical key behaviour, while verification still sees every slot.
    assert sorted(exfat.files["/"][1]) == ["A.txt", "a.txt"]


def test_unknown_directory_is_not_silently_resolved(tmp_path: Path) -> None:
    image = tmp_path / "names.bin"
    build_exfat_image(image, ["a.txt"], upcase_mapping=ASCII_UPCASE)

    exfat = open_image(image)
    with pytest.raises(KeyError):
        exfat.verify_name("a.txt", "missing")
