import struct
import unittest
from hashlib import sha256

import pefile


_RSRC_VA = 0x1000
_RSRC_RAW = 0x400
_RESOURCE_TYPE = 100
_RESOURCE_NAME = 1
_LANGS = (0x0409, 0x0804)
_PAYLOADS = {
    0x0409: b"ContosoApp-locale-en-US-1.2.3.4",
    0x0804: b"ContosoApp-locale-zh-CN-1.2.3.4",
}
_VERSION_STRINGS = {
    "ProductName": "Contoso App",
    "FileVersion": "1.2.3.4",
    "ProductVersion": "1.2.3.4",
}


def _utf16z(value):
    return value.encode("utf-16-le") + b"\x00\x00"


def _pad4(blob):
    return blob + b"\x00" * (-len(blob) % 4)


def _build_version_info(strings, language=0x0409, codepage=0x04B0):
    entries = b""
    for key, value in strings.items():
        entry = struct.pack("<HHH", 0, len(value) + 1, 1) + _utf16z(key)
        entry = _pad4(entry) + _utf16z(value)
        entry = _pad4(entry)
        entries += struct.pack("<H", len(entry)) + entry[2:]

    table = struct.pack("<HHH", 0, 0, 1) + _utf16z(f"{language:04x}{codepage:04x}")
    table = _pad4(table) + entries
    table = struct.pack("<H", len(table)) + table[2:]

    string_file_info = struct.pack("<HHH", 0, 0, 1) + _utf16z("StringFileInfo")
    string_file_info = _pad4(string_file_info) + table
    string_file_info = struct.pack("<H", len(string_file_info)) + string_file_info[2:]

    fixed = struct.pack(
        "<13I",
        0xFEEF04BD,
        0x00010000,
        0x00010002,
        0x00030004,
        0x00010002,
        0x00030004,
        0x3F,
        0,
        4,
        2,
        0,
        0,
        0,
    )
    blob = struct.pack("<HHH", 0, len(fixed), 0) + _utf16z("VS_VERSION_INFO")
    blob = _pad4(blob) + fixed + string_file_info
    return struct.pack("<H", len(blob)) + blob[2:]


class _ResourceDir:
    def __init__(self):
        self.entries = []


class _ResourceData:
    def __init__(self, payload):
        self.payload = payload


def _build_resource_section(root, section_va):
    offset = 0

    def layout(directory):
        nonlocal offset
        directory.offset = offset
        offset += 16 + 8 * len(directory.entries)
        for _, child in directory.entries:
            if isinstance(child, _ResourceDir):
                layout(child)
        for _, child in directory.entries:
            if isinstance(child, _ResourceData):
                child.entry_offset = offset
                offset += 16
        for _, child in directory.entries:
            if isinstance(child, _ResourceData) and child.payload is not None:
                child.data_offset = offset
                offset += len(child.payload)
                offset += -offset % 4

    layout(root)
    section = bytearray(offset)

    def emit(directory):
        struct.pack_into(
            "<IIHHHH",
            section,
            directory.offset,
            0,
            0,
            0,
            0,
            0,
            len(directory.entries),
        )
        for index, (entry_id, child) in enumerate(directory.entries):
            entry_offset = directory.offset + 16 + 8 * index
            if isinstance(child, _ResourceDir):
                value = 0x80000000 | child.offset
            else:
                value = child.entry_offset
            struct.pack_into("<II", section, entry_offset, entry_id, value)

        for _, child in directory.entries:
            if isinstance(child, _ResourceDir):
                emit(child)
            elif child.payload is None:
                struct.pack_into("<IIII", section, child.entry_offset, 0x7FFF0000, 0x30, 0, 0)
            else:
                struct.pack_into(
                    "<IIII",
                    section,
                    child.entry_offset,
                    section_va + child.data_offset,
                    len(child.payload),
                    0,
                    0,
                )
                start = child.data_offset
                section[start : start + len(child.payload)] = child.payload

    emit(root)
    return bytes(section)


def _create_pe_with_resources(resource_section):
    raw_size = (len(resource_section) + 0x1FF) & ~0x1FF
    size_of_image = _RSRC_VA + ((len(resource_section) + 0xFFF) & ~0xFFF)

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = struct.pack("<I", 64)

    file_header = (
        struct.pack("<H", 0x014C)
        + struct.pack("<H", 1)
        + struct.pack("<III", 0, 0, 0)
        + struct.pack("<H", 0xE0)
        + struct.pack("<H", 0x0102)
    )

    optional_header = (
        struct.pack("<H", 0x010B)
        + struct.pack("<BB", 14, 0)
        + struct.pack("<III", 0, 0, 0)
        + struct.pack("<I", _RSRC_VA)
        + struct.pack("<II", _RSRC_VA, 0)
        + struct.pack("<I", 0x400000)
        + struct.pack("<II", 0x1000, 0x200)
        + struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
        + struct.pack("<I", 0)
        + struct.pack("<I", size_of_image)
        + struct.pack("<I", 0x200)
        + struct.pack("<I", 0)
        + struct.pack("<H", 2)
        + struct.pack("<H", 0x8100)
        + struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
        + struct.pack("<II", 0, 16)
        + b"\x00" * 16
        + struct.pack("<II", _RSRC_VA, len(resource_section))
        + b"\x00" * (128 - 24)
    )
    assert len(optional_header) == 0xE0

    section_header = (
        b".rsrc\x00\x00\x00"
        + struct.pack("<I", len(resource_section))
        + struct.pack("<I", _RSRC_VA)
        + struct.pack("<I", raw_size)
        + struct.pack("<I", _RSRC_RAW)
        + struct.pack("<IIHHI", 0, 0, 0, 0, 0x40000040)
    )

    headers = bytes(dos_header) + b"PE\x00\x00" + file_header
    headers += optional_header + section_header
    pe_bytes = headers.ljust(_RSRC_RAW, b"\x00")
    return pe_bytes + resource_section.ljust(raw_size, b"\x00")


def _create_localized_package_pe(complete_language):
    version_languages = _ResourceDir()
    version_languages.entries.append(
        (0x0409, _ResourceData(_build_version_info(_VERSION_STRINGS)))
    )
    version_names = _ResourceDir()
    version_names.entries.append((1, version_languages))

    package_languages = _ResourceDir()
    for language, payload in _PAYLOADS.items():
        data = payload if language == complete_language else None
        package_languages.entries.append((language, _ResourceData(data)))
    package_names = _ResourceDir()
    package_names.entries.append((_RESOURCE_NAME, package_languages))

    root = _ResourceDir()
    root.entries.append((16, version_names))
    root.entries.append((_RESOURCE_TYPE, package_names))
    resource_section = _build_resource_section(root, _RSRC_VA)
    return _create_pe_with_resources(resource_section)


class ResourceVerificationTests(unittest.TestCase):
    def test_two_synthetic_materials_keep_independent_sources(self):
        records = [
            {"lang": 0x0409, "product": "Contoso App", "version": "1.2.3.4"},
            {"lang": 0x0804, "product": "Contoso App", "version": "1.2.3.4"},
        ]

        for complete_language in _LANGS:
            with self.subTest(complete_language=complete_language):
                raw_pe = _create_localized_package_pe(complete_language)
                pe = pefile.PE(data=raw_pe, fast_load=True)
                before = bytes(pe.write())
                source = f"fixture-complete-{complete_language:04x}"

                report = pe.verify_resource_packages(
                    _RESOURCE_TYPE,
                    name=_RESOURCE_NAME,
                    packages=records,
                    source=source,
                )

                self.assertEqual(bytes(pe.write()), before)
                self.assertEqual(report["source"], source)
                self.assertEqual(
                    report["version_info"]["ProductName"], "Contoso App"
                )
                self.assertEqual(
                    report["version_info"]["FileVersion"], "1.2.3.4"
                )
                self.assertEqual(len(report["packages"]), 2)

                by_language = {item["lang"]: item for item in report["packages"]}
                confirmed = by_language[complete_language]
                broken_language = next(
                    language for language in _LANGS if language != complete_language
                )
                broken = by_language[broken_language]

                self.assertEqual(confirmed["version_string"], "1.2.3.4")
                self.assertEqual(broken["version_string"], "1.2.3.4")
                self.assertIsNot(confirmed["package"], broken["package"])
                self.assertIsNot(confirmed["evidence"], broken["evidence"])
                self.assertEqual(confirmed["status"], "confirmed")
                self.assertEqual(confirmed["errors"], [])
                self.assertEqual(broken["status"], "error")
                self.assertTrue(broken["errors"])

                evidence = confirmed["evidence"]
                payload = _PAYLOADS[complete_language]
                self.assertEqual(evidence["size"], len(payload))
                self.assertEqual(evidence["sha256"], sha256(payload).hexdigest())
                layers = evidence["layers"]
                self.assertEqual(
                    [layer["level"] for layer in layers],
                    ["type", "name", "lang"],
                )

                type_id, type_target = struct.unpack_from(
                    "<II", raw_pe, layers[0]["entry_offset"]
                )
                self.assertEqual(type_id, _RESOURCE_TYPE)
                self.assertTrue(type_target & 0x80000000)
                name_id, name_target = struct.unpack_from(
                    "<II", raw_pe, layers[1]["entry_offset"]
                )
                self.assertEqual(name_id, _RESOURCE_NAME)
                self.assertTrue(name_target & 0x80000000)
                language_id, language_target = struct.unpack_from(
                    "<II", raw_pe, layers[2]["entry_offset"]
                )
                self.assertEqual(language_id, complete_language)
                self.assertFalse(language_target & 0x80000000)

                resource_file_offset = evidence["data_offset"] - (
                    evidence["data_rva"] - _RSRC_VA
                )
                self.assertEqual(
                    resource_file_offset + language_target,
                    evidence["data_entry_offset"],
                )
                data_rva, size, _, _ = struct.unpack_from(
                    "<IIII", raw_pe, evidence["data_entry_offset"]
                )
                self.assertEqual(data_rva, evidence["data_rva"])
                self.assertEqual(size, evidence["size"])
                start = evidence["data_offset"]
                self.assertEqual(
                    raw_pe[start : start + evidence["size"]], payload
                )


    def test_missing_broken_and_named_version_paths(self):
        pe = pefile.PE(data=_create_localized_package_pe(0x0409))

        confirmed = pe.verify_resource(_RESOURCE_TYPE, name=1, lang=0x0409)
        self.assertEqual(confirmed["status"], "confirmed")

        broken = pe.verify_resource(_RESOURCE_TYPE, name=1, lang=0x0804)
        self.assertEqual(broken["status"], "error")
        self.assertTrue(broken["errors"])
        self.assertEqual(
            [layer["level"] for layer in broken["evidence"]["layers"]],
            ["type", "name", "lang"],
        )
        self.assertNotIn("sha256", broken["evidence"])

        missing_language = pe.verify_resource(
            _RESOURCE_TYPE, name=1, lang=0x0411
        )
        self.assertEqual(missing_language["status"], "missing")
        self.assertIsNone(missing_language["evidence"])

        unknown_type = pe.verify_resource(999, name=1, lang=0x0409)
        unknown_name = pe.verify_resource(
            _RESOURCE_TYPE, name=999, lang=0x0409
        )
        self.assertEqual(unknown_type["status"], "missing")
        self.assertEqual(unknown_name["status"], "missing")

        version = pe.verify_resource(
            "RT_VERSION", name=1, lang=0x0409
        )
        self.assertEqual(version["status"], "confirmed")
        expected_version_blob = _build_version_info(_VERSION_STRINGS)
        self.assertEqual(
            version["evidence"]["sha256"],
            sha256(expected_version_blob).hexdigest(),
        )

        primary = pe.verify_resource(
            _RESOURCE_TYPE, name=1, lang=0x09
        )
        self.assertEqual(primary["status"], "confirmed")
        self.assertEqual(
            primary["evidence"]["layers"][2]["id"], 0x0409
        )


if __name__ == "__main__":
    unittest.main()
