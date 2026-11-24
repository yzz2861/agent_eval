import hashlib
import struct
import unittest

import pefile


FILE_ALIGNMENT = 512
SECTION_ALIGNMENT = 4096
SECURITY_DIRECTORY_INDEX = 4


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def certificate_table(payload_size=32):
    return struct.pack("<IHH", payload_size + 8, 0x0200, 2) + b"\xab" * payload_size


def section_header(name, virtual_size, virtual_address, raw_size, raw_pointer, characteristics):
    return struct.pack(
        "<8sIIIIIIHHI",
        name.encode("ascii").ljust(8, b"\x00"),
        virtual_size,
        virtual_address,
        raw_size,
        raw_pointer,
        0,
        0,
        0,
        0,
        characteristics,
    )


def build_sample(plus=False, security_directory=None, cert=None, overlay=b"OVL"):
    number_of_sections = 2
    size_optional = 240 if plus else 224
    optional_offset = 64 + 4 + 20
    section_table_offset = optional_offset + size_optional
    size_of_headers = 512
    text_pointer = 512
    data_pointer = 576
    end_of_sections = 640

    trailing = bytearray()
    cert_offset = 0
    cert_size = 0
    if cert is not None:
        trailing.extend(overlay or b"")
        while len(trailing) % 8:
            trailing.append(0)
        cert_offset = end_of_sections + len(trailing)
        cert_size = len(cert)
        trailing.extend(cert)
    elif overlay:
        trailing.extend(overlay)

    if security_directory is not None:
        security_va, security_size = security_directory
    else:
        security_va, security_size = cert_offset, cert_size

    if plus:
        optional = struct.pack(
            "<HBBIIIII",
            pefile.OPTIONAL_HEADER_MAGIC_PE32_PLUS,
            14,
            0,
            128,
            64,
            0,
            0x1000,
            0x1000,
        )
        optional += struct.pack("<QII", 0x140000000, SECTION_ALIGNMENT, FILE_ALIGNMENT)
    else:
        optional = struct.pack(
            "<HBBIIIIII",
            pefile.OPTIONAL_HEADER_MAGIC_PE32,
            14,
            0,
            128,
            64,
            0,
            0x1000,
            0x1000,
            0x2000,
        )
        optional += struct.pack("<III", 0x400000, SECTION_ALIGNMENT, FILE_ALIGNMENT)

    optional += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    optional += struct.pack("<I", 0)
    optional += struct.pack("<II", 0x3000, size_of_headers)
    optional += struct.pack("<IHH", 0x11223344, 2, 0x8100)

    if plus:
        optional += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
    else:
        optional += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    optional += struct.pack("<II", 0, 16)

    directories = [(0, 0)] * 16
    directories[SECURITY_DIRECTORY_INDEX] = (security_va, security_size)
    optional += b"".join(struct.pack("<II", va, size) for va, size in directories)
    assert len(optional) == size_optional

    coff = struct.pack(
        "<HHIIIHH",
        0x8664 if plus else 0x14C,
        number_of_sections,
        0,
        0,
        0,
        size_optional,
        0x0102,
    )
    text_header = section_header(
        ".text", 64, 0x1000, 64, text_pointer, 0x60000020
    )
    data_header = section_header(
        ".data", 64, 0x2000, 64, data_pointer, 0xC0000040
    )

    image = bytearray(size_of_headers + 128 + len(trailing))
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 60, 64)
    offset = 64
    image[offset:offset + 4] = b"PE\x00\x00"
    offset += 4
    image[offset:offset + len(coff)] = coff
    offset += len(coff)
    image[offset:offset + len(optional)] = optional
    offset += len(optional)
    image[offset:offset + 40] = text_header
    offset += 40
    image[offset:offset + 40] = data_header

    image[text_pointer:text_pointer + 64] = b"\xCC" * 64
    image[data_pointer:data_pointer + 64] = b"D" * 64
    image[end_of_sections:end_of_sections + len(trailing)] = trailing
    return bytes(image)


def reference_ranges(data):
    e_lfanew = u32(data, 0x3C)
    file_header = e_lfanew + 4
    number_of_sections = u16(data, file_header + 2)
    size_optional = u16(data, file_header + 16)
    optional_offset = file_header + 20
    magic = u16(data, optional_offset)
    checksum_offset = optional_offset + 64
    number_rva_offset = optional_offset + (92 if magic == 0x10B else 108)
    number_rva = u32(data, number_rva_offset)

    security_offset = None
    cert_offset = cert_size = 0
    if number_rva > SECURITY_DIRECTORY_INDEX:
        security_offset = (
            optional_offset
            + size_optional
            - number_rva * 8
            + SECURITY_DIRECTORY_INDEX * 8
        )
        cert_offset = u32(data, security_offset)
        cert_size = u32(data, security_offset + 4)

    section_table = optional_offset + size_optional
    sections = []
    for index in range(number_of_sections):
        entry = section_table + index * 40
        raw_size = u32(data, entry + 16)
        pointer = u32(data, entry + 20)
        if raw_size:
            sections.append((pointer, pointer + raw_size))
    sections.sort()

    header_end = max(
        u32(data, optional_offset + 60),
        section_table + number_of_sections * 40,
    )
    exclusions = [(checksum_offset, checksum_offset + 4)]
    if security_offset is not None:
        exclusions.append((security_offset, security_offset + 8))
    if cert_offset or cert_size:
        exclusions.append((cert_offset, cert_offset + cert_size))
    exclusions.sort()

    trailing_start = max(header_end, max((end for _, end in sections), default=0))
    candidates = [(0, header_end)] + sections
    if trailing_start < len(data):
        candidates.append((trailing_start, len(data)))

    ranges = []
    for start, end in candidates:
        cursor = start
        for excluded_start, excluded_end in exclusions:
            if excluded_end <= cursor:
                continue
            if excluded_start >= end:
                break
            clipped = max(cursor, excluded_start)
            if clipped > cursor:
                ranges.append((cursor, clipped))
            cursor = max(cursor, min(end, excluded_end))
        if cursor < end:
            ranges.append((cursor, end))
    ranges.sort()
    return ranges


def digest_ranges(data, ranges, factory):
    hasher = factory()
    for start, end in ranges:
        hasher.update(data[start:end])
    return hasher.digest()


class AuthenticodeCoverageTests(unittest.TestCase):
    def test_ranges_and_byte_mutation_oracle_pe32_and_plus(self):
        for plus in (False, True):
            with self.subTest(plus=plus):
                data = build_sample(plus=plus, cert=certificate_table())
                pe = pefile.PE(data=data, fast_load=True)
                coverage = pe.get_authenticode_coverage()
                self.assertEqual(
                    coverage.status,
                    pefile.AUTHENTICODE_STATUS_PROVABLE,
                    coverage.reasons,
                )
                reference = reference_ranges(data)
                self.assertEqual(
                    [(item.start, item.end) for item in coverage.hashed_intervals],
                    reference,
                )
                self.assertEqual(
                    pe.compute_authenticode_digest(hashlib.sha256),
                    digest_ranges(data, reference, hashlib.sha256),
                )

                baseline = digest_ranges(data, reference, hashlib.sha256)
                hashed = [
                    offset
                    for start, end in reference
                    for offset in range(start, end)
                ]
                for offset in range(len(data)):
                    mutated = bytearray(data)
                    mutated[offset] ^= 0xFF
                    digest = digest_ranges(bytes(mutated), reference, hashlib.sha256)
                    inside = any(start <= offset < end for start, end in reference)
                    if inside:
                        self.assertNotEqual(digest, baseline, offset)
                        self.assertEqual(coverage.classification(offset), "hashed")
                    else:
                        self.assertEqual(digest, baseline, offset)
                        self.assertEqual(coverage.classification(offset), "excluded")
                self.assertEqual(len(hashed), coverage.total_hashed_bytes())

    def test_exclusion_mapping(self):
        data = build_sample(cert=certificate_table())
        coverage = pefile.PE(data=data, fast_load=True).get_authenticode_coverage()
        categories = {item.category for item in coverage.exclusions}
        self.assertEqual(
            categories,
            {
                pefile.AUTHENTICODE_EXCLUSION_CHECKSUM,
                pefile.AUTHENTICODE_EXCLUSION_SECURITY_DIRECTORY,
                pefile.AUTHENTICODE_EXCLUSION_CERTIFICATE_TABLE,
            },
        )
        cert = next(
            item
            for item in coverage.exclusions
            if item.category == pefile.AUTHENTICODE_EXCLUSION_CERTIFICATE_TABLE
        )
        self.assertTrue(cert.in_overlay)
        self.assertIsNone(cert.mapped_section_index)
        self.assertIsNotNone(coverage.overlay_offset)

    def test_malformed_layouts_are_unprovable_and_refuse_digest(self):
        cases = [
            ((768, 0), "one of VirtualAddress/Size"),
            ((1048576, 256), "outside the file"),
            ((768, 4), "WIN_CERTIFICATE header"),
        ]
        for security_directory, fragment in cases:
            with self.subTest(security_directory=security_directory):
                data = build_sample(security_directory=security_directory)
                pe = pefile.PE(data=data, fast_load=True)
                coverage = pe.get_authenticode_coverage()
                self.assertEqual(
                    coverage.status, pefile.AUTHENTICODE_STATUS_UNPROVABLE
                )
                self.assertTrue(any(fragment in reason for reason in coverage.reasons))
                with self.assertRaises(pefile.PEFormatError):
                    pe.compute_authenticode_digest()

    def test_certificate_in_executable_section_is_anomaly(self):
        data = build_sample(security_directory=(512, 32), overlay=b"")
        coverage = pefile.PE(data=data, fast_load=True).get_authenticode_coverage()
        cert = next(
            item
            for item in coverage.exclusions
            if item.category == pefile.AUTHENTICODE_EXCLUSION_CERTIFICATE_TABLE
        )
        self.assertEqual(coverage.status, pefile.AUTHENTICODE_STATUS_UNPROVABLE)
        self.assertTrue(cert.executable)
        self.assertEqual(cert.mapped_section_name, ".text")
        self.assertTrue(any("executable section" in note for note in coverage.anomalies))

    def test_overlapping_exclusions_are_unprovable(self):
        checksum_offset = 64 + 4 + 20 + 64
        data = build_sample(security_directory=(checksum_offset, 8), overlay=b"")
        coverage = pefile.PE(data=data, fast_load=True).get_authenticode_coverage()
        self.assertEqual(coverage.status, pefile.AUTHENTICODE_STATUS_UNPROVABLE)
        self.assertTrue(any("overlap" in reason.lower() for reason in coverage.reasons))


if __name__ == "__main__":
    unittest.main()
