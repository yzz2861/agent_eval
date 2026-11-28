# -*- coding: utf-8 -*-

"""Rule registry mirroring the current ``filetype`` matching capability.

Every entry is one *recognition rule*. A single format name can be backed by
several rules (for example ``zst`` accepts both regular frames and skippable
frames). The registry is built in exactly the order in which
``filetype.match`` walks ``filetype.types.TYPES``: the first rule returning
``True`` wins.
"""

from __future__ import absolute_import

import struct

from filetype.types import TYPES


class Rule(object):
    """One matcher rule together with the evidence required to prove it.

    Attributes:
        rule_id: stable identifier inside the current rule set.
        extension: advertised file extension (format name).
        mime: advertised MIME type.
        matcher: live ``filetype.types.Type`` instance used for matching.
        min_bytes: minimum header length that carries enough evidence.
        description: human readable signature description.
    """

    def __init__(self, rule_id, extension, mime, matcher, min_bytes,
                 description, predicate=None):
        self.rule_id = rule_id
        self.extension = extension
        self.mime = mime
        self.matcher = matcher
        self.min_bytes = min_bytes
        self.description = description
        self._predicate = predicate

    @property
    def format(self):
        return self.extension

    def match(self, buf):
        """Evaluate this specific rule against a header buffer."""
        if self._predicate is not None:
            return self._predicate(buf)
        return self.matcher.match(buf)

    def __repr__(self):
        return 'Rule(%s, %s)' % (self.rule_id, self.extension)


# Predicates below split matchers that bundle several alternative signatures
# behind one filetype Type instance into individually addressable rules.
def _zstd_frame_predicate(buf):
    return (
        len(buf) > 3
        and buf[0] in (0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28)
        and buf[1] == 0xb5 and buf[2] == 0x2f and buf[3] == 0xfd
    )


def _zstd_skippable_predicate(buf):
    if len(buf) < 8:
        return False
    magic = struct.unpack('<L', bytes(buf[:4]))[0] & 0xFFFFFFF0
    if magic != 0x184D2A50:
        return False
    user_data_len = struct.unpack('<L', bytes(buf[4:8]))[0]
    if len(buf) < 8 + user_data_len:
        return False
    next_frame = buf[8 + user_data_len:]
    return _zstd_frame_predicate(next_frame)


def _zip_local_header_predicate(buf):
    return (len(buf) > 3 and buf[0] == 0x50 and buf[1] == 0x4B
            and buf[2] == 0x03 and buf[3] == 0x04)


def _zip_empty_spanned_predicate(buf):
    return (len(buf) > 3 and buf[0] == 0x50 and buf[1] == 0x4B
            and buf[2] == 0x05 and buf[3] == 0x06)


def _zip_spanned_predicate(buf):
    return (len(buf) > 3 and buf[0] == 0x50 and buf[1] == 0x4B
            and buf[2] == 0x07 and buf[3] == 0x08)


def _jxl_codestream_predicate(buf):
    return len(buf) > 1 and buf[0] == 0xFF and buf[1] == 0x0A


def _jxl_container_predicate(buf):
    return (
        len(buf) > 11
        and buf[0:12] == b'\x00\x00\x00\x0cJXL \r\n\x87\n'
    )


def _mp3_id3_predicate(buf):
    return len(buf) > 2 and buf[0:3] == b'ID3'


def _mp3_frame_sync_predicate(buf):
    if len(buf) <= 2 or buf[0] != 0xFF:
        return False
    return buf[1] in (0xE2, 0xE3, 0xF2, 0xF3, 0xFA, 0xFB)


def _m4a_ftyp_predicate(buf):
    return (len(buf) > 10 and buf[4] == 0x66 and buf[5] == 0x74
            and buf[6] == 0x79 and buf[7] == 0x70
            and buf[8] == 0x4D and buf[9] == 0x34 and buf[10] == 0x41)


def _m4a_legacy_predicate(buf):
    return len(buf) > 3 and buf[0:4] == b'M4A '


def _woff_flavor_predicate(flavors):
    def predicate(buf):
        return (len(buf) > 7 and buf[0:4] == b'wOFF'
                and tuple(buf[4:8]) in flavors)
    return predicate


def _woff2_flavor_predicate(flavors):
    def predicate(buf):
        return (len(buf) > 7 and buf[0:4] == b'wOF2'
                and tuple(buf[4:8]) in flavors)
    return predicate


_WOFF_FLAVORS = (
    (0x00, 0x01, 0x00, 0x00),
    (0x4F, 0x54, 0x54, 0x4F),
    (0x74, 0x72, 0x75, 0x65),
)


_OLE_MAGIC = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'


def _doc_root_entry_predicate(buf):
    return (len(buf) > 515 and buf[0:8] == _OLE_MAGIC
            and buf[512:516] == b'\xEC\xA5\xC1\x00')


def _doc_worddoc_stream_predicate(buf):
    if len(buf) <= 2142 or buf[0:8] != _OLE_MAGIC:
        return False
    return (
        b'\x00\x0A\x00\x00\x00MSWordDoc\x00\x10\x00\x00\x00Word.Document.8\x00\xF49\xB2q'
        in buf[2075:2142]
        or b'W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t\x00'
        in buf[0x580:0x598]
    )


def _doc_root_name_predicate(buf):
    return (
        len(buf) > 663 and buf[0:8] == _OLE_MAGIC
        and buf[512:531] == b'R\x00o\x00o\x00t\x00 \x00E\x00n\x00t\x00r\x00y'
        and buf[640:663] == b'W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t'
    )


def _xls_root_entry_predicate(buf):
    return (len(buf) > 520 and buf[0:8] == _OLE_MAGIC
            and buf[512:516] == b'\xFD\xFF\xFF\xFF'
            and buf[518] in (0x00, 0x02))


def _xls_biff_predicate(buf):
    return (len(buf) > 520 and buf[0:8] == _OLE_MAGIC
            and buf[512:520] == b'\x09\x08\x10\x00\x00\x06\x05\x00')


def _xls_calc_stream_predicate(buf):
    return (len(buf) > 2095 and buf[0:8] == _OLE_MAGIC
            and b'\xE2\x00\x00\x00\\\x00p\x00\x04\x00\x00Calc'
            in buf[1568:2095])


def _ppt_predicate(signature):
    def predicate(buf):
        return (len(buf) > 524 and buf[0:8] == _OLE_MAGIC
                and buf[512:516] == signature)
    return predicate


def _ppt_fd_predicate(buf):
    return (len(buf) > 524 and buf[0:8] == _OLE_MAGIC
            and buf[512:516] == b'\xFD\xFF\xFF\xFF'
            and buf[522:524] == b'\x00\x00')


def _ppt_ms97_predicate(buf):
    return (len(buf) > 2096 and buf[0:8] == _OLE_MAGIC
            and buf[2072:2096]
            == b'\x00\xB9)\xE8\x11\x00\x00\x00MS PowerPoint 97')


# Multi-rule formats. Key is the extension; each entry is an ordered list of
# (rule suffix, minimum header bytes, description, predicate). The rule id is
# "<extension>.<suffix>", so an old approval can name the exact rule that was
# signed off before the weekend rule update.
MULTI_RULE_SPECS = {
    'jxl': [
        ('codestream', 2, 'JPEG XL codestream magic FF 0A',
         _jxl_codestream_predicate),
        ('container', 12, 'JPEG XL ISO-BMFF container box JXL ',
         _jxl_container_predicate),
    ],
    'mp3': [
        ('id3', 3, 'ID3v2 header tag ID3', _mp3_id3_predicate),
        ('frame-sync', 3, 'MPEG audio frame sync 0xFFEx/0xFFFx',
         _mp3_frame_sync_predicate),
    ],
    'm4a': [
        ('ftyp', 11, 'ISO-BMFF ftyp brand M4A', _m4a_ftyp_predicate),
        ('legacy', 4, 'legacy big-endian M4A header', _m4a_legacy_predicate),
    ],
    'doc': [
        ('root-entry', 516, 'OLE compound root entry WordDocument signature',
         _doc_root_entry_predicate),
        ('worddoc-stream', 2143, 'OLE WordDocument stream marker',
         _doc_worddoc_stream_predicate),
        ('root-entry-name', 664, 'OLE Root Entry and WordDocument names',
         _doc_root_name_predicate),
    ],
    'xls': [
        ('root-entry', 521, 'OLE root entry workbook marker FD FF FF FF',
         _xls_root_entry_predicate),
        ('biff', 520, 'OLE BIFF workbook header 09 08 10 00 00 06 05 00',
         _xls_biff_predicate),
        ('calc-stream', 2096, 'OLE Calc stream marker',
         _xls_calc_stream_predicate),
    ],
    'ppt': [
        ('root-entry-a0', 525, 'OLE PowerPoint root entry A0 46 1D F0',
         _ppt_predicate(b'\xA0\x46\x1D\xF0')),
        ('root-entry-00', 525, 'OLE PowerPoint root entry 00 6E 1E F0',
         _ppt_predicate(b'\x00\x6E\x1E\xF0')),
        ('root-entry-0f', 525, 'OLE PowerPoint root entry 0F 00 E8 03',
         _ppt_predicate(b'\x0F\x00\xE8\x03')),
        ('root-entry-fd', 524, 'OLE PowerPoint root entry FD FF FF FF',
         _ppt_fd_predicate),
        ('msppt97', 2096, 'MS PowerPoint 97 stream marker',
         _ppt_ms97_predicate),
    ],
    'zip': [
        ('local-header', 4, 'ZIP local file header PK 03 04',
         _zip_local_header_predicate),
        ('empty-spanned', 4, 'ZIP empty/spanned marker PK 05 06',
         _zip_empty_spanned_predicate),
        ('spanned', 4, 'ZIP spanned archive marker PK 07 08',
         _zip_spanned_predicate),
    ],
    'zst': [
        ('frame', 4, 'Zstandard frame magic 28 B5 2F FD family',
         _zstd_frame_predicate),
        ('skippable', 16,
         'Zstandard skippable frame followed by a regular frame',
         _zstd_skippable_predicate),
    ],
    'dcm': [
        ('image-group', 132, 'DICM prefix at offset 128, image group', None),
        ('archive-group', 132, 'DICM prefix at offset 128, archive group', None),
    ],
    'woff': [
        ('woff', 8, 'WOFF header with 00 01 00 00 flavor',
         _woff_flavor_predicate([_WOFF_FLAVORS[0]])),
        ('ottico', 8, 'WOFF header with OTTO flavor',
         _woff_flavor_predicate([_WOFF_FLAVORS[1]])),
        ('truetype', 8, 'WOFF header with true flavor',
         _woff_flavor_predicate([_WOFF_FLAVORS[2]])),
    ],
    'woff2': [
        ('woff', 8, 'WOFF2 header with 00 01 00 00 flavor',
         _woff2_flavor_predicate([_WOFF_FLAVORS[0]])),
        ('ottico', 8, 'WOFF2 header with OTTO flavor',
         _woff2_flavor_predicate([_WOFF_FLAVORS[1]])),
        ('truetype', 8, 'WOFF2 header with true flavor',
         _woff2_flavor_predicate([_WOFF_FLAVORS[2]])),
    ],
}

# Single-rule formats: extension -> (minimum header bytes, description).
SINGLE_RULE_SPECS = {
    'dwg': (4, 'AC10 AutoCAD drawing magic'),
    'xcf': (10, 'XCF GIMP native header'),
    'jpg': (3, 'JPEG SOI plus marker FF D8 FF'),
    'jpx': (51, 'JPEG 2000 JP2 ftyp box'),
    'apng': (8, 'PNG signature followed by an acTL chunk'),
    'png': (4, 'PNG signature 89 50 4E 47'),
    'gif': (3, 'GIF87a/89a header'),
    'webp': (14, 'RIFF container with WEBP form type'),
    'tif': (10, 'TIFF II/MM endian header without CR2 marker'),
    'cr2': (10, 'TIFF endian header plus CR2 marker'),
    'bmp': (2, 'Windows bitmap BM marker'),
    'jxr': (3, 'JPEG XR II BC marker'),
    'psd': (4, 'Adobe Photoshop 8BPS marker'),
    'ico': (4, 'ICO 00 00 01 00 marker'),
    'heic': (16, 'ISO-BMFF ftyp heic/mif1/msf1 brand'),
    'avif': (16, 'ISO-BMFF ftyp avif/avis/mif1 brand'),
    'qoi': (4, 'QOI qoif marker'),
    'dds': (4, 'DirectDraw Surface DDS marker'),
    'aac': (2, 'AAC ADTS FF F1 / FF F9 sync'),
    'midi': (4, 'MIDI MThd marker'),
    'ogg': (4, 'OGG OggS capture pattern'),
    'flac': (4, 'FLAC fLaC marker'),
    'wav': (12, 'RIFF container with WAVE form type'),
    'amr': (6, 'AMR #!AMR newline marker'),
    'aiff': (12, 'FORM container with AIFF form type'),
    '3gp': (11, '3GP ftyp 3gp brand'),
    'mp4': (16, 'ISO-BMFF ftyp mp41/mp42/isom brand'),
    'm4v': (11, 'M4V ftyp M4V box'),
    'mkv': (4, 'EBML header plus matroska doctype'),
    'mov': (16, 'ISO-BMFF ftyp qt brand'),
    'avi': (12, 'RIFF container with AVI form type'),
    'wmv': (10, 'ASF/WMV GUID header'),
    'mpg': (4, 'MPEG-PS pack start 00 00 01 Bx'),
    'webm': (4, 'EBML header plus webm doctype'),
    'flv': (4, 'Flash video FLV 01 header'),
    'ttf': (5, 'SFNT TrueType 00 01 00 00 marker'),
    'otf': (5, 'SFNT OpenType OTTO marker'),
    'docx': (30, 'ZIP package containing word/ OOXML parts'),
    'odt': (38, 'ZIP mimetype entry for ODF text'),
    'xlsx': (30, 'ZIP package containing xl/ OOXML parts'),
    'ods': (38, 'ZIP mimetype entry for ODF sheet'),
    'pptx': (30, 'ZIP package containing ppt/ OOXML parts'),
    'odp': (38, 'ZIP mimetype entry for ODF presentation'),
    'br': (4, 'Brotli CE B2 CF 81 marker'),
    'rpm': (4, 'RPM ED AB EE DB lead'),
    'epub': (58, 'ZIP mimetype application/epub+zip entry'),
    'tar': (262, 'POSIX ustar magic at offset 257'),
    'rar': (7, 'RAR Rar marker'),
    'gz': (3, 'gzip 1F 8B 08 marker'),
    'bz2': (3, 'bzip2 BZh marker'),
    '7z': (6, '7z 37 7A BC AF 27 1C marker'),
    'pdf': (4, '%PDF marker, optional UTF-8 BOM'),
    'exe': (2, 'DOS/PE MZ executable marker'),
    'swf': (3, 'Flash FWS/CWS/ZWS header'),
    'rtf': (5, 'RTF {\\rtf marker'),
    'nes': (4, 'NES ROM NES 1A marker'),
    'crx': (4, 'Chrome extension Cr24 marker'),
    'cab': (4, 'Microsoft cabinet MSCF/ISc( marker'),
    'eot': (36, 'Embedded OpenType LP header'),
    'ps': (2, 'PostScript %! marker'),
    'xz': (6, 'xz FD 37 7A 58 5A 00 marker'),
    'sqlite': (4, 'SQLite format 3 header'),
    'deb': (21, 'ar archive with debian-binary member'),
    'ar': (7, 'ar !<arch> marker'),
    'Z': (2, 'Unix compress 1F A0 / 1F 9D marker'),
    'lzo': (8, 'lzop LZP marker'),
    'lz': (4, 'lzip LZIP marker'),
    'elf': (53, 'ELF 7F 45 4C 46 header'),
    'lz4': (4, 'LZ4 frame 04 22 4D 18 marker'),
    'wasm': (8, 'WebAssembly 00asm version 1 marker'),
}


def _build_rules():
    rules = []
    occurrence = {}
    matcher_counts = {}
    for matcher in TYPES:
        matcher_counts[matcher.extension] = matcher_counts.get(
            matcher.extension, 0) + 1
    for matcher in TYPES:
        ext = matcher.extension
        if ext in MULTI_RULE_SPECS:
            index = occurrence.get(ext, 0)
            specs = MULTI_RULE_SPECS[ext]
            if len(specs) == matcher_counts[ext]:
                # One spec per matcher position (e.g. DICM exists in two
                # matcher groups with distinct rule ids).
                suffix, min_bytes, description, predicate = specs[index]
                occurrence[ext] = index + 1
                entries = [(suffix, min_bytes, description, predicate)]
            else:
                # One matcher instance backs several alternative rules.
                entries = specs
            for suffix, min_bytes, description, predicate in entries:
                rules.append(Rule(
                    rule_id='%s.%s' % (ext, suffix),
                    extension=ext,
                    mime=matcher.mime,
                    matcher=matcher,
                    min_bytes=min_bytes,
                    description=description,
                    predicate=predicate,
                ))
        else:
            min_bytes, description = SINGLE_RULE_SPECS[ext]
            rules.append(Rule(
                rule_id=ext,
                extension=ext,
                mime=matcher.mime,
                matcher=matcher,
                min_bytes=min_bytes,
                description=description,
            ))
    return rules


RULES = _build_rules()


def find_rule(rule_id):
    """Return the rule with the given id or ``None`` if it no longer exists."""
    for rule in RULES:
        if rule.rule_id == rule_id:
            return rule
    return None


def rules_for_format(extension):
    """Return every current rule producing ``extension``, in match order."""
    return [rule for rule in RULES if rule.extension == extension]
