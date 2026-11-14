"""
Helpers for building small, synthetic EVTX files used to exercise the secure
template-graph handling without depending on hand-captured malicious samples.

The layout follows the on-disk structures parsed by `Evtx.Evtx` and
`Evtx.Nodes`:

  - a 0x1000 byte file header followed by one or more 0x10000 byte chunks;
  - each chunk has a 0x200 byte header, a record area, a free area that may
    also hold (non-resident) template definitions, and template/string
    pointer tables at fixed offsets;
  - records hold a binary XML root: an optional stream-start token, a
    template instance token, then the substitution array.
"""

import binascii
import struct

import Evtx.Nodes as e_nodes

CHUNK_SIZE = 0x10000
FILE_HEADER_SIZE = 0x1000
CHUNK_HEADER_SIZE = 0x200
RECORD_HEADER_SIZE = 0x18


def _dword(value):
    return struct.pack("<I", value)


def _word(value):
    return struct.pack("<H", value)


def _byte(value):
    return struct.pack("<B", value)


def _qword(value):
    return struct.pack("<Q", value)


def name_string(name, next_offset=0):
    encoded = name.encode("utf-16-le")
    return (
        _dword(next_offset)
        + _word(0)
        + _word(len(encoded) // 2)
        + encoded
        + b"\x00\x00"
    )


def template_definition(template_id, body, next_offset=0, guid=None, prefix=True):
    """
    Build a template definition structure (the 0x18 byte header plus the
    binary XML body).

    When `prefix` is set the ten bytes the chunk template table expects are
    emitted ahead of the definition: the 0x0C template-instance token and a
    dword back-pointer equal to the chunk-relative definition offset.  The
    pointer is patched in by `ChunkBuilder.place_template`, which also returns
    the definition offset (skipping the prefix).
    """
    if guid is None:
        guid = b"\x11" * 16
    # the on-disk header is 0x18 bytes: next_offset (0x0), template_id (0x4),
    # a GUID read from offset 0x04 (overlapping the id and the following
    # sixteen bytes) and the body data length at offset 0x14.  The GUID
    # therefore starts four bytes into the id field.
    definition = _dword(next_offset) + _dword(template_id) + guid[4:] + _dword(len(body)) + body
    if prefix:
        # the chunk template table reads the 0x0C token ten bytes before the
        # definition and the back-pointer four bytes before it.
        # ofs-10: token 0x0C; ofs-9: flag byte; ofs-8..ofs-7: unknown;
        # ofs-4..ofs-1: back-pointer to the definition offset.
        return _byte(0x0C) + _byte(0x01) + _word(0) + _dword(0) + _word(0) + definition
    return definition


def template_instance(template_id, template_offset):
    return _byte(0x0C) + _byte(0x01) + _dword(template_id) + _dword(template_offset)


def resident_template_instance(template_id, body, guid=None):
    """
    Build a template instance whose definition immediately follows the
    instance token inside the record (a resident template).  The instance's
    template offset is a placeholder patched in once the containing record is
    laid out, so callers use `patch_resident_offset` after placement.
    """
    definition = template_definition(template_id, body, guid=guid, prefix=False)
    instance = _byte(0x0C) + _byte(0x01) + _dword(template_id) + _dword(0)
    return instance, definition


def patch_resident_offset(blob, instance_relative_offset, definition_relative_offset):
    struct.pack_into("<I", blob, instance_relative_offset + 6, definition_relative_offset)


def inline_name_string(name):
    """Build a NameStringNode suitable for embedding inside an element."""
    encoded = name.encode("utf-16-le")
    return _dword(0) + _word(0) + _word(len(encoded) // 2) + encoded + b"\x00\x00"


def open_element(name_node_chunk_offset, body_length, inline_name):
    """
    Build a flagged OpenStartElement (0x41) carrying an inline
    NameStringNode, matching the layout in real event logs.  The name node's
    chunk-relative offset is patched in after the containing record is laid
    out; callers pass the eventual value in `name_node_chunk_offset`.
    """
    return (
        _byte(0x41)
        + _word(0xFFFF)
        + _dword(body_length)
        + _dword(name_node_chunk_offset)
        + _dword(0)
        + inline_name
    )


def substitution(index, type_, conditional=False):
    token = 0x0E if conditional else 0x0D
    return _byte(token) + _word(index) + _byte(type_)


# offset inside an element tag at which the inline NameStringNode's
# chunk-relative offset is stored.
ELEMENT_NAME_OFFSET_FIELD = 7


def element_name_offset_position():
    # body-relative: stream start (4) then the element tag field at byte 7.
    return 4 + ELEMENT_NAME_OFFSET_FIELD


def patch_element_name_offset(chunk_buf, body_chunk_offset, name_node_chunk_offset):
    position = body_chunk_offset + element_name_offset_position()
    struct.pack_into("<I", chunk_buf, position, name_node_chunk_offset)


def simple_template_body(name="Test", sub_index=0, sub_type=e_nodes.NODE_TYPES.UNSIGNED_DWORD):
    """
    Build the body of a renderable template:
    <Name>[substitution]</Name>.

    The element embeds an inline NameStringNode whose chunk-relative offset is
    left as a zero placeholder; `patch_element_name_offsets` fills it in once
    the body has been placed in a chunk.
    """
    inline_name = inline_name_string(name)
    # the size covers the remaining element tokens up to CloseElement.
    inner = _byte(0x02) + substitution(sub_index, sub_type) + _byte(0x04)
    element = open_element(0, len(inner), inline_name)
    body = (
        _byte(0x0F) + _byte(0x01) + _word(0x0001)  # start of stream
        + element
        + inner
        + _byte(0x00)  # end of stream
    )
    return body


def substitution_array(entries):
    """
    Build a substitution array.  Each entry is (size, type, value_bytes).
    """
    out = _dword(len(entries))
    values = b""
    for size, type_, value in entries:
        out += _word(size) + _byte(type_) + _byte(0)
        values += value
    return out + values

def record(record_num, root_bytes, timestamp=0):
    size = RECORD_HEADER_SIZE + len(root_bytes) + 8
    head = _dword(0x2A2A) + _dword(size) + _qword(record_num) + _qword(timestamp)
    tail = _dword(size - 4) + _dword(0x2A2A)
    return head + root_bytes + tail


class ChunkBuilder(object):
    def __init__(self, record_numbers):
        self.buf = bytearray(CHUNK_SIZE)
        self.record_numbers = record_numbers
        self._record_offset = CHUNK_HEADER_SIZE
        # templates and strings grow downward from the top of the usable chunk
        # area, well clear of the small records built by these tests and of
        # the pointer tables in the 0x200-byte chunk header.
        # strings live just above the record area.  Non-resident templates are
        # placed at lower offsets than the records that reference them so the
        # parser classifies the instances as non-resident; the cursor grows
        # upward and must stay below the record area.
        # non-resident templates are allocated in the gap between the 0x200
        # record area start and the (small) first record.  Definitions used by
        # non-resident tests are kept short enough to fit in this gap, so the
        # record still begins at 0x200 while the template offset stays below
        # the instance offset.
        self._next_free = 0x4000
        self._next_string = 0x600
        self._template_pointers = []
        self._string_pointers = []

    def add_record(self, data):
        offset = self._record_offset
        self.buf[offset : offset + len(data)] = data
        self._record_offset += len(data)
        return offset

    def add_resident_record(self, record_num, template_id, body, substitutions, timestamp=0):
        """
        Add a record whose root references an inline (resident) template and
        patch all internal offsets: the instance back-pointer and the inline
        element NameStringNode chunk offset.
        """
        instance, definition = resident_template_instance(template_id, body)
        root = bytearray(
            _byte(0x0F) + _byte(0x01) + _word(0x0001)
            + instance + definition
            + substitution_array(substitutions)
        )
        record_blob = record(record_num, bytes(root), timestamp=timestamp)
        record_offset = self.add_record(record_blob)
        root_offset = record_offset + RECORD_HEADER_SIZE
        instance_rel = root_offset + 4
        definition_rel = instance_rel + len(instance)
        patch_resident_offset(self.buf, instance_rel, definition_rel)
        # the body begins at the definition offset plus the 0x18 header.
        body_offset = definition_rel + 0x18
        # the inline NameStringNode follows the 15-byte element tag.
        name_node_offset = body_offset + 4 + 15
        patch_element_name_offset(self.buf, body_offset, name_node_offset)
        return record_offset

    def add_non_resident_record(self, record_num, template_id, template_offset, body, substitutions):
        """
        Add a record whose root instance points at a template definition that
        lives outside the record (a shared, non-resident template).
        """
        root = bytearray(
            _byte(0x0F) + _byte(0x01) + _word(0x0001)
            + template_instance(template_id, template_offset)
            + substitution_array(substitutions)
        )
        record_offset = self.add_record(record(record_num, bytes(root)))
        # the root's instance is followed directly by the substitution array;
        # non-resident instances have no inline definition, so make sure the
        # referenced offset is not mistaken for a resident one.
        return record_offset

    def place_standalone_template(self, template_id, body, table=True):
        """
        Place a non-resident template definition (with the chunk-table prefix)
        in the free area and return its chunk-relative definition offset.  The
        embedded inline element name offset is patched to point at the inline
        NameStringNode.
        """
        data = template_definition(template_id, body)
        definition_offset = self.place_template(data, table=table)
        body_offset = definition_offset + 0x18
        name_node_offset = body_offset + 4 + 15
        patch_element_name_offset(self.buf, body_offset, name_node_offset)
        return definition_offset

    def place_raw_template_at(self, offset, template_id, body):
        """
        Write a prefix-less template definition at an explicit chunk offset
        without registering it in the template table.  Used to construct
        cyclic and otherwise hostile template graphs at controlled addresses.
        """
        data = template_definition(template_id, body, prefix=False)
        if offset <= self._record_offset or offset + len(data) >= 0x10000:
            raise RuntimeError("raw template must sit above the record area")
        self.buf[offset : offset + len(data)] = data
        return offset

    def place_template(self, data, table=True):
        # `data` may carry a ten-byte instance-token prefix; the chunk table
        # points at the definition that follows it, and the back-pointer in
        # the prefix must equal that definition offset.
        prefix = 10 if len(data) > 0 and data[0] == 0x0C else 0
        self._next_free -= len(data)
        block_offset = self._next_free
        offset = block_offset + prefix
        if self._next_free <= self._record_offset:
            raise RuntimeError("synthetic chunk overflow: templates overlap records")
        self.buf[block_offset : block_offset + len(data)] = data
        if prefix:
            struct.pack_into("<I", self.buf, block_offset + 4, offset)
        if table:
            self._template_pointers.append(offset)
        return offset

    def place_string(self, data):
        offset = self._next_string
        self._next_string += len(data)
        if self._next_string >= 0x800:
            raise RuntimeError("synthetic chunk overflow: strings overlap records")
        self.buf[offset : offset + len(data)] = data
        self._string_pointers.append(offset)
        return offset

    def build(self, first_record=1, last_record=1):
        next_record_offset = self._record_offset
        last_record_offset = next_record_offset - 0x200 if self._record_offset > CHUNK_HEADER_SIZE else next_record_offset
        self.buf[0:8] = b"ElfChnk\x00"
        struct.pack_into("<Q", self.buf, 0x08, first_record)
        struct.pack_into("<Q", self.buf, 0x10, last_record)
        struct.pack_into("<Q", self.buf, 0x18, first_record)
        struct.pack_into("<Q", self.buf, 0x20, last_record)
        struct.pack_into("<I", self.buf, 0x28, 0x80)
        struct.pack_into("<I", self.buf, 0x2C, last_record_offset)
        struct.pack_into("<I", self.buf, 0x30, next_record_offset)
        struct.pack_into("<I", self.buf, 0x34, 0)  # data checksum, rewritten below

        for index, pointer in enumerate(self._string_pointers[:64]):
            struct.pack_into("<I", self.buf, 0x80 + index * 4, pointer)
        for index, pointer in enumerate(self._template_pointers[:32]):
            struct.pack_into("<I", self.buf, 0x180 + index * 4, pointer)

        header_data = bytes(self.buf[0:0x78]) + bytes(self.buf[0x80:0x200])
        checksum = binascii.crc32(header_data) & 0xFFFFFFFF
        struct.pack_into("<I", self.buf, 0x78, checksum)
        data_checksum = binascii.crc32(bytes(self.buf[0x200:next_record_offset])) & 0xFFFFFFFF
        struct.pack_into("<I", self.buf, 0x34, data_checksum)
        return bytes(self.buf)


class EvtxBuilder(object):
    def __init__(self, chunks):
        self.chunks = chunks

    def build(self):
        chunk_count = len(self.chunks)
        header = bytearray(FILE_HEADER_SIZE)
        header[0:8] = b"ElfFile\x00"
        struct.pack_into("<Q", header, 0x10, 0)  # oldest chunk
        struct.pack_into("<Q", header, 0x18, chunk_count - 1)
        struct.pack_into("<Q", header, 0x20, 1)
        struct.pack_into("<I", header, 0x24, 0x80)  # header size
        # the parser's implicit field ordering places these words at
        # 0x28/0x2A and the chunk size/count at 0x2C/0x2E.
        struct.pack_into("<H", header, 0x28, 0x1000)  # header chunk size
        struct.pack_into("<H", header, 0x2A, chunk_count)
        struct.pack_into("<H", header, 0x2C, 1)  # minor version
        struct.pack_into("<H", header, 0x2E, 3)  # major version
        struct.pack_into("<I", header, 0x78, 1)
        checksum = binascii.crc32(bytes(header[0:0x78])) & 0xFFFFFFFF
        struct.pack_into("<I", header, 0x7C, checksum)
        return bytes(header) + b"".join(self.chunks)
