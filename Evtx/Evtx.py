#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v.0.3.0
from __future__ import absolute_import

import re
import sys
import mmap
import logging
import binascii
from functools import wraps

import Evtx.Views as e_views

from .Nodes import (
    RootNode,
    TemplateNode,
    NameStringNode,
    TemplateException,
    DuplicateTemplateException,
    UndefinedTemplateException,
    TemplateConflictException,
)
from .BinaryParser import Block, ParseException

logger = logging.getLogger(__name__)


class TemplateRegistry(object):
    """
    File-wide registry of template definitions.

    Each chunk owns its own template cache (keyed by chunk + offset + id),
    while this registry records every structural fingerprint (a checksum of
    the definition bytes) seen for a template id across the whole file.

    Template ids are content hashes rather than globally unique keys, so real
    logs routinely reuse an id for structurally different definitions in
    different chunks; such differences are therefore tracked but not rejected
    by default.  Strict mode (used when a caller explicitly wants the secure
    graph policy, including the synthetic attack cases) turns a cross-chunk
    id collision with a different definition into a
    `TemplateConflictException`.
    """

    def __init__(self, strict=False):
        self._strict = strict
        # template_id -> (fingerprint, chunk offset, chunk-relative offset)
        self._definitions = {}
        # template_id -> set of distinct fingerprints observed
        self._fingerprints = {}

    def register(self, template_node):
        template_id = template_node.template_id()
        fingerprint = self._fingerprint(template_node)
        existing = self._definitions.get(template_id)
        observed = self._fingerprints.setdefault(template_id, set())
        if fingerprint not in observed:
            if existing is not None and self._strict:
                raise TemplateConflictException(
                    "template id {} is defined with conflicting structures in chunks at offsets {} and {}".format(
                        hex(template_id), hex(existing[1]), hex(template_node._chunk.offset())
                    )
                )
            observed.add(fingerprint)
        if existing is None:
            self._definitions[template_id] = (
                fingerprint,
                template_node._chunk.offset(),
                template_node.offset() - template_node._chunk.offset(),
            )

    @staticmethod
    def _fingerprint(template_node):
        start = template_node.offset()
        length = template_node.length()
        return binascii.crc32(bytes(template_node._buf[start : start + length])) & 0xFFFFFFFF

    def __contains__(self, template_id):
        return template_id in self._definitions

    def definitions(self):
        return dict(self._definitions)

    def has_conflict(self, template_id):
        """
        @return True when the given id has been used by structurally
          different template definitions in more than one chunk.
        """
        return len(self._fingerprints.get(template_id, ())) > 1


class InvalidRecordException(ParseException):
    def __init__(self):
        super(InvalidRecordException, self).__init__("Invalid record structure")


class Evtx(object):
    """
    A convenience class that makes it easy to open an
      EVTX file and start iterating the important structures.
    Note, this class must be used in a context statement
       (see the `with` keyword).
    Note, this class will mmap the target file, so ensure
      your platform supports this operation.
    """

    def __init__(self, filename):
        """
        @type filename:  str
        @param filename: A string that contains the path
          to the EVTX file to open.
        """
        self._filename = filename
        self._buf = None
        self._f = None
        self._fh = None

    def __enter__(self):
        self._f = open(self._filename, "rb")
        self._buf = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self._fh = FileHeader(self._buf, 0x0)
        return self

    def __exit__(self, type, value, traceback):
        self._buf.close()
        self._f.close()
        self._fh = None

    def ensure_contexted(func):
        """
        This decorator ensure that an instance of the
          Evtx class is used within a context statement.  That is,
          that the `with` statement is used, or `__enter__()`
          and `__exit__()` are called explicitly.
        """

        @wraps(func)
        def wrapped(self, *args, **kwargs):
            if self._buf is None:
                raise TypeError("An Evtx object must be used with" " a context (see the `with` statement).")
            else:
                return func(self, *args, **kwargs)

        return wrapped

    @ensure_contexted
    def chunks(self):
        """
        Get each of the ChunkHeaders from within this EVTX file.

        @rtype generator of ChunkHeader
        @return A generator of ChunkHeaders from this EVTX file.
        """
        for chunk in self._fh.chunks():
            yield chunk

    @ensure_contexted
    def records(self):
        """
        Get each of the Records from within this EVTX file.

        @rtype generator of Record
        @return A generator of Records from this EVTX file.
        """
        for chunk in self.chunks():
            for record in chunk.records():
                yield record

    @ensure_contexted
    def get_record(self, record_num):
        """
        Get a Record by record number.

        @type record_num:  int
        @param record_num: The record number of the the record to fetch.
        @rtype Record or None
        @return The record request by record number, or None if
          the record is not found.
        """
        return self._fh.get_record(record_num)

    @ensure_contexted
    def get_file_header(self):
        return self._fh


class FileHeader(Block):
    def __init__(self, buf, offset, strict_templates=False):
        logger.debug("FILE HEADER at {}.".format(hex(offset)))
        super(FileHeader, self).__init__(buf, offset)
        self._strict_templates = strict_templates
        self._template_registry = TemplateRegistry(strict=strict_templates)
        self.declare_field("string", "magic", 0x0, length=8)
        self.declare_field("qword", "oldest_chunk")
        self.declare_field("qword", "current_chunk_number")
        self.declare_field("qword", "next_record_number")
        self.declare_field("dword", "header_size")
        self.declare_field("word", "minor_version")
        self.declare_field("word", "major_version")
        self.declare_field("word", "header_chunk_size")
        self.declare_field("word", "chunk_count")
        self.declare_field("binary", "unused1", length=0x4C)
        self.declare_field("dword", "flags")
        self.declare_field("dword", "checksum")

    def __repr__(self):
        return "FileHeader(buf={!r}, offset={!r})".format(self._buf, self._offset)

    def __str__(self):
        return "FileHeader(offset={})".format(hex(self._offset))

    def check_magic(self):
        """
        @return A boolean that indicates if the first eight bytes of
          the FileHeader match the expected magic value.
        """
        try:
            return self.magic() == "ElfFile\x00"
        except UnicodeDecodeError:
            return False

    def calculate_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum off the first 0x78 bytes.
          This is consistent with the checksum stored by the FileHeader.
        """
        return binascii.crc32(self.unpack_binary(0, 0x78)) & 0xFFFFFFFF

    def verify(self):
        """
        @return A boolean that indicates that the FileHeader
          successfully passes a set of heuristic checks that
          all EVTX FileHeaders should pass.
        """
        return (
            self.check_magic()
            and self.major_version() == 0x3
            and self.minor_version() == 0x1
            and self.header_chunk_size() == 0x1000
            and self.checksum() == self.calculate_checksum()
        )

    def is_dirty(self):
        """
        @return A boolean that indicates that the log has been
          opened and was changed, though not all changes might be
          reflected in the file header.
        """
        return self.flags() & 0x1 == 0x1

    def is_full(self):
        """
        @return A boolean that indicates that the log
          has reached its maximum configured size and the retention
          policy in effect does not allow to reclaim a suitable amount
          of space from the oldest records and an event message could
          not be written to the log file.
        """
        return self.flags() & 0x2 == 0x2

    def first_chunk(self):
        """
        @return A ChunkHeader instance that is the first chunk
          in the log file, which is always found directly after
          the FileHeader.
        """
        ofs = self._offset + self.header_chunk_size()
        return ChunkHeader(self._buf, ofs)

    def current_chunk(self):
        """
        @return A ChunkHeader instance that is the current chunk
          indicated by the FileHeader.
        """
        ofs = self._offset + self.header_chunk_size()
        ofs += self.current_chunk_number() * 0x10000
        return ChunkHeader(self._buf, ofs)

    def chunks(self, include_inactive=False):
        """
        @return A generator that yields the chunks of the log file
          starting with the first chunk, which is always found directly
          after the FileHeader.

        If `include_inactive` is set to true, enumerate chunks beyond those
        declared in the file header (and may therefore be corrupt).
        """
        if include_inactive:
            chunk_count = sys.maxsize
        else:
            chunk_count = self.chunk_count()

        i = 0
        ofs = self._offset + self.header_chunk_size()
        while ofs + 0x10000 <= len(self._buf) and i < chunk_count:
            yield ChunkHeader(
                self._buf,
                ofs,
                template_registry=self._template_registry,
                strict_templates=self._strict_templates,
            )
            ofs += 0x10000
            i += 1

    def get_record(self, record_num):
        """
        Get a Record by record number.

        @type record_num:  int
        @param record_num: The record number of the the record to fetch.
        @rtype Record or None
        @return The record request by record number, or None if the
          record is not found.
        """
        for chunk in self.chunks():
            first_record = chunk.log_first_record_number()
            last_record = chunk.log_last_record_number()
            if not (first_record <= record_num <= last_record):
                continue
            for record in chunk.records():
                if record.record_num() == record_num:
                    return record
        return None


class Template(object):
    def __init__(self, template_node):
        self._template_node = template_node
        self._xml = None

    def _load_xml(self):
        """
        TODO(wb): One day, nodes should generate format strings
          instead of the XML format made-up abomination.
        """
        if self._xml is not None:
            return
        matcher = r"\[(?:Normal|Conditional) Substitution\(index=(\d+), type=\d+\)\]"
        self._xml = re.sub(
            matcher, "{\\1:}", self._template_node.template_format().replace("{", "{{").replace("}", "}}")
        )

    def make_substitutions(self, substitutions):
        """

        @type substitutions: list of VariantTypeNode
        """
        self._load_xml()
        return self._xml.format(*[n.xml() for n in substitutions])

    def node(self):
        return self._template_node


class ChunkHeader(Block):
    def __init__(self, buf, offset, template_registry=None, strict_templates=False):
        logger.debug("CHUNK HEADER at {}.".format(hex(offset)))
        super(ChunkHeader, self).__init__(buf, offset)
        self._strings = None
        self._templates = None
        # chunk-relative template offset -> template id, so the cache key
        # carries the chunk, the offset and the template id rather than the
        # id alone.
        self._template_ids = {}
        self._template_registry = template_registry
        self._strict_templates = strict_templates
        self._template_cache_hits = 0

        self.declare_field("string", "magic", 0x0, length=8)
        self.declare_field("qword", "file_first_record_number")
        self.declare_field("qword", "file_last_record_number")
        self.declare_field("qword", "log_first_record_number")
        self.declare_field("qword", "log_last_record_number")
        self.declare_field("dword", "header_size")
        self.declare_field("dword", "last_record_offset")
        self.declare_field("dword", "next_record_offset")
        self.declare_field("dword", "data_checksum")
        self.declare_field("binary", "unused", length=0x44)
        self.declare_field("dword", "header_checksum")

    def __repr__(self):
        return "ChunkHeader(buf={!r}, offset={!r})".format(self._buf, self._offset)

    def __str__(self):
        return "ChunkHeader(offset={})".format(hex(self._offset))

    def check_magic(self):
        """
        @return A boolean that indicates if the first eight bytes of
          the ChunkHeader match the expected magic value.
        """
        try:
            return self.magic() == "ElfChnk\x00"
        except UnicodeDecodeError:
            return False

    def calculate_header_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum of the ChunkHeader fields.
        """
        data = self.unpack_binary(0x0, 0x78)
        data += self.unpack_binary(0x80, 0x180)
        return binascii.crc32(data) & 0xFFFFFFFF

    def calculate_data_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum of the Chunk data.
        """
        data = self.unpack_binary(0x200, self.next_record_offset() - 0x200)
        return binascii.crc32(data) & 0xFFFFFFFF

    def verify(self):
        """
        @return A boolean that indicates that the FileHeader
          successfully passes a set of heuristic checks that
          all EVTX ChunkHeaders should pass.
        """
        return (
            self.check_magic()
            and self.calculate_header_checksum() == self.header_checksum()
            and self.calculate_data_checksum() == self.data_checksum()
        )

    def _load_strings(self):
        if self._strings is None:
            self._strings = {}
        for i in range(64):
            ofs = self.unpack_dword(0x80 + (i * 4))
            while ofs > 0:
                string_node = self.add_string(ofs)
                ofs = string_node.next_offset()

    def strings(self):
        """
        @return A dict(offset --> NameStringNode)
        """
        if not self._strings:
            self._load_strings()
        return self._strings

    def add_string(self, offset, parent=None):
        """
        @param offset An integer offset that is relative to the start of
          this chunk.
        @param parent (Optional) The parent of the newly created
           NameStringNode instance. (Default: this chunk).
        @return None
        """
        if self._strings is None:
            self._load_strings()
        string_node = NameStringNode(self._buf, self._offset + offset, self, parent or self)
        self._strings[offset] = string_node
        return string_node

    def _load_templates(self):
        """
        @return None
        """
        if self._templates is None:
            self._templates = {}
        for i in range(32):
            try:
                ofs = self.unpack_dword(0x180 + (i * 4))
            except ParseException:
                logger.warning("Unable to read template table entry %d", i)
                continue
            while ofs > 0:
                try:
                    # unclear why these are found before the offset
                    # this is a direct port from A.S.'s code
                    token = self.unpack_byte(ofs - 10)
                    pointer = self.unpack_dword(ofs - 4)
                    if token != 0x0C or pointer != ofs:
                        logger.warning("Unexpected token encountered")
                        ofs = 0
                        continue
                    template = self.add_template(ofs)
                    ofs = template.next_offset()
                except TemplateException as exc:
                    # one bad template definition must not make every other
                    # record in this chunk unreadable.
                    logger.warning("Skipping invalid template at chunk offset %s: %s", hex(ofs), exc)
                    break

    def add_template(self, offset, parent=None, expected_template_id=None):
        """
        @param offset An integer which contains the chunk-relative offset
           to a template to load into this Chunk.
        @param parent (Optional) The parent of the newly created
           TemplateNode instance. (Default: this chunk).
        @param expected_template_id (Optional) The template id carried by the
           template instance that caused this definition to be loaded.  When
           provided it must match the definition's own template id.
        @return Newly added TemplateNode instance.
        """
        if self._templates is None:
            self._load_templates()

        cached = self._templates.get(offset)
        if cached is not None:
            self._template_cache_hits += 1
            if expected_template_id is not None and cached.template_id() != expected_template_id:
                raise UndefinedTemplateException(
                    "template instance id {} does not match cached definition id {} at offset {}".format(
                        hex(expected_template_id), hex(cached.template_id()), hex(offset)
                    )
                )
            return cached

        if offset <= 0 or offset >= 0x10000:
            raise UndefinedTemplateException(
                "template offset {} is outside the chunk data area".format(hex(offset))
            )

        node = TemplateNode(self._buf, self._offset + offset, self, parent or self)
        try:
            node_length = node.length()
        except ParseException as exc:
            raise UndefinedTemplateException("unable to measure template at offset {}".format(hex(offset))) from exc
        if offset + node_length > 0x10000:
            raise UndefinedTemplateException(
                "template at offset {} extends beyond the chunk boundary".format(hex(offset))
            )

        template_id = node.template_id()
        if expected_template_id is not None and template_id != expected_template_id:
            raise UndefinedTemplateException(
                "template instance id {} does not match definition id {} at offset {}".format(
                    hex(expected_template_id), hex(template_id), hex(offset)
                )
            )

        existing_offset = self._template_ids.get(template_id)
        if existing_offset is not None and existing_offset != offset:
            existing = self._templates[existing_offset]
            different_definition = TemplateRegistry._fingerprint(existing) != TemplateRegistry._fingerprint(node)
            if different_definition:
                raise DuplicateTemplateException(
                    "duplicate template id {} at chunk offsets {} and {}".format(
                        hex(template_id), hex(existing_offset), hex(offset)
                    )
                )
            # identical definition re-encountered at another offset: keep the
            # first authoritative entry and treat this as a cache hit.
            self._template_cache_hits += 1
            return existing

        self._templates[offset] = node
        self._template_ids[template_id] = offset
        if self._template_registry is not None:
            # In strict mode register() raises a descriptive
            # TemplateConflictException for cross-chunk id collisions; in the
            # default mode all distinct definitions are merely recorded.
            self._template_registry.register(node)
        return node

    def get_template(self, offset, parent=None, expected_template_id=None):
        """
        Resolve a template definition by chunk-relative offset, loading it on
        demand when it is referenced by a non-resident template instance.

        Every resolution goes through this method (or `add_template`) so the
        cache key always includes the chunk and the offset, and so undefined,
        duplicate or conflicting references fail explicitly.
        """
        if offset <= 0 or offset >= 0x10000:
            raise UndefinedTemplateException(
                "template offset {} is outside the chunk data area".format(hex(offset))
            )
        cached = self.templates().get(offset)
        if cached is None:
            return self.add_template(offset, parent=parent, expected_template_id=expected_template_id)
        self._template_cache_hits += 1
        if expected_template_id is not None and cached.template_id() != expected_template_id:
            raise UndefinedTemplateException(
                "template instance id {} does not match cached definition id {} at offset {}".format(
                    hex(expected_template_id), hex(cached.template_id()), hex(offset)
                )
            )
        return cached

    def template_cache_hits(self):
        """
        @return The number of times a template definition was served from the
          chunk's cache rather than freshly parsed.
        """
        return self._template_cache_hits

    def templates(self):
        """
        @return A dict(offset --> Template) of all encountered
          templates in this Chunk.
        """
        if not self._templates:
            self._load_templates()
        return self._templates

    def first_record(self):
        return Record(self._buf, self._offset + 0x200, self)

    def records(self):
        try:
            record = self.first_record()
        except InvalidRecordException:
            return
        while record._offset < self._offset + self.next_record_offset() and record.length() > 0:
            yield record
            try:
                record = Record(self._buf, record._offset + record.length(), self)
            except InvalidRecordException:
                return


class Record(Block):
    def __init__(self, buf, offset, chunk):
        logger.debug("Record at {}.".format(hex(offset)))
        super(Record, self).__init__(buf, offset)
        self._chunk = chunk

        self.declare_field("dword", "magic", 0x0)  # 0x00002a2a
        self.declare_field("dword", "size")
        self.declare_field("qword", "record_num")
        self.declare_field("filetime", "timestamp")

        if self.size() > 0x10000:
            raise InvalidRecordException()

        self.declare_field("dword", "size2", self.size() - 4)

    def __repr__(self):
        return "Record(buf={!r}, offset={!r})".format(self._buf, self._offset)

    def __str__(self):
        return "Record(offset={})".format(hex(self._offset))

    def root(self):
        return RootNode(self._buf, self._offset + 0x18, self._chunk, self)

    def length(self):
        return self.size()

    def verify(self):
        return self.size() == self.size2()

    def data(self):
        """
        Return the raw data block which makes up this record as a bytestring.

        @rtype str
        @return A string that is a copy of the buffer that makes
          up this record.
        """
        return self._buf[self.offset() : self.offset() + self.size()]

    def xml(self):
        """
        render the record into XML.
        does not include the xml declaration header.

        Returns:
          str: the rendered xml document.
        """
        return e_views.evtx_record_xml_view(self)

    def lxml(self):
        """
        render the record into a lxml document.
        this is useful for querying data from the record using xpath, etc.

        note: lxml must be installed.

        Returns:
          lxml.etree.ElementTree: the rendered and parsed xml document.

        Raises:
          ImportError: if lxml is not installed.
        """
        import lxml.etree

        return lxml.etree.fromstring((e_views.XML_HEADER + self.xml()).encode("utf-8"))
