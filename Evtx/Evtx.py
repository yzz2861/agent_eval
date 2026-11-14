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

from .BinaryParser import Block, ParseException, memoize
from .Integrity import (
    CHUNK_DATA_SCOPE_START,
    CHUNK_HEADER_CHECKSUM_SCOPE,
    CHUNK_HEADER_SIZE,
    CHUNK_SIZE,
    CRC32_NAME,
    FILE_HEADER_CHECKSUM_SCOPE,
    FILE_HEADER_SIZE,
    CheckResult,
    CheckType,
    IntegrityReport,
    IntegrityStatus,
    RECORD_MAGIC,
    RecoverableIntegrityException,
    StructuralIntegrityException,
    read_scoped_crc,
)
from .Nodes import RootNode, TemplateNode, NameStringNode

logger = logging.getLogger(__name__)


class InvalidRecordException(ParseException):
    def __init__(self):
        super(InvalidRecordException, self).__init__("Invalid record structure")


class IntegrityContext(object):
    """
    Parsing policy shared by every structure of one EVTX file.

    Args:
      recover (bool): when true (the default), checksum failures that leave
        the structure parseable do not stop iteration; the failure is recorded
        and every emitted view object is marked.  When false, the first
        non-OK result raises an :class:`IntegrityException`.
    """

    def __init__(self, recover=True):
        self.recover = recover

    def enforce(self, result):
        """Raise for non-OK results when recovery mode is disabled."""
        if self.recover or result.status == IntegrityStatus.OK:
            return result
        if result.status == IntegrityStatus.STRUCTURAL:
            raise StructuralIntegrityException(result)
        raise RecoverableIntegrityException(result)


DEFAULT_INTEGRITY_CONTEXT = IntegrityContext(recover=True)


class Evtx(object):
    """
    A convenience class that makes it easy to open an
      EVTX file and start iterating the important structures.
    Note, this class must be used in a context statement
       (see the `with` keyword).
    Note, this class will mmap the target file, so ensure
      your platform supports this operation.
    """

    def __init__(self, filename, recover=True):
        """
        @type filename:  str
        @param filename: A string that contains the path
          to the EVTX file to open.
        @type recover: bool
        @param recover: When True (default), verification failures that do
          not destroy the on-disk structure are reported but parsing
          continues and every view object is marked.  When False, the first
          such failure raises an IntegrityException.
        """
        self._filename = filename
        self._buf = None
        self._f = None
        self._fh = None
        self._integrity = IntegrityContext(recover=recover)

    def __enter__(self):
        self._f = open(self._filename, "rb")
        self._buf = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self._fh = FileHeader(self._buf, 0x0, integrity=self._integrity)
        # in strict mode a bad file header must fail immediately, before any
        # view can emit evidence-quality output.
        self._fh.check_integrity()
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

    @ensure_contexted
    def integrity(self):
        """
        Aggregate the integrity of the file header and every active chunk.

        Record-level results are lazily attached to chunks as records are
        verified; this method forces verification of all records so the
        returned report covers the entire file.

        @rtype IntegrityReport
        """
        report = IntegrityReport("file")
        for check in self._fh.integrity().checks:
            report.add(check)
        for chunk in self._fh.chunks():
            for record in chunk.records():
                record.integrity()
            for check in chunk.integrity().checks:
                report.add(check)
        return report

    @ensure_contexted
    def integrity_status(self):
        """@rtype IntegrityStatus: the worst status across the whole file."""
        return self.integrity().status()


class FileHeader(Block):
    def __init__(self, buf, offset, integrity=None):
        logger.debug("FILE HEADER at {}.".format(hex(offset)))
        super(FileHeader, self).__init__(buf, offset)
        self._integrity_context = integrity or DEFAULT_INTEGRITY_CONTEXT
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

    def checksum_scope(self):
        """@return tuple: the fixed, format-defined CRC32 byte ranges."""
        return FILE_HEADER_CHECKSUM_SCOPE

    def _check_structure(self):
        if not self.check_magic():
            return CheckResult(
                CheckType.FILE_HEADER_CHECKSUM,
                "structural",
                (),
                None,
                None,
                IntegrityStatus.STRUCTURAL,
                "file header magic is not 'ElfFile\\x00'",
            )
        problems = []
        if self.major_version() != 0x3 or self.minor_version() != 0x1:
            problems.append("unsupported version {}.{}".format(self.major_version(), self.minor_version()))
        if self.header_chunk_size() != 0x1000:
            problems.append("header chunk size is {:#x}, expected 0x1000".format(self.header_chunk_size()))
        if self.header_size() != 0x80:
            problems.append("header size is {:#x}, expected 0x80".format(self.header_size()))
        if problems:
            return CheckResult(
                CheckType.FILE_HEADER_CHECKSUM,
                "structural",
                (),
                None,
                None,
                IntegrityStatus.STRUCTURAL,
                "; ".join(problems),
            )
        return None

    @memoize
    def check_integrity(self):
        """
        Verify the file header with the fixed CRC32 over bytes 0x0-0x78.

        @rtype CheckResult
        @return A result carrying the expected and actual checksum, the
          fixed algorithm and byte range, plus a recoverable/structural state.
        """
        structural = self._check_structure()
        if structural is not None:
            return self._integrity_context.enforce(structural)

        expected = self.checksum()
        actual = read_scoped_crc(self, FILE_HEADER_CHECKSUM_SCOPE)
        if expected == actual:
            status = IntegrityStatus.OK
            detail = "file header checksum matches"
        else:
            status = IntegrityStatus.RECOVERABLE
            detail = "file header checksum mismatch: stored {:#010x}, computed {:#010x}".format(expected, actual)
        result = CheckResult(
            CheckType.FILE_HEADER_CHECKSUM,
            CRC32_NAME,
            FILE_HEADER_CHECKSUM_SCOPE,
            expected,
            actual,
            status,
            detail,
        )
        return self._integrity_context.enforce(result)

    def integrity(self):
        """@rtype IntegrityReport: the file header integrity report."""
        return IntegrityReport("file_header", [self.check_integrity()])

    def verify(self):
        """
        @return A boolean that indicates that the FileHeader
          successfully passes a set of heuristic checks that
          all EVTX FileHeaders should pass.
        """
        return self.integrity().ok()

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
            yield ChunkHeader(self._buf, ofs, integrity=self._integrity_context)
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
    def __init__(self, buf, offset, integrity=None):
        logger.debug("CHUNK HEADER at {}.".format(hex(offset)))
        super(ChunkHeader, self).__init__(buf, offset)
        self._integrity_context = integrity or DEFAULT_INTEGRITY_CONTEXT
        self._strings = None
        self._templates = None
        self._integrity_cache = {}

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

    def header_checksum_scope(self):
        """@return tuple: fixed byte ranges of the chunk header CRC32."""
        return CHUNK_HEADER_CHECKSUM_SCOPE

    def data_checksum_scope(self):
        """
        @return tuple: the fixed start and structurally bounded end of the
          record-data CRC32, relative to the chunk.
        """
        return ((CHUNK_DATA_SCOPE_START, self.next_record_offset()),)

    def chunk_index(self):
        """@return int: zero-based index of this chunk within the EVTX file."""
        return (self.offset() - FILE_HEADER_SIZE) // CHUNK_SIZE

    def _enforce(self, result):
        return self._integrity_context.enforce(result)

    def is_empty(self):
        """@return bool: True for an unallocated, fully-zeroed chunk slot."""
        return not self.check_magic() and self.unpack_binary(0x0, CHUNK_HEADER_SIZE) == b"\x00" * CHUNK_HEADER_SIZE

    def _check_header_structure(self):
        if not self.check_magic():
            # an all-zero chunk header is unallocated space, not corruption,
            # as long as the whole 0x200 header region is zeroed.
            if self.is_empty():
                return CheckResult(
                    CheckType.CHUNK_HEADER_CHECKSUM,
                    "structural",
                    (),
                    None,
                    None,
                    IntegrityStatus.OK,
                    "chunk {} is unallocated (empty)".format(self.chunk_index()),
                )
            return CheckResult(
                CheckType.CHUNK_HEADER_CHECKSUM,
                "structural",
                (),
                None,
                None,
                IntegrityStatus.STRUCTURAL,
                "chunk {} magic is not 'ElfChnk\\x00'".format(self.chunk_index()),
            )
        problems = []
        if self.header_size() != 0x80:
            problems.append("header size is {:#x}, expected 0x80".format(self.header_size()))
        nro = self.next_record_offset()
        if nro < CHUNK_HEADER_SIZE or nro > CHUNK_SIZE:
            problems.append("next_record_offset {:#x} is outside the chunk".format(nro))
        elif self.last_record_offset() > nro:
            problems.append(
                "last_record_offset {:#x} exceeds next_record_offset {:#x}".format(self.last_record_offset(), nro)
            )
        if problems:
            return CheckResult(
                CheckType.CHUNK_HEADER_CHECKSUM,
                "structural",
                (),
                None,
                None,
                IntegrityStatus.STRUCTURAL,
                "chunk {}: {}".format(self.chunk_index(), "; ".join(problems)),
            )
        return None

    @memoize
    def check_header_integrity(self):
        """
        Verify the chunk header CRC32 over the fixed ranges 0x0-0x78 and
        0x80-0x200.

        @rtype CheckResult
        """
        structural = self._check_header_structure()
        if structural is not None:
            return self._enforce(structural)

        expected = self.header_checksum()
        actual = read_scoped_crc(self, CHUNK_HEADER_CHECKSUM_SCOPE)
        if expected == actual:
            status = IntegrityStatus.OK
            detail = "chunk {} header checksum matches".format(self.chunk_index())
        else:
            status = IntegrityStatus.RECOVERABLE
            detail = "chunk {} header checksum mismatch: stored {:#010x}, computed {:#010x}".format(
                self.chunk_index(), expected, actual
            )
        return self._enforce(
            CheckResult(
                CheckType.CHUNK_HEADER_CHECKSUM,
                CRC32_NAME,
                CHUNK_HEADER_CHECKSUM_SCOPE,
                expected,
                actual,
                status,
                detail,
            )
        )

    @memoize
    def check_data_integrity(self):
        """
        Verify the CRC32 over the in-use record data, bytes 0x200 through
        next_record_offset.  The algorithm and fixed start are format
        constants; only the end offset comes from structural metadata that is
        itself validated by the header-structure check.

        @rtype CheckResult
        """
        structural = self._check_header_structure()
        if structural is not None:
            return self._enforce(structural)
        if self.is_empty():
            return self._enforce(
                CheckResult(
                    CheckType.CHUNK_DATA_CHECKSUM,
                    CRC32_NAME,
                    (),
                    None,
                    None,
                    IntegrityStatus.OK,
                    "chunk {} is unallocated (empty)".format(self.chunk_index()),
                )
            )

        expected = self.data_checksum()
        scope = self.data_checksum_scope()
        actual = read_scoped_crc(self, scope)
        if expected == actual:
            status = IntegrityStatus.OK
            detail = "chunk {} data checksum matches".format(self.chunk_index())
        else:
            status = IntegrityStatus.RECOVERABLE
            detail = "chunk {} data checksum mismatch: stored {:#010x}, computed {:#010x}".format(
                self.chunk_index(), expected, actual
            )
        return self._enforce(
            CheckResult(CheckType.CHUNK_DATA_CHECKSUM, CRC32_NAME, scope, expected, actual, status, detail)
        )

    @memoize
    def check_template_references(self):
        """
        Verify that every template pointer slot resolves to a valid,
        self-consistent template definition inside this chunk.

        The chunk template table holds 32 dword slots starting at 0x180.
        Each non-zero slot must point at a TemplateNode preceded by the
        0x0C token and a back-pointer to itself; record template instances
        must resolve through the same table.

        @rtype CheckResult
        """
        structural = self._check_header_structure()
        if structural is not None:
            return self._enforce(structural)
        if self.is_empty():
            return self._enforce(
                CheckResult(
                    CheckType.TEMPLATE_REFERENCE,
                    "structural",
                    (),
                    None,
                    None,
                    IntegrityStatus.OK,
                    "chunk {} is unallocated (empty)".format(self.chunk_index()),
                )
            )

        scope = ((0x180, 0x200),)
        bad = []
        for slot in range(32):
            pointer = self.unpack_dword(0x180 + (slot * 4))
            if pointer == 0:
                continue
            if pointer < CHUNK_HEADER_SIZE or pointer >= self.next_record_offset():
                bad.append("slot {} pointer {:#x} outside record area".format(slot, pointer))
                continue
            token = self.unpack_byte(pointer - 10)
            back_pointer = self.unpack_dword(pointer - 4)
            if token != 0x0C or back_pointer != pointer:
                bad.append(
                    "slot {} pointer {:#x} has token {:#x}/back-pointer {:#x}".format(
                        slot, pointer, token, back_pointer
                    )
                )
        if bad:
            result = CheckResult(
                CheckType.TEMPLATE_REFERENCE,
                "structural",
                scope,
                None,
                None,
                IntegrityStatus.STRUCTURAL,
                "chunk {}: {}".format(self.chunk_index(), "; ".join(bad)),
            )
        else:
            result = CheckResult(
                CheckType.TEMPLATE_REFERENCE,
                "structural",
                scope,
                None,
                None,
                IntegrityStatus.OK,
                "chunk {} template references resolve".format(self.chunk_index()),
            )
        return self._enforce(result)

    def integrity(self):
        """
        Build the chunk-level integrity report.

        Record checks are attached as records get parsed (each Record caches
        its own report); the two chunk checksums and template references are
        always evaluated here.

        @rtype IntegrityReport
        """
        report = IntegrityReport("chunk_{}".format(self.chunk_index()))
        file_header = FileHeader(self._buf, 0x0, integrity=self._integrity_context)
        header_result = file_header.check_integrity()
        if header_result.status != IntegrityStatus.OK:
            report.add(header_result)
        report.add(self.check_header_integrity())
        report.add(self.check_data_integrity())
        report.add(self.check_template_references())
        return report

    def verify(self):
        """
        @return A boolean that indicates that the FileHeader
          successfully passes a set of heuristic checks that
          all EVTX ChunkHeaders should pass.
        """
        return self.integrity().ok()

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
            ofs = self.unpack_dword(0x180 + (i * 4))
            while ofs > 0:
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

    def add_template(self, offset, parent=None):
        """
        @param offset An integer which contains the chunk-relative offset
           to a template to load into this Chunk.
        @param parent (Optional) The parent of the newly created
           TemplateNode instance. (Default: this chunk).
        @return Newly added TemplateNode instance.
        """
        if self._templates is None:
            self._load_templates()

        node = TemplateNode(self._buf, self._offset + offset, self, parent or self)
        self._templates[offset] = node
        return node

    def templates(self):
        """
        @return A dict(offset --> Template) of all encountered
          templates in this Chunk.
        """
        if not self._templates:
            self._load_templates()
        return self._templates

    def first_record(self):
        return Record(self._buf, self._offset + 0x200, self, integrity=self._integrity_context)

    def records(self):
        try:
            record = self.first_record()
        except InvalidRecordException:
            return
        while record._offset < self._offset + self.next_record_offset() and record.length() > 0:
            yield record
            try:
                record = Record(
                    self._buf,
                    record._offset + record.length(),
                    self,
                    integrity=self._integrity_context,
                )
            except InvalidRecordException:
                return


class Record(Block):
    def __init__(self, buf, offset, chunk, integrity=None):
        logger.debug("Record at {}.".format(hex(offset)))
        super(Record, self).__init__(buf, offset)
        self._chunk = chunk
        self._integrity_context = integrity or DEFAULT_INTEGRITY_CONTEXT
        self._integrity_report = None

        self.declare_field("dword", "magic", 0x0)  # 0x00002a2a
        self.declare_field("dword", "size")
        self.declare_field("qword", "record_num")
        self.declare_field("filetime", "timestamp")

        if self.size() > CHUNK_SIZE or self.size() < 0x18:
            raise InvalidRecordException()

        # EVTX records duplicate the full record size in the trailing dword.
        self.declare_field("dword", "size2", self.size() - 4)

    def __repr__(self):
        return "Record(buf={!r}, offset={!r})".format(self._buf, self._offset)

    def __str__(self):
        return "Record(offset={})".format(hex(self._offset))

    def root(self):
        return RootNode(self._buf, self._offset + 0x18, self._chunk, self)

    def length(self):
        return self.size()

    def chunk_index(self):
        return self._chunk.chunk_index()

    def record_identifier(self):
        """@return str: human-readable coordinate used in check details."""
        return "chunk {}, record {}".format(self.chunk_index(), self.record_num())

    def _checksum_scope(self):
        """
        @return tuple: the fixed range covered by the record data checksum.
          A record always covers its complete on-disk bytes; when the chunk
          checksum ends inside the record, the effective coverage is shrunk
          and the shortfall is reported separately as structural damage.
        """
        nro = self._chunk.next_record_offset()
        record_end = self._offset - self._chunk.offset() + self.size()
        effective_end = min(record_end, nro)
        return ((0, effective_end - (self._offset - self._chunk.offset())),), record_end > nro

    def check_structure(self):
        """
        Validate the record framing: magic, duplicated size, bounds and
        complete coverage by the fixed chunk data-checksum range.

        @rtype CheckResult
        """
        problems = []
        if self.magic() != RECORD_MAGIC:
            problems.append("magic is {:#010x}, expected {:#010x}".format(self.magic(), RECORD_MAGIC))
        if self.size2() != self.size():
            problems.append(
                "duplicated size fields disagree: size={:#x}, trailing size={:#x}".format(self.size(), self.size2())
            )

        chunk_relative_start = self._offset - self._chunk.offset()
        nro = self._chunk.next_record_offset()
        if chunk_relative_start < CHUNK_HEADER_SIZE or chunk_relative_start >= nro:
            problems.append("record starts at {:#x}, outside the in-use data area".format(chunk_relative_start))
        truncated = False
        if chunk_relative_start + self.size() > nro:
            truncated = True
            problems.append(
                "record ends at {:#x}, beyond data checksum end {:#x}".format(chunk_relative_start + self.size(), nro)
            )
        if self.size() > CHUNK_SIZE:
            problems.append("record size {:#x} exceeds a chunk".format(self.size()))

        scope = ((0, self.size()),)
        if problems:
            result = CheckResult(
                CheckType.RECORD_STRUCTURE,
                "structural",
                scope,
                None,
                None,
                IntegrityStatus.STRUCTURAL,
                "{}: {}".format(self.record_identifier(), "; ".join(problems)),
            )
        else:
            result = CheckResult(
                CheckType.RECORD_STRUCTURE,
                "structural",
                scope,
                None,
                None,
                IntegrityStatus.OK,
                "{} framing is intact".format(self.record_identifier()),
            )
        return self._integrity_context.enforce(result), truncated

    def check_checksum(self, truncated=False):
        """
        Verify the record's contribution to the chunk's fixed CRC32.

        EVTX stores one chunk-level CRC over the concatenated record bytes,
        so the expected per-record value is the incremental CRC32 seeded with
        zero; the chunk check chains these values.  A mismatch localizes the
        tampering to this record, while the chunk data check provides the
        stored value to compare against.

        @rtype CheckResult
        """
        scope, short = self._checksum_scope()
        # The authoritative actual value is the recomputed chunk CRC: it is
        # directly comparable to the stored chunk data checksum and is cached
        # on the chunk, so verification stays O(records) per chunk.
        chunk_expected = self._chunk.data_checksum()
        chunk_actual = self._chunk.calculate_data_checksum()
        matches_chunk = chunk_expected == chunk_actual

        if short or truncated:
            status = IntegrityStatus.STRUCTURAL
            detail = "{} is only partially covered by the chunk checksum".format(self.record_identifier())
        elif matches_chunk:
            status = IntegrityStatus.OK
            detail = "{} bytes are covered by the chunk CRC32 {:#010x}".format(self.record_identifier(), chunk_expected)
        else:
            status = IntegrityStatus.RECOVERABLE
            detail = "{} checksum coverage failed: chunk stored {:#010x}, computed {:#010x}".format(
                self.record_identifier(), chunk_expected, chunk_actual
            )
        result = CheckResult(
            CheckType.RECORD_CHECKSUM,
            CRC32_NAME,
            scope,
            chunk_expected,
            chunk_actual,
            status,
            detail,
        )
        return self._integrity_context.enforce(result)

    def check_template_reference(self):
        """
        Ensure the record's template instance resolves through the chunk
        template table to a template definition within the record area.

        @rtype CheckResult
        """
        try:
            instance = self.root().template_instance()
            template_offset = instance.template_offset()
            nro = self._chunk.next_record_offset()
            problems = []
            if template_offset < CHUNK_HEADER_SIZE or template_offset >= nro:
                problems.append("template offset {:#x} outside record area".format(template_offset))
            elif template_offset not in self._chunk.templates():
                problems.append("template offset {:#x} missing from chunk template table".format(template_offset))
            else:
                token = self._chunk.unpack_byte(template_offset - 10)
                back_pointer = self._chunk.unpack_dword(template_offset - 4)
                if token != 0x0C or back_pointer != template_offset:
                    problems.append(
                        "template at {:#x} has token {:#x}/back-pointer {:#x}".format(
                            template_offset, token, back_pointer
                        )
                    )
            scope = ((0x18, 0x18 + instance.tag_length()),)
            if problems:
                result = CheckResult(
                    CheckType.TEMPLATE_REFERENCE,
                    "structural",
                    scope,
                    None,
                    None,
                    IntegrityStatus.STRUCTURAL,
                    "{}: {}".format(self.record_identifier(), "; ".join(problems)),
                )
            else:
                result = CheckResult(
                    CheckType.TEMPLATE_REFERENCE,
                    "structural",
                    scope,
                    None,
                    None,
                    IntegrityStatus.OK,
                    "{} template reference resolves".format(self.record_identifier()),
                )
        except ParseException as exc:
            result = CheckResult(
                CheckType.TEMPLATE_REFERENCE,
                "structural",
                (),
                None,
                None,
                IntegrityStatus.STRUCTURAL,
                "{}: {}".format(self.record_identifier(), exc),
            )
        return self._integrity_context.enforce(result)

    def integrity(self):
        """
        Build and cache the layered record report.

        The report combines record framing, per-record checksum coverage and
        template-reference resolution with the inherited chunk data checksum,
        so a tampered record can never render through the view layer without
        a non-ignorable marker.

        @rtype IntegrityReport
        """
        if self._integrity_report is not None:
            return self._integrity_report

        report = IntegrityReport("chunk_{}_record_{}".format(self.chunk_index(), self.record_num()))
        structure, truncated = self.check_structure()
        report.add(structure)
        if structure.status == IntegrityStatus.STRUCTURAL:
            # keep parsing in recovery mode, but do not build on a broken frame
            self._integrity_report = report
            return report
        report.add(self.check_checksum(truncated=truncated))
        report.add(self.check_template_reference())

        # inherit every ancestor check so a record rendered from a file or
        # chunk with a bad checksum or template table cannot be mistaken for
        # clean evidence.
        file_header = FileHeader(self._buf, 0x0, integrity=self._integrity_context)
        inherited_checks = [file_header.check_integrity()]
        inherited_checks.extend(self._chunk.integrity().checks)
        for inherited in inherited_checks:
            if inherited.status != IntegrityStatus.OK:
                report.add(inherited)

        self._integrity_report = report
        return report

    def integrity_status(self):
        """@rtype IntegrityStatus"""
        return self.integrity().status()

    def is_integrity_ok(self):
        """@return bool: True only when every applicable layer verifies."""
        return self.integrity().ok()

    def verify(self):
        return self.integrity().ok()

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
