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
import datetime
from functools import wraps

import Evtx.Views as e_views

from .Nodes import RootNode, TemplateNode, NameStringNode
from .BinaryParser import Block, ParseException, OverrunBufferException

logger = logging.getLogger(__name__)


class InvalidRecordException(ParseException):
    def __init__(self):
        super(InvalidRecordException, self).__init__("Invalid record structure")


# ---------------------------------------------------------------------------
# Forensic layout validation
#
# A chunk is 0x10000 bytes.  Its 0x200 byte header is followed by the record
# area, which runs from offset 0x200 up to the chunk-relative
# `next_record_offset`.  Records are laid out contiguously inside that area.
# Everything at, or after, `next_record_offset` is non-record space: it holds
# common-string/template nodes referenced by the chunk header plus genuinely
# unallocated chunk slack, neither of which may be iterated as events.
#
# The record offset *table* is the ordered collection of record start offsets
# reconstructed from this physical layout.  Untrusted files may tamper with
# record sizes (and therefore the reconstructed table) so that entries point
# at overlapping regions, go backwards, escape into slack or leave the chunk
# entirely.  The issue codes below classify every such condition instead of
# blindly trusting the offsets.
# ---------------------------------------------------------------------------

CHUNK_SIZE = 0x10000
CHUNK_HEADER_SIZE = 0x200
RECORD_MAGIC = 0x2A2A
RECORD_HEADER_SIZE = 0x18

# Analysis modes.
# STRICT_FORENSIC only yields records whose chunk offset table satisfies the
# strict physical layout; any structural anomaly makes the chunk untrusted.
# RECOVERY yields every individually parseable record, but the chunk and each
# record carry explicit trust/mode markers describing the anomalies.
STRICT_FORENSIC = "strict_forensic"
RECOVERY = "recovery"
ANALYSIS_MODES = (STRICT_FORENSIC, RECOVERY)

# Fatal layout issues: the chunk offset table cannot be trusted at all.
ISSUE_CORRUPT_CHUNK = "corrupt_chunk"
ISSUE_TRUNCATED_CHUNK = "truncated_chunk"
ISSUE_OFFSET_OUTSIDE_RECORD_AREA = "offset_outside_record_area"
ISSUE_OFFSET_OUTSIDE_CHUNK = "offset_outside_chunk"
ISSUE_DUPLICATE_OFFSET = "duplicate_offset"
ISSUE_OVERLAPPING_RECORDS = "overlapping_records"
ISSUE_RECORD_OVERRUN = "record_overrun"
ISSUE_ZERO_LENGTH_RECORD = "zero_length_record"
ISSUE_BAD_RECORD_MAGIC = "bad_record_magic"
ISSUE_BAD_RECORD_SIZE = "bad_record_size"

# Slack is reported separately via ChunkValidationReport.slack_record_offsets,
# because self-consistent retired records in slack are normal after EVTX log
# rotation.  Keep this code as a non-fatal, documented classification so callers
# can still distinguish explicitly planted slack pseudo-records when desired.
ISSUE_RECORD_IN_SLACK = "record_in_slack"

# Non-fatal semantic issues: physical layout is intact, but the metadata
# inside the records is suspicious.  These are recorded, never trusted.
ISSUE_UNSORTED_OFFSETS = "unsorted_offsets"
ISSUE_RECORD_NUMBER_NOT_INCREASING = "record_number_not_increasing"
ISSUE_TIMESTAMP_NOT_INCREASING = "timestamp_not_increasing"

FATAL_ISSUES = frozenset(
    [
        ISSUE_CORRUPT_CHUNK,
        ISSUE_TRUNCATED_CHUNK,
        ISSUE_OFFSET_OUTSIDE_RECORD_AREA,
        ISSUE_OFFSET_OUTSIDE_CHUNK,
        ISSUE_DUPLICATE_OFFSET,
        ISSUE_OVERLAPPING_RECORDS,
        ISSUE_RECORD_OVERRUN,
        ISSUE_ZERO_LENGTH_RECORD,
        ISSUE_BAD_RECORD_MAGIC,
        ISSUE_BAD_RECORD_SIZE,
    ]
)


class LayoutIssue(Exception):
    """
    A single, classified anomaly found while validating the physical layout
      of an EVTX chunk or one of its records.

    Instances never carry raw record/chunk bytes, only integer offsets and
      short machine-readable issue codes, so logging them cannot leak whole
      binary blobs into error output.
    """

    def __init__(self, code, offset=None, detail=None, chunk_index=None):
        self.code = code
        self.offset = offset
        self.detail = detail
        self.chunk_index = chunk_index
        # Additional offsets sharing the same classification; populated by
        # ChunkValidationReport when the same issue code recurs.
        self.extra_offsets = []
        message = code
        if chunk_index is not None:
            message = "chunk {}: {}".format(chunk_index, message)
        if offset is not None:
            message += " at chunk offset {:#x}".format(offset)
        if detail is not None:
            message += ": {}".format(detail)
        super(LayoutIssue, self).__init__(message)

    def __repr__(self):
        return "LayoutIssue(code={!r}, offset={!r}, detail={!r}, chunk_index={!r})".format(
            self.code, self.offset, self.detail, self.chunk_index
        )


class ChunkValidationReport(object):
    """
    The result of validating one chunk's record offset table.

    Attributes:
      chunk_index (int): zero based index of the chunk within the file.
      mode (str): the analysis mode used while collecting records.
      issues (list[LayoutIssue]): classified anomalies, in detection order.
      records (list[Record]): records accepted under the selected mode.
      trusted (bool): True only when no fatal layout issue was detected.
    """

    def __init__(self, chunk_index, mode):
        self.chunk_index = chunk_index
        self.mode = mode
        self.issues = []
        self.records = []
        self.trusted = True
        # Chunk-relative offsets of self-consistent record-like structures
        # found in unallocated chunk slack.  They are never yielded as records;
        # the list exists so forensic reviewers can audit slack content.
        self.slack_record_offsets = []

    def add_issue(self, issue):
        for existing in self.issues:
            if existing.code == issue.code:
                if issue.offset is not None and issue.offset != existing.offset:
                    existing.extra_offsets.append(issue.offset)
                return
        self.issues.append(issue)
        issue.extra_offsets = []
        if issue.code in FATAL_ISSUES:
            self.trusted = False

    def issue_codes(self):
        return [issue.code for issue in self.issues]

    def has_issue(self, code):
        return code in self.issue_codes()

    def __repr__(self):
        return "ChunkValidationReport(chunk_index={!r}, mode={!r}, trusted={!r}, issues={!r})".format(
            self.chunk_index, self.mode, self.trusted, self.issue_codes()
        )


class Evtx(object):
    """
    A convenience class that makes it easy to open an
      EVTX file and start iterating the important structures.
    Note, this class must be used in a context statement
       (see the `with` keyword).
    Note, this class will mmap the target file, so ensure
      your platform supports this operation.
    """

    def __init__(self, filename, mode=RECOVERY):
        """
        @type filename:  str
        @param filename: A string that contains the path
          to the EVTX file to open.
        @type mode: str
        @param mode: STRICT_FORENSIC or RECOVERY.  Strict forensic mode
          suppresses records from any chunk whose offset table violates the
          physical layout; recovery mode yields parseable records but marks
          them untrusted.  The mode can also be supplied per iteration call.
        """
        if mode not in ANALYSIS_MODES:
            raise ValueError("mode must be one of {!r}".format(ANALYSIS_MODES))
        self._filename = filename
        self._mode = mode
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
                raise TypeError("An Evtx object must be used with a context (see the `with` statement).")
            else:
                return func(self, *args, **kwargs)

        return wrapped

    @property
    def mode(self):
        return self._mode

    @ensure_contexted
    def chunks(self, mode=None):
        """
        Get each of the ChunkHeaders from within this EVTX file.

        @rtype generator of ChunkHeader
        @return A generator of ChunkHeaders from this EVTX file.
        """
        selected_mode = mode or self._mode
        for chunk in self._fh.chunks():
            chunk._mode = selected_mode
            yield chunk

    @ensure_contexted
    def records(self, mode=None):
        """
        Get each of the Records from within this EVTX file.

        @rtype generator of Record
        @return A generator of Records from this EVTX file.
        """
        selected_mode = mode or self._mode
        for chunk in self.chunks(mode=selected_mode):
            for record in chunk.records(mode=selected_mode):
                yield record

    @ensure_contexted
    def validation_reports(self, mode=None):
        """
        Validate every chunk's record offset table and yield one
          ChunkValidationReport per chunk.

        @rtype generator of ChunkValidationReport
        """
        selected_mode = mode or self._mode
        for chunk_index, chunk in enumerate(self._fh.chunks()):
            yield chunk.validate(mode=selected_mode, chunk_index=chunk_index)

    @ensure_contexted
    def is_layout_valid(self, mode=None):
        """
        @rtype bool
        @return True when no chunk has a fatal physical layout issue.
          Semantic anomalies (record number or timestamp regressions) are
          still reported but do not make the layout invalid.
        """
        selected_mode = mode or self._mode
        return all(report.trusted for report in self.validation_reports(mode=selected_mode))

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
    def __init__(self, buf, offset):
        logger.debug("FILE HEADER at {}.".format(hex(offset)))
        super(FileHeader, self).__init__(buf, offset)
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
        while ofs < len(self._buf) and i < chunk_count and (ofs - self._offset) < len(self._buf):
            yield ChunkHeader(self._buf, ofs)
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
            for record in chunk.records():
                if record.record_num() == record_num:
                    return record
        return None

    def validation_reports(self, mode=RECOVERY):
        """
        Yield one ChunkValidationReport per chunk in file order.

        @rtype generator of ChunkValidationReport
        """
        for chunk_index, chunk in enumerate(self.chunks()):
            yield chunk.validate(mode=mode, chunk_index=chunk_index)


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
    def __init__(self, buf, offset):
        logger.debug("CHUNK HEADER at {}.".format(hex(offset)))
        super(ChunkHeader, self).__init__(buf, offset)
        self._strings = None
        self._templates = None
        self._mode = RECOVERY
        self._validation_cache = {}

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
        data_length = max(0, min(self.next_record_offset(), len(self._buf) - self._offset) - 0x200)
        data = self.unpack_binary(0x200, data_length)
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

    # ------------------------------------------------------------------
    # Forensic layout validation and mode-aware record iteration.
    # ------------------------------------------------------------------

    def _buffer_covers(self, relative_offset, length):
        """
        Safe bounds check that never raises on a truncated mmap.
        """
        start = self._offset + relative_offset
        return relative_offset >= 0 and length >= 0 and start >= 0 and start + length <= len(self._buf)

    def _read_dword_safe(self, relative_offset):
        if not self._buffer_covers(relative_offset, 4):
            raise OverrunBufferException(self._offset + relative_offset, len(self._buf))
        return self.unpack_dword(relative_offset)

    def is_truncated(self):
        """
        @rtype bool
        @return True when the underlying buffer does not contain the full
          0x10000 bytes claimed by this chunk header.
        """
        return self._offset + CHUNK_SIZE > len(self._buf)

    def record_area_end(self):
        """
        @rtype int
        @return The chunk-relative offset at which the record area ends and
          slack/common storage begins.  Clamped to the chunk boundary so a
          corrupt header cannot point outside the chunk.
        """
        return max(CHUNK_HEADER_SIZE, min(CHUNK_SIZE, self.next_record_offset()))

    def slack_offset(self):
        """
        @rtype int
        @return Absolute file offset of the first slack byte of this chunk.
        """
        return self._offset + self.record_area_end()

    def _build_candidate_records(self, report):
        """
        Walk the physical record area and reconstruct the record offset
          table, classifying every structural problem encountered.

        The walk starts at the fixed 0x200 record area start.  Each entry is
          validated before it is trusted, so overlapping, duplicated,
          out-of-order, zero-length, overrun and slack-bound entries are all
          detected rather than blindly seeked to.

        @rtype list[tuple[int, Record]]
        @return Pairs of (chunk-relative offset, Record) for every entry that
          could at least be instantiated, even if the surrounding table is
          fatal.  Structural failures stop the physical walk.
        """
        candidates = []
        seen_offsets = set()
        previous_end = CHUNK_HEADER_SIZE
        relative_offset = CHUNK_HEADER_SIZE
        area_end = self.record_area_end()

        while relative_offset < area_end:
            if relative_offset in seen_offsets:
                report.add_issue(LayoutIssue(ISSUE_DUPLICATE_OFFSET, offset=relative_offset))
                break
            seen_offsets.add(relative_offset)

            if not self._buffer_covers(relative_offset, RECORD_HEADER_SIZE):
                report.add_issue(
                    LayoutIssue(
                        ISSUE_TRUNCATED_CHUNK, offset=relative_offset, detail="record header extends past end of file"
                    )
                )
                break

            magic = self._read_dword_safe(relative_offset)
            if magic != RECORD_MAGIC:
                report.add_issue(
                    LayoutIssue(
                        ISSUE_BAD_RECORD_MAGIC, offset=relative_offset, detail="expected {:#x}".format(RECORD_MAGIC)
                    )
                )
                break

            size = self._read_dword_safe(relative_offset + 4)
            if size == 0:
                report.add_issue(
                    LayoutIssue(
                        ISSUE_DUPLICATE_OFFSET,
                        offset=relative_offset,
                        detail="zero stride re-enters the current offset",
                    )
                )
                report.add_issue(LayoutIssue(ISSUE_ZERO_LENGTH_RECORD, offset=relative_offset))
                break
            if size < RECORD_HEADER_SIZE or size > CHUNK_SIZE:
                report.add_issue(LayoutIssue(ISSUE_BAD_RECORD_SIZE, offset=relative_offset, detail=size))
                break

            record_end = relative_offset + size
            if record_end > CHUNK_SIZE:
                code = ISSUE_OFFSET_OUTSIDE_CHUNK
                report.add_issue(
                    LayoutIssue(
                        code,
                        offset=relative_offset,
                        detail="length {} ends at {:#x}, beyond chunk boundary {:#x}".format(
                            size, record_end, CHUNK_SIZE
                        ),
                    )
                )
            elif record_end > area_end:
                code = ISSUE_RECORD_OVERRUN
                report.add_issue(
                    LayoutIssue(code, offset=relative_offset, detail="length {} ends at {:#x}".format(size, record_end))
                )
                if not self._buffer_covers(
                    relative_offset, min(size, max(0, len(self._buf) - self._offset - relative_offset))
                ):
                    break

            if not self._buffer_covers(relative_offset, size):
                report.add_issue(
                    LayoutIssue(
                        ISSUE_TRUNCATED_CHUNK, offset=relative_offset, detail="record body extends past end of file"
                    )
                )
                break

            try:
                record = Record(self._buf, self._offset + relative_offset, self)
            except InvalidRecordException:
                report.add_issue(LayoutIssue(ISSUE_BAD_RECORD_SIZE, offset=relative_offset, detail=size))
                break

            if record.verify() is False:
                report.add_issue(
                    LayoutIssue(ISSUE_BAD_RECORD_SIZE, offset=relative_offset, detail="trailing size mismatch")
                )

            if relative_offset < previous_end:
                report.add_issue(
                    LayoutIssue(
                        ISSUE_OVERLAPPING_RECORDS,
                        offset=relative_offset,
                        detail="previous record ends at {:#x}".format(previous_end),
                    )
                )
            previous_end = max(previous_end, record_end)

            record._validation_offset = relative_offset
            candidates.append((relative_offset, record))
            relative_offset = record_end

        return candidates

    def _check_offset_table(self, candidates, report):
        """
        Validate the reconstructed offset table as a whole: entries must be
          strictly ascending, inside the record area, non-overlapping and
          bounded by the chunk.  Record number and timestamp ordering are
          semantic checks: violations are recorded but stay non-fatal.
        """
        offsets = [offset for offset, _ in candidates]
        area_end = self.record_area_end()

        for offset in offsets:
            if offset < CHUNK_HEADER_SIZE or offset >= area_end:
                report.add_issue(LayoutIssue(ISSUE_OFFSET_OUTSIDE_RECORD_AREA, offset=offset))
            if offset < 0 or offset >= CHUNK_SIZE:
                report.add_issue(LayoutIssue(ISSUE_OFFSET_OUTSIDE_CHUNK, offset=offset))

        for earlier, later in zip(offsets, offsets[1:]):
            if later < earlier:
                report.add_issue(
                    LayoutIssue(ISSUE_UNSORTED_OFFSETS, offset=later, detail="previous offset {:#x}".format(earlier))
                )
                break

        for (offset, record), (next_offset, _) in zip(candidates, candidates[1:]):
            if offset + record.size() > next_offset:
                report.add_issue(
                    LayoutIssue(
                        ISSUE_OVERLAPPING_RECORDS, offset=next_offset, detail="overlaps record at {:#x}".format(offset)
                    )
                )

        previous_number = None
        previous_timestamp = None
        for offset, record in candidates:
            try:
                number = record.record_num()
                if previous_number is not None and number <= previous_number:
                    report.add_issue(
                        LayoutIssue(
                            ISSUE_RECORD_NUMBER_NOT_INCREASING, offset=offset, detail="record number {}".format(number)
                        )
                    )
                previous_number = number
            except (ParseException, OverrunBufferException):
                report.add_issue(LayoutIssue(ISSUE_CORRUPT_CHUNK, offset=offset, detail="unreadable record number"))
            try:
                timestamp = record.timestamp()
                if (
                    previous_timestamp is not None
                    and isinstance(timestamp, datetime.datetime)
                    and isinstance(previous_timestamp, datetime.datetime)
                    and self._timestamp_orders_before(timestamp, previous_timestamp)
                ):
                    report.add_issue(
                        LayoutIssue(ISSUE_TIMESTAMP_NOT_INCREASING, offset=offset, detail="timestamp regresses")
                    )
                previous_timestamp = timestamp
            except (ParseException, OverrunBufferException, ValueError):
                report.add_issue(LayoutIssue(ISSUE_CORRUPT_CHUNK, offset=offset, detail="unreadable timestamp"))

    @staticmethod
    def _timestamp_orders_before(current, previous):
        """
        Compare two parsed filetimes even when one is the naive datetime.min
          emitted for a zero/invalid filetime and the other is timezone aware.
          Naive datetime.min is treated as the earliest possible instant.
        """
        if current.tzinfo is None and previous.tzinfo is not None:
            return current == datetime.datetime.min
        if current.tzinfo is not None and previous.tzinfo is None:
            return False
        return current < previous

    def _check_interior_record_magics(self, candidates, report):
        """
        A strictly sequential walk can never reach a record header planted
          inside the body of an earlier record, which makes this a practical
          hiding place for forged events.  Scan the whole record area for
          record magics and classify any magic that falls inside an accepted
          record interval (but is not that record's own start) as an
          overlapping, out-of-order offset-table entry.
        """
        if not candidates:
            return
        accepted_starts = {offset for offset, _ in candidates}
        intervals = [(offset, offset + record.size()) for offset, record in candidates]
        cursor = CHUNK_HEADER_SIZE
        scan_end = min(CHUNK_SIZE, len(self._buf) - self._offset)
        while cursor + RECORD_HEADER_SIZE <= scan_end:
            if (
                self._read_dword_safe(cursor) == RECORD_MAGIC
                and cursor not in accepted_starts
                and self._is_self_consistent_record(cursor, scan_end)
            ):
                for start, end in intervals:
                    if start < cursor < end:
                        report.add_issue(
                            LayoutIssue(
                                ISSUE_OVERLAPPING_RECORDS,
                                offset=cursor,
                                detail="record header hidden inside record at {:#x}".format(start),
                            )
                        )
                        report.add_issue(
                            LayoutIssue(
                                ISSUE_UNSORTED_OFFSETS,
                                offset=cursor,
                                detail="offset precedes containing record end {:#x}".format(end),
                            )
                        )
                        return
            cursor += 1

    def _check_slack(self, report):
        """
        The region at or after `next_record_offset` holds common string and
          template nodes referenced by the chunk header, plus genuinely
          unallocated chunk slack.  Real EVTX files routinely keep complete,
          self-consistent retired records in this slack after log rotation, so
          slack content is never treated as part of the record offset table and
          is never yielded in either analysis mode.  Record-like slack entries
          are collected on the report for forensic review instead of being
          trusted as events.
        """
        area_end = self.record_area_end()
        scan_end = min(CHUNK_SIZE, len(self._buf) - self._offset)
        allocated = self._allocated_node_ranges(scan_end)
        cursor = area_end
        while cursor + RECORD_HEADER_SIZE <= scan_end:
            if self._read_dword_safe(cursor) == RECORD_MAGIC:
                inside_allocated_node = any(start <= cursor < end for start, end in allocated)
                if not inside_allocated_node and self._is_self_consistent_record(cursor, scan_end):
                    report.slack_record_offsets.append(cursor)
            cursor += 1

    def _is_self_consistent_record(self, relative_offset, scan_end):
        """
        @rtype bool
        @return True when the bytes at the given chunk-relative offset form a
          record with a sane length and matching trailing size field.  Used to
          distinguish complete retired records (benign slack) from planted,
          half-formed pseudo-record headers in unallocated slack.
        """
        try:
            size = self._read_dword_safe(relative_offset + 4)
        except OverrunBufferException:
            return False
        if size < RECORD_HEADER_SIZE or size > CHUNK_SIZE:
            return False
        if relative_offset + size > scan_end:
            return False
        try:
            trailing_size = self._read_dword_safe(relative_offset + size - 4)
        except OverrunBufferException:
            return False
        return size == trailing_size

    def _allocated_node_ranges(self, scan_end):
        """
        Reconstruct the byte extents of every common-string and template
          node reachable from the chunk header pointer tables.  These extents
          are allocated metadata, not slack, even when they happen to contain
          record-like byte sequences.  All reads stay inside the available
          buffer and the chunk boundary.

        @rtype list[tuple[int, int]]
        @return Merged, non-overlapping (start, end) chunk-relative ranges.
        """
        ranges = []

        for slot in range(64):
            offset = self._read_dword_safe(0x80 + slot * 4)
            visited = set()
            while offset and offset not in visited and offset + 10 <= scan_end:
                visited.add(offset)
                string_length = self.unpack_word(offset + 6)
                end = offset + 10 + string_length * 2
                ranges.append((offset, min(end, scan_end)))
                offset = self._read_dword_safe(offset)

        for slot in range(32):
            offset = self._read_dword_safe(0x180 + slot * 4)
            if offset and offset + 0x18 <= scan_end:
                data_length = self._read_dword_safe(offset + 0x14)
                end = offset + 0x18 + data_length
                ranges.append((offset, min(end, scan_end)))

        if not ranges:
            return []

        ranges.sort()
        merged = []
        for start, end in ranges:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    def validate(self, mode=RECOVERY, chunk_index=None):
        """
        Validate this chunk's record offset table and produce a classified
          report.  Reports are cached per mode because record iteration and
          forensic checks share the same physical walk.

        @type mode: str
        @param mode: STRICT_FORENSIC or RECOVERY.
        @type chunk_index: int
        @param chunk_index: Optional index of the chunk in the file.
        @rtype ChunkValidationReport
        """
        if mode not in ANALYSIS_MODES:
            raise ValueError("mode must be one of {!r}".format(ANALYSIS_MODES))
        if mode in self._validation_cache:
            report = self._validation_cache[mode]
            if chunk_index is not None:
                report.chunk_index = chunk_index
            return report

        report = ChunkValidationReport(chunk_index, mode)

        if not self.check_magic():
            report.add_issue(LayoutIssue(ISSUE_CORRUPT_CHUNK, detail="bad chunk magic"))
            self._validation_cache[mode] = report
            return report

        if self.is_truncated():
            report.add_issue(
                LayoutIssue(
                    ISSUE_TRUNCATED_CHUNK, detail="buffer ends at {:#x} bytes".format(len(self._buf) - self._offset)
                )
            )

        try:
            area_end = self.record_area_end()
            if not (CHUNK_HEADER_SIZE <= area_end <= CHUNK_SIZE):
                report.add_issue(LayoutIssue(ISSUE_CORRUPT_CHUNK, detail="invalid next_record_offset"))
            candidates = self._build_candidate_records(report)
            self._check_offset_table(candidates, report)
            self._check_interior_record_magics(candidates, report)
            self._check_slack(report)
        except OverrunBufferException as exception:
            report.add_issue(LayoutIssue(ISSUE_TRUNCATED_CHUNK, detail=str(exception)))
            candidates = []

        if report.trusted or mode == RECOVERY:
            for offset, record in candidates:
                record._trusted = report.trusted
                record._analysis_mode = mode
                record._validation_issues = [issue for issue in report.issues if issue.offset == offset]
                report.records.append(record)

        self._validation_cache[mode] = report
        return report

    def validation_report(self, mode=None):
        """
        Convenience wrapper around `validate` using the chunk's active mode
          when no explicit mode is supplied.
        """
        return self.validate(mode or self._mode)

    def is_trusted(self, mode=None):
        """
        @rtype bool
        @return True when the chunk has no fatal layout issue.
        """
        return self.validate(mode or self._mode).trusted

    def issues(self, mode=None):
        """
        @rtype list[LayoutIssue]
        """
        return self.validate(mode or self._mode).issues

    def slack_record_offsets(self, mode=None):
        """
        @rtype list[int]
        @return Chunk-relative offsets of self-consistent record-like
          structures located in unallocated chunk slack.  These entries are
          never returned by `records` in either analysis mode; they are exposed
          only so forensic tooling can audit slack content.
        """
        report = self.validate(mode or self._mode)
        return list(report.slack_record_offsets)

    def first_record(self, mode=None):
        """
        @return The first accepted Record, or None when the chunk cannot be
          parsed under the selected mode.
        """
        report = self.validate(mode or self._mode)
        if not report.records:
            return None
        return report.records[0]

    def records(self, mode=None):
        """
        Yield the records accepted under the selected analysis mode.

        Strict forensic mode yields nothing for a chunk with any fatal layout
          issue.  Recovery mode yields every individually parseable record,
          marked untrusted, so callers can distinguish trusted evidence from
          best-effort recovery.  Slack bytes are never yielded as records in
          either mode.
        """
        report = self.validate(mode or self._mode)
        for record in report.records:
            yield record


class Record(Block):
    def __init__(self, buf, offset, chunk):
        logger.debug("Record at {}.".format(hex(offset)))
        super(Record, self).__init__(buf, offset)
        self._chunk = chunk
        self._trusted = True
        self._analysis_mode = RECOVERY
        self._validation_issues = []
        self._validation_offset = None

        self.declare_field("dword", "magic", 0x0)  # 0x00002a2a
        self.declare_field("dword", "size")
        self.declare_field("qword", "record_num")
        self.declare_field("filetime", "timestamp")

        if self.size() <= 0 or self.size() > 0x10000:
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

    @property
    def trusted(self):
        """
        @rtype bool
        @return True when the owning chunk's strict layout checks found no
          fatal issue affecting the table that produced this record.
        """
        return self._trusted

    @property
    def analysis_mode(self):
        """
        @rtype str
        @return STRICT_FORENSIC or RECOVERY, marking how the record was
          accepted for iteration.
        """
        return self._analysis_mode

    def validation_issues(self):
        """
        @rtype list[LayoutIssue]
        @return Classified anomalies recorded for the record's offset.  An
          empty list means no offset-specific anomaly was detected, though
          chunk-wide issues may still exist.
        """
        return list(self._validation_issues)

    def chunk_relative_offset(self):
        """
        @rtype int
        @return Offset of the record relative to the start of its chunk.
        """
        if self._validation_offset is not None:
            return self._validation_offset
        return self._offset - self._chunk.offset()

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
