#!/usr/bin/python
#    This file is part of python-evtx.
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
"""
Layered integrity verification for EVTX files.

The EVTX format protects four distinct structures with checksums and
structural invariants:

  1. the file header (a single CRC32 over a fixed byte range),
  2. each chunk header (a CRC32 over two fixed byte ranges),
  3. the record data of each chunk (one CRC32 covering the concatenated,
     in-use event record bytes), and
  4. the event records themselves (magic, duplicated size and template
     references).

The algorithm and the byte ranges are properties of the EVTX format and are
therefore hard-coded here.  Nothing in the analyzed file is allowed to choose
an algorithm or to alter the scope of a checksum; see the ``*_SCOPE``
constants.

Two failure states are distinguished:

  - ``RECOVERABLE``: a verification check (typically a checksum) failed, but
    the surrounding structure is still parseable.  Recovery mode keeps
    parsing, yet every rendered view object carries a non-ignorable marker.
  - ``STRUCTURAL``: the structure is broken (bad magic, impossible sizes or
    pointers, truncated data).  The data cannot be trusted as evidence.
"""

from __future__ import absolute_import

import binascii
import enum

CRC32_NAME = "CRC32/ISO-HDLC"


class IntegrityStatus(str, enum.Enum):
    """
    The verification state of a single structure.

    ``OK`` means every applicable check passed.  ``RECOVERABLE`` means a
    checksum or other verification check failed but the bytes could still be
    parsed.  ``STRUCTURAL`` means the structure itself is broken and the
    resulting data must not be treated as intact evidence.
    """

    OK = "ok"
    RECOVERABLE = "recoverable"
    STRUCTURAL = "structural"


class CheckType(str, enum.Enum):
    """The four integrity layers of an EVTX file."""

    FILE_HEADER_CHECKSUM = "file_header_checksum"
    CHUNK_HEADER_CHECKSUM = "chunk_header_checksum"
    CHUNK_DATA_CHECKSUM = "chunk_data_checksum"
    RECORD_CHECKSUM = "record_checksum"
    RECORD_STRUCTURE = "record_structure"
    TEMPLATE_REFERENCE = "template_reference"


# Fixed byte ranges (inclusive start offset, exclusive end offset), relative
# to the start of the structure they protect.  These are defined by the EVTX
# on-disk format and must never be derived from file contents.
FILE_HEADER_CHECKSUM_SCOPE = ((0x0, 0x78),)
CHUNK_HEADER_CHECKSUM_SCOPE = ((0x0, 0x78), (0x80, 0x200))
# chunk record data starts after the 0x200 byte chunk header and ends at the
# next-record offset; the end is structural metadata, not an algorithm choice.
CHUNK_DATA_SCOPE_START = 0x200

CHUNK_SIZE = 0x10000
CHUNK_HEADER_SIZE = 0x200
FILE_HEADER_SIZE = 0x1000
RECORD_MAGIC = 0x2A2A


def crc32(data, seed=0):
    """
    Compute the unsigned 32-bit CRC32 used by every EVTX checksum.

    The optional ``seed`` enables incremental, per-record computation while
    producing exactly the same value as a single CRC over the concatenated
    bytes.
    """
    return binascii.crc32(data, seed) & 0xFFFFFFFF


def worst_status(statuses):
    """
    Return the most severe status from an iterable.

    Structural damage dominates recoverable failures, which dominate a clean
    result.
    """
    order = {
        IntegrityStatus.OK: 0,
        IntegrityStatus.RECOVERABLE: 1,
        IntegrityStatus.STRUCTURAL: 2,
    }
    worst = IntegrityStatus.OK
    for status in statuses:
        if order[status] > order[worst]:
            worst = status
    return worst


class CheckResult(object):
    """
    The outcome of one integrity check.

    Attributes:
      check (CheckType): the layer that was verified.
      algorithm (str): the fixed algorithm used (always CRC32 for checksum
        checks; structural checks use ``"structural"``).
      scope (tuple[tuple[int, int], ...]): the fixed, relative byte ranges
        covered by the check, as half-open ``(start, end)`` offsets.
      expected (int|None): the value the structure should contain.
      actual (int|None): the value observed in or computed from the file.
      status (IntegrityStatus): the resulting verification state.
      detail (str): a human readable explanation, including coordinates such
        as chunk and record numbers when available.
    """

    def __init__(self, check, algorithm, scope, expected, actual, status, detail=""):
        self.check = check
        self.algorithm = algorithm
        self.scope = tuple(scope)
        self.expected = expected
        self.actual = actual
        self.status = status
        self.detail = detail

    def __repr__(self):
        return (
            "CheckResult(check={!r}, status={!r}, expected={!r}, actual={!r}, "
            "algorithm={!r}, scope={!r}, detail={!r})"
        ).format(self.check, self.status, self.expected, self.actual, self.algorithm, self.scope, self.detail)

    def passed(self):
        return self.status == IntegrityStatus.OK

    def to_dict(self):
        """Serialize the result for JSON views and tooling."""
        return {
            "check": self.check.value,
            "status": self.status.value,
            "algorithm": self.algorithm,
            "scope": [list(rng) for rng in self.scope],
            "expected": None if self.expected is None else int(self.expected),
            "actual": None if self.actual is None else int(self.actual),
            "detail": self.detail,
        }


class IntegrityReport(object):
    """
    All check results collected for one EVTX structure (file, chunk, record).
    """

    def __init__(self, target, checks=None):
        self.target = target
        self.checks = list(checks) if checks else []

    def add(self, check):
        self.checks.append(check)
        return check

    def status(self):
        return worst_status(check.status for check in self.checks)

    def ok(self):
        return self.status() == IntegrityStatus.OK

    def failures(self):
        return [check for check in self.checks if not check.passed()]

    def to_dict(self):
        return {
            "target": self.target,
            "status": self.status().value,
            "checks": [check.to_dict() for check in self.checks],
        }

    def __repr__(self):
        return "IntegrityReport(target={!r}, status={!r}, failures={})".format(
            self.target, self.status(), len(self.failures())
        )


class IntegrityException(Exception):
    """Base class for integrity failures raised outside recovery mode."""


class RecoverableIntegrityException(IntegrityException):
    """Raised in strict mode when a verification check fails but parsing can continue."""

    def __init__(self, result):
        super(RecoverableIntegrityException, self).__init__(result.detail or result.check.value)
        self.result = result


class StructuralIntegrityException(IntegrityException):
    """Raised when a structure is broken beyond safe interpretation."""

    def __init__(self, result):
        super(StructuralIntegrityException, self).__init__(result.detail or result.check.value)
        self.result = result


def read_scoped_crc(block, ranges):
    """
    Compute the fixed CRC32 over the given half-open relative byte ranges.

    The ranges come exclusively from the format constants above, never from
    the analyzed file, so an attacker cannot influence checksum scope.
    """
    crc = 0
    for start, end in ranges:
        crc = crc32(block.unpack_binary(start, end - start), crc)
    return crc
