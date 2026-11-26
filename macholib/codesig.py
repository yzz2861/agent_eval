"""
Read-only verification of embedded Mach-O code directory page hashes.

This module walks every slice of a (possibly universal) Mach-O file,
follows its ``LC_CODE_SIGNATURE`` load command to the embedded signature
SuperBlob and recomputes the *normal code slots* recorded in the primary
and alternate CodeDirectory blobs from the raw slice bytes.  Contiguous
paged directories using SHA-1 or SHA-256 are supported; the last page is
hashed with its actual (short) length.

Every directory is verified independently: a directory that uses a
scatter vector, an unknown hash algorithm, or that is truncated is
reported as such without affecting the conclusions of the other
directories.

The result of a verification is evidence about *page contents* only.
Even when every recorded digest matches the recomputed page hashes, this
says nothing about the identity or trustworthiness of the signer: the
signature itself is not validated here.
"""

from __future__ import absolute_import

import hashlib
import struct

from macholib.MachO import MachO
from macholib.mach_o import CPU_TYPE_NAMES, LC_CODE_SIGNATURE

__all__ = [
    "verify_code_signature",
    "VerificationResult",
    "SliceVerification",
    "CodeDirectoryVerification",
    "PageSlotVerification",
    "CSMAGIC_CODEDIRECTORY",
    "CSMAGIC_EMBEDDED_SIGNATURE",
    "CSSLOT_CODEDIRECTORY",
    "CSSLOT_ALTERNATE_CODEDIRECTORIES",
    "CS_HASHTYPE_SHA1",
    "CS_HASHTYPE_SHA256",
    "STATUS_OK",
    "STATUS_MISMATCH",
    "STATUS_UNSUPPORTED",
    "STATUS_TRUNCATED",
    "DISCLAIMER",
]

# CSMAGIC values from <kern/cs_blobs.h>
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0

# CodeDirectory "slot" indices in the SuperBlob index
CSSLOT_CODEDIRECTORY = 0x0000
CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
CSSLOT_ALTERNATE_CODEDIRECTORIES_MAX = 0x1005

# cdHashType values; only the contiguous paged SHA-1 and SHA-256
# directories are supported by this module.
CS_HASHTYPE_SHA1 = 1
CS_HASHTYPE_SHA256 = 2

_HASH_CONSTRUCTORS = {
    CS_HASHTYPE_SHA1: hashlib.sha1,
    CS_HASHTYPE_SHA256: hashlib.sha256,
}

_HASH_NAMES = {
    CS_HASHTYPE_SHA1: "sha1",
    CS_HASHTYPE_SHA256: "sha256",
}

STATUS_OK = "ok"
STATUS_MISMATCH = "mismatch"
STATUS_UNSUPPORTED = "unsupported"
STATUS_TRUNCATED = "truncated"

DISCLAIMER = (
    "Only page contents were recomputed and compared with the digests "
    "recorded in the embedded code directories; even a fully matching "
    "result is not evidence about the identity or trustworthiness of "
    "the signer."
)

# Fixed part of the CodeDirectory header, up to and including spare2.
_CD_FIXED_FORMAT = ">9I4BI"
_CD_FIXED_SIZE = struct.calcsize(_CD_FIXED_FORMAT)

# Compatibility versions of the CodeDirectory blob.
_CD_VERSION_SCATTER = 0x20100
_CD_VERSION_CODELIMIT64 = 0x20300


class PageSlotVerification(object):
    """
    Result of recomputing one normal code slot (one page).

    ``file_offset``/``length`` locate the page in the file,
    ``expected`` is the digest recorded in the code directory and
    ``actual`` the digest recomputed from the file contents
    (``None`` when the page data is missing from the file).
    """

    def __init__(self, index, file_offset, length, expected, actual):
        self.index = index
        self.file_offset = file_offset
        self.length = length
        self.expected = expected
        self.actual = actual

    @property
    def file_range(self):
        """
        Half-open file range ``(start, end)`` covered by this slot.
        """
        return (self.file_offset, self.file_offset + self.length)

    @property
    def matches(self):
        return self.actual is not None and self.actual == self.expected

    def describe(self):
        return {
            "slot": self.index,
            "file_range": self.file_range,
            "expected": _hex(self.expected),
            "actual": None if self.actual is None else _hex(self.actual),
            "matches": self.matches,
        }

    def __repr__(self):
        return "<PageSlotVerification slot=%d file_range=%r matches=%r>" % (
            self.index,
            self.file_range,
            self.matches,
        )


class CodeDirectoryVerification(object):
    """
    Verification outcome for one CodeDirectory blob.

    ``status`` is one of ``"ok"``, ``"mismatch"``,
    ``"unsupported"`` or ``"truncated"``; ``reason`` explains
    non-ok statuses.  ``slots`` holds one
    :class:`PageSlotVerification` per normal code slot and is empty
    for directories that could not be interpreted at all.
    """

    def __init__(self, slot_type, file_offset):
        self.slot_type = slot_type
        self.file_offset = file_offset
        self.status = STATUS_OK
        self.reason = None
        self.hash_type = None
        self.hash_name = None
        self.page_size = None
        self.code_limit = None
        self.slots = []

    @property
    def is_alternate(self):
        return self.slot_type != CSSLOT_CODEDIRECTORY

    @property
    def matches(self):
        return self.status == STATUS_OK and all(slot.matches for slot in self.slots)

    def describe(self):
        return {
            "slot_type": self.slot_type,
            "is_alternate": self.is_alternate,
            "file_offset": self.file_offset,
            "status": self.status,
            "reason": self.reason,
            "hash_type": self.hash_type,
            "hash_name": self.hash_name,
            "page_size": self.page_size,
            "code_limit": self.code_limit,
            "slots": [slot.describe() for slot in self.slots],
        }

    def __repr__(self):
        return "<CodeDirectoryVerification slot_type=0x%x status=%r>" % (
            self.slot_type,
            self.status,
        )


class SliceVerification(object):
    """
    Verification outcome for one Mach-O slice of the file.

    ``offset``/``size`` locate the slice in the file, ``arch``
    is the CPU type name and ``directories`` the per-directory
    results.  A slice-level problem (no signature, malformed
    SuperBlob, ...) is reported in ``error``.
    """

    def __init__(self, cputype, offset, size):
        self.cputype = cputype
        self.arch = CPU_TYPE_NAMES.get(cputype, str(cputype))
        self.offset = offset
        self.size = size
        self.signature_offset = None
        self.signature_size = None
        self.directories = []
        self.error = None

    @property
    def matches(self):
        return (
            self.error is None
            and bool(self.directories)
            and all(directory.matches for directory in self.directories)
        )

    def describe(self):
        return {
            "arch": self.arch,
            "cputype": self.cputype,
            "offset": self.offset,
            "size": self.size,
            "signature_offset": self.signature_offset,
            "signature_size": self.signature_size,
            "error": self.error,
            "directories": [directory.describe() for directory in self.directories],
        }

    def __repr__(self):
        return "<SliceVerification arch=%r offset=%d error=%r>" % (
            self.arch,
            self.offset,
            self.error,
        )


class VerificationResult(object):
    """
    Outcome of verifying all slices of one file.

    The ``note`` attribute is a reminder that matching page hashes
    are evidence about page contents only, never about signer trust.
    """

    note = DISCLAIMER

    def __init__(self, filename, slices):
        self.filename = filename
        self.slices = slices

    @property
    def matches(self):
        return bool(self.slices) and all(slice_.matches for slice_ in self.slices)

    def describe(self):
        return {
            "filename": self.filename,
            "matches": self.matches,
            "note": self.note,
            "slices": [slice_.describe() for slice_ in self.slices],
        }

    def __repr__(self):
        return "<VerificationResult filename=%r matches=%r>" % (
            self.filename,
            self.matches,
        )


def _hex(value):
    return "".join("%02x" % byte for byte in bytearray(value))


def verify_code_signature(filename):
    """
    Recompute the normal code slots of every embedded CodeDirectory in
    *filename* and compare them with the recorded digests.

    Returns a :class:`VerificationResult`.  The file is only read,
    never modified.
    """
    macho = MachO(filename)
    with open(filename, "rb") as fp:
        data = fp.read()

    slices = []
    for header in macho.headers:
        slices.append(_verify_slice(header, data))
    return VerificationResult(filename, slices)


def _verify_slice(header, data):
    result = SliceVerification(int(header.header.cputype), header.offset, header.size)

    command = None
    for cmd_load, cmd, _cmd_data in header.commands:
        if cmd_load.cmd == LC_CODE_SIGNATURE:
            command = cmd
            break

    if command is None:
        result.error = "slice has no LC_CODE_SIGNATURE load command"
        return result

    sig_offset = header.offset + int(command.dataoff)
    sig_size = int(command.datasize)
    result.signature_offset = sig_offset
    result.signature_size = sig_size

    slice_end = min(header.offset + header.size, len(data))
    if sig_offset < header.offset or sig_offset + sig_size > slice_end:
        result.error = "code signature data is truncated"
        return result

    sig = data[sig_offset : sig_offset + sig_size]
    if len(sig) < 12:
        result.error = "code signature data is truncated"
        return result

    magic, _length, count = struct.unpack_from(">3I", sig, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        result.error = "unsupported signature blob magic 0x%08x" % (magic,)
        return result
    if _length > len(sig):
        result.error = "signature SuperBlob is truncated"
        return result

    for index in range(count):
        if 12 + 8 * (index + 1) > len(sig):
            result.error = "signature SuperBlob index is truncated"
            break
        slot_type, blob_offset = struct.unpack_from(">2I", sig, 12 + 8 * index)
        if slot_type == CSSLOT_CODEDIRECTORY or (
            CSSLOT_ALTERNATE_CODEDIRECTORIES
            <= slot_type
            <= CSSLOT_ALTERNATE_CODEDIRECTORIES_MAX
        ):
            result.directories.append(
                _verify_directory(
                    data,
                    header.offset,
                    slice_end,
                    sig_offset,
                    sig,
                    slot_type,
                    blob_offset,
                )
            )

    return result


def _verify_directory(
    data, slice_offset, slice_end, sig_offset, sig, slot_type, blob_offset
):
    directory = CodeDirectoryVerification(slot_type, sig_offset + blob_offset)

    available = len(sig) - blob_offset
    if available < _CD_FIXED_SIZE:
        directory.status = STATUS_TRUNCATED
        directory.reason = "code directory header is truncated"
        return directory

    (
        magic,
        blob_length,
        version,
        _flags,
        hash_offset,
        _ident_offset,
        _n_special_slots,
        n_code_slots,
        code_limit,
        hash_size,
        hash_type,
        _platform,
        page_shift,
        _spare2,
    ) = struct.unpack_from(_CD_FIXED_FORMAT, sig, blob_offset)

    if magic != CSMAGIC_CODEDIRECTORY:
        directory.status = STATUS_UNSUPPORTED
        directory.reason = "not a code directory blob (magic 0x%08x)" % (magic,)
        return directory

    if blob_length > available:
        directory.status = STATUS_TRUNCATED
        directory.reason = "code directory blob is truncated"
        return directory

    directory.hash_type = hash_type
    directory.hash_name = _HASH_NAMES.get(hash_type)

    if version >= _CD_VERSION_SCATTER:
        if _CD_FIXED_SIZE + 4 > blob_length:
            directory.status = STATUS_TRUNCATED
            directory.reason = "code directory scatter field is truncated"
            return directory
        (scatter_offset,) = struct.unpack_from(">I", sig, blob_offset + _CD_FIXED_SIZE)
        if scatter_offset != 0:
            directory.status = STATUS_UNSUPPORTED
            directory.reason = "code directory uses a scatter vector"
            return directory

    if version >= _CD_VERSION_CODELIMIT64:
        if _CD_FIXED_SIZE + 20 > blob_length:
            directory.status = STATUS_TRUNCATED
            directory.reason = "code directory is truncated"
            return directory
        (code_limit64,) = struct.unpack_from(
            ">Q", sig, blob_offset + _CD_FIXED_SIZE + 12
        )
        if code_limit64:
            code_limit = code_limit64

    constructor = _HASH_CONSTRUCTORS.get(hash_type)
    if constructor is None:
        directory.status = STATUS_UNSUPPORTED
        directory.reason = "unknown hash type %d" % (hash_type,)
        return directory

    if hash_size != constructor().digest_size:
        directory.status = STATUS_UNSUPPORTED
        directory.reason = "hash size %d does not match the %s digest size" % (
            hash_size,
            directory.hash_name,
        )
        return directory

    if page_shift == 0:
        page_size = code_limit
    elif page_shift < 32:
        page_size = 1 << page_shift
    else:
        directory.status = STATUS_UNSUPPORTED
        directory.reason = "unsupported page size shift %d" % (page_shift,)
        return directory

    directory.page_size = page_size
    directory.code_limit = code_limit

    if hash_offset + n_code_slots * hash_size > blob_length:
        directory.status = STATUS_TRUNCATED
        directory.reason = "hash slots extend beyond the code directory"
        return directory

    for index in range(n_code_slots):
        page_start = index * page_size
        length = min(page_size, code_limit - page_start)
        if length < 0:
            length = 0
        file_offset = slice_offset + page_start
        expected = sig[
            blob_offset
            + hash_offset
            + index * hash_size : blob_offset
            + hash_offset
            + (index + 1) * hash_size
        ]
        if file_offset + length > slice_end:
            actual = None
        else:
            actual = constructor(data[file_offset : file_offset + length]).digest()
        directory.slots.append(
            PageSlotVerification(index, file_offset, length, expected, actual)
        )

    if any(slot.actual is None for slot in directory.slots):
        directory.status = STATUS_TRUNCATED
        directory.reason = "code pages extend beyond the slice data"
    elif not all(slot.matches for slot in directory.slots):
        directory.status = STATUS_MISMATCH
        directory.reason = "one or more code slots do not match"
    else:
        directory.status = STATUS_OK

    return directory
