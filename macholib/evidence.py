"""
Address-range evidence audit for offline Mach-O images.

When preserving an observed address range from an offline exhibit, only
bytes that actually exist on disk may be included in the attachment.
This module walks the segment/section load commands of a selected
architecture slice and classifies every address of a query range into
one of three categories:

* FILE_BACKED -- the address maps to bytes present in the file.  The
  chunk records the original file range (file_offset) as stored in the
  architecture slice's segment command, so the bytes can be carved
  straight from the exhibit.
* ZERO_FILL -- the loader materializes the bytes as zeroes at load
  time, either because the address lies past the segment's filesize
  (vmsize > filesize) or because it falls inside a zerofill section
  (S_ZEROFILL, S_GB_ZEROFILL or S_THREAD_LOCAL_ZEROFILL).  There are
  no corresponding disk bytes.
* UNMAPPED -- no segment of the selected slice covers the address, so
  the image holds no evidence for it.

A single query may cross all three categories; the result is a list of
EvidenceChunk items cut at every category, segment and section
boundary.  Observed (runtime) addresses are translated into the
image's vmaddr space with the slide of the mapping context, and chunk
addresses are reported back in the observed address space.
"""

from __future__ import print_function

import sys

from .mach_o import (
    CPU_TYPE_NAMES,
    LC_SEGMENT,
    LC_SEGMENT_64,
    S_GB_ZEROFILL,
    S_THREAD_LOCAL_ZEROFILL,
    S_ZEROFILL,
    SECTION_TYPE,
)
from .MachO import MachO

if sys.version_info[0] == 2:
    string_types = basestring  # noqa: F821
else:
    string_types = str

__all__ = [
    "FILE_BACKED",
    "ZERO_FILL",
    "UNMAPPED",
    "EvidenceChunk",
    "audit_address_range",
    "audit_file",
    "select_header",
]

#: The address maps to bytes present in the file.
FILE_BACKED = "file-backed"

#: The loader zero-fills the address; no bytes exist in the file.
ZERO_FILL = "zero-fill"

#: No segment of the selected slice covers the address.
UNMAPPED = "unmapped"

_ZEROFILL_SECTION_TYPES = {S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL}

#: Mask for the capability bits of cpusubtype.
_CPU_SUBTYPE_MASK = 0x00FFFFFF


class EvidenceChunk(object):
    """
    One classified run of addresses inside an audited range.

    address and size describe the run in the observed address space of
    the query.  image_address is the same start address in the image's
    vmaddr space (address minus the mapping slide).  file_offset is
    only set for FILE_BACKED chunks and is the offset of the run in the
    on-disk file exactly as recorded by the selected architecture
    slice's segment command (absolute for both thin and fat files).
    """

    def __init__(
        self,
        address,
        size,
        category,
        image_address=None,
        segname=None,
        sectname=None,
        file_offset=None,
    ):
        self.address = address
        self.size = size
        self.category = category
        self.image_address = image_address
        self.segname = segname
        self.sectname = sectname
        self.file_offset = file_offset

    @property
    def end(self):
        return self.address + self.size

    def __repr__(self):
        return (
            "<EvidenceChunk address=%#x size=%#x category=%r segment=%r "
            "section=%r file_offset=%r>"
            % (
                self.address,
                self.size,
                self.category,
                self.segname,
                self.sectname,
                self.file_offset,
            )
        )

    def __eq__(self, other):
        if not isinstance(other, EvidenceChunk):
            return NotImplemented
        return self.describe() == other.describe()

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def describe(self):
        """
        Return a JSON-serializable description of this chunk.
        """
        return {
            "address": self.address,
            "size": self.size,
            "category": self.category,
            "image_address": self.image_address,
            "segment": self.segname,
            "section": self.sectname,
            "file_offset": self.file_offset,
        }


def _clean_name(value):
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    return value.rstrip("\x00")


def _cputype_value(cputype):
    if isinstance(cputype, string_types):
        wanted = cputype.upper()
        for value, name in CPU_TYPE_NAMES.items():
            if name.upper() == wanted:
                return value
        raise ValueError("unknown CPU type name: %r" % (cputype,))
    return cputype


def select_header(macho, cputype=None, cpusubtype=None):
    """
    Select the architecture slice of *macho* (a macholib.MachO.MachO
    instance) to audit against.

    cputype may be an integer cpu type or a name from CPU_TYPE_NAMES
    (for example 'x86_64' or 'ARM64').  cpusubtype is compared without
    its capability bits.  When both are omitted the file must contain
    exactly one slice.
    """
    if cputype is None and cpusubtype is None:
        if len(macho.headers) != 1:
            raise ValueError(
                "%r contains %d architecture slices, specify cputype"
                % (macho.filename, len(macho.headers))
            )
        return macho.headers[0]

    wanted_type = _cputype_value(cputype) if cputype is not None else None
    matches = []
    for header in macho.headers:
        hdr = header.header
        if wanted_type is not None and hdr.cputype != wanted_type:
            continue
        if cpusubtype is not None:
            masked = hdr.cpusubtype & _CPU_SUBTYPE_MASK
            if masked != (cpusubtype & _CPU_SUBTYPE_MASK):
                continue
        matches.append(header)

    if not matches:
        raise ValueError(
            "no architecture slice in %r matches cputype=%r cpusubtype=%r"
            % (macho.filename, cputype, cpusubtype)
        )
    if len(matches) > 1:
        raise ValueError(
            "cputype=%r cpusubtype=%r matches %d slices in %r"
            % (cputype, cpusubtype, len(matches), macho.filename)
        )
    return matches[0]


def _segments(header):
    for cmd_load, cmd_cmd, cmd_data in header.commands:
        if cmd_load.cmd in (LC_SEGMENT, LC_SEGMENT_64):
            yield {
                "segname": _clean_name(cmd_cmd.segname),
                "vmaddr": int(cmd_cmd.vmaddr),
                "vmsize": int(cmd_cmd.vmsize),
                "fileoff": int(cmd_cmd.fileoff),
                "filesize": int(cmd_cmd.filesize),
                "sections": cmd_data,
            }


def _classify(image_address, size, segments, slide):
    for seg in segments:
        seg_end = seg["vmaddr"] + seg["vmsize"]
        if not (seg["vmaddr"] <= image_address < seg_end):
            continue

        section = None
        for sect in seg["sections"]:
            sect_size = int(sect.size)
            if sect_size == 0:
                continue
            if int(sect.addr) <= image_address < int(sect.addr) + sect_size:
                section = sect
                break

        if section is not None and (
            int(section.flags) & SECTION_TYPE
        ) in _ZEROFILL_SECTION_TYPES:
            category = ZERO_FILL
            file_offset = None
        elif image_address - seg["vmaddr"] < seg["filesize"]:
            category = FILE_BACKED
            file_offset = seg["fileoff"] + (image_address - seg["vmaddr"])
        else:
            # Past the segment's filesize the loader zero-fills up to
            # vmsize; there are no bytes on disk for this run.
            category = ZERO_FILL
            file_offset = None

        return EvidenceChunk(
            address=image_address + slide,
            size=size,
            category=category,
            image_address=image_address,
            segname=seg["segname"],
            sectname=(
                _clean_name(section.sectname) if section is not None else None
            ),
            file_offset=file_offset,
        )

    return EvidenceChunk(
        address=image_address + slide,
        size=size,
        category=UNMAPPED,
        image_address=image_address,
    )


def _mergeable(first, second):
    if first.category != second.category:
        return False
    if first.segname != second.segname or first.sectname != second.sectname:
        return False
    if first.file_offset is None or second.file_offset is None:
        return first.file_offset is second.file_offset
    return first.file_offset + first.size == second.file_offset


def audit_address_range(header, address, size, slide=0):
    """
    Audit the observed address range [address, address + size) against
    the segment/section map of *header* (a macholib.MachO.MachOHeader).

    slide is the slide of the mapping context: observed addresses equal
    image vmaddrs plus slide.  The result is a list of EvidenceChunk
    items, cut at every category, segment and section boundary,
    covering the whole query range in order.
    """
    if size <= 0:
        raise ValueError("size must be positive, got %r" % (size,))

    image_start = address - slide
    image_end = image_start + size

    segments = list(_segments(header))

    edges = {image_start, image_end}
    for seg in segments:
        boundaries = [
            seg["vmaddr"],
            seg["vmaddr"] + seg["vmsize"],
            seg["vmaddr"] + seg["filesize"],
        ]
        for sect in seg["sections"]:
            if int(sect.size) == 0:
                continue
            boundaries.append(int(sect.addr))
            boundaries.append(int(sect.addr) + int(sect.size))
        for point in boundaries:
            if image_start < point < image_end:
                edges.add(point)

    points = sorted(edges)
    chunks = []
    for low, high in zip(points, points[1:]):
        chunk = _classify(low, high - low, segments, slide)
        if chunks and _mergeable(chunks[-1], chunk):
            chunks[-1].size += chunk.size
        else:
            chunks.append(chunk)
    return chunks


def audit_file(filename, address, size, cputype=None, cpusubtype=None, slide=0):
    """
    Open *filename* as a Mach-O exhibit, select the architecture slice
    matching cputype/cpusubtype and audit the observed address range
    [address, address + size) with mapping slide *slide*.

    Returns a list of EvidenceChunk items.
    """
    macho = MachO(filename)
    header = select_header(macho, cputype=cputype, cpusubtype=cpusubtype)
    return audit_address_range(header, address, size, slide=slide)
