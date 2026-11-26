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
"""
Offline relocation checking for EVTX evidence addresses.

When two collectors each export the same Windows channel, and one of them
writes an independent archive header, the record positions recorded on a
handover sheet (evidence addresses) may not line up with the second export.
This module re-establishes the correspondence offline, without trusting the
rendered (display) text of records.

Each record address is described by structural signals only:

  - channel identity: the <Channel> of the record's System metadata,
  - original record identifier: the record number from the record header,
  - in-chunk position: the record's offset relative to its chunk header,
  - archive version markers: the file header version/layout fields.

Every source address is then classified against the target archive as:

  - PRECISE: exactly one target record shares the channel identity and
    record identifier, it sits at the same in-chunk position, and the
    archive version markers agree. The address is precisely recoverable.
  - CANDIDATE: one or more target records share the channel identity and
    record identifier, but the correspondence cannot be confirmed
    (duplicate record identifiers, shifted in-chunk position, or
    mismatched archive version markers). All candidate addresses are
    reported; none is picked automatically, and display text is never
    used to prefer one address over another.
  - UNRESOLVED: no target record shares the channel identity and record
    identifier, so the source address cannot be associated.
"""
from __future__ import absolute_import

import re
import enum
import logging
import dataclasses
from typing import Dict, List, Tuple, Optional

import Evtx.Evtx as evtx

logger = logging.getLogger(__name__)

CHANNEL_PATTERN = re.compile(r"<Channel>(.*?)</Channel>")


class Classification(enum.Enum):
    PRECISE = "precise"
    CANDIDATE = "candidate"
    UNRESOLVED = "unresolved"


@dataclasses.dataclass(frozen=True)
class ArchiveMarkers:
    """
    Version/layout markers of an EVTX archive, taken from its file header.
    Two exports of the same channel only share a common address space when
    these markers agree; an independently written archive header breaks
    that assumption.
    """

    major_version: int
    minor_version: int
    chunk_count: int
    next_record_number: int
    is_dirty: bool
    is_full: bool

    @classmethod
    def from_file_header(cls, file_header):
        return cls(
            major_version=file_header.major_version(),
            minor_version=file_header.minor_version(),
            chunk_count=file_header.chunk_count(),
            next_record_number=file_header.next_record_number(),
            is_dirty=file_header.is_dirty(),
            is_full=file_header.is_full(),
        )


@dataclasses.dataclass(frozen=True)
class RecordAddress:
    """
    The structural address of a single record within an EVTX archive.
    """

    record_num: int
    channel: Optional[str]
    file_offset: int
    chunk_index: int
    position_in_chunk: int

    def to_dict(self):
        return {
            "record_num": self.record_num,
            "channel": self.channel,
            "file_offset": self.file_offset,
            "chunk_index": self.chunk_index,
            "position_in_chunk": self.position_in_chunk,
        }


@dataclasses.dataclass
class RelocationEntry:
    """
    The classification of one source record address against a target archive.
    """

    source: RecordAddress
    classification: Classification
    candidates: List[RecordAddress]
    reason: str

    def to_dict(self):
        return {
            "source": self.source.to_dict(),
            "classification": self.classification.value,
            "candidates": [c.to_dict() for c in self.candidates],
            "reason": self.reason,
        }


@dataclasses.dataclass
class RelocationReport:
    """
    The result of relocating every record address of a source archive
    into a target archive.
    """

    source_markers: ArchiveMarkers
    target_markers: ArchiveMarkers
    markers_match: bool
    entries: List[RelocationEntry]

    def counts(self):
        result = {classification: 0 for classification in Classification}
        for entry in self.entries:
            result[entry.classification] += 1
        return result

    def is_precise(self):
        """
        @return True if every source address was precisely recovered.
        """
        return all(entry.classification == Classification.PRECISE for entry in self.entries)

    def to_dict(self):
        return {
            "source_markers": dataclasses.asdict(self.source_markers),
            "target_markers": dataclasses.asdict(self.target_markers),
            "markers_match": self.markers_match,
            "counts": {classification.value: count for classification, count in self.counts().items()},
            "entries": [entry.to_dict() for entry in self.entries],
        }


def extract_channel(record):
    """
    Extract the channel identity of a record from its System metadata.

    @rtype str or None
    @return The channel name, or None if it cannot be determined.
    """
    try:
        xml = record.xml()
    except Exception:
        logger.debug("failed to render record %d for channel extraction", record.record_num())
        return None
    match = CHANNEL_PATTERN.search(xml)
    if match is None:
        return None
    return match.group(1)


def collect_archive(path):
    """
    Collect the archive version markers and the structural address of every
    record in the EVTX file at the given path.

    @rtype (ArchiveMarkers, list of RecordAddress)
    """
    addresses = []
    with evtx.Evtx(path) as log:
        markers = ArchiveMarkers.from_file_header(log.get_file_header())
        for chunk_index, chunk in enumerate(log.chunks()):
            for record in chunk.records():
                addresses.append(
                    RecordAddress(
                        record_num=record.record_num(),
                        channel=extract_channel(record),
                        file_offset=record.offset(),
                        chunk_index=chunk_index,
                        position_in_chunk=record.offset() - chunk.offset(),
                    )
                )
    return markers, addresses


def classify(source, candidates, markers_match):
    """
    Classify one source record address against the target records that share
    its channel identity and original record identifier.

    @type source: RecordAddress
    @type candidates: list of RecordAddress
    @type markers_match: bool
    @rtype RelocationEntry
    """
    if not candidates:
        return RelocationEntry(
            source=source,
            classification=Classification.UNRESOLVED,
            candidates=[],
            reason="no record in the target archive shares the channel identity and record identifier",
        )
    if len(candidates) > 1:
        return RelocationEntry(
            source=source,
            classification=Classification.CANDIDATE,
            candidates=candidates,
            reason=(
                "duplicate record identifier: {} candidate addresses; "
                "manual selection required, display text must not be used to pick an address".format(len(candidates))
            ),
        )
    candidate = candidates[0]
    if not markers_match:
        return RelocationEntry(
            source=source,
            classification=Classification.CANDIDATE,
            candidates=candidates,
            reason="archive version markers differ; the target header was written independently",
        )
    if candidate.position_in_chunk != source.position_in_chunk:
        return RelocationEntry(
            source=source,
            classification=Classification.CANDIDATE,
            candidates=candidates,
            reason="in-chunk position shifted from {:#x} to {:#x}".format(
                source.position_in_chunk, candidate.position_in_chunk
            ),
        )
    return RelocationEntry(
        source=source,
        classification=Classification.PRECISE,
        candidates=candidates,
        reason="channel identity, record identifier, in-chunk position, and archive markers all agree",
    )


def relocate(source_path, target_path):
    """
    Relocate every record address of the source archive into the target
    archive, classifying each as PRECISE, CANDIDATE, or UNRESOLVED.

    @type source_path: str
    @type target_path: str
    @rtype RelocationReport
    """
    source_markers, source_addresses = collect_archive(source_path)
    target_markers, target_addresses = collect_archive(target_path)
    markers_match = source_markers == target_markers

    index = {}  # type: Dict[Tuple[Optional[str], int], List[RecordAddress]]
    for address in target_addresses:
        index.setdefault((address.channel, address.record_num), []).append(address)

    entries = []
    for source in source_addresses:
        candidates = index.get((source.channel, source.record_num), [])
        entries.append(classify(source, candidates, markers_match))

    return RelocationReport(
        source_markers=source_markers,
        target_markers=target_markers,
        markers_match=markers_match,
        entries=entries,
    )
