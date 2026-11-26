#!/usr/bin/env python
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
Offline relocation check between two EVTX exports of the same channel.

Compares a source archive (the one referenced by a handover sheet) against
a target archive (for example, a second collector's export with an
independently written archive header) and classifies every source record
address as precisely recoverable, candidate, or unresolvable.

Exit status is 0 when every source address is precisely recoverable,
and 1 otherwise.
"""
import sys
import json
import argparse

from Evtx.Relocation import relocate, Classification


def format_entry(entry):
    source = entry.source
    head = "record={} channel={} src={:#x}(chunk {}+{:#x})".format(
        source.record_num,
        source.channel,
        source.file_offset,
        source.chunk_index,
        source.position_in_chunk,
    )
    if entry.classification == Classification.PRECISE:
        return "{} PRECISE -> {:#x}".format(head, entry.candidates[0].file_offset)
    if entry.classification == Classification.UNRESOLVED:
        return "{} UNRESOLVED ({})".format(head, entry.reason)
    lines = ["{} CANDIDATE ({})".format(head, entry.reason)]
    for candidate in entry.candidates:
        lines.append(
            "    candidate: {:#x}(chunk {}+{:#x})".format(
                candidate.file_offset, candidate.chunk_index, candidate.position_in_chunk
            )
        )
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline relocation check between two EVTX exports of the same channel."
    )
    parser.add_argument("source_evtx", type=str, help="Path to the source EVTX archive (handover sheet reference)")
    parser.add_argument("target_evtx", type=str, help="Path to the target EVTX archive to relocate into")
    parser.add_argument("--json", action="store_true", help="Emit the comparison report as JSON")
    args = parser.parse_args(argv)

    report = relocate(args.source_evtx, args.target_evtx)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print("archive version markers match: {}".format(report.markers_match))
        if not report.markers_match:
            print("  source: {}".format(report.source_markers))
            print("  target: {}".format(report.target_markers))
        for entry in report.entries:
            print(format_entry(entry))
        counts = report.counts()
        print(
            "summary: {} precise, {} candidate, {} unresolved".format(
                counts[Classification.PRECISE],
                counts[Classification.CANDIDATE],
                counts[Classification.UNRESOLVED],
            )
        )

    return 0 if report.is_precise() else 1


if __name__ == "__main__":
    sys.exit(main())
