#!/usr/bin/env python3
#   This file is part of python-evtx.
#
#   Purpose: render each record of an EVTX file and place an offline annotation
#     next to it, resolved from a separately collected message dictionary.
#     The dictionary is aligned with the record's provider, event version, and
#     language, and every annotated item keeps its provenance (record vs.
#     dictionary).  An explicit fallback language may be given.
import json

import Evtx.Evtx as evtx

from Evtx.Annotation import annotate_record, MessageDictionary


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Dump a binary EVTX file as XML alongside offline annotations from a message dictionary."
    )
    parser.add_argument("evtx", type=str, action="store", help="Path to the Windows EVTX event log file")
    parser.add_argument(
        "-d",
        "--dictionary",
        type=str,
        action="store",
        required=True,
        help="Path to the offline message dictionary (JSON)",
    )
    parser.add_argument(
        "-l",
        "--language",
        type=str,
        action="store",
        default="en-US",
        help="Preferred message language tag, such as zh-CN (default: en-US)",
    )
    parser.add_argument(
        "-f",
        "--fallback-language",
        type=str,
        action="store",
        default=None,
        help="Explicit fallback language tag used when the preferred language is unavailable",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        action="store",
        help="Path of output JSON file (default: write JSON lines to stdout)",
    )
    args = parser.parse_args()

    dictionary = MessageDictionary.load(args.dictionary)

    entries = []
    with evtx.Evtx(args.evtx) as log:
        for record in log.records():
            entries.append(
                {
                    "xml": record.xml(),
                    "annotation": annotate_record(record, dictionary, args.language, args.fallback_language),
                }
            )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as outfile:
            json.dump(entries, outfile, ensure_ascii=False, indent=2)
    else:
        for entry in entries:
            print(json.dumps(entry, ensure_ascii=False))


if __name__ == "__main__":
    main()
