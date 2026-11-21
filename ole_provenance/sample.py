"""
Build the demonstration exhibits.

The sample models a handover:

* ``original.ole`` is the source exhibit.  Its ``Evidence`` storage holds
  two streams with byte-identical content (``StreamA`` and ``StreamB_copy``
  - the same bytes may belong to two different exhibits) plus one unique
  stream (``Table``).
* ``derived.ole`` is the handover package.  The export rewrote directory
  positions, renamed one stream (``streamB_copy`` became
  ``renamed_export``) and left ``StreamA`` behind.
* ``export_log.json`` carries the source proofs recorded at export time;
  they are the verification material later merged into the sidecar.
"""

import json

from .cfbf_writer import Storage, Stream, write_ole

SHARED_BYTES = (b"SHARED-EXHIBIT-BYTES " * 200)[:4096 + 37]
TABLE_BYTES = (b"unique table payload \x01\x02\x03" * 260)[:5000]

ORIGINAL_NAME = "original.ole"
DERIVED_NAME = "derived.ole"
EXPORT_LOG_NAME = "export_log.json"


def build_sample(outdir):
    """Write the sample files into *outdir*; returns the export-log dict."""
    import os

    os.makedirs(str(outdir), exist_ok=True)
    original = os.path.join(str(outdir), ORIGINAL_NAME)
    derived = os.path.join(str(outdir), DERIVED_NAME)
    export_log_path = os.path.join(str(outdir), EXPORT_LOG_NAME)

    write_ole(original, [
        Storage("Evidence", [
            Stream("StreamA", SHARED_BYTES),
            Stream("streamB_copy", SHARED_BYTES),
            Stream("Table", TABLE_BYTES),
        ]),
    ])

    # derived package: directory rewritten, one stream renamed, one dropped
    write_ole(derived, [
        Storage("Handover", [
            Stream("Table", TABLE_BYTES),
            Stream("renamed_export", SHARED_BYTES),
        ]),
    ])

    export_log = {
        "tool": "sample-export 1.0",
        "proofs": [
            {
                "id": "proof-1",
                "derived_path": "Handover/renamed_export",
                "original_path": "Evidence/streamB_copy",
                "export_name": "renamed_export",
                "note": "renamed from Evidence/streamB_copy during export",
            },
            {
                "id": "proof-2",
                "derived_path": "Handover/Table",
                "original_path": "Evidence/Table",
                "export_name": "Table",
                "note": "copied unchanged",
            },
        ],
    }
    with open(export_log_path, "w", encoding="utf-8") as handle:
        json.dump(export_log, handle, indent=2)
        handle.write("\n")
    return export_log
