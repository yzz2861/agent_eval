"""
ole_provenance - original-vs-derived OLE stream mapping with a sidecar.

When a few OLE streams are extracted from a larger exhibit document into a
derived handover package, the derived file rewrites directory positions and
may rename streams.  This package builds a JSON *sidecar* carrying only
verification material (names, sizes, SHA-256 hashes, byte ranges, and
optional source proofs) and resolves, for every stream in the derived
package, which directory entry and which byte ranges of the original file it
corresponds to - or why only parallel candidates can be offered.

Both files are always read through olefile's reading interface; the sidecar
never carries stream bytes.
"""

from .sidecar import (
    SIDECAR_FORMAT,
    build_sidecar,
    resolve_mapping,
    drop_source_proof,
    load_sidecar,
    save_sidecar,
)

__all__ = [
    "SIDECAR_FORMAT",
    "build_sidecar",
    "resolve_mapping",
    "drop_source_proof",
    "load_sidecar",
    "save_sidecar",
]

__version__ = "0.1.0"
