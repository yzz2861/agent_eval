"""
Build and resolve an original-vs-derived OLE stream mapping sidecar.

Sidecar principles
------------------
* Both the original exhibit and the derived handover package are read
  exclusively through olefile's reading interface (``OleFileIO``,
  ``openstream`` and the parsed FAT/MiniFAT/directory metadata).
* The sidecar carries verification material only: stream paths, names,
  sizes, SHA-256 hashes, byte ranges inside the original file, and
  optional *source proofs* (e.g. an export-log entry recorded at handover
  time).  It never carries stream bytes.
* Resolution is recomputed from whatever evidence remains in the sidecar.
  Identical bytes may belong to two different exhibits and names may have
  changed during export, so a content hash alone can yield several
  candidates.  A source proof is what narrows parallel candidates down to
  a unique correspondence; removing a proof automatically degrades the
  verdict from ``unique`` back to ``ambiguous``.

Verdicts
--------
* ``unique``    - exactly one original directory entry remains eligible.
* ``ambiguous`` - several original entries share the same bytes and no
                  surviving proof singles one out; all parallel candidates
                  are reported with their byte ranges.
* ``unmatched`` - no original entry holds these bytes (content changed or
                  the stream did not come from this original).
"""

import hashlib
import json

import olefile

SIDECAR_FORMAT = "ole-stream-provenance/1"

STATUS_UNIQUE = "unique"
STATUS_AMBIGUOUS = "ambiguous"
STATUS_UNMATCHED = "unmatched"


# --------------------------------------------------------------------------
# reading helpers (everything goes through olefile)
# --------------------------------------------------------------------------

def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _merge_ranges(segments, size):
    """Truncate (offset, length) segments to *size* bytes and merge
    contiguous ones.  Returns a list of [offset, length] pairs."""
    ranges = []
    remaining = size
    for offset, length in segments:
        if remaining <= 0:
            break
        take = min(length, remaining)
        if ranges and ranges[-1][0] + ranges[-1][1] == offset:
            ranges[-1][1] += take
        else:
            ranges.append([offset, take])
        remaining -= take
    return ranges


def stream_byte_ranges(ole, entry):
    """
    Byte ranges occupied by *entry*'s stream inside the OLE file, computed
    from the FAT/MiniFAT chains parsed by olefile.

    :returns: (ranges, chain_kind) where ranges is a list of
        [file_offset, length] pairs and chain_kind is "fat", "minifat" or
        "empty".
    """
    if entry.size == 0:
        return [], "empty"
    entry.build_sect_chain(ole)
    if entry.is_minifat:
        root = ole.root
        root.build_sect_chain(ole)
        segments = []
        for mini_sid in entry.sect_chain:
            mini_offset = mini_sid * ole.minisectorsize
            sector_index, within = divmod(mini_offset, ole.sectorsize)
            file_offset = (root.sect_chain[sector_index] + 1) * ole.sectorsize + within
            segments.append((file_offset, ole.minisectorsize))
        return _merge_ranges(segments, entry.size), "minifat"
    segments = [
        ((sid + 1) * ole.sectorsize, ole.sectorsize) for sid in entry.sect_chain
    ]
    return _merge_ranges(segments, entry.size), "fat"


def collect_streams(ole):
    """
    Snapshot every stream of an open OleFileIO: path, name, size, SHA-256
    of the content read through olefile, and byte ranges inside the file.
    """
    streams = []
    for path_components in ole.listdir(streams=True, storages=False):
        path = "/".join(path_components)
        data = ole.openstream(path_components).read()
        entry = ole.direntries[ole._find(path_components)]
        ranges, chain_kind = stream_byte_ranges(ole, entry)
        streams.append({
            "path": path,
            "name": entry.name,
            "sid": entry.sid,
            "size": entry.size,
            "sha256": _sha256(data),
            "chain": chain_kind,
            "byte_ranges": ranges,
        })
    return streams


# --------------------------------------------------------------------------
# sidecar build
# --------------------------------------------------------------------------

def build_sidecar(original_path, derived_path, proofs=None, note=None):
    """
    Build the mapping sidecar between an original exhibit OLE file and a
    derived handover OLE file.

    :param original_path: path of the original exhibit file.
    :param derived_path: path of the derived handover package.
    :param proofs: iterable of source-proof dicts, each with at least
        ``id``, ``derived_path`` and ``original_path`` (typically emitted
        by the export tool at handover time).
    :param note: free-text note stored in the sidecar header.
    :returns: the sidecar dict.
    """
    with olefile.OleFileIO(original_path) as ole:
        original_streams = collect_streams(ole)
    with olefile.OleFileIO(derived_path) as ole:
        derived_streams = collect_streams(ole)

    return {
        "format": SIDECAR_FORMAT,
        "note": note or "",
        "original": {
            "file_name": str(original_path),
            "file_sha256": _file_sha256(original_path),
            "entries": original_streams,
        },
        "derived": {
            "file_name": str(derived_path),
            "file_sha256": _file_sha256(derived_path),
            "streams": derived_streams,
        },
        "source_proofs": [dict(proof) for proof in (proofs or [])],
    }


# --------------------------------------------------------------------------
# resolution
# --------------------------------------------------------------------------

def _entry_view(entry, derived_name=None):
    view = {
        "sid": entry["sid"],
        "path": entry["path"],
        "name": entry["name"],
        "size": entry["size"],
        "sha256": entry["sha256"],
        "byte_ranges": entry["byte_ranges"],
    }
    if derived_name is not None:
        # Names may have been rewritten during export, so equality is only
        # a corroborating hint, never decisive evidence.
        view["name_hint"] = entry["name"] == derived_name
    return view


def resolve_stream(stream, original_entries, proofs):
    """Resolve one derived stream against the original entries."""
    evidence = []
    warnings = []

    candidates = [
        entry for entry in original_entries
        if entry["sha256"] == stream["sha256"] and entry["size"] == stream["size"]
    ]
    if candidates:
        evidence.append("content sha256+size match (%d candidate(s))" % len(candidates))

    applicable = [p for p in proofs if p.get("derived_path") == stream["path"]]
    proven, contradicted = [], []
    for proof in applicable:
        hit = [c for c in candidates if c["path"] == proof.get("original_path")]
        if hit:
            proven.append((proof, hit[0]))
            evidence.append(
                "source proof %s -> %s" % (proof.get("id"), proof.get("original_path"))
            )
        else:
            contradicted.append(proof)
            warnings.append(
                "source proof %s points to %s, whose bytes do not match"
                % (proof.get("id"), proof.get("original_path"))
            )

    result = {
        "derived_path": stream["path"],
        "derived_name": stream["name"],
        "status": None,
        "match": None,
        "candidates": [],
        "evidence": evidence,
        "warnings": warnings,
    }

    if not candidates:
        result["status"] = STATUS_UNMATCHED
        result["reason"] = (
            "no directory entry in the original holds these bytes; the "
            "stream was modified after export or did not come from this original"
        )
        return result

    if len(proven) == 1:
        result["status"] = STATUS_UNIQUE
        result["match"] = _entry_view(proven[0][1], stream["name"])
        result["reason"] = "singled out by source proof %s" % proven[0][0].get("id")
        return result

    if len(proven) > 1:
        result["status"] = STATUS_AMBIGUOUS
        result["candidates"] = [_entry_view(entry, stream["name"]) for _, entry in proven]
        result["reason"] = "conflicting source proofs; parallel candidates retained"
        return result

    if len(candidates) == 1:
        result["status"] = STATUS_UNIQUE
        result["match"] = _entry_view(candidates[0], stream["name"])
        result["reason"] = "only one original directory entry holds these bytes"
        return result

    result["status"] = STATUS_AMBIGUOUS
    result["candidates"] = [_entry_view(entry, stream["name"]) for entry in candidates]
    result["reason"] = (
        "identical bytes occur under %d original directory entries and no "
        "source proof singles one out; only parallel candidates can be given"
        % len(candidates)
    )
    return result


def resolve_mapping(sidecar, verify_files=True):
    """
    Resolve every derived stream of the sidecar against the original.

    :param sidecar: sidecar dict produced by :func:`build_sidecar`.
    :param verify_files: when True, re-open both files through olefile and
        re-check every hash recorded in the sidecar, so a tampered file or
        a stale sidecar is flagged instead of silently trusted.
    :returns: report dict with one resolution per derived stream.
    """
    if sidecar.get("format") != SIDECAR_FORMAT:
        raise ValueError("unsupported sidecar format: %r" % sidecar.get("format"))

    warnings = []
    if verify_files:
        warnings.extend(_verify_side(sidecar["original"], "original"))
        warnings.extend(_verify_side(sidecar["derived"], "derived"))

    proofs = sidecar.get("source_proofs", [])
    resolutions = [
        resolve_stream(stream, sidecar["original"]["entries"], proofs)
        for stream in sidecar["derived"]["streams"]
    ]
    return {
        "format": SIDECAR_FORMAT,
        "original_file": sidecar["original"]["file_name"],
        "derived_file": sidecar["derived"]["file_name"],
        "proofs_used": len(proofs),
        "warnings": warnings,
        "resolutions": resolutions,
    }


def _verify_side(side, label):
    """Re-read one file through olefile and compare with the sidecar."""
    warnings = []
    file_name = side["file_name"]
    try:
        actual_file_hash = _file_sha256(file_name)
    except OSError as exc:
        return ["%s: cannot re-open %s (%s)" % (label, file_name, exc)]
    if actual_file_hash != side["file_sha256"]:
        warnings.append(
            "%s: file %s no longer matches the sidecar file hash"
            % (label, file_name)
        )
        return warnings
    key = "entries" if "entries" in side else "streams"
    with olefile.OleFileIO(file_name) as ole:
        actual = {s["path"]: s for s in collect_streams(ole)}
    for recorded in side[key]:
        current = actual.get(recorded["path"])
        if current is None:
            warnings.append("%s: stream %s missing on disk" % (label, recorded["path"]))
        elif current["sha256"] != recorded["sha256"]:
            warnings.append(
                "%s: stream %s content changed since the sidecar was built"
                % (label, recorded["path"])
            )
    return warnings


# --------------------------------------------------------------------------
# proof maintenance
# --------------------------------------------------------------------------

def drop_source_proof(sidecar, proof_id):
    """
    Remove one source proof from the sidecar.  Resolution is recomputed
    from the remaining evidence, so a unique correspondence backed only by
    that proof automatically degrades to ambiguity.

    :returns: the removed proof dict.
    :raises KeyError: if no proof carries this id.
    """
    proofs = sidecar.get("source_proofs", [])
    for index, proof in enumerate(proofs):
        if proof.get("id") == proof_id:
            return proofs.pop(index)
    raise KeyError("no source proof with id %r" % (proof_id,))


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------

def load_sidecar(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_sidecar(sidecar, path):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(sidecar, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
