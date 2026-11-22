"""Read-only hive enumeration, citation chains and log recovery.

Every byte-level operation runs against in-memory copies.  Primary hives and
transaction logs on disk are only opened with read access; the recovered view
of a logged hive is materialised inside a ``BytesIO`` buffer.
"""

import hashlib
import io
import os

from Registry import Registry, RegistryLog, RegistryParse

from .models import Citation, Reachability


FIRST_HBIN_OFFSET = 0x1000


def _hex(value):
    return "0x%x" % value


def fingerprint_nk(nk_record):
    """Stable content fingerprint of a key record (excluding cell location)."""
    digest = hashlib.sha256()
    digest.update(b"nk\n")
    digest.update(nk_record.name().encode("utf-16le", errors="replace"))
    digest.update(b"\n")
    digest.update(str(nk_record.timestamp()).encode("utf-8"))
    digest.update(b"\n")
    digest.update(str(nk_record.values_number()).encode("ascii"))
    return digest.hexdigest()


def fingerprint_vk(vk_record):
    """Stable content fingerprint of a value record and its raw data."""
    digest = hashlib.sha256()
    digest.update(b"vk\n")
    digest.update(vk_record.name().encode("utf-16le", errors="replace"))
    digest.update(b"\n")
    digest.update(str(vk_record.data_type()).encode("ascii"))
    digest.update(b"\n")
    digest.update(vk_record.raw_data())
    return digest.hexdigest()


def index_hbins(regf):
    """Materialise the HBIN blocks once so lookups stay linear."""
    return list(regf.hbins())


def hbin_for_offset(hbins, absolute_offset):
    """Return the HBIN block that contains absolute_offset."""
    current = hbins[0]
    for hbin in hbins:
        if hbin.offset() <= absolute_offset:
            current = hbin
        else:
            break
    return current


def _nk_citations(nk_record, hbins):
    """Build the layer-by-layer raw citations for a key record."""
    hbin = hbin_for_offset(hbins, nk_record.offset())
    cell = RegistryParse.HBINCell(
        nk_record._buf, nk_record.offset() - 0x4, hbin
    )
    citations = [
        Citation(
            layer="REGF header",
            detail="hive root anchor, first HBIN at %s" % _hex(FIRST_HBIN_OFFSET),
            offset=0,
        ),
        Citation(
            layer="HBIN block",
            detail="allocation block hosting the cell",
            offset=hbin.offset(),
        ),
        Citation(
            layer="HBIN cell",
            detail="cell size %d, data id %r" % (cell.size(), cell.data_id()),
            offset=cell.offset(),
        ),
        Citation(
            layer="NK record",
            detail="key '%s'" % nk_record.name(),
            offset=nk_record.offset(),
        ),
    ]
    if not nk_record.is_root() and nk_record.has_parent_key():
        parent = nk_record.parent_key()
        citations.append(
            Citation(
                layer="parent NK link",
                detail="parent key '%s'" % parent.name(),
                offset=parent.offset(),
            )
        )
    return citations


def _vk_citations(vk_record, nk_record, hbins):
    """Build the layer-by-layer raw citations for a value record."""
    hbin = hbin_for_offset(hbins, vk_record.offset())
    cell = RegistryParse.HBINCell(
        vk_record._buf, vk_record.offset() - 0x4, hbin
    )
    citations = [
        Citation(
            layer="REGF header",
            detail="hive root anchor, first HBIN at %s" % _hex(FIRST_HBIN_OFFSET),
            offset=0,
        ),
        Citation(
            layer="HBIN block",
            detail="allocation block hosting the cell",
            offset=hbin.offset(),
        ),
        Citation(
            layer="HBIN cell",
            detail="cell size %d, data id %r" % (cell.size(), cell.data_id()),
            offset=cell.offset(),
        ),
        Citation(
            layer="NK record",
            detail="owning key '%s'" % nk_record.name(),
            offset=nk_record.offset(),
        ),
        Citation(
            layer="VK record",
            detail="value '%s'" % (vk_record.name() or "(default)"),
            offset=vk_record.offset(),
        ),
        Citation(
            layer="data cell",
            detail="raw value bytes, length %d" % vk_record.data_length(),
            offset=vk_record.data_offset(),
        ),
    ]
    return citations


def _walk_reachable(key, reachable_nk, reachable_vk, vk_owner):
    """Collect reachable NK/VK offsets and map each VK to its owning NK."""
    nk = key._nkrecord
    reachable_nk.add(nk.offset())
    for value in key.values():
        vk_offset = value._vkrecord.offset()
        reachable_vk.add(vk_offset)
        vk_owner[vk_offset] = nk
    for subkey in key.subkeys():
        _walk_reachable(subkey, reachable_nk, reachable_vk, vk_owner)


def _all_cells(regf):
    """Enumerate every allocated HBIN cell, tolerating trailing slack space."""
    for hbin in regf.hbins():
        try:
            for cell in hbin.cells():
                if cell.is_free():
                    continue
                yield cell
        except RegistryParse.RegistryStructureDoesNotExist:
            continue


def _nk_path(nk_record):
    """Best-effort registry path for a record, even when it is orphaned."""
    try:
        return nk_record.path()
    except (RegistryParse.ParseException, RegistryParse.RegistryStructureDoesNotExist):
        return "\\[orphan]\\%s" % nk_record.name()


def parse_primary(buffer_bytes):
    """Parse a primary hive and return header info plus all occurrences.

    Every allocated NK/VK cell is enumerated, not only the live tree.
    Records reached from the root key are marked ``reachable``; allocated but
    unlinked cells are marked ``unreachable`` so their weak provenance is
    visible in the binding report.
    """
    regf = RegistryParse.REGFBlock(buffer_bytes, 0, False)
    registry = Registry.Registry(io.BytesIO(buffer_bytes))

    reachable_nk = set()
    reachable_vk = set()
    vk_owner = {}
    _walk_reachable(registry.root(), reachable_nk, reachable_vk, vk_owner)

    header = {
        "hive_name": regf.hive_name(),
        "hive_sequence1": regf.hive_sequence1(),
        "hive_sequence2": regf.hive_sequence2(),
        "checksum_valid": regf.validate_checksum(),
        "recovery_required": regf.recovery_required()._asdict(),
        "hbins_size": regf.hbins_size(),
    }

    hbins = index_hbins(regf)
    occurrences = []
    nk_by_offset = {}
    for cell in _all_cells(regf):
        if cell.data_id() != b"nk":
            continue
        try:
            nk = cell.child()
        except RegistryParse.ParseException:
            continue
        nk_by_offset[nk.offset()] = nk
        reachability = (
            Reachability.REACHABLE
            if nk.offset() in reachable_nk
            else Reachability.UNREACHABLE
        )
        occurrences.append(
            {
                "record_kind": "key",
                "registry_path": _nk_path(nk),
                "value_name": None,
                "value_type": None,
                "timestamp": str(nk.timestamp()),
                "relative_offset": nk.offset() - FIRST_HBIN_OFFSET,
                "absolute_offset": nk.offset(),
                "content_fingerprint": fingerprint_nk(nk),
                "reachability": reachability,
                "citations": _nk_citations(nk, hbins),
            }
        )

    for cell in _all_cells(regf):
        if cell.data_id() != b"vk":
            continue
        try:
            vk = cell.child()
        except RegistryParse.ParseException:
            continue
        owner_nk = vk_owner.get(vk.offset())
        owner = nk_by_offset.get(owner_nk.offset()) if owner_nk is not None else None
        owner_name = owner.name() if owner is not None else "[unlinked owner]"
        owner_path = _nk_path(owner) if owner is not None else "[orphan]"
        reachability = (
            Reachability.REACHABLE
            if vk.offset() in reachable_vk
            else Reachability.UNREACHABLE
        )
        citations = _vk_citations(vk, owner, hbins) if owner is not None else [
            Citation(
                layer="REGF header",
                detail="hive root anchor, first HBIN at %s" % _hex(FIRST_HBIN_OFFSET),
                offset=0,
            ),
            Citation(
                layer="HBIN block",
                detail="allocation block hosting the cell",
                offset=hbin_for_offset(hbins, vk.offset()).offset(),
            ),
            Citation(
                layer="HBIN cell",
                detail="cell size %d, data id %r" % (cell.size(), cell.data_id()),
                offset=cell.offset(),
            ),
            Citation(
                layer="VK record",
                detail="value '%s' with no reachable owning NK" % (vk.name() or "(default)"),
                offset=vk.offset(),
            ),
        ]
        occurrences.append(
            {
                "record_kind": "value",
                "registry_path": owner_path,
                "value_name": vk.name(),
                "value_type": vk.data_type_str(),
                "timestamp": str(owner.timestamp()) if owner is not None else None,
                "relative_offset": vk.offset() - FIRST_HBIN_OFFSET,
                "absolute_offset": vk.offset(),
                "content_fingerprint": fingerprint_vk(vk),
                "reachability": reachability,
                "citations": citations,
                "owner_name": owner_name,
            }
        )

    return header, occurrences


def recover_with_logs(primary_bytes, log_paths):
    """Apply eligible logs to an in-memory copy, never touching disk.

    Returns ``(recovered_bytes, log_reports)`` where each report records the
    eligibility decision, sequence numbers, HvLE entries and dirty-page
    references that justify the source chain of the recovered view.
    """
    work = io.BytesIO(primary_bytes)
    reports = []

    logs = []
    for log_path in log_paths:
        work.seek(0)
        log = RegistryLog.RegistryLog(work, log_path)
        log_bytes = open(log_path, "rb").read()
        log_regf = RegistryParse.REGFBlock(log_bytes, 0, False)
        entries = []
        for entry in log_regf.log_entries():
            references = [
                {
                    "offset_hex": _hex(reference.offset()),
                    "size": reference.size(),
                    "primary_offset_hex": _hex(
                        reference.offset() + FIRST_HBIN_OFFSET
                    ),
                }
                for reference in entry.dirty_pages_references()
            ]
            entries.append(
                {
                    "sequence": entry.sequence(),
                    "hive_flags": entry.hive_flags(),
                    "hbins_size": entry.hbins_size(),
                    "dirty_pages": references,
                    "hash_valid": entry.validate_log_entry(),
                }
            )
        logs.append((log_path, log, entries))
        reports.append(
            {
                "relative_path": log_path,
                "eligible": log.is_eligible_log(),
                "first_log_sequence": log.first_log_sequence(),
                "entries": entries,
            }
        )

    eligible = [(path, log) for path, log, _ in logs if log.is_eligible_log()]
    if eligible:
        primary_regf = RegistryParse.REGFBlock(primary_bytes, 0, False)
        if len(eligible) == 1:
            path, log = eligible[0]
            work.seek(0)
            sequence = log.recover_hive()
            for report in reports:
                if report["relative_path"] == path:
                    report["applied"] = True
                    report["applied_sequence"] = sequence
        else:
            candidate_a = eligible[0]
            candidate_b = eligible[1]
            if candidate_a[1].is_starting_log(candidate_b[1]):
                first_path, first_log = candidate_a
                second_path, second_log = candidate_b
            else:
                first_path, first_log = candidate_b
                second_path, second_log = candidate_a
            work.seek(0)
            first_sequence = first_log.recover_hive()
            second_sequence = second_log.recover_hive_continue(
                first_sequence + 1
            )
            for report in reports:
                if report["relative_path"] == first_path:
                    report["applied"] = True
                    report["applied_sequence"] = first_sequence
                if report["relative_path"] == second_path:
                    report["applied"] = True
                    report["applied_sequence"] = second_sequence

    work.seek(0)
    recovered_bytes = work.read()
    return recovered_bytes, reports


def read_file(path):
    """Read a file in binary mode; isolated so callers never write in place."""
    with open(path, "rb") as handle:
        return handle.read()


def detect_kind(path, buffer_bytes):
    """Classify a file from its REGF signature and file type field."""
    if len(buffer_bytes) < 4 or buffer_bytes[:4] != b"regf":
        return None
    try:
        regf = RegistryParse.REGFBlock(buffer_bytes, 0, False)
    except RegistryParse.ParseException:
        return None
    if regf.is_primary_file():
        return "primary"
    if regf.is_new_transaction_log_file():
        return "transaction_log"
    if regf.is_old_transaction_log_file():
        return "transaction_log_unsupported"
    return "unknown_registry"


def relpath(path, root):
    """Bundle-relative POSIX path for stable, portable manifests."""
    return os.path.relpath(path, root).replace(os.sep, "/")
