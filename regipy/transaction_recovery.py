import logging
import os

from construct import ConstError, Int32sl, StreamError

from regipy.exceptions import RegistryRecoveryException
from regipy.hive_types import DIRT_TRANSACTION_LOG_MAGIC, HVLE_TRANSACTION_LOG_MAGIC
from regipy.recovery import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    SOURCE_PRIMARY_HIVE,
    SOURCE_TRANSACTION_LOG,
    RecoveredRecord,
    RecoveryDiagnostics,
    TransactionLogRecoveryResult,
    _apply_entries_to_buffer,
    _apply_header_state,
    _detect_log_magic,
    _order_and_chain,
    _parse_dirt_block,
    _scan_hvle_entries,
)
from regipy.registry import RegistryHive
from regipy.structs import REGF_HEADER_SIZE

logger = logging.getLogger(__name__)


def _coalesce_provenance(provenance):
    """Merge overlapping dirty-page ranges. Pages are replayed in sequence
    order, so when two page images overlap the later replay wins. The returned
    list is sorted and contains no overlapping ranges."""
    if not provenance:
        return []
    ordered = sorted(provenance, key=lambda item: (item.offset, item.size))
    merged = []
    for item in ordered:
        if not merged or item.offset > merged[-1].offset + merged[-1].size:
            merged.append(item)
            continue
        last = merged[-1]
        if item.offset + item.size <= last.offset + last.size:
            continue
        if item.offset > last.offset:
            last.size = item.offset - last.offset
            merged.append(item)
        else:
            last.size = item.offset + item.size - last.offset
            last.source = item.source
            last.log_path = item.log_path
            last.sequence_number = item.sequence_number
            last.dirty_page_offset = item.dirty_page_offset
    return [item for item in merged if item.size > 0]


def _covering_ranges(provenance, offset, size):
    end = offset + size
    return [item for item in provenance if item.offset < end and item.offset + item.size > offset]


def _interval_provenance(provenance, offset, size):
    """Classify a byte interval of the merged hive image.

    An interval fully covered by one validated dirty page is high confidence;
    an interval straddling a page boundary (partly primary, partly log) is
    medium confidence; an interval no dirty page touched stays primary.
    """
    ranges = _covering_ranges(provenance, offset, size)
    if size <= 0:
        # A non-positive cell size means the cell size field itself is corrupt,
        # so any record built on it is low confidence regardless of coverage.
        return SOURCE_TRANSACTION_LOG, CONFIDENCE_LOW, ranges
    if not ranges:
        return SOURCE_PRIMARY_HIVE, CONFIDENCE_HIGH, ranges
    if len(ranges) == 1 and ranges[0].offset <= offset and ranges[0].offset + ranges[0].size >= offset + size:
        return SOURCE_TRANSACTION_LOG, CONFIDENCE_HIGH, ranges
    return SOURCE_TRANSACTION_LOG, CONFIDENCE_MEDIUM, ranges


def _record_cell_span(stream, record_offset):
    """Return the (cell_start, cell_size) of the cell whose body starts at
    *record_offset* (an absolute file offset): the 4-byte signed cell size
    immediately precedes the body."""
    stream.seek(record_offset - 4)
    cell_size = Int32sl.parse_stream(stream) * -1
    return record_offset - 4, cell_size


def _parent_list_provenance(merged_hive, coalesced, subkey_path):
    """Return the provenance ranges covering the subkey-list cell of the
    parent of *subkey_path*. A deleted key whose own NK cell was never rewritten
    is resurrected precisely because this parent list page was replayed, so its
    provenance (and sequence number) come from here."""
    from regipy.exceptions import RegistryKeyNotFoundException

    parent_path = subkey_path.rpartition(chr(92))[0] or chr(92)
    try:
        parent_nk = merged_hive.get_key(parent_path)
    except RegistryKeyNotFoundException:
        return []
    if not parent_nk.header.subkey_count:
        return []
    # subkeys_list_offset is bins-relative and points at the list cell size
    # field; the provenance ranges use absolute file offsets.
    list_cell_offset = REGF_HEADER_SIZE + parent_nk.header.subkeys_list_offset
    return _covering_ranges(coalesced, list_cell_offset, 8)


def _merge_logs(registry_hive, hive_path, log_paths, restored_hive_buffer):
    provenance = []
    applied_entries = 0
    dirty_pages = 0
    log_magics = {path: _detect_log_magic(path) for path in log_paths}

    if any(magic != HVLE_TRANSACTION_LOG_MAGIC for magic in log_magics.values()):
        for log_path in reversed(log_paths):
            magic = log_magics[log_path]
            if magic == DIRT_TRANSACTION_LOG_MAGIC:
                with open(log_path, "rb") as transaction_log:
                    transaction_log.seek(512, 0)
                    dirt_buffer, page_count = _parse_dirt_block(
                        hive_path,
                        transaction_log,
                        registry_hive.header.hive_bins_data_size,
                        log_path=log_path,
                        provenance=provenance,
                    )
                restored_hive_buffer.seek(0)
                restored_hive_buffer.write(dirt_buffer.getvalue())
                restored_hive_buffer.truncate()
                dirty_pages += page_count
                applied_entries += 1
            elif magic == HVLE_TRANSACTION_LOG_MAGIC:
                log_size = os.path.getsize(log_path)
                entries = [
                    (sequence, bin_size, pages, log_size, log_path)
                    for sequence, bin_size, pages in _scan_hvle_entries(log_path)
                ]
                page_count, last_sequence, last_bin_size = _apply_entries_to_buffer(
                    entries,
                    restored_hive_buffer,
                    restored_hive_buffer.getbuffer().nbytes,
                    registry_hive.header.secondary_sequence_num,
                    provenance=provenance,
                )
                _apply_header_state(restored_hive_buffer, last_sequence, last_bin_size)
                dirty_pages += page_count
                applied_entries += len(entries)
            else:
                raise RegistryRecoveryException(f"The transaction log vector magic was not expected: {magic} (log {log_path})")
        return provenance, applied_entries, dirty_pages

    entries_by_log = []
    for log_path in log_paths:
        log_size = os.path.getsize(log_path)
        entries = [
            (sequence, bin_size, pages, log_size, log_path) for sequence, bin_size, pages in _scan_hvle_entries(log_path)
        ]
        entries_by_log.append(entries)

    ordered_entries = _order_and_chain(entries_by_log, registry_hive.header.secondary_sequence_num)
    applied_entries = len(ordered_entries)
    dirty_pages, last_sequence, last_bin_size = _apply_entries_to_buffer(
        ordered_entries,
        restored_hive_buffer,
        restored_hive_buffer.getbuffer().nbytes,
        registry_hive.header.secondary_sequence_num,
        provenance=provenance,
    )
    _apply_header_state(restored_hive_buffer, last_sequence, last_bin_size)
    return provenance, applied_entries, dirty_pages


def _annotate_records(merged_hive, primary_hive, provenance):
    """Walk every reachable key of the merged hive and annotate each NK (and
    each of its VK values) with the provenance of its underlying bytes.

    A record whose path does not exist in the on-disk primary hive is flagged
    deleted_from_primary: the forensic case the transaction logs recover (a key
    or value removed from the live hive but still present in replayed pages).
    """
    from construct import Int32ul

    from regipy.structs import VALUE_KEY

    coalesced = _coalesce_provenance(provenance)
    primary_paths = set()
    for primary_entry in _safe_recurse(primary_hive):
        primary_paths.add(primary_entry.path)
    records = []

    for subkey in _safe_recurse(merged_hive):
        nk = merged_hive.get_key(subkey.path)
        cell_start, cell_size = _record_cell_span(merged_hive._stream, nk.offset)
        source, confidence, ranges = _interval_provenance(coalesced, cell_start, cell_size)
        deleted = subkey.path not in primary_paths
        unallocated = cell_size <= 0
        if deleted:
            # A key absent from the primary hive becomes reachable again only
            # because a replayed dirty page restored a parent subkey list.
            # Attribute it to that log page; an unallocated (slack-space) NK
            # cell is medium confidence because its own bytes were not rewritten.
            parent_ranges = _parent_list_provenance(merged_hive, coalesced, subkey.path)
            if parent_ranges:
                source = SOURCE_TRANSACTION_LOG
                ranges = parent_ranges
            confidence = CONFIDENCE_MEDIUM if unallocated else CONFIDENCE_HIGH
        records.append(
            RecoveredRecord(
                record_type="NK",
                path=subkey.path,
                value_name=None,
                source=source,
                confidence=confidence,
                deleted_from_primary=deleted,
                log_path=ranges[0].log_path if ranges else None,
                sequence_number=ranges[0].sequence_number if ranges else None,
                log_backed_offsets=[item.offset for item in ranges],
            )
        )

        if not nk.values_count:
            continue
        primary_value_names = _primary_value_names(primary_hive, subkey.path)
        list_offset = REGF_HEADER_SIZE + 4 + nk.header.values_list_offset
        merged_hive._stream.seek(list_offset)
        try:
            vk_offsets = [REGF_HEADER_SIZE + 4 + Int32ul.parse_stream(merged_hive._stream) for _ in range(nk.values_count)]
        except StreamError:
            # A truncated/corrupt values list is handled the same way iter_values
            # does: stop reading values for this NK but keep all NK annotations.
            logger.warning("Bad VK offset list at %s, skipping value annotation", subkey.path)
            vk_offsets = []
        for body_offset in vk_offsets:
            try:
                value_name = _read_vk_name(merged_hive._stream, body_offset, VALUE_KEY)
            except (ConstError, StreamError):
                # A corrupt VK is skipped by iter_values too; never let it abort
                # the whole recovery annotation run.
                logger.warning("Skipping unparseable VK at offset %s", hex(body_offset))
                continue
            vk_cell_start, vk_cell_size = _record_cell_span(merged_hive._stream, body_offset)
            source, confidence, ranges = _interval_provenance(coalesced, vk_cell_start, vk_cell_size)
            value_deleted = deleted or (primary_value_names is not None and value_name not in primary_value_names)
            records.append(
                RecoveredRecord(
                    record_type="VK",
                    path=subkey.path,
                    value_name=value_name,
                    source=source,
                    confidence=confidence,
                    deleted_from_primary=value_deleted,
                    log_path=ranges[0].log_path if ranges else None,
                    sequence_number=ranges[0].sequence_number if ranges else None,
                    log_backed_offsets=[item.offset for item in ranges],
                )
            )
    return records


def _safe_recurse(hive):
    """Yield recurse_subkeys entries, skipping subtrees whose subkey list or VK
    references are corrupt (a replayed dirty page can carry stale offsets). The
    merged hive is best-effort forensic data, so one bad pointer must not abort
    recovery of every other record."""
    from regipy.exceptions import RegistryParsingException

    generator = hive.recurse_subkeys(as_json=False, fetch_values=False)
    while True:
        try:
            yield next(generator)
        except StopIteration:
            return
        except RegistryParsingException as ex:
            logger.warning("Skipping corrupt subtree during recovery annotation: %s", ex)
            continue


def _read_vk_name(stream, body_offset, value_key_struct):
    stream.seek(body_offset)
    vk = value_key_struct.parse_stream(stream)
    if vk.name_size == 0:
        return "(default)"
    if vk.flags.VALUE_COMP_NAME:
        return vk.name.decode("ascii", errors="replace")
    return vk.name.decode("utf-16-le", errors="replace")


def _primary_value_names(primary_hive, path):
    """Return the set of value names the primary hive holds at *path*, or None
    when the path does not exist in the primary hive at all."""
    from regipy.exceptions import RegistryKeyNotFoundException

    try:
        nk = primary_hive.get_key(path)
    except RegistryKeyNotFoundException:
        return None
    if not nk.values_count:
        return set()
    return {value.name for value in nk.iter_values()}


def recover_hive_with_transaction_logs(hive_path, primary_log_path, secondary_log_path=None, hive_type=None):
    """Incrementally parse a registry hive together with its transaction logs.

    The transaction logs (.LOG1/.LOG2) hold the dirty pages that were not flushed
    to the primary hive. This function replays those validated pages onto an
    in-memory copy of the hive (the on-disk primary hive is never modified),
    parses the merged image, and annotates every reachable NK/VK record with the
    source of its bytes (primary hive vs. transaction log), a confidence level,
    and whether the record was deleted from the primary hive.

    Parsing failures raise RegistryRecoveryException with a diagnostic message
    before any merged hive is returned, so a corrupt or mismatched log can never
    pollute the results of parsing the original hive.

    :param hive_path: path to the primary hive
    :param primary_log_path: path to the primary transaction log (.LOG1)
    :param secondary_log_path: optional path to the secondary log (.LOG2)
    :param hive_type: optional explicit hive type (same meaning as RegistryHive)
    :return: TransactionLogRecoveryResult
    """
    log_paths = [path for path in (primary_log_path, secondary_log_path) if path]
    if not log_paths:
        raise RegistryRecoveryException("At least one transaction log path is required for recovery")

    primary_hive = RegistryHive(hive_path, hive_type=hive_type)

    from io import BytesIO

    with open(hive_path, "rb") as hive_file:
        restored_hive_buffer = BytesIO(hive_file.read())

    # Capture the recovery module own diagnostics (hash failures, sequence gaps,
    # stale logs) so callers receive them programmatically, not only via logging.
    import logging as _logging

    recovery_logger = _logging.getLogger("regipy.recovery")
    captured_warnings = []

    class _CollectWarnings(_logging.Handler):
        def emit(self, record):
            captured_warnings.append(self.format(record))

    handler = _CollectWarnings()
    handler.setLevel(_logging.WARNING)
    recovery_logger.addHandler(handler)
    try:
        provenance, applied_entries, dirty_pages = _merge_logs(primary_hive, hive_path, log_paths, restored_hive_buffer)
    finally:
        recovery_logger.removeHandler(handler)
    merged_hive_bytes = restored_hive_buffer.getvalue()

    try:
        merged_hive = RegistryHive.from_bytes(merged_hive_bytes, hive_type=hive_type or primary_hive.hive_type)
    except Exception as ex:
        raise RegistryRecoveryException(
            f"The merged hive image could not be parsed after applying the transaction logs: {ex}. "
            "The primary hive was not modified; refusing to return partial results."
        )

    recovered_records = _annotate_records(merged_hive, primary_hive, provenance)
    deleted_count = sum(1 for record in recovered_records if record.deleted_from_primary)

    diagnostics = RecoveryDiagnostics(
        primary_hive_path=hive_path,
        log_paths=log_paths,
        applied_entries=applied_entries,
        recovered_dirty_pages=dirty_pages,
        recovered_records=len(recovered_records),
        recovered_deleted_records=deleted_count,
        warnings=captured_warnings,
    )
    return TransactionLogRecoveryResult(
        registry_hive=merged_hive,
        recovered_records=recovered_records,
        diagnostics=diagnostics,
        merged_hive_bytes=merged_hive_bytes,
    )
