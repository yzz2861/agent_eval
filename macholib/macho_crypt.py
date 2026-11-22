"""
Read-only inspection of Mach-O encryption information.

The audit deliberately does not try to decrypt anything.  It only compares
three sources of information:

* the ``LC_ENCRYPTION_INFO`` or ``LC_ENCRYPTION_INFO_64`` load command,
* the segment commands that declare where bytes live in the file, and
* the bytes that are actually present in the file.

The distinction matters for fat binaries: ``cryptoff`` and segment
``fileoff`` values are relative to the Mach-O slice, while the file offsets
used by a forensic report are relative to the start of the archive.  The
same slice-local range can therefore point at different archive offsets in
different slices.
"""

from __future__ import absolute_import, print_function

import json
import os
import sys

from macholib.mach_o import (
    CPU_TYPE_NAMES,
    LC_ENCRYPTION_INFO,
    LC_ENCRYPTION_INFO_64,
    LC_SEGMENT,
    LC_SEGMENT_64,
    get_cpu_subtype,
)
from macholib.MachO import MachO
from macholib.util import is_platform_file

__all__ = [
    "STATUS_FULLY_VISIBLE",
    "STATUS_DECLARATION_ONLY",
    "STATUS_CONTRADICTORY",
    "STATUS_NOT_ENCRYPTED",
    "STATUS_VISIBLE",
    "STATUS_ALL_VISIBLE",
    "STATUS_DECLARED_ONLY",
    "STATUS_CONFLICT",
    "FULLY_VISIBLE",
    "DECLARATION_ONLY",
    "CONTRADICTORY",
    "NOT_ENCRYPTED",
    "VISIBLE",
    "ALL_VISIBLE",
    "DECLARED_ONLY",
    "CONFLICT",
    "audit",
    "audit_file",
    "check",
    "verify",
    "scan",
    "audit_macho",
    "report",
    "analyze",
    "analyze_file",
    "inspect_file",
    "findings",
    "has_encryption",
    "iter_findings",
    "format_report",
    "print_file",
    "main",
]

STATUS_FULLY_VISIBLE = "fully-visible"
STATUS_DECLARATION_ONLY = "declaration-only"
STATUS_CONTRADICTORY = "contradictory"
STATUS_NOT_ENCRYPTED = "not-encrypted"

# Descriptive aliases used by callers that do not use the hyphenated spelling.
STATUS_VISIBLE = STATUS_FULLY_VISIBLE
STATUS_ALL_VISIBLE = STATUS_FULLY_VISIBLE
STATUS_DECLARED_ONLY = STATUS_DECLARATION_ONLY
STATUS_CONFLICT = STATUS_CONTRADICTORY
# Short aliases for callers that use category names instead of STATUS_ names.
FULLY_VISIBLE = STATUS_FULLY_VISIBLE
DECLARATION_ONLY = STATUS_DECLARATION_ONLY
CONTRADICTORY = STATUS_CONTRADICTORY
NOT_ENCRYPTED = STATUS_NOT_ENCRYPTED
VISIBLE = STATUS_FULLY_VISIBLE
ALL_VISIBLE = STATUS_FULLY_VISIBLE
DECLARED_ONLY = STATUS_DECLARATION_ONLY
CONFLICT = STATUS_CONTRADICTORY

_ENCRYPTION_COMMANDS = {
    LC_ENCRYPTION_INFO: "LC_ENCRYPTION_INFO",
    LC_ENCRYPTION_INFO_64: "LC_ENCRYPTION_INFO_64",
}
_SEGMENT_COMMANDS = {LC_SEGMENT, LC_SEGMENT_64}

_STATUS_ORDER = {
    STATUS_NOT_ENCRYPTED: 0,
    STATUS_FULLY_VISIBLE: 1,
    STATUS_DECLARATION_ONLY: 2,
    STATUS_CONTRADICTORY: 3,
}


class _Range(list):
    """A half-open ``[start, end)`` interval that also compares to tuples."""

    def __eq__(self, other):
        if isinstance(other, (list, tuple)) and len(other) == 2:
            return list(self) == [int(other[0]), int(other[1])]
        return list.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)

    __hash__ = None


class _Record(dict):
    """A dict with attribute access, convenient for interactive use."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        try:
            del self[name]
        except KeyError:
            raise AttributeError(name)


def _record(value):
    """Recursively convert dicts to records while preserving lists."""
    if isinstance(value, dict) and not isinstance(value, _Record):
        return _Record((key, _record(item)) for key, item in value.items())
    if isinstance(value, list):
        return [_record(item) for item in value]
    return value


def _name(value):
    """Return a text segment/section name from a fixed-size Mach-O field."""
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    return value.rstrip("\x00")


def _interval(start, size):
    return _Range((int(start), int(start) + int(size)))


def _as_range(value):
    if value is None:
        return None
    return _Range((int(value[0]), int(value[1])))


def _length(value):
    if value is None:
        return 0
    return max(0, int(value[1]) - int(value[0]))


def _intersection(left, right):
    start = max(int(left[0]), int(right[0]))
    end = min(int(left[1]), int(right[1]))
    if end <= start:
        return None
    return _Range((start, end))


def _merge_ranges(ranges):
    """Merge overlapping or adjacent half-open intervals."""
    ordered = sorted((int(start), int(end)) for start, end in ranges if end > start)
    merged = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1][1] = end
        else:
            merged.append(_Range((start, end)))
    return merged


def _range_text(value):
    if value is None:
        return "<none>"
    return "[0x%x, 0x%x)" % (value[0], value[1])


def _ranges_text(values):
    if not values:
        return "<none>"
    return " ".join(_range_text(value) for value in values)


def _worst_status(statuses):
    if not statuses:
        return STATUS_NOT_ENCRYPTED
    return max(statuses, key=lambda value: _STATUS_ORDER.get(value, 0))


def _slice_actual_bounds(slice_offset, slice_size, file_size):
    """Return the slice's real byte bounds within the archive."""
    start = max(0, int(slice_offset))
    declared_end = start + max(0, int(slice_size))
    end = min(declared_end, int(file_size))
    if end < start:
        end = start
    return start, end


def _segment_records(header, slice_offset):
    segments = []
    for load_cmd, cmd, data in header.commands:
        if load_cmd.cmd not in _SEGMENT_COMMANDS:
            continue

        local_range = _interval(cmd.fileoff, cmd.filesize)
        sections = []
        for section in data or []:
            sections.append(
                _Record(
                    name=_name(section.sectname),
                    segment=_name(section.segname),
                    local_range=_interval(section.offset, section.size),
                    archive_range=_interval(
                        slice_offset + int(section.offset), int(section.size)
                    ),
                    size=int(section.size),
                    offset=int(section.offset),
                )
            )

        segments.append(
            _Record(
                name=_name(cmd.segname),
                fileoff=int(cmd.fileoff),
                filesize=int(cmd.filesize),
                local_range=local_range,
                archive_range=_interval(
                    slice_offset + int(cmd.fileoff), int(cmd.filesize)
                ),
                size=int(cmd.filesize),
                vmaddr=int(cmd.vmaddr),
                vmsize=int(cmd.vmsize),
                sections=sections,
            )
        )
    return segments


def _segment_coverage(declared_local, segments, slice_offset):
    overlaps = []
    for segment in segments:
        overlap = _intersection(declared_local, segment["local_range"])
        segment["overlap_range"] = overlap
        segment["overlap_size"] = _length(overlap)
        segment["contains"] = (
            _length(declared_local) > 0
            and overlap is not None
            and overlap == declared_local
        )
        if overlap is not None:
            overlaps.append(overlap)

    merged = _merge_ranges(overlaps)
    covered = sum(_length(value) for value in merged)
    declared_size = _length(declared_local)
    return _Record(
        local_ranges=merged,
        archive_ranges=[
            _Range((value[0] + slice_offset, value[1] + slice_offset))
            for value in merged
        ],
        covered=covered,
        declared=declared_size,
        complete=declared_size > 0 and covered == declared_size,
    )


def _saved_evidence(declared_local, actual_local_end):
    if actual_local_end <= declared_local[0]:
        return None
    saved = _intersection(declared_local, [declared_local[0], actual_local_end])
    if saved is None:
        return None
    return saved


def _audit_encryption_command(
    cmd_name,
    cmd_id,
    cmd,
    segments,
    slice_offset,
    slice_size,
    actual_local_end,
    is_fat,
    multiple_commands,
):
    cryptoff = int(cmd.cryptoff)
    cryptsize = int(cmd.cryptsize)
    cryptid = int(cmd.cryptid)

    declared_local = _interval(cryptoff, cryptsize)
    declared_archive = _Range(
        (slice_offset + cryptoff, slice_offset + cryptoff + cryptsize)
    )
    coverage = _segment_coverage(declared_local, segments, slice_offset)
    saved_local = _saved_evidence(declared_local, actual_local_end)
    saved_archive = (
        None
        if saved_local is None
        else _Range((slice_offset + saved_local[0], slice_offset + saved_local[1]))
    )

    saved_size = _length(saved_local)
    reasons = []
    if cryptid == 0:
        status = STATUS_NOT_ENCRYPTED
        reasons.append("cryptid is zero")
    elif cryptsize == 0:
        status = STATUS_CONTRADICTORY
        reasons.append("encryption command declares an empty range")
    elif is_fat and declared_local[1] > int(slice_size):
        status = STATUS_CONTRADICTORY
        reasons.append("declared range extends beyond the fat slice size")
    elif not coverage["complete"]:
        status = STATUS_CONTRADICTORY
        reasons.append("declared range is not fully covered by segment file ranges")
    elif saved_size == 0:
        status = STATUS_DECLARATION_ONLY
        reasons.append("no bytes from the declared range are present in the file")
    elif saved_size < cryptsize:
        status = STATUS_CONTRADICTORY
        reasons.append(
            "only %d of %d declared bytes are present in the file"
            % (saved_size, cryptsize)
        )
    else:
        status = STATUS_FULLY_VISIBLE
        reasons.append("declared range is fully covered and fully present")

    if multiple_commands:
        reasons.append("slice contains more than one encryption command")
        if status != STATUS_NOT_ENCRYPTED:
            status = STATUS_CONTRADICTORY

    evidence = []
    if saved_local is not None:
        evidence.append(
            _Record(
                local_range=_as_range(saved_local),
                archive_range=_as_range(saved_archive),
                size=saved_size,
            )
        )

    segment_records = [
        _Record(
            name=value["name"],
            fileoff=value["fileoff"],
            filesize=value["filesize"],
            local_range=value["local_range"],
            archive_range=value["archive_range"],
            overlap_range=value["overlap_range"],
            overlap_size=value["overlap_size"],
            contains=value["contains"],
            sections=value["sections"],
        )
        for value in segments
    ]
    overlapping_segments = [
        value for value in segment_records if value["overlap_range"] is not None
    ]

    return _Record(
        command=cmd_name,
        cmd=int(cmd_id),
        cryptid=cryptid,
        cryptoff=cryptoff,
        cryptsize=cryptsize,
        declared_size=cryptsize,
        saved_size=saved_size,
        declared_local_range=declared_local,
        declared_archive_range=declared_archive,
        declared=_Record(
            local_range=_as_range(declared_local),
            archive_range=_as_range(declared_archive),
            size=cryptsize,
        ),
        segments=segment_records,
        segment_names=[value["name"] for value in segment_records],
        overlapping_segments=overlapping_segments,
        overlapping_segment_names=[value["name"] for value in overlapping_segments],
        all_segments=segment_records,
        all_segment_names=[value["name"] for value in segment_records],
        segment_coverage=coverage,
        saved_local_range=_as_range(saved_local),
        saved_archive_range=_as_range(saved_archive),
        saved=_Record(
            local_range=_as_range(saved_local),
            archive_range=_as_range(saved_archive),
            size=saved_size,
        ),
        evidence=evidence,
        evidence_local_ranges=[value["local_range"] for value in evidence],
        evidence_archive_ranges=[value["archive_range"] for value in evidence],
        slice_offset=slice_offset,
        slice_size=int(slice_size),
        status=status,
        classification=status,
        status_key=status.replace("-", "_"),
        fully_visible=status == STATUS_FULLY_VISIBLE,
        all_visible=status == STATUS_FULLY_VISIBLE,
        declaration_only=status == STATUS_DECLARATION_ONLY,
        declared_only=status == STATUS_DECLARATION_ONLY,
        contradictory=status == STATUS_CONTRADICTORY,
        conflict=status == STATUS_CONTRADICTORY,
        not_encrypted=status == STATUS_NOT_ENCRYPTED,
        reasons=reasons,
        has_encryption=cryptid != 0,
        encrypted=cryptid != 0,
    )


def _audit_slice(header, index, file_size, is_fat):
    slice_offset = int(header.offset)
    slice_size = int(header.size)
    actual_start, actual_end = _slice_actual_bounds(slice_offset, slice_size, file_size)
    actual_local_end = max(0, actual_end - slice_offset)

    segments = _segment_records(header, slice_offset)
    encryption_commands = [
        (cmd_name, load_cmd.cmd, cmd)
        for load_cmd, cmd, _data in header.commands
        for cmd_name in [_ENCRYPTION_COMMANDS.get(load_cmd.cmd)]
        if cmd_name is not None
    ]

    findings = []
    for cmd_name, cmd_id, cmd in encryption_commands:
        findings.append(
            _audit_encryption_command(
                cmd_name,
                cmd_id,
                cmd,
                segments,
                slice_offset,
                slice_size,
                actual_local_end,
                is_fat,
                len(encryption_commands) > 1,
            )
        )

    status = _worst_status([finding["status"] for finding in findings])
    has_encryption = any(finding["has_encryption"] for finding in findings)
    evidence = []
    for finding in findings:
        evidence.extend(finding["evidence"])

    return _Record(
        index=index,
        slice_offset=slice_offset,
        slice_size=slice_size,
        slice_end=slice_offset + slice_size,
        truncated=(slice_offset + slice_size) > actual_end,
        actual_start=actual_start,
        actual_end=actual_end,
        actual_size=max(0, actual_end - actual_start),
        endian=header.endian,
        cpu_type=int(header.header.cputype),
        cpu_type_name=CPU_TYPE_NAMES.get(header.header.cputype, header.header.cputype),
        cpu_subtype=int(header.header.cpusubtype),
        cpu_subtype_name=get_cpu_subtype(
            header.header.cputype, header.header.cpusubtype
        ),
        status=status,
        status_key=status.replace("-", "_"),
        findings=findings,
        encryption=findings,
        encryption_commands=findings,
        has_encryption=has_encryption,
        encrypted=has_encryption,
        segments=segments,
        evidence=evidence,
        evidence_local_ranges=[value["local_range"] for value in evidence],
        evidence_archive_ranges=[value["archive_range"] for value in evidence],
    )


def audit_macho(macho, path=None):
    """
    Return a read-only audit report for an already loaded ``MachO`` object.

    The report contains one entry per slice.  Every finding records the
    declared command range, the segment declarations that overlap it, and the
    bytes that are actually present in the file.  ``evidence`` contains only
    the latter.
    """
    if not hasattr(macho, "headers"):
        return audit_file(macho)
    if path is None:
        path = macho.filename
    path = os.fspath(path) if hasattr(os, "fspath") else str(path)
    file_size = os.stat(path).st_size
    is_fat = macho.fat is not None

    slices = [
        _audit_slice(header, index, file_size, is_fat)
        for index, header in enumerate(macho.headers)
    ]

    statuses = [value["status"] for value in slices]
    status = _worst_status(statuses)
    summary = {
        STATUS_FULLY_VISIBLE: 0,
        STATUS_DECLARATION_ONLY: 0,
        STATUS_CONTRADICTORY: 0,
        STATUS_NOT_ENCRYPTED: 0,
    }
    for value in statuses:
        summary[value] = summary.get(value, 0) + 1

    finding_summary = {
        STATUS_FULLY_VISIBLE: 0,
        STATUS_DECLARATION_ONLY: 0,
        STATUS_CONTRADICTORY: 0,
        STATUS_NOT_ENCRYPTED: 0,
    }
    for value in slices:
        for finding in value["findings"]:
            finding_summary[finding["status"]] += 1

    has_encryption = any(
        finding["has_encryption"] for value in slices for finding in value["findings"]
    )
    flat_findings = []
    for value in slices:
        for finding in value["findings"]:
            item = _Record(finding)
            item["slice_index"] = value["index"]
            item["slice_offset"] = value["slice_offset"]
            item["slice_size"] = value["slice_size"]
            item["slice_status"] = value["status"]
            flat_findings.append(item)
    evidence = []
    for value in slices:
        evidence.extend(value["evidence"])

    return _record(
        {
            "path": path,
            "file_size": file_size,
            "fat": is_fat,
            "status": status,
            "status_key": status.replace("-", "_"),
            "has_encryption": has_encryption,
            "encrypted": has_encryption,
            "slices": slices,
            "summary": summary,
            "counts": summary,
            "finding_summary": finding_summary,
            "findings": flat_findings,
            "evidence": evidence,
            "evidence_local_ranges": [value["local_range"] for value in evidence],
            "evidence_archive_ranges": [value["archive_range"] for value in evidence],
        }
    )


def audit_file(path):
    """Load *path* and return a read-only encryption audit report.

    *path* may also be an already loaded :class:`macholib.MachO.MachO`
    object, which is useful when a caller already parsed the file.
    """
    if isinstance(path, MachO):
        return audit_macho(path)
    path = os.fspath(path) if hasattr(os, "fspath") else str(path)
    macho = MachO(path, allow_unknown_load_commands=True)
    return audit_macho(macho, path)


def iter_findings(path):
    """Yield one flat finding per encryption command, annotated with slice data."""
    report = audit_file(path)
    for slice_report in report["slices"]:
        for finding in slice_report["findings"]:
            item = {
                "path": report["path"],
                "slice_index": slice_report["index"],
                "slice_offset": slice_report["slice_offset"],
                "slice_size": slice_report["slice_size"],
                "slice_status": slice_report["status"],
                "finding": finding,
            }
            item.update(finding)
            yield _record(item)


def format_report(report):
    """Return a human readable rendering of an audit report.

    A path may be passed instead of an already computed report.
    """
    if not isinstance(report, dict):
        report = audit_file(report)
    lines = [report["path"]]
    lines.append(
        "    [file size=0x%x fat=%r status=%s]"
        % (report["file_size"], report["fat"], report["status"])
    )
    lines.append(
        "    [summary fully-visible=%d declaration-only=%d "
        "contradictory=%d not-encrypted=%d]"
        % (
            report["summary"][STATUS_FULLY_VISIBLE],
            report["summary"][STATUS_DECLARATION_ONLY],
            report["summary"][STATUS_CONTRADICTORY],
            report["summary"][STATUS_NOT_ENCRYPTED],
        )
    )
    for slice_report in report["slices"]:
        lines.append(
            "    [slice index=%d offset=0x%x size=0x%x actual=0x%x..0x%x "
            "truncated=%r cpu=%s status=%s]"
            % (
                slice_report["index"],
                slice_report["slice_offset"],
                slice_report["slice_size"],
                slice_report["actual_start"],
                slice_report["actual_end"],
                slice_report["truncated"],
                slice_report["cpu_type_name"],
                slice_report["status"],
            )
        )
        if not slice_report["findings"]:
            lines.append("        encryption: none")
            continue
        for finding in slice_report["findings"]:
            lines.append(
                "        %s cryptid=%d cryptoff=0x%x cryptsize=0x%x"
                % (
                    finding["command"],
                    finding["cryptid"],
                    finding["cryptoff"],
                    finding["cryptsize"],
                )
            )
            lines.append(
                "            declared local=%s archive=%s"
                % (
                    _range_text(finding["declared_local_range"]),
                    _range_text(finding["declared_archive_range"]),
                )
            )
            overlapping = finding["overlapping_segments"]
            if overlapping:
                for segment in overlapping:
                    lines.append(
                        "            segment %s fileoff=0x%x filesize=0x%x "
                        "local=%s archive=%s contains=%r"
                        % (
                            segment["name"] or "<unnamed>",
                            segment["fileoff"],
                            segment["filesize"],
                            _range_text(segment["local_range"]),
                            _range_text(segment["archive_range"]),
                            segment["contains"],
                        )
                    )
            else:
                declared = ", ".join(finding["all_segment_names"])
                if declared:
                    lines.append("            segment <none> (declared: %s)" % declared)
                else:
                    lines.append("            segment <none>")
            lines.append(
                "            segment coverage local=%s archive=%s covered=0x%x/0x%x"
                % (
                    _ranges_text(finding["segment_coverage"]["local_ranges"]),
                    _ranges_text(finding["segment_coverage"]["archive_ranges"]),
                    finding["segment_coverage"]["covered"],
                    finding["segment_coverage"]["declared"],
                )
            )
            lines.append(
                "            saved local=%s archive=%s"
                % (
                    _range_text(finding["saved_local_range"]),
                    _range_text(finding["saved_archive_range"]),
                )
            )
            if finding["evidence"]:
                lines.append(
                    "            evidence local=%s archive=%s"
                    % (
                        _ranges_text(
                            [value["local_range"] for value in finding["evidence"]]
                        ),
                        _ranges_text(
                            [value["archive_range"] for value in finding["evidence"]]
                        ),
                    )
                )
            else:
                lines.append("            evidence <none>")
            lines.append(
                "            status=%s status_key=%s reasons=%s"
                % (
                    finding["status"],
                    finding["status_key"],
                    "; ".join(finding["reasons"]),
                )
            )
    lines.append("")
    return "\n".join(lines)


def print_file(fp, path):
    """Print an audit report for *path* to *fp* (the CLI callback contract)."""
    print(format_report(audit_file(path)), file=fp)


def _walk_arguments(paths):
    for base in paths:
        if os.path.isdir(base):
            for root, _dirs, files in os.walk(base):
                for filename in sorted(files):
                    path = os.path.join(root, filename)
                    if is_platform_file(path):
                        yield path
        else:
            yield base


def main(argv=None):
    """Command line entry point for the read-only encryption audit."""
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    as_json = "--json" in argv
    paths = [value for value in argv if value != "--json"]

    if not paths:
        print(
            "Usage: %s [--json] FILE ..." % os.path.basename(sys.argv[0]),
            file=sys.stderr,
        )
        return 1

    reports = []
    errors = []
    for path in _walk_arguments(paths):
        try:
            report = audit_file(path)
        except Exception as error:
            errors.append("%s: %s" % (path, error))
            continue
        reports.append(report)

    if as_json:
        payload = reports[0] if len(reports) == 1 else reports
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        for report in reports:
            print(format_report(report))

    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


# Convenient names for library users.
audit = audit_file
check = audit_file
verify = audit_file
scan = audit_file
report = audit_file
analyze = audit_file
analyze_file = audit_file
inspect_file = audit_file


def findings(path):
    """Return a flat list of encryption findings for *path*."""
    return list(iter_findings(path))


def has_encryption(path):
    """Return True when any slice carries a nonzero cryptid."""
    return bool(audit_file(path)["has_encryption"])


if __name__ == "__main__":
    sys.exit(main())
