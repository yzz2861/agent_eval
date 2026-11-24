"""Authenticode digest coverage analysis for pefile.

This module maps the byte ranges that feed an Authenticode PE image digest.
It does not build or verify certificate chains and it does not decide whether
a signature is trusted.
"""

import hashlib
import struct


CHECKSUM = "checksum"
SECURITY_DIRECTORY = "security_directory"
CERTIFICATE_TABLE = "certificate_table"
CONTENT = "content"
GAP = "gap"

PROVABLE = "provable"
UNPROVABLE = "unprovable"
UNSUPPORTED = "unsupported"

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000


class AuthenticodeCoverageError(ValueError):
    """Raised when a strict digest cannot be produced."""


class AttributeDict(dict):
    """Dictionary with attribute access for report objects."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


class AuthenticodeCoverageIssue(AttributeDict):
    """A layout, cross-check, or provability finding."""


class AuthenticodeCoverageRange:
    """A half-open byte interval and its digest-coverage classification."""

    def __init__(
        self,
        start,
        end,
        kind,
        included=True,
        source=None,
        label=None,
        **attributes
    ):
        start = int(start)
        end = int(end)
        if end < start:
            raise ValueError("range end precedes start")

        self.start = start
        self.end = end
        self.offset = start
        self.length = end - start
        self.size = self.length
        self.kind = kind
        self.type = kind
        self.category = kind if kind in (
            CHECKSUM,
            SECURITY_DIRECTORY,
            CERTIFICATE_TABLE,
        ) else CONTENT
        self.included = included
        self.excluded = included is False
        self.source = source
        self.region = source
        self.label = label or kind
        self.attributes = attributes
        for key, value in attributes.items():
            setattr(self, key, value)

    def as_dict(self):
        result = {
            "start": self.start,
            "end": self.end,
            "offset": self.offset,
            "length": self.length,
            "size": self.size,
            "kind": self.kind,
            "type": self.type,
            "category": self.category,
            "included": self.included,
            "excluded": self.excluded,
            "source": self.source,
            "region": self.region,
            "label": self.label,
        }
        result.update(self.attributes)
        return result

    def __iter__(self):
        yield self.start
        yield self.end

    def __len__(self):
        return self.length

    def __contains__(self, offset):
        return self.start <= int(offset) < self.end

    def __repr__(self):
        return (
            "AuthenticodeCoverageRange("
            f"start={self.start}, end={self.end}, "
            f"kind={self.kind!r}, included={self.included})"
        )

    def __eq__(self, other):
        if isinstance(other, AuthenticodeCoverageRange):
            return (
                self.start == other.start
                and self.end == other.end
                and self.kind == other.kind
            )
        if isinstance(other, (tuple, list)) and len(other) == 2:
            start, end_or_length = other
            return (
                (self.start == start and self.end == end_or_length)
                or (self.offset == start and self.length == end_or_length)
            )
        return NotImplemented


def intervals_overlap(start_a, end_a, start_b, end_b):
    start = max(int(start_a), int(start_b))
    end = min(int(end_a), int(end_b))
    if start < end:
        return start, end
    return None


class AuthenticodeCoverage:
    """Ordered Authenticode input coverage and layout cross-checks."""

    def __init__(self, pe=None):
        self.pe = pe
        self.file_size = 0
        self.format = None
        self.magic = None

        self.status = UNPROVABLE
        self.state = UNPROVABLE
        self.coverage_status = UNPROVABLE
        self.provable = False
        self.is_provable = False
        self.verifiable = False
        self.is_verifiable = False
        self.supported = False
        self.complete = False
        self.partition_complete = False
        self.executable_mapping_overlap = False

        # Digest computation is not trust validation.  None means that no
        # signature-validity conclusion is being made.
        self.signature_valid = None
        self.signature_trusted = None
        self.signature_validation = "not_performed"
        self.trust_validation_performed = False

        self.segments = []
        self.ranges = []
        self.digest_ranges = []
        self.digest_input_ranges = []
        self.ordered_digest_ranges = []
        self.ordered_ranges = []
        self.covered_ranges = []
        self.hash_ranges = []
        self.included_ranges = []
        self.excluded_ranges = []
        self.exclusions = []

        self.checksum_range = None
        self.checksum = None
        self.security_directory_range = None
        self.security_directory = None
        self.security_data_directory_range = None
        self.certificate_table_range = None
        self.certificate_table = None
        self.certificate_table_ranges = []

        self.sections = []
        self.section_mappings = []
        self.section_cross_checks = []
        self.overlay_mapping = None
        self.overlay_range = None
        self.overlay_offset = None
        self.overlay_size = 0

        self.issues = []
        self.anomalies = []
        self.findings = []
        self.errors = []
        self.warnings = []
        self.messages = []

        if pe is not None:
            self.analyze(pe)

    def add_issue(
        self,
        code,
        message,
        severity="error",
        anomaly=None,
        unprovable=None,
        **details
    ):
        if anomaly is None:
            anomaly = severity == "anomaly"
        if unprovable is None:
            unprovable = severity in ("error", "unprovable")

        issue = AuthenticodeCoverageIssue(
            code=code,
            message=message,
            severity=severity,
            **details
        )
        self.issues.append(issue)
        self.messages.append(f"{code}: {message}")

        if severity == "error":
            self.errors.append(message)
        elif severity in ("warning", "anomaly"):
            self.warnings.append(message)

        if anomaly:
            self.anomalies.append(issue)
            self.findings = self.anomalies

        if unprovable:
            self.provable = False
        return issue

    def _make_range(
        self,
        start,
        length,
        kind,
        included=True,
        source=None,
        label=None,
        **attributes
    ):
        try:
            start = int(start)
            length = int(length)
        except (TypeError, ValueError):
            self.add_issue(
                "invalid_range",
                f"Range {kind} has non-integer offset or size."
            )
            return None

        if start < 0 or length < 0:
            self.add_issue(
                "invalid_range",
                f"Range {kind} has negative offset or size."
            )
            return None

        range_object = AuthenticodeCoverageRange(
            start,
            start + length,
            kind,
            included=included,
            source=source,
            label=label,
            **attributes
        )
        if range_object.end > self.file_size:
            self.add_issue(
                "range_out_of_bounds",
                f"{kind} range {start:#x}-{range_object.end:#x} extends past "
                f"file size {self.file_size:#x}.",
                range=range_object.as_dict(),
            )
        return range_object

    def _unsupported(self, code, message):
        self.supported = False
        self.provable = False
        self.add_issue(code, message)
        self._finalize()
        return self

    def analyze(self, pe):
        self.pe = pe
        data = getattr(pe, "__data__", None)
        if data is None:
            return self._unsupported(
                "missing_file_data",
                "The PE object does not expose the parsed file bytes."
            )

        try:
            self.file_size = len(data)
        except TypeError:
            return self._unsupported(
                "invalid_file_data",
                "The PE file data does not have a length."
            )

        optional_header = getattr(pe, "OPTIONAL_HEADER", None)
        if optional_header is None:
            return self._unsupported(
                "missing_optional_header",
                "Authenticode coverage requires an optional header."
            )

        self.magic = int(getattr(optional_header, "Magic", 0) or 0)
        if self.magic == 0x10B:
            is_pe32_plus = False
            self.format = "PE32"
        elif self.magic == 0x20B:
            is_pe32_plus = True
            self.format = "PE32+"
        else:
            return self._unsupported(
                "unsupported_optional_header_magic",
                f"Unsupported PE optional header magic {self.magic:#06x}."
            )

        self.supported = True
        self.provable = True
        opt_start = int(optional_header.get_file_offset())

        self.checksum_range = self._make_range(
            opt_start + 0x40,
            4,
            CHECKSUM,
            included=False,
            source="optional_header.CheckSum",
            label="CheckSum",
        )
        self.checksum = self.checksum_range

        data_directories = getattr(
            optional_header, "DATA_DIRECTORY", []
        ) or []
        security_entry = None
        if len(data_directories) > 4:
            security_entry = data_directories[4]

        if security_entry is not None and hasattr(
            security_entry, "get_file_offset"
        ):
            security_start = int(security_entry.get_file_offset())
        else:
            data_directory_start = opt_start + (
                0x70 if is_pe32_plus else 0x60
            )
            security_start = data_directory_start + 4 * 8

        self.security_directory_range = self._make_range(
            security_start,
            8,
            SECURITY_DIRECTORY,
            included=False,
            source="optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]",
            label="IMAGE_DIRECTORY_ENTRY_SECURITY",
        )
        self.security_directory = self.security_directory_range
        self.security_data_directory_range = self.security_directory_range

        header_end = int(getattr(optional_header, "SizeOfHeaders", 0) or 0)
        security_va = 0
        security_size = 0

        if 0 <= security_start and security_start + 8 <= self.file_size:
            security_va, security_size = struct.unpack_from(
                "<II", data, security_start
            )
        elif security_entry is not None:
            security_va = int(
                getattr(security_entry, "VirtualAddress", 0) or 0
            )
            security_size = int(getattr(security_entry, "Size", 0) or 0)
            self.add_issue(
                "security_directory_unreadable",
                "The security data directory entry is outside readable file data."
            )
        else:
            self.add_issue(
                "security_directory_missing",
                "The security data directory entry is not present in the parsed PE."
            )

        if security_va != 0 or security_size != 0:
            if (security_va == 0) != (security_size == 0):
                self.add_issue(
                    "invalid_security_directory",
                    "Security directory offset and size must either both be zero "
                    "or both describe the certificate table."
                )
            self.certificate_table_range = self._make_range(
                security_va,
                security_size,
                CERTIFICATE_TABLE,
                included=False,
                source="IMAGE_DIRECTORY_ENTRY_SECURITY",
                label="WIN_CERTIFICATE table",
            )
            self.certificate_table = self.certificate_table_range
            if self.certificate_table_range is not None:
                self.certificate_table_ranges = [
                    self.certificate_table_range
                ]

        self._check_header_layout(header_end)
        self._build_section_mappings(pe)
        self._build_overlay_mapping(pe)
        self._cross_check_exclusions(header_end)
        self._check_exclusion_overlaps()
        self._build_segments(header_end)
        self._check_partition()
        self._finalize()
        return self

    def _exclusion_ranges(self):
        return [
            item
            for item in (
                self.checksum_range,
                self.security_directory_range,
                self.certificate_table_range,
            )
            if item is not None
        ]

    def _check_header_layout(self, header_end):
        checksum_range = self.checksum_range
        security_range = self.security_directory_range

        if (
            checksum_range is not None
            and security_range is not None
            and checksum_range.end > security_range.start
        ):
            self.add_issue(
                "checksum_security_layout_conflict",
                "The CheckSum and security data-directory ranges are not ordered."
            )

        if header_end <= 0:
            self.add_issue(
                "invalid_size_of_headers",
                "SizeOfHeaders is zero or missing."
            )
        elif header_end > self.file_size:
            self.add_issue(
                "size_of_headers_out_of_bounds",
                f"SizeOfHeaders {header_end:#x} exceeds file size "
                f"{self.file_size:#x}."
            )
        elif security_range is not None and security_range.end > header_end:
            self.add_issue(
                "security_directory_outside_headers",
                "The security data directory entry lies beyond SizeOfHeaders."
            )

    def _build_section_mappings(self, pe):
        section_header_end = 0

        for index, section in enumerate(getattr(pe, "sections", []) or []):
            raw_start = getattr(section, "PointerToRawData", None)
            raw_size = getattr(section, "SizeOfRawData", None)
            raw_name = getattr(section, "Name", b"") or b""

            if isinstance(raw_name, bytes):
                null_position = raw_name.find(bytes([0]))
                if null_position >= 0:
                    raw_name = raw_name[:null_position]
                section_name = raw_name.decode("utf-8", "replace")
            else:
                section_name = str(raw_name)

            section_range = self._make_range(
                raw_start if raw_start is not None else 0,
                raw_size if raw_size is not None else 0,
                CONTENT,
                included=True,
                source="section",
                label=section_name or f"section-{index}",
                section_index=index,
                section_name=section_name,
            )

            characteristics = int(
                getattr(section, "Characteristics", 0) or 0
            )
            mapping = AttributeDict(
                index=index,
                name=section_name,
                range=section_range,
                start=section_range.start if section_range else None,
                end=section_range.end if section_range else None,
                offset=section_range.offset if section_range else None,
                length=section_range.length if section_range else 0,
                raw_offset=raw_start,
                raw_size=raw_size,
                virtual_address=getattr(section, "VirtualAddress", None),
                virtual_size=getattr(section, "Misc_VirtualSize", None),
                characteristics=characteristics,
                executable=bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
                writable=bool(characteristics & IMAGE_SCN_MEM_WRITE),
            )
            self.section_mappings.append(mapping)
            self.sections.append(mapping)

            if hasattr(section, "get_file_offset"):
                header_offset = section.get_file_offset()
                if header_offset is not None:
                    section_header_end = max(
                        section_header_end, int(header_offset) + 40
                    )

        header_end = int(getattr(
            getattr(pe, "OPTIONAL_HEADER", None), "SizeOfHeaders", 0
        ) or 0)
        if (
            section_header_end
            and 0 < header_end < section_header_end
            and header_end <= self.file_size
        ):
            self.add_issue(
                "size_of_headers_truncates_section_table",
                "SizeOfHeaders does not cover the parsed section table."
            )

        header_clip_end = min(max(header_end, 0), self.file_size)
        for mapping in self.section_mappings:
            section_range = mapping.range
            if section_range is None or section_range.length == 0:
                continue
            overlap = intervals_overlap(
                section_range.start,
                section_range.end,
                0,
                header_clip_end,
            )
            if overlap is not None:
                self.add_issue(
                    "section_overlaps_headers",
                    f"Section {mapping.name or mapping.index} raw data overlaps "
                    "the PE header digest range.",
                    section=mapping,
                    overlap={"start": overlap[0], "end": overlap[1]},
                )

        ordered_ranges = sorted(
            (
                mapping.range
                for mapping in self.section_mappings
                if mapping.range is not None and mapping.range.length > 0
            ),
            key=lambda item: item.start,
        )
        for previous, current in zip(ordered_ranges, ordered_ranges[1:]):
            if current.start < previous.end:
                self.add_issue(
                    "overlapping_section_ranges",
                    "Two raw section ranges overlap, making ordered digest input "
                    "ambiguous.",
                    previous=previous.as_dict(),
                    current=current.as_dict(),
                )

    def _build_overlay_mapping(self, pe):
        try:
            overlay_start = pe.get_overlay_data_start_offset()
        except Exception as exc:
            self.add_issue(
                "overlay_lookup_failed",
                f"pefile overlay mapping failed: {exc}"
            )
            return

        if overlay_start is None:
            return

        overlay_start = int(overlay_start)
        if not 0 <= overlay_start <= self.file_size:
            self.add_issue(
                "overlay_offset_out_of_bounds",
                f"Overlay offset {overlay_start:#x} is outside the file."
            )
            return

        overlay_range = AuthenticodeCoverageRange(
            overlay_start,
            self.file_size,
            CONTENT,
            included=True,
            source="overlay",
            label="overlay",
        )
        self.overlay_offset = overlay_start
        self.overlay_size = self.file_size - overlay_start
        self.overlay_range = overlay_range
        self.overlay_mapping = AttributeDict(
            offset=overlay_start,
            size=self.overlay_size,
            start=overlay_start,
            end=self.file_size,
            range=overlay_range,
        )

    def _cross_check_exclusions(self, header_end):
        header_clip_end = min(max(int(header_end or 0), 0), self.file_size)

        for exclusion in self._exclusion_ranges():
            mappings = []

            if header_end > 0:
                overlap = intervals_overlap(
                    exclusion.start,
                    exclusion.end,
                    0,
                    header_clip_end,
                )
                if overlap is not None:
                    header_mapping = AttributeDict(
                        scope="header",
                        start=overlap[0],
                        end=overlap[1],
                    )
                    mappings.append(header_mapping)
                    if exclusion.kind == CERTIFICATE_TABLE:
                        self.add_issue(
                            "certificate_table_overlaps_header",
                            "The certificate-table exclusion overlaps the PE "
                            "header hash range.",
                            exclusion=exclusion.as_dict(),
                            overlap=header_mapping,
                        )

            for section_mapping in self.section_mappings:
                section_range = section_mapping.range
                if section_range is None:
                    continue
                overlap = intervals_overlap(
                    exclusion.start,
                    exclusion.end,
                    section_range.start,
                    section_range.end,
                )
                if overlap is None:
                    continue

                mapping = AttributeDict(
                    scope="section",
                    section_index=section_mapping.index,
                    section_name=section_mapping.name,
                    executable=section_mapping.executable,
                    writable=section_mapping.writable,
                    start=overlap[0],
                    end=overlap[1],
                )
                mappings.append(mapping)

                if section_mapping.executable:
                    self.executable_mapping_overlap = True
                    self.add_issue(
                        "excluded_range_in_executable_mapping",
                        "An Authenticode exclusion intersects an executable "
                        "section mapping; those bytes can still be consumed by "
                        "the ordered section hash.",
                        severity="anomaly",
                        anomaly=True,
                        unprovable=True,
                        exclusion=exclusion.as_dict(),
                        section=mapping,
                    )
                else:
                    self.add_issue(
                        "excluded_range_in_section_mapping",
                        "An Authenticode exclusion intersects a raw section "
                        "mapping, making the coverage claim contradictory.",
                        exclusion=exclusion.as_dict(),
                        section=mapping,
                    )

            if self.overlay_range is not None:
                overlap = intervals_overlap(
                    exclusion.start,
                    exclusion.end,
                    self.overlay_range.start,
                    self.overlay_range.end,
                )
                if overlap is not None:
                    mapping = AttributeDict(
                        scope="overlay",
                        start=overlap[0],
                        end=overlap[1],
                    )
                    mappings.append(mapping)

            exclusion.mappings = mappings
            exclusion.attributes["mappings"] = mappings
            exclusion.section_mappings = [
                item for item in mappings if item.scope == "section"
            ]
            exclusion.overlay_mapping = next(
                (item for item in mappings if item.scope == "overlay"),
                None,
            )

    def _check_exclusion_overlaps(self):
        exclusions = self._exclusion_ranges()
        for index, left in enumerate(exclusions):
            for right in exclusions[index + 1:]:
                overlap = intervals_overlap(
                    left.start, left.end, right.start, right.end
                )
                if overlap is not None:
                    self.add_issue(
                        "overlapping_excluded_ranges",
                        "Two Authenticode exclusion ranges overlap; coverage "
                        "cannot be proved.",
                        left=left.as_dict(),
                        right=right.as_dict(),
                        overlap={"start": overlap[0], "end": overlap[1]},
                    )

    def _subtract_exclusions(self, start, end, exclusions):
        pieces = [(int(start), int(end))]
        for exclusion in exclusions:
            if exclusion.length <= 0:
                continue
            remaining = []
            for piece_start, piece_end in pieces:
                overlap = intervals_overlap(
                    piece_start,
                    piece_end,
                    exclusion.start,
                    exclusion.end,
                )
                if overlap is None:
                    remaining.append((piece_start, piece_end))
                    continue
                overlap_start, overlap_end = overlap
                if piece_start < overlap_start:
                    remaining.append((piece_start, overlap_start))
                if overlap_end < piece_end:
                    remaining.append((overlap_end, piece_end))
            pieces = remaining
        return pieces

    def _build_segments(self, header_end):
        exclusions = self._exclusion_ranges()
        segments = list(exclusions)

        checksum = self.checksum_range
        security = self.security_directory_range
        if checksum is not None and security is not None:
            header_pieces = [
                (0, checksum.start, "header_before_checksum", "header"),
                (
                    checksum.end,
                    security.start,
                    "header_between_checksum_and_security_directory",
                    "header",
                ),
                (
                    security.end,
                    header_end,
                    "header_after_security_directory",
                    "header",
                ),
            ]
        else:
            header_pieces = [(0, header_end, "pe_header", "header")]

        for start, end, label, source in header_pieces:
            start = max(0, int(start))
            end = min(self.file_size, int(end))
            if start < end:
                segments.append(
                    AuthenticodeCoverageRange(
                        start,
                        end,
                        CONTENT,
                        included=True,
                        source=source,
                        label=label,
                    )
                )

        source_intervals = []
        safe_header_end = max(0, min(int(header_end or 0), self.file_size))
        if safe_header_end > 0:
            source_intervals.append((0, safe_header_end))

        for mapping in self.section_mappings:
            section_range = mapping.get("range")
            if section_range is None or section_range.length <= 0:
                continue
            segments.append(section_range)
            start = max(0, section_range.start)
            end = min(self.file_size, section_range.end)
            if start < end:
                source_intervals.append((start, end))

        source_intervals.sort(key=lambda item: (item[0], item[1]))
        cursor = 0
        for start, end in source_intervals:
            if end <= cursor:
                continue
            if start > cursor:
                gap_range = AuthenticodeCoverageRange(
                    cursor,
                    start,
                    GAP,
                    included=None,
                    source="unmapped_gap",
                    label="unmapped gap between digest source intervals",
                )
                segments.append(gap_range)
                self.add_issue(
                    "unmapped_layout_gap",
                    "A file interval is not covered by headers or raw section "
                    "data; its Authenticode treatment is not provable.",
                    start=cursor,
                    end=start,
                )
            cursor = max(cursor, end)

        tail_specs = []
        overlay_start = self.overlay_offset
        if (
            overlay_start is not None
            and cursor <= overlay_start < self.file_size
        ):
            if cursor < overlay_start:
                tail_specs.append((cursor, overlay_start, "other"))
            tail_specs.append((overlay_start, self.file_size, "overlay"))
        else:
            tail_specs.append((cursor, self.file_size, "tail"))

        for start, end, source in tail_specs:
            for fragment_start, fragment_end in self._subtract_exclusions(
                start, end, exclusions
            ):
                if fragment_start < fragment_end:
                    segments.append(
                        AuthenticodeCoverageRange(
                            fragment_start,
                            fragment_end,
                            CONTENT,
                            included=True,
                            source=source,
                            label=source,
                        )
                    )

        segments.sort(key=lambda item: (item.start, item.end, item.kind))
        self.segments = segments
        self.ranges = segments
        self.excluded_ranges = sorted(
            exclusions, key=lambda item: (item.start, item.end)
        )
        self.exclusions = self.excluded_ranges
        self.digest_ranges = [
            item
            for item in segments
            if item.included is True and item.length > 0
        ]
        for alias_name in (
            "digest_input_ranges",
            "ordered_digest_ranges",
            "ordered_ranges",
            "covered_ranges",
            "hash_ranges",
                "included_ranges",
            ):
                setattr(self, alias_name, self.digest_ranges)

    def _check_partition(self):
        cursor = 0
        complete = True
        ordered = sorted(
            (item for item in self.segments if item.length > 0),
            key=lambda item: (item.start, item.end),
        )
        for range_object in ordered:
            if range_object.start != cursor:
                complete = False
                self.add_issue(
                    "coverage_partition_failed",
                    "Coverage intervals do not form one ordered, disjoint "
                    "partition of the file.",
                    expected_offset=cursor,
                    actual_offset=range_object.start,
                )
                break
            cursor = range_object.end

        if complete and cursor != self.file_size:
            complete = False
            self.add_issue(
                "coverage_partition_incomplete",
                "Coverage intervals end before the end of the file.",
                expected_offset=self.file_size,
                actual_offset=cursor,
            )

        self.partition_complete = complete
        self.complete = complete
        if not complete:
            self.provable = False

    def _finalize(self):
        if not self.supported:
            self.status = UNSUPPORTED
        elif not self.provable:
            self.status = UNPROVABLE
        else:
            self.status = PROVABLE

        self.state = self.status
        self.coverage_status = self.status
        self.provability_status = self.status
        self.provable = self.status == PROVABLE
        self.is_provable = self.provable
        self.verifiable = self.provable
        self.is_verifiable = self.provable
        self.verifiability = "verifiable" if self.provable else "unverifiable"
        self.provability = "provable" if self.provable else "unprovable"

        self.exclusions = self.excluded_ranges
        self.unsigned_ranges = self.excluded_ranges
        self.non_digest_ranges = self.excluded_ranges
        self.security_directory = self.security_directory_range
        self.security_data_directory_range = self.security_directory_range
        self.certificate_table = self.certificate_table_range

    def get_digest(self, algorithm="sha256", data=None, strict=True):
        if strict and not self.provable:
            raise AuthenticodeCoverageError(
                "Refusing to compute a digest for unprovable Authenticode "
                "coverage; inspect issues and anomalies first."
            )
        if data is None:
            data = getattr(self.pe, "__data__", None)
        if data is None:
            raise AuthenticodeCoverageError("No PE file data is available.")

        hasher = hashlib.new(algorithm)
        for range_object in self.digest_ranges:
            hasher.update(data[range_object.start:range_object.end])
        return hasher.digest()

    def digest(self, algorithm="sha256", data=None, strict=True):
        return self.get_digest(algorithm=algorithm, data=data, strict=strict)

    def hexdigest(self, algorithm="sha256", data=None, strict=True):
        return self.get_digest(
            algorithm=algorithm, data=data, strict=strict
        ).hex()

    def compute_digest(self, algorithm="sha256", data=None, strict=True):
        return self.get_digest(
            algorithm=algorithm, data=data, strict=strict
        )

    def _add_content_range(self, start, end, source, label=None):
        start = max(0, int(start))
        end = min(self.file_size, int(end))
        if start < end:
            range_object = AuthenticodeCoverageRange(
                start,
                end,
                CONTENT,
                included=True,
                source=source,
                label=label or source,
            )
            self.segments.append(range_object)
            return range_object
        return None

    def _build_segments(self, header_end):
        exclusions = self._exclusion_ranges()
        for exclusion in exclusions:
            self.segments.append(exclusion)

        checksum = self.checksum_range
        security = self.security_directory_range
        if checksum is not None and security is not None:
            header_pieces = [
                (0, checksum.start, "header_before_checksum"),
                (
                    checksum.end,
                    security.start,
                    "optional_header_before_security_directory",
                ),
                (
                    security.end,
                    header_end,
                    "headers_after_security_directory",
                ),
            ]
        else:
            header_pieces = [(0, header_end, "pe_headers")]

        for start, end, source in header_pieces:
            self._add_content_range(start, end, "header:" + source, source)

        for mapping in self.section_mappings:
            section_range = mapping.get("range")
            if section_range is not None:
                self.segments.append(section_range)

        source_intervals = []
        safe_header_end = max(0, min(int(header_end or 0), self.file_size))
        if safe_header_end > 0:
            source_intervals.append((0, safe_header_end))

        for mapping in self.section_mappings:
            section_range = mapping.get("range")
            if section_range is None or section_range.length <= 0:
                continue
            start = max(0, section_range.start)
            end = min(self.file_size, section_range.end)
            if start < end:
                source_intervals.append((start, end))

        source_intervals.sort(key=lambda item: (item[0], item[1]))
        cursor = 0
        for start, end in source_intervals:
            if end <= cursor:
                continue
            if start > cursor:
                gap_range = AuthenticodeCoverageRange(
                    cursor,
                    start,
                    GAP,
                    included=None,
                    source="unmapped_gap",
                    label="Unmapped layout gap",
                )
                self.segments.append(gap_range)
                self.add_issue(
                    "unmapped_layout_gap",
                    "A file interval is outside the header and raw section "
                    "layout; digest coverage is not provable.",
                    start=cursor,
                    end=start,
                )
            cursor = max(cursor, end)

        tail_specs = []
        overlay_start = self.overlay_offset
        if (
            overlay_start is not None
            and cursor <= overlay_start < self.file_size
        ):
            if cursor < overlay_start:
                tail_specs.append((cursor, overlay_start, "other_after_sections"))
            tail_specs.append((overlay_start, self.file_size, "overlay"))
        else:
            tail_specs.append((cursor, self.file_size, "tail_after_sections"))

        for start, end, source in tail_specs:
            for fragment_start, fragment_end in self._subtract_exclusions(
                start, end, exclusions
            ):
                self._add_content_range(
                    fragment_start, fragment_end, source, source
                )

        self.segments.sort(key=lambda item: (item.start, item.end, item.kind))
        self.ranges = self.segments
        self.excluded_ranges = sorted(
            exclusions, key=lambda item: (item.start, item.end)
        )
        self.exclusions = self.excluded_ranges
        self.digest_ranges = [
            item
            for item in self.segments
            if item.included is True and item.length > 0
        ]
        for alias_name in (
            "digest_input_ranges",
            "ordered_digest_ranges",
            "ordered_ranges",
            "covered_ranges",
            "hash_ranges",
            "included_ranges",
        ):
            setattr(self, alias_name, self.digest_ranges)

    @staticmethod
    def _jsonable(value):
        if hasattr(value, "as_dict"):
            return value.as_dict()
        if isinstance(value, dict):
            return {
                str(key): AuthenticodeCoverage._jsonable(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [AuthenticodeCoverage._jsonable(item) for item in value]
        return value

    def as_dict(self):
        result = {}
        for key, value in self.__dict__.items():
            if key == "pe":
                continue
            result[key] = self._jsonable(value)
        result["signature_valid"] = None
        result["signature_validation"] = "not_performed"
        return result

    def __getitem__(self, key):
        if key == "as_dict":
            return self.as_dict()
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def get(self, key, default=None):
        return getattr(self, key, default)


def analyze_authenticode_coverage(source=None, **kwargs):
    """Analyze a pefile.PE object or load PE bytes/path."""
    pe = source
    if not hasattr(pe, "OPTIONAL_HEADER"):
        import pefile

        fast_load = kwargs.get("fast_load", True)
        if isinstance(pe, (bytes, bytearray)):
            pe = pefile.PE(data=bytes(pe), fast_load=fast_load)
        elif isinstance(pe, str):
            pe = pefile.PE(pe, fast_load=fast_load)
        else:
            raise TypeError("source must be a pefile.PE, bytes, or PE path")
    return AuthenticodeCoverage(pe)


get_authenticode_coverage = analyze_authenticode_coverage
authenticode_coverage = analyze_authenticode_coverage
analyze_pe_authenticode_coverage = analyze_authenticode_coverage
get_authenticode_coverage_analysis = analyze_authenticode_coverage


def compute_authenticode_digest(source, algorithm="sha256", strict=True):
    coverage = analyze_authenticode_coverage(source)
    return coverage.get_digest(algorithm=algorithm, strict=strict)


def get_authenticode_digest_hex(source, algorithm="sha256", strict=True):
    coverage = analyze_authenticode_coverage(source)
    return coverage.hexdigest(algorithm=algorithm, strict=strict)


get_authenticode_hash = get_authenticode_digest_hex


class AuthenticodeCoverageAnalyzer:
    """Object-oriented alias for callers that prefer an analyzer type."""

    def analyze(self, source, **kwargs):
        return analyze_authenticode_coverage(source, **kwargs)

    __call__ = analyze_authenticode_coverage


AUTHENTICODE_COVERAGE_PROVABLE = PROVABLE
AUTHENTICODE_COVERAGE_UNPROVABLE = UNPROVABLE
AUTHENTICODE_COVERAGE_UNSUPPORTED = UNSUPPORTED
