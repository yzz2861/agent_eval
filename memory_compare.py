"""Read-only comparison of a disk PE against sparse in-memory fragments.

The backend never relocates or otherwise mutates the parsed PE.  It builds a
disk-mapped image, predicts the bytes changed by deterministic base
relocations, records loader-owned IAT slots, and only then compares observed
memory bytes.  Missing observations are reported as unavailable or
indeterminate ranges rather than being zero-filled and judged as tampering.
"""

from collections.abc import Mapping
from heapq import heappop, heappush
import os


__all__ = [
    "MemoryComparisonResult",
    "MemoryFragment",
    "ComparisonFinding",
    "compare_memory_image",
    "compare_memory",
    "compare_memory_images",
    "compare_pe_memory",
    "compare_pe_to_memory",
]


class ComparisonFinding:
    """An interval or point emitted by the comparison backend."""

    def __init__(
        self, kind, rva_start, rva_end=None, actual_image_base=None, **attributes
    ):
        self.kind = str(kind)
        self.rva_start = int(rva_start)
        self.rva_end = self.rva_start if rva_end is None else int(rva_end)
        if self.rva_end < self.rva_start:
            raise ValueError("rva_end must not precede rva_start")

        self.actual_image_base = (
            None if actual_image_base is None else int(actual_image_base)
        )
        if self.actual_image_base is None:
            self.va_start = None
            self.va_end = None
        else:
            self.va_start = self.actual_image_base + self.rva_start
            self.va_end = self.actual_image_base + self.rva_end

        for name, value in attributes.items():
            setattr(self, name, value)

    @property
    def start(self):
        return self.rva_start

    @property
    def end(self):
        return self.rva_end

    @property
    def length(self):
        return self.rva_end - self.rva_start

    def contains_rva(self, rva):
        return self.rva_start <= int(rva) < self.rva_end

    def to_dict(self):
        result = {}
        for name, value in vars(self).items():
            if name.startswith("_"):
                continue
            if isinstance(value, (bytes, bytearray)):
                result[name] = bytes(value).hex()
            elif isinstance(value, ComparisonFinding):
                result[name] = value.to_dict()
            elif isinstance(value, list):
                result[name] = [
                    item.to_dict() if isinstance(item, ComparisonFinding) else item
                    for item in value
                ]
            else:
                result[name] = value
        result["length"] = self.length
        return result

    def __repr__(self):
        return (
            f"{self.kind}(rva={self.rva_start:#x}..{self.rva_end:#x}, "
            f"length={self.length})"
        )


class MemoryFragment:
    """A sparse memory run beginning at an absolute virtual address or RVA."""

    def __init__(self, address, data, source=None, address_space="virtual"):
        self.address = int(address)
        self.data = bytes(data)
        self.source = source
        self.address_space = address_space

    @classmethod
    def at_rva(cls, rva, data, source=None):
        return cls(int(rva), data, source=source, address_space="rva")

    def __repr__(self):
        return f"MemoryFragment({self.address:#x}, {len(self.data)} bytes)"


class MemoryComparisonResult:
    """Structured result of :func:`compare_memory_image`."""

    def __init__(self, disk_pe, actual_image_base, image_size, page_size):
        self.disk_pe = disk_pe
        self.actual_image_base = int(actual_image_base)
        self.image_size = int(image_size)
        self.page_size = int(page_size)

        self.preferred_image_base = None
        self.machine = None
        self.machine_name = None
        self.pointer_size = None
        self.delta = None

        self.warnings = []
        self.claims = []
        self.explanations = self.claims
        self.conflicts = []
        self.conflict_ranges = self.conflicts
        self.fragment_conflicts = []
        self.observed_ranges = []
        self.unavailable_ranges = []
        self.missing_ranges = self.unavailable_ranges
        self.missing_pages = []
        self.unobserved_gaps = []
        self.indeterminate_ranges = []
        self.undecidable_ranges = self.indeterminate_ranges
        self.unknown_relocations = []
        self.unsupported_relocations = []

        self.differences = []
        self.explained_changes = []
        self.exempt_changes = self.explained_changes
        self.explained_ranges = self.explained_changes
        self.unverified_loader_changes = []
        self.suspicious_differences = []
        self.remaining_suspicious_differences = self.suspicious_differences
        self.suspicious_ranges = self.suspicious_differences
        self.indeterminate_differences = []

    @property
    def is_clean(self):
        return not self.suspicious_differences and not self.conflicts

    def summary(self):
        return {
            "image_size": self.image_size,
            "claims": len(self.claims),
            "differences": len(self.differences),
            "explained_changes": len(self.explained_changes),
            "suspicious_differences": len(self.suspicious_differences),
            "indeterminate_differences": len(self.indeterminate_differences),
            "unavailable_ranges": len(self.unavailable_ranges),
            "missing_pages": len(self.missing_pages),
            "conflicts": len(self.conflicts),
            "warnings": len(self.warnings),
        }

    def to_dict(self):
        def convert(value):
            if isinstance(value, ComparisonFinding):
                return value.to_dict()
            if isinstance(value, (bytes, bytearray)):
                return bytes(value).hex()
            if isinstance(value, Mapping):
                return {key: convert(item) for key, item in value.items()}
            if isinstance(value, (list, tuple)):
                return [convert(item) for item in value]
            return value

        return {
            "actual_image_base": self.actual_image_base,
            "preferred_image_base": self.preferred_image_base,
            "image_size": self.image_size,
            "page_size": self.page_size,
            "machine": self.machine,
            "machine_name": self.machine_name,
            "pointer_size": self.pointer_size,
            "delta": self.delta,
            "summary": self.summary(),
            "warnings": list(self.warnings),
            "claims": convert(self.claims),
            "conflicts": convert(self.conflicts),
            "fragment_conflicts": convert(self.fragment_conflicts),
            "observed_ranges": convert(self.observed_ranges),
            "unavailable_ranges": convert(self.unavailable_ranges),
            "missing_pages": convert(self.missing_pages),
            "unobserved_gaps": convert(self.unobserved_gaps),
            "indeterminate_ranges": convert(self.indeterminate_ranges),
            "differences": convert(self.differences),
            "explained_changes": convert(self.explained_changes),
            "unverified_loader_changes": convert(self.unverified_loader_changes),
            "suspicious_differences": convert(self.suspicious_differences),
            "indeterminate_differences": convert(self.indeterminate_differences),
        }


class _IntervalSweep:
    """Small heap-backed sweep used to find intervals covering one RVA."""

    def __init__(self, intervals):
        self.intervals = sorted(
            intervals, key=lambda item: (item.rva_start, item.rva_end)
        )
        self.index = 0
        self.serial = 0
        self.heap = []

    def advance_to(self, rva):
        while (
            self.index < len(self.intervals)
            and self.intervals[self.index].rva_start <= rva
        ):
            interval = self.intervals[self.index]
            self.index += 1
            self.serial += 1
            heappush(
                self.heap,
                (interval.rva_end, self.serial, interval),
            )

        while self.heap and self.heap[0][0] <= rva:
            heappop(self.heap)

    def active(self):
        return [entry[2] for entry in self.heap]


def _load_pe(disk_pe):
    import pefile

    if isinstance(disk_pe, pefile.PE):
        return disk_pe

    if isinstance(disk_pe, (bytes, bytearray, memoryview)):
        return pefile.PE(data=bytes(disk_pe))

    if hasattr(disk_pe, "read"):
        return pefile.PE(data=disk_pe.read())

    if isinstance(disk_pe, (str, os.PathLike)):
        return pefile.PE(name=os.fspath(disk_pe))

    raise TypeError("disk_pe must be a pefile.PE, path, file object, or bytes")


def _normalize_fragments(fragments):
    if fragments is None:
        return []

    if isinstance(fragments, (bytes, bytearray, memoryview)):
        return [(None, bytes(fragments), "contiguous", "virtual")]

    if isinstance(fragments, Mapping):
        result = []
        for address, data in fragments.items():
            result.append((int(address), bytes(data), f"mapping-{address:#x}", None))
        return result

    result = []
    for index, fragment in enumerate(fragments):
        if isinstance(fragment, MemoryFragment):
            result.append(
                (
                    fragment.address,
                    fragment.data,
                    fragment.source or f"fragment-{index}",
                    fragment.address_space,
                )
            )
        elif isinstance(fragment, Mapping):
            address = fragment.get(
                "virtual_address",
                fragment.get("address", fragment.get("base_address", fragment.get("rva"))),
            )
            data = fragment.get("data", b"")
            result.append(
                (
                    int(address),
                    bytes(data),
                    fragment.get("source", f"fragment-{index}"),
                    fragment.get("address_space"),
                )
            )
        elif hasattr(fragment, "address") and hasattr(fragment, "data"):
            address_space = getattr(fragment, "address_space", None)
            result.append(
                (
                    int(fragment.address),
                    bytes(fragment.data),
                    getattr(fragment, "source", f"fragment-{index}"),
                    address_space,
                )
            )
        else:
            address, data = fragment[:2]
            result.append(
                (int(address), bytes(data), f"fragment-{index}", None)
            )
    return result


def _rva_from_address(address, actual_base, image_size, address_space):
    if address is None:
        return 0

    address = int(address)
    if address_space == "rva":
        return address
    if address_space == "auto":
        if actual_base <= address < actual_base + image_size:
            return address - actual_base
        if 0 <= address < image_size:
            return address
        return address - actual_base
    return address - actual_base


def _merge_fragments(
    fragment_inputs, actual_base, image_size, address_space, result
):
    normalized = []
    for address, data, source, fragment_space in fragment_inputs:
        mode = fragment_space or address_space
        try:
            rva = _rva_from_address(
                address, actual_base, image_size, mode
            )
        except (TypeError, ValueError):
            result.warnings.append(f"Ignoring invalid fragment address: {address!r}")
            continue

        original_start = rva
        original_end = rva + len(data)
        clipped_start = max(0, original_start)
        clipped_end = min(image_size, original_end)
        if clipped_start >= clipped_end:
            result.warnings.append(
                f"Fragment {source!r} does not intersect SizeOfImage; ignored"
            )
            continue

        skip = clipped_start - original_start
        data = data[skip : skip + (clipped_end - clipped_start)]
        normalized.append((clipped_start, clipped_end, bytes(data), source))

    normalized.sort(key=lambda item: (item[0], item[1]))

    merged = []
    bad_positions = set()
    for start, end, data, source in normalized:
        if not merged or start > merged[-1][1]:
            merged.append([start, end, bytearray(data), [source]])
            continue

        current = merged[-1]
        overlap_end = min(end, current[1])
        for rva in range(start, overlap_end):
            current_byte = current[2][rva - current[0]]
            new_byte = data[rva - start]
            if current_byte != new_byte:
                bad_positions.add(rva)

        if end > current[1]:
            current[2].extend(data[current[1] - start :])
            current[1] = end
        current[3].append(source)

    fragment_conflicts = []
    for start, end in _group_positions(sorted(bad_positions)):
        conflict = ComparisonFinding(
            "sparse_fragment_conflict",
            start,
            end,
            actual_base,
            description="Overlapping memory fragments contain different bytes",
        )
        result.fragment_conflicts.append(conflict)
        fragment_conflicts.append(conflict)

    for start, end, data, sources in merged:
        result.observed_ranges.append(
            ComparisonFinding(
                "observed_range",
                start,
                end,
                actual_base,
                sources=list(sources),
                observed_bytes=bytes(data),
            )
        )

    return merged, fragment_conflicts


def _group_positions(positions):
    if not positions:
        return []

    groups = []
    start = previous = positions[0]
    for position in positions[1:]:
        if position == previous + 1:
            previous = position
            continue
        groups.append((start, previous + 1))
        start = previous = position
    groups.append((start, previous + 1))
    return groups


def _add_unavailable_ranges(result, page_size):
    cursor = 0
    for observed in result.observed_ranges:
        start, end = observed.rva_start, observed.rva_end
        if start > cursor:
            _classify_unavailable_run(result, cursor, start, page_size)
        cursor = max(cursor, end)

    if cursor < result.image_size:
        _classify_unavailable_run(result, cursor, result.image_size, page_size)


def _classify_unavailable_run(result, start, end, page_size):
    page = start // page_size
    while page * page_size < end:
        page_start = page * page_size
        page_end = min(result.image_size, (page + 1) * page_size)
        low = max(start, page_start)
        high = min(end, page_end)
        if low < high:
            is_full_page = low == page_start and high == page_end
            if is_full_page:
                finding = ComparisonFinding(
                    "missing_page",
                    page_start,
                    page_end,
                    result.actual_image_base,
                    page_number=page,
                    decision="unavailable",
                )
                result.missing_pages.append(finding)
            else:
                finding = ComparisonFinding(
                    "unobserved_gap",
                    low,
                    high,
                    result.actual_image_base,
                    page_number=page,
                    decision="undecidable",
                )
                result.unobserved_gaps.append(finding)

            result.unavailable_ranges.append(finding)
            result.indeterminate_ranges.append(finding)

        page += 1


def _normalize_resolved_iat(
    resolved_iat, actual_base, preferred_base, image_size, pointer_size
):
    normalized = {}
    if not resolved_iat:
        return normalized

    mask = (1 << (8 * pointer_size)) - 1
    for address, value in dict(resolved_iat).items():
        address = int(address)
        if actual_base <= address < actual_base + image_size:
            rva = address - actual_base
        elif preferred_base <= address < preferred_base + image_size:
            rva = address - preferred_base
        else:
            rva = address

        if isinstance(value, (bytes, bytearray)):
            value = int.from_bytes(bytes(value), "little", signed=False)
        normalized[rva] = (int(value) & mask).to_bytes(pointer_size, "little")
    return normalized


def _add_relocation_claims(
    pe, disk_image, actual_base, image_size, result, add_claim, unknown_probe
):
    import pefile

    reloc_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[reloc_index]
    if not directory.VirtualAddress or not directory.Size:
        return

    try:
        pe.parse_data_directories(directories=[reloc_index])
    except Exception as excp:
        result.warnings.append(f"Could not parse base relocations: {excp}")
        return

    supported = {
        pefile.RELOCATION_TYPE["IMAGE_REL_BASED_HIGHLOW"]: (4, "<I"),
        pefile.RELOCATION_TYPE["IMAGE_REL_BASED_DIR64"]: (8, "<Q"),
    }

    relocations = getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []) or []
    for block in relocations:
        block_rva = int(block.struct.VirtualAddress)
        for entry in block.entries:
            reloc_type = int(entry.type)
            rva = int(entry.rva)
            type_name = pefile.RELOCATION_TYPE.get(
                reloc_type, f"IMAGE_REL_BASED_UNKNOWN_{reloc_type}"
            )

            if reloc_type == pefile.RELOCATION_TYPE["IMAGE_REL_BASED_ABSOLUTE"]:
                continue

            if reloc_type in supported:
                width, _format = supported[reloc_type]
                if rva < 0 or rva + width > min(image_size, len(disk_image)):
                    result.warnings.append(
                        f"Relocation {type_name} at {rva:#x} is outside mapped image"
                    )
                    continue

                old_value = int.from_bytes(
                    disk_image[rva : rva + width], "little", signed=False
                )
                mask = (1 << (8 * width)) - 1
                expected_value = (old_value + result.delta) & mask
                expected = expected_value.to_bytes(width, "little")

                architecture_note = None
                if result.machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
                    if reloc_type != pefile.RELOCATION_TYPE["IMAGE_REL_BASED_HIGHLOW"]:
                        architecture_note = "Unexpected relocation type for I386"
                elif result.machine in (
                    pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"],
                    pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_ARM64"],
                ):
                    if reloc_type != pefile.RELOCATION_TYPE["IMAGE_REL_BASED_DIR64"]:
                        architecture_note = (
                            "Unexpected relocation type for 64-bit architecture"
                        )
                if architecture_note:
                    result.warnings.append(
                        f"{architecture_note}: {type_name} at RVA {rva:#x}"
                    )

                add_claim(
                    "base_relocation",
                    rva,
                    rva + width,
                    expected=expected,
                    verification="exact",
                    relocation_type=reloc_type,
                    relocation_type_name=type_name,
                    block_rva=block_rva,
                    old_value=old_value,
                    expected_value=expected_value,
                    architecture_note=architecture_note,
                )
                continue

            known_type = reloc_type in pefile.RELOCATION_TYPE
            kind = (
                "unsupported_relocation_type"
                if known_type
                else "unknown_relocation_type"
            )
            probe_end = min(image_size, rva + max(1, int(unknown_probe)))
            if probe_end <= rva and 0 <= rva < image_size:
                probe_end = rva + 1
            if 0 <= rva < image_size and probe_end > rva:
                uncertainty = ComparisonFinding(
                    kind,
                    rva,
                    probe_end,
                    actual_base,
                    anchor_rva=rva,
                    relocation_type=reloc_type,
                    relocation_type_name=type_name,
                    block_rva=block_rva,
                    conservative_envelope=True,
                    decision="undecidable",
                )
                result.indeterminate_ranges.append(uncertainty)
                if kind == "unknown_relocation_type":
                    result.unknown_relocations.append(uncertainty)
                else:
                    result.unsupported_relocations.append(uncertainty)
            result.warnings.append(
                f"{kind} {reloc_type} ({type_name}) at RVA {rva:#x}; "
                "other relocations remain active"
            )


def _add_iat_claims(
    pe, actual_base, image_size, result, add_claim, resolved_iat
):
    import pefile

    pointer_size = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
    iat_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]
    import_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
    resolved = _normalize_resolved_iat(
        resolved_iat,
        actual_base,
        int(pe.OPTIONAL_HEADER.ImageBase),
        image_size,
        pointer_size,
    )

    try:
        pe.parse_data_directories(directories=[import_index, iat_index])
    except Exception as excp:
        result.warnings.append(f"Could not parse import/IAT directory: {excp}")

    slot_count = 0
    imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []
    for descriptor in imports:
        first_thunk = int(descriptor.struct.FirstThunk)
        dll_name = getattr(descriptor, "dll", b"") or b""
        for index, imported in enumerate(getattr(descriptor, "imports", []) or []):
            rva = first_thunk + index * pointer_size
            preferred_va = int(pe.OPTIONAL_HEADER.ImageBase)
            imported_address = getattr(imported, "address", None)
            if imported_address:
                address_rva = int(imported_address) - preferred_va
                if 0 <= address_rva < image_size:
                    rva = address_rva
            if rva < 0 or rva + pointer_size > image_size:
                result.warnings.append(f"IAT slot at RVA {rva:#x} is outside image")
                continue

            expected = resolved.get(rva)
            import_name = getattr(imported, "name", None)
            if isinstance(import_name, bytes):
                import_name = import_name.decode("utf-8", "replace")

            add_claim(
                "iat_binding",
                rva,
                rva + pointer_size,
                expected=expected,
                verification="exact" if expected is not None else "import_slot",
                dll=dll_name,
                import_name=import_name,
                ordinal=getattr(imported, "ordinal", None),
                iat_rva=rva,
            )
            slot_count += 1

    if slot_count == 0:
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[iat_index]
        if directory.VirtualAddress and directory.Size:
            start = int(directory.VirtualAddress)
            end = min(image_size, start + int(directory.Size))
            if 0 <= start < end:
                add_claim(
                    "iat_directory",
                    start,
                    end,
                    expected=None,
                    verification="data_directory",
                    iat_directory_size=int(directory.Size),
                )


def _add_zero_fill_claims(pe, image_size, add_claim):
    for section in getattr(pe, "sections", []) or []:
        virtual_address = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        virtual_size = int(section.Misc_VirtualSize or 0)
        if virtual_size <= raw_size:
            continue

        start = virtual_address + raw_size
        end = virtual_address + virtual_size
        if 0 <= start < end <= image_size:
            add_claim(
                "bss_zero_fill",
                start,
                end,
                expected=bytes(end - start),
                verification="exact",
                section_name=getattr(section, "Name", b""),
            )


def _build_conflicts(claims, actual_base):
    events = []
    for claim in claims:
        events.append((claim.rva_start, 1, claim.claim_id))
        events.append((claim.rva_end, -1, claim.claim_id))
    events.sort(key=lambda event: (event[0], event[1]))

    active = set()
    previous = None
    conflicts = []
    for position, delta, claim_id in events:
        if previous is not None and position > previous and len(active) >= 2:
            conflicts.append(
                ComparisonFinding(
                    "explanation_conflict",
                    previous,
                    position,
                    actual_base,
                    claim_ids=sorted(active),
                    decision="conflict",
                )
            )

        if delta == 1:
            active.add(claim_id)
        else:
            active.discard(claim_id)
        previous = position

    return conflicts


def _classify_byte(
    rva, memory_byte, claims, uncertainties, fragment_conflicts
):
    claim_ids = tuple(claim.claim_id for claim in claims)

    if fragment_conflicts:
        return {
            "status": "indeterminate",
            "kind": "sparse_fragment_conflict",
            "claim_ids": claim_ids,
            "conflict": False,
            "verification": "observation_conflict",
        }

    if len(claims) > 1:
        exact_matches = []
        mismatching_exact = []
        loader_slots = []
        for claim in claims:
            expected = getattr(claim, "expected", None)
            if expected is None:
                loader_slots.append(claim)
                continue
            expected_byte = expected[rva - claim.rva_start]
            if memory_byte == expected_byte:
                exact_matches.append(claim)
            else:
                mismatching_exact.append(claim)

        if exact_matches:
            return {
                "status": "explained",
                "kind": "overlapping_loader_transforms",
                "claim_ids": claim_ids,
                "conflict": True,
                "verification": "exact",
            }
        if mismatching_exact and not loader_slots:
            return {
                "status": "suspicious",
                "kind": "overlapping_transform_mismatch",
                "claim_ids": claim_ids,
                "conflict": True,
                "verification": "exact",
            }
        return {
            "status": "indeterminate",
            "kind": "explanation_conflict",
            "claim_ids": claim_ids,
            "conflict": True,
            "verification": "conflicting_loader_evidence",
        }

    if len(claims) == 1:
        claim = claims[0]
        expected = getattr(claim, "expected", None)
        if expected is not None:
            expected_byte = expected[rva - claim.rva_start]
            if memory_byte == expected_byte:
                return {
                    "status": "explained",
                    "kind": claim.kind,
                    "claim_ids": claim_ids,
                    "conflict": False,
                    "verification": "exact",
                }
            return {
                "status": "suspicious",
                "kind": claim.kind + "_mismatch",
                "claim_ids": claim_ids,
                "conflict": False,
                "verification": "exact_expected_value_violated",
                "expected_byte": expected_byte,
            }

        return {
            "status": "explained",
            "kind": claim.kind,
            "claim_ids": claim_ids,
            "conflict": False,
            "verification": getattr(claim, "verification", "loader_slot"),
        }

    if uncertainties:
        uncertainty = uncertainties[0]
        return {
            "status": "indeterminate",
            "kind": uncertainty.kind,
            "claim_ids": (),
            "conflict": False,
            "verification": getattr(uncertainty, "decision", "undecidable"),
        }

    return {
        "status": "suspicious",
        "kind": "unexplained_difference",
        "claim_ids": (),
        "conflict": False,
        "verification": "no_loader_evidence",
    }


def compare_memory_image(
    disk_pe,
    memory_fragments=None,
    actual_image_base=None,
    *,
    actual_base=None,
    base_address=None,
    loaded_base=None,
    base=None,
    fragments=None,
    memory_regions=None,
    regions=None,
    address_space="auto",
    page_size=0x1000,
    resolved_iat=None,
    unknown_relocation_probe=16,
):
    """Compare sparse memory against a disk PE and loader transformations.

    ``memory_fragments`` may be :class:`MemoryFragment` objects,
    ``(address, bytes)`` pairs, or a mapping.  In the default ``"auto"``
    mode, addresses inside the loaded image are treated as virtual addresses;
    other small non-negative values are treated as RVAs.  Use
    ``address_space="virtual"``/``"rva"`` or :meth:`MemoryFragment.at_rva`
    to force an interpretation.
    """
    import pefile

    if memory_fragments is None:
        memory_fragments = fragments
    if memory_fragments is None:
        memory_fragments = memory_regions
    if memory_fragments is None:
        memory_fragments = regions
    if actual_image_base is None:
        actual_image_base = actual_base
    if actual_image_base is None:
        actual_image_base = base_address
    if actual_image_base is None:
        actual_image_base = loaded_base
    if actual_image_base is None:
        actual_image_base = base
    if actual_image_base is None:
        raise ValueError("actual_image_base is required for sparse VA fragments")
    if address_space not in ("virtual", "rva", "auto"):
        raise ValueError("address_space must be 'virtual', 'rva', or 'auto'")

    pe = _load_pe(disk_pe)
    actual_base = int(actual_image_base)
    image_size = int(pe.OPTIONAL_HEADER.SizeOfImage)
    if image_size <= 0:
        raise ValueError("PE OptionalHeader.SizeOfImage is invalid")

    result = MemoryComparisonResult(pe, actual_base, image_size, page_size)
    result.preferred_image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    result.delta = actual_base - result.preferred_image_base
    result.machine = int(pe.FILE_HEADER.Machine)
    result.machine_name = pefile.MACHINE_TYPE.get(
        result.machine, f"IMAGE_FILE_MACHINE_UNKNOWN_{result.machine:x}"
    )
    result.pointer_size = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4

    try:
        disk_image = bytearray(pe.get_memory_mapped_image())
    except Exception as excp:
        raise ValueError(f"Could not create mapped disk image: {excp}") from excp
    if len(disk_image) < image_size:
        disk_image.extend(b"\0" * (image_size - len(disk_image)))
    elif len(disk_image) > image_size:
        del disk_image[image_size:]

    claim_counter = 0

    def add_claim(kind, start, end, **attributes):
        nonlocal claim_counter
        claim_counter += 1
        claim = ComparisonFinding(
            kind,
            start,
            end,
            actual_base,
            claim_id=f"evidence-{claim_counter}",
            **attributes,
        )
        result.claims.append(claim)
        return claim

    _add_relocation_claims(
        pe,
        disk_image,
        actual_base,
        image_size,
        result,
        add_claim,
        unknown_relocation_probe,
    )
    _add_iat_claims(
        pe, actual_base, image_size, result, add_claim, resolved_iat
    )
    _add_zero_fill_claims(pe, image_size, add_claim)

    result.conflicts.extend(_build_conflicts(result.claims, actual_base))

    fragment_inputs = _normalize_fragments(memory_fragments)
    observed, fragment_conflicts = _merge_fragments(
        fragment_inputs, actual_base, image_size, address_space, result
    )
    _add_unavailable_ranges(result, int(page_size))

    claim_sweep = _IntervalSweep(result.claims)
    uncertainty_sweep = _IntervalSweep(result.indeterminate_ranges)
    conflict_sweep = _IntervalSweep(fragment_conflicts)

    current = None

    def finish_current():
        nonlocal current
        if current is None:
            return
        current.disk_bytes = bytes(current.disk_bytes)
        current.memory_bytes = bytes(current.memory_bytes)
        result.differences.append(current)
        if current.status == "explained":
            result.explained_changes.append(current)
            if current.verification != "exact":
                result.unverified_loader_changes.append(current)
        elif current.status == "suspicious":
            result.suspicious_differences.append(current)
        else:
            result.indeterminate_differences.append(current)
        current = None

    for observed_start, observed_end, memory_bytes, _sources in observed:
        for offset, memory_byte in enumerate(memory_bytes):
            rva = observed_start + offset
            disk_byte = disk_image[rva]

            if memory_byte == disk_byte:
                finish_current()
                continue

            claim_sweep.advance_to(rva)
            uncertainty_sweep.advance_to(rva)
            conflict_sweep.advance_to(rva)

            classification = _classify_byte(
                rva,
                memory_byte,
                claim_sweep.active(),
                uncertainty_sweep.active(),
                conflict_sweep.active(),
            )
            key = (
                classification["status"],
                classification["kind"],
                classification["claim_ids"],
                classification["conflict"],
                classification["verification"],
            )

            if (
                current is not None
                and rva == current.rva_end
                and current.classification_key == key
            ):
                current.rva_end = rva + 1
                current.va_end = actual_base + current.rva_end
                current.disk_bytes.append(disk_byte)
                current.memory_bytes.append(memory_byte)
                if "expected_byte" in classification:
                    current.expected_byte = classification["expected_byte"]
                continue

            finish_current()
            current = ComparisonFinding(
                "memory_difference",
                rva,
                rva + 1,
                actual_base,
                status=classification["status"],
                explanation=classification["kind"],
                claim_ids=list(classification["claim_ids"]),
                conflict=classification["conflict"],
                verification=classification["verification"],
                expected_byte=classification.get("expected_byte"),
                decision=classification["status"],
            )
            current.classification_key = key
            current.disk_bytes = bytearray([disk_byte])
            current.memory_bytes = bytearray([memory_byte])

        finish_current()

    try:
        result.warnings.extend(pe.get_warnings())
    except Exception:
        pass

    return result


compare_pe_memory = compare_memory_image
compare_pe_to_memory = compare_memory_image
compare_memory = compare_memory_image
compare_memory_images = compare_memory_image
