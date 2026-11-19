"""Delta-debugging style reduction of failing PE samples.

A failing sample is reduced by deleting whole data directories and whole
sections.  A candidate is accepted only when (1) the failure predicate still
fires and (2) the deep-path coverage fingerprint of the original sample is
still reached, so reduction can never silently turn a deep failure into a
trivial DOS-header rejection.
"""

from dataclasses import dataclass, field

from .coverage import DirectoryCoverage
from . import pe_constants as C


@dataclass
class ReductionResult:
    data: bytes
    original_size: int
    reduced_size: int
    removed_directories: list = field(default_factory=list)
    removed_sections: list = field(default_factory=list)
    iterations: int = 0

    @property
    def shrink_ratio(self):
        if self.original_size == 0:
            return 0.0
        return self.reduced_size / self.original_size


def _fingerprint(parse_callable):
    """Directory parse events plus max resource depth for one parse."""
    with DirectoryCoverage() as tracer:
        try:
            parse_callable()
        except Exception:
            pass
    report = tracer.report
    return (
        frozenset(report.directory_hits.items()),
        report.resource_max_depth,
    )


def _covers_fingerprint(candidate_fp, required_fp):
    """A reduced image must still enter every parser the failure reached."""
    candidate_hits, candidate_depth = candidate_fp
    required_hits, required_depth = required_fp
    candidate_map = dict(candidate_hits)
    for name, count in required_hits:
        if candidate_map.get(name, 0) < 1:
            return False
    return candidate_depth >= required_depth


def _zero_directory(data, directory_index):
    import pefile

    pe = pefile.PE(data=bytes(data), fast_load=True)
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
    if entry.VirtualAddress == 0 and entry.Size == 0:
        return None
    mutated = bytearray(data)
    offset = entry.get_file_offset()
    mutated[offset:offset + 8] = b"\x00" * 8
    return bytes(mutated)


def _drop_section(data, section_name):
    import pefile
    import struct

    pe = pefile.PE(data=bytes(data), fast_load=True)
    target = None
    for section in pe.sections:
        label = section.Name.rstrip(b"\x00")
        if label == section_name:
            target = section
    if target is None or len(pe.sections) <= 1:
        return None

    mutated = bytearray(data)
    header_offset = target.get_file_offset()
    header_size = target.sizeof()
    mutated[header_offset:header_offset + header_size] = b"\x00" * header_size
    raw = target.PointerToRawData
    raw_size = target.SizeOfRawData
    if raw and raw_size:
        mutated[raw:raw + raw_size] = b"\x00" * raw_size

    count_field = pe.FILE_HEADER.get_file_offset() + 2
    struct.pack_into(
        "<H",
        mutated,
        count_field,
        pe.FILE_HEADER.NumberOfSections - 1,
    )
    return bytes(mutated)


def reduce_failure(data, failure_predicate, parse_callable_factory):
    """Shrink a failing sample while preserving its deep-path fingerprint.

    Parameters
    ----------
    data:
        The raw bytes of a sample known to trigger ``failure_predicate``.
    failure_predicate:
        Callable ``(bytes) -> bool`` returning True while the failure is
        still reproduced.
    parse_callable_factory:
        Callable ``(bytes) -> zero-arg callable`` used by the coverage
        tracer to observe which directory parsers are reached.
    """
    original = bytes(data)
    if not failure_predicate(original):
        raise ValueError("input does not trigger the failure predicate")

    required_fp = _fingerprint(parse_callable_factory(original))
    current = original
    result = ReductionResult(
        data=current,
        original_size=len(original),
        reduced_size=len(current),
    )

    def accept(candidate):
        if candidate is None or len(candidate) >= len(current):
            return False
        if not failure_predicate(candidate):
            return False
        candidate_fp = _fingerprint(parse_callable_factory(candidate))
        return _covers_fingerprint(candidate_fp, required_fp)

    import pefile

    directory_indices = list(C.DIRECTORY_NAMES.keys())
    for directory_index in directory_indices:
        result.iterations += 1
        candidate = _zero_directory(current, directory_index)
        if accept(candidate):
            result.removed_directories.append(
                C.DIRECTORY_NAMES[directory_index]
            )
            current = candidate

    section_names = []
    pe = pefile.PE(data=bytes(current), fast_load=True)
    for section in pe.sections:
        section_names.append(section.Name.rstrip(b"\x00"))
    for section_name in section_names:
        result.iterations += 1
        candidate = _drop_section(current, section_name)
        if accept(candidate):
            result.removed_sections.append(
                section_name.decode(errors="replace")
            )
            current = candidate

    current = _trim_trailing_slack(
        current,
        failure_predicate,
        parse_callable_factory,
        required_fp,
    )

    result.data = current
    result.reduced_size = len(current)
    return result


def _trim_trailing_slack(data, failure_predicate, parse_factory, required_fp):
    """Shrink trailing filler bytes while keeping the failure and fingerprint."""
    import pefile

    pe = pefile.PE(data=bytes(data), fast_load=True)
    last_used = 0
    for section in pe.sections:
        end = section.PointerToRawData + section.SizeOfRawData
        last_used = max(last_used, end)
    headers_end = pe.OPTIONAL_HEADER.SizeOfHeaders
    last_used = max(last_used, headers_end)

    current = bytes(data)
    low = last_used
    high = len(current)
    best = current
    while low < high:
        mid = (low + high + 1) // 2
        aligned = ((mid + 0x1FF) // 0x200) * 0x200
        candidate = current[:aligned]
        if len(candidate) >= len(current):
            high = mid - 1
            continue
        if not failure_predicate(candidate):
            high = mid - 1
            continue
        candidate_fp = _fingerprint(parse_factory(candidate))
        if not _covers_fingerprint(candidate_fp, required_fp):
            high = mid - 1
            continue
        best = candidate
        low = mid
    return best
