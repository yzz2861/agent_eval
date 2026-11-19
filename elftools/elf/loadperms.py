#-------------------------------------------------------------------------------
# elftools: elf/loadperms.py
#
# Static analysis of PT_LOAD segment mapping permissions.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
""" Load-permission analysis for PT_LOAD segments.

    This module answers one question: given an explicit page size and an
    explicit mapping policy, what permissions does each mapped page of an
    ELF image end up with, and where do writable+executable (W+X) pages
    come from?

    Scope and limitations (read before trusting the output):

    - Only PT_LOAD program headers are considered. Section flags (SHF_WRITE,
      SHF_EXECINSTR) are NOT runtime permissions: sections are a link-time
      view and are never consulted here.
    - The analysis is purely static. No code is executed, emulated, or
      loaded; no native extensions are used.
    - The mapping model is a page-granular policy in the spirit of common
      mmap-based loaders (e.g. Linux): a page spanned by several segments
      receives the union of their permissions. Real kernel loaders differ
      in details (bss handling, RELRO, PT_GNU_STACK, loader-specific
      fixups), so this module does NOT claim to model every kernel loader.
      The policy is an explicit input precisely so callers must choose one.
    - Structural problems (address overflow, p_align contradictions,
      unsupported ABI) are reported as independent diagnostics; they do not
      abort the analysis of the remaining, well-formed segments.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from .constants import P_FLAGS

if TYPE_CHECKING:
    from .elffile import ELFFile

__all__ = [
    'MappingPolicy',
    'DiagnosticKind',
    'Diagnostic',
    'SegmentMapping',
    'PagePermission',
    'WXConflict',
    'LoadPermissionReport',
    'analyze_load_permissions',
    'SUPPORTED_OSABIS',
]


class MappingPolicy(Enum):
    """ How segment permissions are turned into page permissions.

        SEGMENT_ONLY: each segment keeps exactly its own p_flags; overlaps
            between segments are ignored. This mirrors naive firmware
            analysis tools that look at one PT_LOAD at a time and therefore
            never see W+X created by overlapping segments.

        PAGE_UNION: permissions are computed per page; a page covered by
            several segments gets the union of their p_flags. This mirrors
            page-granular mmap-style loaders and is the policy under which
            a W-only segment and an X-only segment sharing one page produce
            a W+X page.
    """
    SEGMENT_ONLY = 'segment_only'
    PAGE_UNION = 'page_union'


class DiagnosticKind(Enum):
    ADDRESS_OVERFLOW = 'address_overflow'
    ALIGNMENT_CONTRADICTION = 'alignment_contradiction'
    UNSUPPORTED_ABI = 'unsupported_abi'


# ABIs for which the page-granular mapping model is considered meaningful.
# Anything else (including unrecognized raw values) is reported as
# UNSUPPORTED_ABI (analysis still proceeds).
SUPPORTED_OSABIS = frozenset({'ELFOSABI_SYSV', 'ELFOSABI_LINUX'})

_PERM_MASK = P_FLAGS.PF_R | P_FLAGS.PF_W | P_FLAGS.PF_X


@dataclass(frozen=True)
class Diagnostic:
    """ A single, independently reported structural problem. """
    kind: DiagnosticKind
    message: str
    segment_index: int | None = None


@dataclass(frozen=True)
class SegmentMapping:
    """ Static view of one PT_LOAD segment.

        file_range:   [start, end) file offsets backing the segment.
        vaddr_range:  [start, end) virtual addresses (p_memsz long).
        zero_fill_range: [start, end) virtual addresses beyond p_filesz
                      that a loader must zero (empty when memsz <= filesz).
        page_range:   [start, end) pages touched by vaddr_range.
        perms:        p_flags restricted to PF_R|PF_W|PF_X.
    """
    index: int
    file_range: tuple[int, int]
    vaddr_range: tuple[int, int]
    zero_fill_range: tuple[int, int]
    page_range: tuple[int, int]
    perms: int

    @property
    def perms_string(self) -> str:
        return _perms_to_string(self.perms)


@dataclass(frozen=True)
class PagePermission:
    """ Final permissions of one page under the chosen policy. """
    page_range: tuple[int, int]
    perms: int
    segment_indices: tuple[int, ...]

    @property
    def perms_string(self) -> str:
        return _perms_to_string(self.perms)

    @property
    def is_wx(self) -> bool:
        return bool(self.perms & P_FLAGS.PF_W) and bool(self.perms & P_FLAGS.PF_X)


@dataclass(frozen=True)
class WXConflict:
    """ A minimal maximal interval of contiguous W+X pages.

        segment_indices: indices of the PT_LOAD segments whose union of
            flags creates the W+X permission on this interval.
        explanation: human-readable description of which segments
            contribute W and which contribute X.
    """
    vaddr_range: tuple[int, int]
    segment_indices: tuple[int, ...]
    explanation: str


@dataclass
class LoadPermissionReport:
    """ Result of analyze_load_permissions. """
    page_size: int
    policy: MappingPolicy
    segments: list[SegmentMapping] = field(default_factory=list)
    pages: list[PagePermission] = field(default_factory=list)
    wx_conflicts: list[WXConflict] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.diagnostics

    def diagnostics_of(self, kind: DiagnosticKind) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.kind is kind]


def _perms_to_string(perms: int) -> str:
    return ''.join((
        'R' if perms & P_FLAGS.PF_R else '-',
        'W' if perms & P_FLAGS.PF_W else '-',
        'X' if perms & P_FLAGS.PF_X else '-',
    ))


def analyze_load_permissions(
    elffile: ELFFile,
    page_size: int,
    policy: MappingPolicy = MappingPolicy.PAGE_UNION,
) -> LoadPermissionReport:
    """ Analyze PT_LOAD mapping permissions of an ELF file.

        elffile:   an ELFFile opened on the image to analyze.
        page_size: mapping granularity in bytes; must be a power of two.
        policy:    explicit MappingPolicy (see its documentation).

        Returns a LoadPermissionReport with per-segment mappings, final
        per-page permissions, minimal W+X conflict intervals with their
        source segment indices, and independent diagnostics. Never raises
        for malformed segment tables; structural problems become
        Diagnostic entries instead. Raises ValueError only for invalid
        page_size or policy arguments.
    """
    if page_size <= 0 or page_size & (page_size - 1):
        raise ValueError(f'page_size must be a positive power of two, got {page_size!r}')
    if not isinstance(policy, MappingPolicy):
        raise ValueError(f'policy must be a MappingPolicy, got {policy!r}')

    report = LoadPermissionReport(page_size=page_size, policy=policy)

    osabi = elffile.header['e_ident']['EI_OSABI']
    if osabi not in SUPPORTED_OSABIS:
        report.diagnostics.append(Diagnostic(
            kind=DiagnosticKind.UNSUPPORTED_ABI,
            message=(f'EI_OSABI={osabi!r} is not in the supported set '
                     f'{sorted(SUPPORTED_OSABIS)}; results use the generic '
                     f"page-granular model and may not match this ABI's loader"),
        ))

    addr_bits = elffile.elfclass
    addr_space = 1 << addr_bits

    # page -> (perms, set of contributing segment indices)
    page_perms: dict[int, int] = {}
    page_contribs: dict[int, set[int]] = {}

    for index, segment in enumerate(elffile.iter_segments()):
        if segment['p_type'] != 'PT_LOAD':
            continue

        vaddr = segment['p_vaddr']
        memsz = segment['p_memsz']
        filesz = segment['p_filesz']
        offset = segment['p_offset']
        align = segment['p_align']
        perms = segment['p_flags'] & _PERM_MASK

        overflow = memsz > 0 and (vaddr >= addr_space or memsz > addr_space - vaddr)
        if overflow:
            report.diagnostics.append(Diagnostic(
                kind=DiagnosticKind.ADDRESS_OVERFLOW,
                message=(f'PT_LOAD[{index}] vaddr={vaddr:#x} memsz={memsz:#x} '
                         f'overflows the {addr_bits}-bit address space'),
                segment_index=index,
            ))

        if align > 1 and (vaddr - offset) % align != 0:
            report.diagnostics.append(Diagnostic(
                kind=DiagnosticKind.ALIGNMENT_CONTRADICTION,
                message=(f'PT_LOAD[{index}] p_vaddr={vaddr:#x} and '
                         f'p_offset={offset:#x} are not congruent modulo '
                         f'p_align={align:#x}'),
                segment_index=index,
            ))

        vend = vaddr + memsz
        zero_start = vaddr + min(filesz, memsz)
        mapping = SegmentMapping(
            index=index,
            file_range=(offset, offset + filesz),
            vaddr_range=(vaddr, vend),
            zero_fill_range=((zero_start, vend) if vend > zero_start
                             else (zero_start, zero_start)),
            page_range=(vaddr - (vaddr % page_size),
                        -(-vend // page_size) * page_size),
            perms=perms,
        )
        report.segments.append(mapping)

        if overflow or memsz == 0:
            # Do not derive page permissions from a range that does not fit
            # the address space; the diagnostic above stands on its own.
            continue

        first_page = vaddr - (vaddr % page_size)
        if policy is MappingPolicy.SEGMENT_ONLY:
            for page in range(first_page, vend, page_size):
                report.pages.append(PagePermission(
                    page_range=(page, page + page_size),
                    perms=perms,
                    segment_indices=(index,),
                ))
        else:
            for page in range(first_page, vend, page_size):
                page_perms[page] = page_perms.get(page, 0) | perms
                page_contribs.setdefault(page, set()).add(index)

    if policy is MappingPolicy.PAGE_UNION:
        for page in sorted(page_perms):
            report.pages.append(PagePermission(
                page_range=(page, page + page_size),
                perms=page_perms[page],
                segment_indices=tuple(sorted(page_contribs[page])),
            ))

    report.wx_conflicts.extend(_find_wx_conflicts(report))
    return report


def _find_wx_conflicts(report: LoadPermissionReport) -> list[WXConflict]:
    """ Merge contiguous W+X pages into minimal maximal intervals. """
    conflicts: list[WXConflict] = []
    for page in report.pages:
        if not page.is_wx:
            continue
        start, end = page.page_range
        if conflicts and conflicts[-1].vaddr_range[1] == start:
            prev = conflicts[-1]
            merged_indices = tuple(sorted(set(prev.segment_indices) |
                                          set(page.segment_indices)))
            conflicts[-1] = WXConflict(
                vaddr_range=(prev.vaddr_range[0], end),
                segment_indices=merged_indices,
                explanation=_explain(merged_indices, report),
            )
        else:
            conflicts.append(WXConflict(
                vaddr_range=(start, end),
                segment_indices=page.segment_indices,
                explanation=_explain(page.segment_indices, report),
            ))
    return conflicts


def _explain(segment_indices: tuple[int, ...],
             report: LoadPermissionReport) -> str:
    by_index = {m.index: m for m in report.segments}
    parts = []
    for idx in segment_indices:
        mapping = by_index.get(idx)
        if mapping is None:
            continue
        roles = []
        if mapping.perms & P_FLAGS.PF_W:
            roles.append('W')
        if mapping.perms & P_FLAGS.PF_X:
            roles.append('X')
        parts.append(f'PT_LOAD[{idx}] ({mapping.perms_string}'
                     f'{", contributes " + "+".join(roles) if roles else ""})')
    if report.policy is MappingPolicy.PAGE_UNION:
        return 'W+X arises from the per-page union of ' + ' and '.join(parts)
    return 'W+X is granted directly by ' + ' and '.join(parts)
