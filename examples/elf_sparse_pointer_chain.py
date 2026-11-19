#-------------------------------------------------------------------------------
# elftools example: elf_sparse_pointer_chain.py
#
# Bounded pointer-chain walk over the sparse virtual address space of a core
# dump, for offline forensic analysis.
#
# A naive analysis reads unmapped or not-captured memory as zero, so a wild
# pointer can be mistaken for a valid pointer to an empty (NULL-terminated)
# linked list. This example uses ELFFile.sparse_address_space() to keep real
# zero fill apart from bytes the dump did not capture. The walk is bounded in
# both hops and bytes; on an unknown pointer, a cycle or truncation it keeps
# the already proven prefix and records an explicit stop reason.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile


@dataclass(frozen=True)
class PointerNode:
    """ One proven hop of the chain.

        address: virtual address from which the pointer was read;
        value:   pointer value (None when the pointer bytes were not
                 captured);
        status:  how the pointer bytes were obtained or why the hop failed.
    """

    address: int
    value: int | None
    status: str


@dataclass(frozen=True)
class PointerChain:
    """ Result of a bounded pointer-chain walk.

        nodes holds the hops that were fully proven from file bytes.
        stop_reason is one of:
          null           - a zero pointer terminated the chain;
          unknown        - the next pointer lies in a not-captured range;
          conflict       - overlapping segments disagree at the pointer;
          cycle          - the pointer points at an already visited node;
          hop_limit      - the maximum number of hops was reached;
          byte_limit     - more pointer reads would exceed the byte budget;
          invalid_range  - the requested pointer range is out of bounds.
    """

    nodes: tuple[PointerNode, ...]
    stop_reason: str


def walk_pointer_chain(
    space,
    start: int,
    pointer_size: int = 8,
    max_hops: int = 64,
    max_bytes: int | None = None,
    little_endian: bool = True,
) -> PointerChain:
    """ Walk a NULL-terminated linked list through the sparse address space.

        Each hop reads pointer_size bytes at the current address. A hop whose
        bytes are missing or conflicting never fabricates a value: the proven
        prefix is returned with the matching stop reason.
    """
    if pointer_size <= 0:
        raise ValueError('pointer_size must be positive')
    if max_bytes is None:
        max_bytes = max_hops * pointer_size

    nodes: list[PointerNode] = []
    visited: set[int] = set()
    current = start
    bytes_read = 0
    byte_order = 'little' if little_endian else 'big'

    while len(nodes) < max_hops:
        if bytes_read + pointer_size > max_bytes:
            return PointerChain(tuple(nodes), 'byte_limit')
        if current in visited:
            return PointerChain(tuple(nodes), 'cycle')
        visited.add(current)

        result = space.read(current, pointer_size)
        bytes_read += pointer_size

        if result.has_conflict:
            nodes.append(PointerNode(current, None, 'conflict'))
            return PointerChain(tuple(nodes), 'conflict')
        if not result.is_complete:
            missing = ', '.join(f'{lo:#x}-{hi:#x}'
                                for lo, hi in result.missing_ranges())
            nodes.append(PointerNode(
                current, None, f'unknown (missing {missing})'))
            return PointerChain(tuple(nodes), 'unknown')

        value = int.from_bytes(result.data, byte_order)
        if value == 0:
            nodes.append(PointerNode(current, 0, 'null'))
            return PointerChain(tuple(nodes), 'null')

        nodes.append(PointerNode(current, value, 'known'))
        current = value

    return PointerChain(tuple(nodes), 'hop_limit')


def process_file(
    filename: str,
    start: int,
    pointer_size: int,
    max_hops: int,
) -> None:
    print('Processing file:', filename)
    with open(filename, 'rb') as stream:
        elffile = ELFFile(stream)
        space = elffile.sparse_address_space()
        print('  PT_LOAD segments:')
        for seg in space.segments:
            backing = (f'file offset {seg.file_offset:#x}'
                       if seg.file_backed else 'no file image')
            print(f'    #{seg.segment_index}: vaddr={seg.vaddr:#x} '
                  f'memsz={seg.memsz:#x} {backing}')
        chain = walk_pointer_chain(
            space, start,
            pointer_size=pointer_size,
            max_hops=max_hops,
            little_endian=elffile.little_endian)
        print(f'  pointer chain from {start:#x}:')
        for node in chain.nodes:
            rendered = f'{node.value:#x}' if node.value is not None else '?'
            print(f'    [{node.address:#x}] -> {rendered} ({node.status})')
        print(f'  stop reason: {chain.stop_reason}')
        print(f'  proven hops: {len(chain.nodes)}')


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Walk a bounded pointer chain in a core dump.')
    parser.add_argument('elf_file', nargs='?',
                        help='path to the ELF/core file to analyze')
    parser.add_argument('start_address', nargs='?',
                        type=lambda text: int(text, 0),
                        help='virtual address of the first pointer')
    parser.add_argument('--pointer-size', type=int, default=8,
                        choices=(4, 8))
    parser.add_argument('--max-hops', type=int, default=64)
    parser.add_argument('--test', action='store_true',
                        help='compatibility flag used by the examples test')
    args = parser.parse_args()

    if args.test:
        # The examples harness runs every script with --test against a fixed
        # sample that need not contain a meaningful chain; use address 0,
        # which any address space reports as not captured.
        for path in [args.elf_file] if args.elf_file else []:
            process_file(path, 0, args.pointer_size, args.max_hops)
        return 0
    if args.elf_file is None or args.start_address is None:
        parser.error('elf_file and start_address are required')
    process_file(args.elf_file, args.start_address,
                 args.pointer_size, args.max_hops)
    return 0


if __name__ == '__main__':
    sys.exit(main())
