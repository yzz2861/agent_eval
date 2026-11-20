"""Build a small two-slice Mach-O sample for data-in-code evidence tests."""

from __future__ import absolute_import, print_function

import os
import struct
import sys

from macholib import mach_o

TEXT_CANDIDATE_OFFSET = 0x100
TEXT_CANDIDATE_SIZE = 0x40
VM_BASE = 0x100000000
TEXT_PAYLOAD = b"".join(struct.pack(">I", index * 4) for index in range(16))

DEFAULT_DATA_IN_CODE_ENTRIES = (
    (TEXT_CANDIDATE_OFFSET, 0x10, mach_o.DICE_KIND_JUMP_TABLE32),
    (TEXT_CANDIDATE_OFFSET + 8, 0x08, mach_o.DICE_KIND_DATA),
)


def _align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def _make_symbols(endian, section_address, names):
    names = list(names)
    string_table = b"\x00"
    offsets = []
    for name in names:
        offsets.append(len(string_table))
        string_table += name.encode("ascii") + b"\x00"

    symbol_data = b""
    for index, name_offset in enumerate(offsets):
        virtual_address = section_address + (index * 8)
        symbol_data += struct.pack(
            endian + "IBBHq",
            name_offset,
            mach_o.N_SECT | mach_o.N_EXT,
            1,
            0,
            virtual_address,
        )
    return string_table, symbol_data


def build_slice(
    endian,
    cputype,
    cpusubtype=0,
    data_in_code_entries=DEFAULT_DATA_IN_CODE_ENTRIES,
    symbol_names=("_table", "_entry"),
):
    include_data_in_code = data_in_code_entries is not None
    commands = []
    load_command_size = 0

    text_file_offset = TEXT_CANDIDATE_OFFSET
    text_virtual_address = VM_BASE + text_file_offset
    string_table_offset = text_file_offset + TEXT_CANDIDATE_SIZE
    string_table, symbol_data = _make_symbols(
        endian, text_virtual_address, symbol_names
    )
    symbol_table_offset = _align(string_table_offset + len(string_table), 8)
    symbol_count = len(symbol_names)

    command_count = 2 + int(include_data_in_code)
    segment_command_size = 72 + mach_o.section_64._size_
    data_in_code_command_size = 16
    symtab_command_size = 24
    load_command_size = (
        segment_command_size
        + data_in_code_command_size * int(include_data_in_code)
        + symtab_command_size
    )

    data_in_code_offset = 0
    data_in_code_size = 0
    if include_data_in_code:
        data_in_code_offset = _align(symbol_table_offset + len(symbol_data), 8)
        data_in_code_size = len(data_in_code_entries) * mach_o.data_in_code_entry._size_

    slice_size = _align(
        max(
            string_table_offset + len(string_table),
            symbol_table_offset + len(symbol_data),
            data_in_code_offset + data_in_code_size,
        ),
        0x100,
    )

    segment_command = struct.pack(
        endian + "II16sQQQQiiII",
        mach_o.LC_SEGMENT_64,
        segment_command_size,
        b"__TEXT",
        VM_BASE,
        slice_size,
        0,
        slice_size,
        5,
        5,
        1,
        0,
    )
    section_command = struct.pack(
        endian + "16s16sQQIIIIIIII",
        b"__text",
        b"__TEXT",
        text_virtual_address,
        TEXT_CANDIDATE_SIZE,
        text_file_offset,
        2,
        0,
        0,
        mach_o.S_ATTR_PURE_INSTRUCTIONS | mach_o.S_ATTR_SOME_INSTRUCTIONS,
        0,
        0,
        0,
    )
    commands.append(segment_command + section_command)

    if include_data_in_code:
        commands.append(
            struct.pack(
                endian + "IIII",
                mach_o.LC_DATA_IN_CODE,
                data_in_code_command_size,
                data_in_code_offset,
                data_in_code_size,
            )
        )

    commands.append(
        struct.pack(
            endian + "IIIIII",
            mach_o.LC_SYMTAB,
            symtab_command_size,
            symbol_table_offset,
            symbol_count,
            string_table_offset,
            len(string_table),
        )
    )

    header = struct.pack(
        endian + "IIIIIIII",
        mach_o.MH_MAGIC_64,
        cputype,
        cpusubtype,
        mach_o.MH_EXECUTE,
        command_count,
        load_command_size,
        0,
        0,
    )

    image = bytearray(slice_size)
    cursor = 0
    image[cursor : cursor + len(header)] = header  # noqa: E203
    cursor += len(header)
    for command in commands:
        image[cursor : cursor + len(command)] = command  # noqa: E203
        cursor += len(command)

    image[text_file_offset : text_file_offset + TEXT_CANDIDATE_SIZE] = (  # noqa: E203
        TEXT_PAYLOAD
    )
    image[
        string_table_offset : string_table_offset + len(string_table)  # noqa: E203
    ] = string_table
    image[
        symbol_table_offset : symbol_table_offset + len(symbol_data)  # noqa: E203
    ] = symbol_data

    if include_data_in_code:
        table = b"".join(
            struct.pack(endian + "IHH", offset, length, kind)
            for offset, length, kind in data_in_code_entries
        )
        image[data_in_code_offset : data_in_code_offset + len(table)] = (  # noqa: E203
            table
        )

    return bytes(image)


def build_dual_slice_sample(
    slice0_entries=DEFAULT_DATA_IN_CODE_ENTRIES,
    slice1_entries=None,
):
    slice0 = build_slice(
        ">",
        0x01000012,
        data_in_code_entries=slice0_entries,
        symbol_names=("_table", "_entry"),
    )
    slice1 = build_slice(
        "<",
        0x01000007,
        data_in_code_entries=slice1_entries,
        symbol_names=("_table", "_entry"),
    )

    slice0_offset = 0x1000
    slice1_offset = 0x2000
    fat_header = struct.pack(">II", mach_o.FAT_MAGIC, 2)
    architectures = struct.pack(
        ">iiIII",
        0x01000012,
        0,
        slice0_offset,
        len(slice0),
        12,
    ) + struct.pack(
        ">iiIII",
        0x01000007,
        0,
        slice1_offset,
        len(slice1),
        12,
    )

    image = bytearray(slice1_offset + len(slice1))
    image[: len(fat_header) + len(architectures)] = fat_header + architectures
    image[slice0_offset : slice0_offset + len(slice0)] = slice0  # noqa: E203
    image[slice1_offset : slice1_offset + len(slice1)] = slice1  # noqa: E203
    return bytes(image)


def sample_path():
    return os.path.join(os.path.dirname(__file__), "dual_slice_data_in_code.bin")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    path = argv[0] if argv else sample_path()
    with open(path, "wb") as output:
        output.write(build_dual_slice_sample())
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
