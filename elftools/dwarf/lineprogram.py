#-------------------------------------------------------------------------------
# elftools: dwarf/lineprogram.py
#
# DWARF line number program
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import copy
from functools import cached_property
from typing import IO, TYPE_CHECKING, Any, NamedTuple

from ..common.exceptions import DWARFError
from ..common.utils import struct_parse
from .constants import DW_LNE, DW_LNS

if TYPE_CHECKING:
    from ..construct.lib.container import Container
    from .structs import DWARFStructs


# LineProgramEntry - an entry in the line program.
# A line program is a sequence of encoded entries. Some of these entries add a
# new LineState (mapping between line and address), and some don't.
#
# command:
#   The command/opcode - always numeric. For standard commands - it's the opcode
#   that can be matched with one of the DW_LNS constants. For extended commands
#   it's the extended opcode that can be matched with one of the DW_LNE
#   constants. For special commands, it's the opcode itself.
#
# args:
#   A list of decoded arguments of the command.
#
# is_extended:
#   Since extended commands are encoded by a zero followed by an extended
#   opcode, and these extended opcodes overlap with other opcodes, this
#   flag is needed to mark that the command has an extended opcode.
#
# state:
#   For commands that add a new state, it's the relevant LineState object.
#   For commands that don't add a new state, it's None.
#
class LineProgramEntry(NamedTuple):
    command: int
    is_extended: bool
    args: list[int]
    state: LineState | None


class LineProgramError(DWARFError):
    """A line program state boundary was violated.

    The decoder records the opcode offset and the file register value that
    were current when decoding failed, as well as the dimension that was
    rejected (file, address, line, entry count, ...).
    """
    def __init__(
        self,
        message: str,
        *,
        opcode_offset: int,
        current_file: int,
        dimension: str,
        opcode: int | None = None,
        is_extended: bool = False,
    ) -> None:
        self.opcode_offset = opcode_offset
        self.offset = opcode_offset
        self.current_file = current_file
        self.file = current_file
        self.dimension = dimension
        self.rejected_dimension = dimension
        self.opcode = opcode
        self.is_extended = is_extended
        super().__init__(
            f"{message} at opcode offset 0x{opcode_offset:x} "
            f"(file {current_file}, dimension {dimension})")


class LineState:
    """ Represents a line program state (or a "row" in the matrix
        describing debug location information for addresses).
        The instance variables of this class are the "state machine registers"
        described in section 6.2.2 of DWARFv3
    """
    def __init__(self, default_is_stmt: int) -> None:
        self.address = 0
        self.file = 1
        self.line = 1
        self.column = 0
        self.op_index = 0
        self.is_stmt = default_is_stmt
        self.basic_block = False
        self.end_sequence = False
        self.prologue_end = False
        self.epilogue_begin = False
        self.isa = 0
        self.discriminator = 0

    def __repr__(self) -> str:
        return '\n'.join((
            f'<LineState {id(self):x}:',
            f'  address = 0x{self.address:x}',
            *(
                f'  {attr} = {getattr(self, attr)}'
                for attr in ('file', 'line', 'column', 'is_stmt', 'basic_block',
                    'end_sequence', 'prologue_end', 'epilogue_begin', 'isa',
                    'discriminator')
            ),
            '>',
        ))


class LineProgram:
    """ Builds a "line table", which is essentially the matrix described
        in section 6.2 of DWARFv3. It's a list of LineState objects,
        sorted by increasing address, so it can be used to obtain the
        state information for each address.
    """
    def __init__(
        self,
        header: Container,
        stream: IO[bytes],
        structs: DWARFStructs,
        program_start_offset: int,
        program_end_offset: int,
        max_entries: int | None = None,
        max_sequence_offset: int | None = None,
        **limit_aliases: int | None,
    ) -> None:
        """
            header:
                The header of this line program. Note: LineProgram may modify
                its header by appending file entries if DW_LNE.define_file
                instructions are encountered.

            stream:
                The stream this program can be read from.

            structs:
                A DWARFStructs instance suitable for this line program

            program_{start|end}_offset:
                Offset in the debug_line section stream where this program
                starts (the actual program, after the header), and where it
                ends.
                The actual range includes start but not end: [start, end - 1]

            max_entries:
                Maximum number of decoded LineProgramEntry objects. None
                (the default) keeps the historical unbounded behavior.

            max_sequence_offset:
                Maximum cumulative address advance within one sequence.
                The counter is reset by DW_LNE.end_sequence. None keeps the
                historical unbounded behavior.
        """
        aliases = {
            'max_line_entries': 'max_entries',
            'max_entry_count': 'max_entries',
            'max_sequence_address_advance': 'max_sequence_offset',
            'max_address_advance': 'max_sequence_offset',
        }
        for alias, canonical in aliases.items():
            if alias not in limit_aliases:
                continue
            if canonical == 'max_entries':
                if max_entries is not None:
                    raise TypeError(f"{alias} and max_entries are mutually exclusive")
                max_entries = limit_aliases.pop(alias)
            else:
                if max_sequence_offset is not None:
                    raise TypeError(
                        f"{alias} and max_sequence_offset are mutually exclusive")
                max_sequence_offset = limit_aliases.pop(alias)
        if limit_aliases:
            unexpected = next(iter(limit_aliases))
            raise TypeError(f"unexpected line program limit: {unexpected}")

        self.max_entries = self._check_limit('max_entries', max_entries)
        self.max_sequence_offset = self._check_limit(
            'max_sequence_offset', max_sequence_offset)
        self.stream = stream
        self.header = header
        self.structs = structs
        self.program_start_offset = program_start_offset
        self.program_end_offset = program_end_offset

    def get_entries(self) -> list[LineProgramEntry]:
        """ Get the decoded entries for this line program. Return a list of
            LineProgramEntry objects.
            Note that this contains more information than absolutely required
            for the line table. The line table can be easily extracted from
            the list of entries by looking only at entries with non-None
            state. The extra information is mainly for the purposes of display
            with readelf and debugging.
        """
        return self._decode_line_program

    #------ PRIVATE ------#

    def __getitem__(self, name: str) -> Any:
        """ Implement dict-like access to header entries
        """
        return self.header[name]

    @staticmethod
    def _check_limit(name: str, value: int | None) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer or None")
        if value < 0:
            raise ValueError(f"{name} must be non-negative")
        return value

    def _file_table_size(self) -> int:
        """ Return the number of entries in the current line table's file
            table. DWARF5 stores it as file_names in the raw header; the
            DWARFInfo compatibility layer also creates file_entry.
        """
        file_entries = self.header.get('file_entry', None)
        if file_entries is not None:
            return len(file_entries)
        file_names = self.header.get('file_names', None)
        if file_names is not None:
            return len(file_names)
        return 0

    def _file_index_base(self) -> int:
        # File numbers are 1-based before DWARF5 and 0-based in DWARF5.
        return 0 if self.header['version'] >= 5 else 1

    @cached_property
    def _decode_line_program(self) -> list[LineProgramEntry]:
        entries = []
        state = LineState(self.header['default_is_stmt'])
        sequence_offset = 0
        file_table_size = self._file_table_size()
        file_index_base = self._file_index_base()
        address_bits = 8 * self.structs.address_size
        address_max = (1 << address_bits) - 1
        line_max = (1 << address_bits) - 1
        max_entries = self.max_entries
        max_sequence_offset = self.max_sequence_offset

        def reject(
            offset: int,
            dimension: str,
            message: str,
            *,
            opcode: int | None = None,
            is_extended: bool = False,
            file_index: int | None = None,
        ) -> None:
            if file_index is None:
                file_index = state.file
            raise LineProgramError(
                message,
                opcode_offset=offset,
                current_file=file_index,
                dimension=dimension,
                opcode=opcode,
                is_extended=is_extended)

        def check_file_index(
            offset: int,
            file_index: int,
            opcode: int,
            is_extended: bool = False,
        ) -> None:
            if file_table_size == 0:
                valid_range = 'the file table is empty'
            else:
                valid_range = (
                    f"valid range is {file_index_base}.."
                    f"{file_index_base + file_table_size - 1}")
            if not (file_index_base <= file_index <
                    file_index_base + file_table_size):
                reject(
                    offset, 'file',
                    f"file index {file_index} is outside the current line "
                    f"table ({valid_range})",
                    opcode=opcode, is_extended=is_extended)

        def check_entry_limit(
            offset: int,
            opcode: int,
            is_extended: bool = False,
        ) -> None:
            if max_entries is not None and len(entries) >= max_entries:
                reject(
                    offset, 'entry_count',
                    f"line table entry count exceeds configured "
                    f"max_entries={max_entries}",
                    opcode=opcode, is_extended=is_extended)

        def advance_address(
            offset: int,
            addend: int,
            opcode: int,
            is_extended: bool = False,
        ) -> None:
            nonlocal sequence_offset
            new_address = state.address + addend
            if addend < 0 or new_address > address_max:
                reject(
                    offset, 'address',
                    f"address overflow: 0x{state.address:x} + 0x{addend:x} "
                    f"exceeds the {address_bits}-bit target limit "
                    f"0x{address_max:x}",
                    opcode=opcode, is_extended=is_extended)
            new_sequence_offset = sequence_offset + addend
            if (max_sequence_offset is not None and
                    new_sequence_offset > max_sequence_offset):
                reject(
                    offset, 'sequence_offset',
                    f"sequence cumulative address offset {new_sequence_offset} "
                    f"exceeds configured max_sequence_offset="
                    f"{max_sequence_offset}",
                    opcode=opcode, is_extended=is_extended)
            state.address = new_address
            sequence_offset = new_sequence_offset

        def advance_line(
            offset: int,
            addend: int,
            opcode: int,
            is_extended: bool = False,
        ) -> None:
            new_line = state.line + addend
            if new_line < 0 or new_line > line_max:
                reject(
                    offset, 'line',
                    f"line number overflow: {state.line} + ({addend}) is "
                    f"outside 0..{line_max}",
                    opcode=opcode, is_extended=is_extended)
            state.line = new_line

        def add_entry_new_state(
            cmd: int,
            args: list[int],
            offset: int,
            is_extended: bool = False,
        ) -> None:
            # Add an entry that sets a new state.
            # After adding, clear some state registers.
            check_file_index(offset, state.file, cmd, is_extended)
            check_entry_limit(offset, cmd, is_extended)
            entries.append(LineProgramEntry(
                cmd, is_extended, args, copy.copy(state)))
            state.discriminator = 0
            state.basic_block = False
            state.prologue_end = False
            state.epilogue_begin = False

        def add_entry_old_state(
            cmd: int,
            args: list[int],
            offset: int,
            is_extended: bool = False,
        ) -> None:
            # Add an entry that doesn't visibly set a new state
            check_entry_limit(offset, cmd, is_extended)
            entries.append(LineProgramEntry(cmd, is_extended, args, None))

        offset = self.program_start_offset
        while offset < self.program_end_offset:
            opcode: int = struct_parse(
                self.structs.the_Dwarf_uint8,
                self.stream,
                offset)

            # As an exercise in avoiding premature optimization, if...elif
            # chains are used here for standard and extended opcodes instead
            # of dispatch tables. This keeps the code much cleaner. Besides,
            # the majority of instructions in a typical program are special
            # opcodes anyway.
            if opcode >= self.header['opcode_base']:
                # Special opcode (follow the recipe in 6.2.5.1)
                maximum_operations_per_instruction: int = self['maximum_operations_per_instruction']
                if self['line_range'] <= 0:
                    reject(
                        offset, 'line_range',
                        f"invalid line_range {self['line_range']}",
                        opcode=opcode)
                if maximum_operations_per_instruction <= 0:
                    reject(
                        offset, 'maximum_operations_per_instruction',
                        f"invalid maximum_operations_per_instruction "
                        f"{maximum_operations_per_instruction}",
                        opcode=opcode)
                adjusted_opcode: int = opcode - self['opcode_base']
                operation_advance: int = adjusted_opcode // self['line_range']
                address_addend: int = (
                    self['minimum_instruction_length'] *
                        ((state.op_index + operation_advance) //
                          maximum_operations_per_instruction))
                advance_address(offset, address_addend, opcode)
                state.op_index = (state.op_index + operation_advance) % maximum_operations_per_instruction
                line_addend: int = self['line_base'] + (adjusted_opcode % self['line_range'])
                advance_line(offset, line_addend, opcode)
                add_entry_new_state(
                    opcode, [line_addend, address_addend, state.op_index],
                    offset)
            elif opcode == 0:
                # Extended opcode: start with a zero byte, followed by
                # instruction size and the instruction itself.
                inst_len: int = struct_parse(self.structs.the_Dwarf_uleb128,
                                        self.stream)
                if inst_len < 1:
                    reject(
                        offset, 'extended_length',
                        f"extended opcode length {inst_len} does not include "
                        f"an opcode byte",
                        opcode=opcode, is_extended=True)
                inst_end: int = self.stream.tell() + inst_len
                ex_opcode: int = struct_parse(self.structs.the_Dwarf_uint8,
                                         self.stream)

                if ex_opcode == DW_LNE.end_sequence:
                    state.end_sequence = True
                    state.is_stmt = 0
                    add_entry_new_state(
                        ex_opcode, [], offset, is_extended=True)
                    # reset state
                    state = LineState(self.header['default_is_stmt'])
                    sequence_offset = 0
                elif ex_opcode == DW_LNE.set_address:
                    operand: int = struct_parse(self.structs.the_Dwarf_target_addr,
                                           self.stream)
                    if operand > address_max:
                        reject(
                            offset, 'address',
                            f"set_address operand 0x{operand:x} exceeds the "
                            f"{address_bits}-bit target limit "
                            f"0x{address_max:x}",
                            opcode=ex_opcode, is_extended=True)
                    state.address = operand
                    add_entry_old_state(
                        ex_opcode, [operand], offset, is_extended=True)
                elif ex_opcode == DW_LNE.define_file:
                    operand = struct_parse(
                        self.structs.Dwarf_lineprog_file_entry, self.stream)
                    if self.header.get('file_entry', None) is None:
                        self.header['file_entry'] = [operand]
                    else:
                        self['file_entry'].append(operand)
                    file_table_size = self._file_table_size()
                    add_entry_old_state(
                        ex_opcode, [operand], offset, is_extended=True)
                elif ex_opcode == DW_LNE.set_discriminator:
                    operand = struct_parse(self.structs.the_Dwarf_uleb128,
                                           self.stream)
                    state.discriminator = operand
                else:
                    # Unknown, but need to roll forward the stream because the
                    # length is specified. The extended opcode itself counts
                    # toward the declared length.
                    self.stream.seek(inst_end)
                    offset = self.stream.tell()
                    continue

                # Known extended opcodes must not consume more bytes than
                # their declared length. Extra declared bytes are skipped.
                if self.stream.tell() > inst_end:
                    reject(
                        offset, 'extended_length',
                        f"extended opcode consumed past its declared length "
                        f"{inst_len}",
                        opcode=ex_opcode, is_extended=True)
                self.stream.seek(inst_end)
            else: # 0 < opcode < opcode_base
                # Standard opcode
                if opcode == DW_LNS.copy:
                    add_entry_new_state(opcode, [], offset)
                elif opcode == DW_LNS.advance_pc:
                    operand = struct_parse(self.structs.the_Dwarf_uleb128,
                                           self.stream)
                    address_addend = (
                        operand * self.header['minimum_instruction_length'])
                    advance_address(offset, address_addend, opcode)
                    add_entry_old_state(
                        opcode, [address_addend], offset)
                elif opcode == DW_LNS.advance_line:
                    operand = struct_parse(self.structs.the_Dwarf_sleb128,
                                           self.stream)
                    advance_line(offset, operand, opcode)
                elif opcode == DW_LNS.set_file:
                    operand = struct_parse(self.structs.the_Dwarf_uleb128,
                                           self.stream)
                    check_file_index(offset, operand, opcode)
                    state.file = operand
                    add_entry_old_state(opcode, [operand], offset)
                elif opcode == DW_LNS.set_column:
                    operand = struct_parse(self.structs.the_Dwarf_uleb128,
                                           self.stream)
                    state.column = operand
                    add_entry_old_state(opcode, [operand], offset)
                elif opcode == DW_LNS.negate_stmt:
                    state.is_stmt = not state.is_stmt
                    add_entry_old_state(opcode, [], offset)
                elif opcode == DW_LNS.set_basic_block:
                    state.basic_block = True
                    add_entry_old_state(opcode, [], offset)
                elif opcode == DW_LNS.const_add_pc:
                    if self['line_range'] <= 0:
                        reject(
                            offset, 'line_range',
                            f"invalid line_range {self['line_range']}",
                            opcode=opcode)
                    adjusted_opcode = 255 - self['opcode_base']
                    address_addend = ((adjusted_opcode // self['line_range']) *
                                      self['minimum_instruction_length'])
                    advance_address(offset, address_addend, opcode)
                    add_entry_old_state(opcode, [address_addend], offset)
                elif opcode == DW_LNS.fixed_advance_pc:
                    operand = struct_parse(self.structs.the_Dwarf_uint16,
                                           self.stream)
                    advance_address(offset, operand, opcode)
                    add_entry_old_state(opcode, [operand], offset)
                elif opcode == DW_LNS.set_prologue_end:
                    state.prologue_end = True
                    add_entry_old_state(opcode, [], offset)
                elif opcode == DW_LNS.set_epilogue_begin:
                    state.epilogue_begin = True
                    add_entry_old_state(opcode, [], offset)
                elif opcode == DW_LNS.set_isa:
                    operand = struct_parse(self.structs.the_Dwarf_uleb128,
                                           self.stream)
                    state.isa = operand
                    add_entry_old_state(opcode, [operand], offset)
                else:
                    # Standard opcodes unknown to this decoder still have
                    # their operand count in the header. Skip those operands
                    # so decoding can continue at the next instruction.
                    operand_count = self.header['standard_opcode_lengths'][
                        opcode - 1]
                    for _ in range(operand_count):
                        struct_parse(self.structs.the_Dwarf_uleb128,
                                     self.stream)
                    offset = self.stream.tell()
                    continue
            offset = self.stream.tell()
        # A program that reaches program_end without end_sequence is left
        # as decoded: no synthetic terminal row is fabricated.
        return entries
