#-------------------------------------------------------------------------------
# elftools: common/exceptions.py
#
# Exception classes for elftools
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
class ELFError(Exception):
    pass

class ELFRelocationError(ELFError):
    pass

class ELFParseError(ELFError):
    pass

class NoteParseError(ELFParseError):
    """ Raised when an ELF note header, name, or descriptor is malformed.

        ``offset`` is the file offset of the failing byte range and
        ``category`` is a stable, machine-readable failure category such as
        ``truncated_header`` or ``desc_out_of_bounds``.
    """
    def __init__(
        self,
        offset: int,
        category: str,
        message: str = '',
        *,
        note_offset: int | None = None,
        source_type: str | None = None,
        source_offset: int | None = None,
    ) -> None:
        self.offset = offset
        self.category = category
        self.message = message
        self.note_offset = note_offset
        self.source_type = source_type
        self.source_offset = source_offset

        location = f'file offset 0x{offset:x}'
        if note_offset is not None and note_offset != offset:
            location += f' (note at 0x{note_offset:x})'
        if source_type is not None and source_offset is not None:
            location += f' ({source_type}+0x{source_offset:x})'
        detail = f': {message}' if message else ''
        super().__init__(f'Malformed ELF note at {location}: {category}{detail}')

class NoteDuplicateError(NoteParseError):
    """ Raised when duplicate note owner/type pairs are rejected by policy.
    """
    def __init__(
        self,
        offset: int,
        category: str = 'duplicate_note_type',
        message: str = '',
        *,
        note_offset: int | None = None,
        source_type: str | None = None,
        source_offset: int | None = None,
    ) -> None:
        super().__init__(
            offset,
            category,
            message,
            note_offset=note_offset,
            source_type=source_type,
            source_offset=source_offset,
        )

class ELFCompressionError(ELFError):
    pass

class DWARFError(Exception):
    pass
