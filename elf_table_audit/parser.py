"""Read-only iteration over ar(1) archives (``.a`` firmware bundles).

The parser is deliberately minimal: it only understands the common ``!<arch>\\n``
global header and the 60-byte member headers used by GNU/SysV and BSD archives.
Nothing is ever executed or loaded; member bytes are returned as in-memory
``bytes`` so downstream :class:`~elftools.elf.elffile.ELFFile` parsing stays
read-only as well.
"""

from __future__ import annotations

from dataclasses import dataclass
import io

from elftools.elf.elffile import ELFFile

ELF_MAGIC = b"\x7fELF"

AR_GLOBAL_MAGIC = b"!<arch>\n"
AR_MEMBER_HEADER_SIZE = 60


class ArchiveFormatError(ValueError):
    """Raised when a buffer does not look like a well-formed ar archive."""


@dataclass(frozen=True)
class ArchiveMember:
    """A single archive member with its *unparsed* payload bytes."""

    name: str
    data: bytes
    size: int

    @property
    def is_elf(self) -> bool:
        return self.data[:4] == b"\x7fELF"


def _parse_member_name(raw_name: str, long_names: bytes | None) -> str:
    name = raw_name.strip()
    # BSD style long name "#1/N": the first N payload bytes hold the real name.
    # Checked first because "#1/20" must not be read as a GNU numeric offset.
    if name.startswith("#1/"):
        return name
    if name.endswith("/"):
        name = name[:-1]
    # GNU/SysV long name table reference: "//" table, member header name "N/".
    if long_names is not None and raw_name.strip().endswith("/") and name.isdigit():
        offset = int(name)
        slash_nl = b"/" + bytes([10])
        plain_nl = bytes([10])
        end = long_names.find(slash_nl, offset)
        if end == -1:
            end = long_names.find(plain_nl, offset)
        if end != -1:
            return long_names[offset:end].rstrip(b"/").decode("utf-8", "replace")
    return name


def iter_archive_members(buffer: bytes) -> list[ArchiveMember]:
    """Parse an ar archive buffer and return all members.

    Symbol index members (``/``, ``__.SYMDEF``) and the GNU long-name table
    (``//``) are consumed for metadata but not returned as object members.
    """
    if not buffer.startswith(AR_GLOBAL_MAGIC):
        raise ArchiveFormatError("missing ar global magic '!<arch>\\n'")

    members: list[ArchiveMember] = []
    long_names: bytes | None = None
    pos = len(AR_GLOBAL_MAGIC)

    while pos < len(buffer):
        if pos + AR_MEMBER_HEADER_SIZE > len(buffer):
            raise ArchiveFormatError(f"truncated member header at offset {pos}")
        header = buffer[pos : pos + AR_MEMBER_HEADER_SIZE]
        pos += AR_MEMBER_HEADER_SIZE
        if header[58:60] != b"`\n":
            raise ArchiveFormatError(f"bad member header delimiter at offset {pos - 60}")

        raw_name = header[0:16].decode("ascii", "replace")
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError as exc:
            raise ArchiveFormatError("invalid member size field") from exc
        if pos + size > len(buffer):
            raise ArchiveFormatError("member payload exceeds archive length")

        payload = buffer[pos : pos + size]
        pos += size
        if size % 2 == 1:
            pos += 1  # padding newline between members

        name = raw_name.strip()
        if name == "//":
            long_names = payload
            continue
        if name in ("/", "/SYM64/") or name.split(None, 1)[0] == "__.SYMDEF":
            continue  # symbol index, not an object member

        resolved = _parse_member_name(raw_name, long_names)
        if resolved.startswith("#1/"):
            name_len = int(resolved.split("/", 2)[1])
            resolved = payload[:name_len].rstrip(b"\x00").decode("utf-8", "replace")
            payload = payload[name_len:]

        # Re-check after resolving BSD in-payload names: symbol indexes
        # such as __.SYMDEF SORTED carry archive metadata, not object code.
        if resolved.split(None, 1)[0] == "__.SYMDEF":
            continue

        members.append(ArchiveMember(name=resolved, data=payload, size=len(payload)))

    return members

def _is_elf(buffer: bytes) -> bool:
    return buffer[:4] == b"\x7fELF"


def open_elf_inputs(path: str):
    """Yield (member_name, ELFFile, source) tuples read-only.

    A plain ``.o`` yields one tuple with ``member_name=None``.  An ar archive
    yields one tuple per ELF member; non-ELF members are skipped.  All bytes
    are read up front into memory so the on-disk file is never modified and
    no member is executed or loaded.
    """
    import io

    from elftools.elf.elffile import ELFFile

    with open(path, "rb") as handle:
        buffer = handle.read()

    if _is_elf(buffer):
        yield None, ELFFile(io.BytesIO(buffer)), path
        return
    if buffer.startswith(AR_GLOBAL_MAGIC):
        for member in iter_archive_members(buffer):
            if not member.is_elf:
                continue
            stream = io.BytesIO(member.data)
            yield member.name, ELFFile(stream), f"{path}!{member.name}"
        return
    raise ArchiveFormatError(f"{path}: neither an ELF object nor an ar archive")
