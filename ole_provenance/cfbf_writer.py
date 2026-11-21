"""
Minimal Compound File Binary Format writer, used to build sample exhibits.

It supports exactly what the samples need: a root storage, nested storages
and streams of at least the mini-stream cutoff (4096 bytes), so every
stream lives in the regular FAT and no MiniFAT has to be emitted.  Sectors
are laid out sequentially, which lets the sample generator rewrite
directory positions between the original and the derived package simply by
ordering entries differently.
"""

import struct

FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

SECTOR_SIZE = 512
MINI_CUTOFF = 4096
DIRENTRY_SIZE = 128
ENTRIES_PER_SECTOR = SECTOR_SIZE // DIRENTRY_SIZE
FAT_ENTRIES_PER_SECTOR = SECTOR_SIZE // 4
HEADER_DIFAT_SLOTS = 109

_TYPE_EMPTY = 0
_TYPE_STORAGE = 1
_TYPE_STREAM = 2
_TYPE_ROOT = 5

_STRUCT_HEADER = struct.Struct("<8s16sHHHHH6sIIIIIIIII")
_STRUCT_DIRENTRY = struct.Struct("<64sHBBIII16sIQQIII")


class Stream:
    def __init__(self, name, data):
        if len(data) < MINI_CUTOFF:
            raise ValueError(
                "sample writer only supports streams >= %d bytes" % MINI_CUTOFF
            )
        self.name = name
        self.data = bytes(data)


class Storage:
    def __init__(self, name, children=()):
        self.name = name
        self.children = list(children)


def _dir_entry(name, entry_type, color, left, right, child, start, size):
    if name:
        name_utf16 = name.encode("utf-16-le") + b"\x00\x00"
    else:
        name_utf16 = b""
    if len(name_utf16) > 64:
        raise ValueError("directory name too long: %r" % name)
    return _STRUCT_DIRENTRY.pack(
        name_utf16.ljust(64, b"\x00"),
        len(name_utf16),
        entry_type,
        color,
        left,
        right,
        child,
        b"\x00" * 16,  # CLSID
        0,             # state bits
        0,             # creation time
        0,             # modification time
        start,
        size & 0xFFFFFFFF,
        (size >> 32) & 0xFFFFFFFF,
    )


def _assign_sids(children, entries, next_sid):
    """Append directory entries for *children* (right-chained siblings) and
    return the sid of the first sibling."""
    first_sid = next_sid if children else NOSTREAM
    sids = []
    for child in children:
        sids.append(next_sid)
        next_sid += 1
    for index, (child, sid) in enumerate(zip(children, sids)):
        right = sids[index + 1] if index + 1 < len(sids) else NOSTREAM
        entries.append((child, sid, right))
    for child in children:
        if isinstance(child, Storage):
            child_sid, next_sid = _assign_sids(child.children, entries, next_sid)
            child._child_sid = child_sid
    return first_sid, next_sid


def write_ole(path, children):
    """
    Write an OLE compound file containing *children* (Stream/Storage
    objects) under the root storage.
    """
    entries = []
    root_child_sid, _ = _assign_sids(list(children), entries, 1)

    # lay out stream data sectors in directory order
    sector_chains = {}
    next_sector = 0
    for child, sid, _right in entries:
        if isinstance(child, Stream):
            count = -(-len(child.data) // SECTOR_SIZE)
            sector_chains[sid] = list(range(next_sector, next_sector + count))
            next_sector += count

    dir_sector_count = -(-((len(entries) + 1) * DIRENTRY_SIZE) // SECTOR_SIZE)
    dir_start = next_sector
    next_sector += dir_sector_count

    # fixed point: FAT sectors themselves need FAT entries
    fat_count = 0
    while True:
        total = next_sector + fat_count
        needed = -(-total // FAT_ENTRIES_PER_SECTOR)
        if needed == fat_count:
            break
        fat_count = needed
    fat_start = next_sector
    total_sectors = next_sector + fat_count

    fat = [FREESECT] * (fat_count * FAT_ENTRIES_PER_SECTOR)
    for chain in sector_chains.values():
        for position, sector in enumerate(chain):
            fat[sector] = chain[position + 1] if position + 1 < len(chain) else ENDOFCHAIN
    for sector in range(dir_start, dir_start + dir_sector_count):
        fat[sector] = sector + 1 if sector < dir_start + dir_sector_count - 1 else ENDOFCHAIN
    for sector in range(fat_start, fat_start + fat_count):
        fat[sector] = FATSECT

    difat = [fat_start + i for i in range(fat_count)]
    if len(difat) > HEADER_DIFAT_SLOTS:
        raise ValueError("sample too large: needs a DIFAT sector")
    difat += [FREESECT] * (HEADER_DIFAT_SLOTS - len(difat))

    header = _STRUCT_HEADER.pack(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        b"\x00" * 16,  # CLSID
        0x003E,        # minor version
        3,             # major version
        0xFFFE,        # byte order
        9,             # sector shift -> 512
        6,             # mini sector shift -> 64
        b"\x00" * 6,   # reserved
        0,             # directory sectors (version 3)
        fat_count,
        dir_start,
        0,             # transaction signature
        MINI_CUTOFF,
        ENDOFCHAIN,    # first MiniFAT sector
        0,             # MiniFAT sector count
        ENDOFCHAIN,    # first DIFAT sector
        0,             # DIFAT sector count
    ) + struct.pack("<%dI" % HEADER_DIFAT_SLOTS, *difat)

    dir_entries = [
        _dir_entry("Root Entry", _TYPE_ROOT, 1, NOSTREAM, NOSTREAM,
                   root_child_sid, ENDOFCHAIN, 0)
    ]
    for child, _sid, right in entries:
        if isinstance(child, Stream):
            dir_entries.append(_dir_entry(
                child.name, _TYPE_STREAM, 1, NOSTREAM, right, NOSTREAM,
                sector_chains[_sid][0], len(child.data),
            ))
        else:
            dir_entries.append(_dir_entry(
                child.name, _TYPE_STORAGE, 1, NOSTREAM, right,
                child._child_sid, 0, 0,
            ))
    while len(dir_entries) % ENTRIES_PER_SECTOR:
        dir_entries.append(
            _dir_entry("", _TYPE_EMPTY, 0, NOSTREAM, NOSTREAM, NOSTREAM, 0, 0)
        )

    body = bytearray()
    for child, sid, _right in entries:
        if isinstance(child, Stream):
            body += child.data
            body += b"\x00" * (-len(child.data) % SECTOR_SIZE)
    body += b"".join(dir_entries)
    for sector in range(fat_count):
        base = sector * FAT_ENTRIES_PER_SECTOR
        body += struct.pack(
            "<%dI" % FAT_ENTRIES_PER_SECTOR,
            *fat[base:base + FAT_ENTRIES_PER_SECTOR],
        )

    with open(path, "wb") as handle:
        handle.write(header)
        handle.write(body)
    return total_sectors
