"""Deterministic GNU/SysV ar archive builder for test fixtures.

Only the subset needed to bundle relocatable ELF members is emitted: the
global magic, a GNU long-name table (``//``) when required and one 60-byte
header per member.  It never executes member contents.
"""

from __future__ import annotations

import sys

AR_GLOBAL_MAGIC = b"!<arch>\n"
HEADER_TEMPLATE = "{name:<16}{mtime:<12}{uid:<6}{gid:<6}{mode:<8}{size:<10}`\n"


def _member_header(name: str, size: int) -> bytes:
    header = HEADER_TEMPLATE.format(
        name=name, mtime=0, uid=0, gid=0, mode="100644", size=size
    )
    return header.encode("ascii")


def build_archive(members: list[tuple[str, bytes]]) -> bytes:
    short, long = [], []
    long_blob = b""
    for name, _ in members:
        field = name + "/"
        if len(field) <= 15:
            short.append(field)
        else:
            long.append(name)
    if long:
        long_blob = "".join(n + "/\n" for n in long).encode("utf-8")
    out = bytearray(AR_GLOBAL_MAGIC)
    if long_blob:
        out += _member_header("//", len(long_blob))
        out += long_blob
        if len(long_blob) % 2 == 1:
            out += b"\n"
    long_offsets = {}
    cursor = 0
    for name in long:
        long_offsets[name] = cursor
        cursor += len(name) + 2
    for (name, payload), short_name in zip(members, short + [None] * len(members)):
        if len(name + "/") <= 15:
            name_field = name + "/"
        else:
            name_field = str(long_offsets[name]) + "/"
        out += _member_header(name_field, len(payload))
        out += payload
        if len(payload) % 2 == 1:
            out += b"\n"
    return bytes(out)


def main(argv: list[str]) -> int:
    output = argv[1]
    members = []
    for path in argv[2:]:
        with open(path, "rb") as handle:
            members.append((path.split("/")[-1], handle.read()))
    with open(output, "wb") as handle:
        handle.write(build_archive(members))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
