# -*- coding: utf-8 -*-

"""
Layered inspection example.

Two ordinary zip archives are handed over to the records room. Both carry an
attachment that shares the exact same declared name, but only one keeps its
actual bytes locally. A caller-supplied, read-only adapter knows how to
enumerate and read each archive; :func:`filetype.inspect_layers` then reports,
layer by layer, which attachment is identified by its signature bytes and
which layer is still missing read evidence ("pending").

Run with: python examples/layered_archive.py
"""

from __future__ import absolute_import, print_function

import os
import tempfile
import zipfile

import filetype
from filetype.layers import Entry, ContainerAdapter, IDENTIFIED, PENDING


# Minimal valid PNG header; enough for the signature matchers.
PNG_SIGNATURE = bytearray([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
])

# Both archives declare an attachment under the same name.
ATTACHMENT_NAME = "evidence/attachment.bin"

# Header window read for every member, mirroring the engine limit.
HEADER_READ_BYTES = 8192


class ZipArchiveAdapter(ContainerAdapter):
    """
    Read-only local adapter for ordinary zip archives.

    The engine never opens a file itself: this adapter performs all local
    reads against an already open :class:`zipfile.ZipFile`. Members listed in
    ``missing`` are still declared by the archive (the upper layer claims the
    child) but their payload cannot be read locally, so they yield no
    signature evidence.
    """

    def __init__(self, archive, missing=()):
        self._archive = archive
        self._missing = set(missing)

    def children(self, entry):
        # Only the synthetic root enumerates archive members; every member
        # is a leaf as far as this zip adapter is concerned.
        if entry.name != "root":
            return ()
        members = []
        for info in self._archive.infolist():
            if info.is_dir():
                continue
            readable = info.filename not in self._missing
            members.append(Entry(
                reference=info if readable else None,
                name=info.filename,
                declared_extension=os.path.splitext(info.filename)[1][1:]
                or None
            ))
        return members

    def read_signature(self, entry):
        if entry.reference is None:
            return None
        with self._archive.open(entry.reference) as member:
            return member.read(HEADER_READ_BYTES)


def build_archive(path, payload):
    """Creates an ordinary zip archive carrying one same-named attachment."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.txt", "records-room handover note\n")
        archive.writestr(ATTACHMENT_NAME, bytes(payload))


def run_report(label, archive_path, missing=()):
    """Runs the read-only layered inspection against one archive."""
    print("== %s: %s" % (label, os.path.basename(archive_path)))
    with zipfile.ZipFile(archive_path) as archive:
        adapter = ZipArchiveAdapter(archive, missing=missing)
        records = filetype.inspect_layers(adapter)

    for record in records:
        declared = record.declared_extension or "n/a"
        print(
            "  layer %d  %-28s status=%-10s mime=%-12s declared-ext=%s "
            "evidence=%d bytes%s"
            % (
                record.depth,
                "/".join(record.path),
                record.status,
                record.mime or "-",
                declared,
                len(record.signature),
                "  [" + record.reason + "]" if record.pending else ""
            )
        )
    print("")
    return records


def main():
    workdir = tempfile.mkdtemp(prefix="records-room-")
    archive_a = os.path.join(workdir, "archive-a.zip")
    archive_b = os.path.join(workdir, "archive-b.zip")

    # Both archives look identical from the outside and declare the same
    # attachment name; only archive-b loses the local read evidence.
    build_archive(archive_a, PNG_SIGNATURE + b"\x00" * 32)
    build_archive(archive_b, PNG_SIGNATURE + b"\x00" * 32)

    records_a = run_report("intact archive", archive_a)
    records_b = run_report(
        "attachment evidence missing", archive_b,
        missing=(ATTACHMENT_NAME,)
    )

    attachment_a = next(
        record for record in records_a
        if record.entry.name == ATTACHMENT_NAME
    )
    attachment_b = next(
        record for record in records_b
        if record.entry.name == ATTACHMENT_NAME
    )

    print("-- investigation summary --")
    print(
        "archive-a attachment: %s as %s from %d confirmed signature bytes"
        % (
            attachment_a.status,
            attachment_a.mime,
            len(attachment_a.signature)
        )
    )
    print(
        "archive-b attachment: %s, the upper layer claims the child but no "
        "local read evidence exists"
        % attachment_b.status
    )
    assert attachment_a.status == IDENTIFIED
    assert attachment_b.status == PENDING


if __name__ == "__main__":
    main()
