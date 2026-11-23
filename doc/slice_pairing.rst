Slice pairing audit
===================

``macholib.slice_pairing`` performs a read-only audit of release material
made up of:

* one universal (fat) Mach-O binary,
* the same binary split into thin files per architecture, and
* standalone debug Mach-O files.

The module only opens the input files in ``"rb"`` mode.  It uses the
``macholib.mach_o`` structure definitions for both byte orders and never runs
``lipo``, ``otool``, ``file`` or the binaries themselves.

Identity
--------

A slice is identified by the tuple::

    (LC_UUID, cputype, cpusubtype)

Every load command is retained with its origin:

``path``
    Input file the command came from.

``kind``
    ``universal``, ``archive`` or ``debug``.

``slice_index``
    Index in a ``fat_arch`` table, or ``0`` for a thin file.

``command_index``
    Index in the slice's ``ncmds`` order.

``slice_offset`` / ``file_offset``
    Command position relative to the slice and relative to the file.

``uuid_slice_offset`` / ``uuid_file_offset``
    Position of the 16 UUID bytes for ``LC_UUID`` commands.

For fat containers the slice record also keeps ``fat_arch`` (the declared
CPU values, offset, size, alignment and ``table_offset`` of the entry).

Report buckets
--------------

``unique``
    Exactly one readable material of every present kind claims the identity,
    at least two kinds are present, and no candidate was dropped.  These are
    the correspondences with sufficient evidence.

``duplicates``
    More than one material of the same kind claims the identity, one UUID is
    claimed with different CPU values, or a slice contains several
    ``LC_UUID`` commands.  The first candidate is never consumed implicitly.

``incomplete``
    A command was truncated or its size fields are inconsistent, so the
    identity is not trusted.  Missing ``LC_UUID`` material is listed here as
    ``unidentified`` rather than guessed from CPU values.

``unmatched``
    A readable identity has no counterpart in another input kind.  When the
    caller supplies ``expected_kinds``, a missing required kind is reported
    here as a coverage gap as well.

``problems`` contains flat findings suitable for a release gate.  Findings
carry a primary ``path`` when the culprit is known (for example the archive
whose UUID no longer agrees with the universal slice), plus ``related`` and
``paths`` for every material involved.

Input order
-----------

Inputs and report entries are sorted by kind, file path, slice index and
command index.  Two reports built from the same files in a different order
are equal.  Grouping is performed on the complete candidate set before any
classification, so a duplicate archive is reported as a duplicate instead of
being paired first and leaving its sibling unmatched.

Python API
----------

.. code-block:: python

    from macholib.slice_pairing import build_pairing_report

    report = build_pairing_report(
        universal="build/Universal.bin",
        archive="build/slices",              # directory or iterable of paths
        debug="build/dSYMs",
        expected_kinds=("universal", "archive", "debug"),
    )

    for finding in report["problems"]:
        print(finding["code"], finding["path"], finding["message"])

``materials`` accepts a mapping such as
``{"archive": ["a.bin", "b.bin"], "debug": ["a.dSYM"]}``.  Explicit file
paths are always inspected, including malformed ones; directories are walked
in sorted order and filtered to files that start with a Mach-O or fat magic.

The result is an ordinary JSON-serializable dictionary with the keys
``schema``, ``inputs``, ``summary``, ``slices``, ``commands``,
``uuid_commands``, ``unique``, ``duplicates``, ``incomplete``, ``unmatched``
and ``problems``.

Command line
------------

.. code-block:: console

    python -m macholib.slice_pairing \
        --universal build/Universal.bin \
        --archive build/slices \
        --debug build/dSYMs \
        --json --pretty --fail-on-problems

Positional arguments accept ``KIND=PATH`` (for example
``archive=build/slices/arm64.bin``).  ``--expected`` takes a comma separated
list of required kinds.  By default the exit status is zero after a report;
``--fail-on-problems`` returns status 2 when any bucket is not fully paired.

The compatibility import ``macholib.slice_audit`` exports the same API.
