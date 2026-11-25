:mod:`macholib.slice_diff` --- Read-only pairwise slice audit
===================================================================

.. module:: macholib.slice_diff
   :synopsis: Read-only pairwise comparison of fat Mach-O files

This module compares two fat (universal) Mach-O files without modifying
either input.  It explains the differences that a packaging tool creates when
it rewrites dylib references, and isolates the changes those rewrites cannot
account for.

Architecture slices are matched by CPU type and subtype, so the comparison
handles reordered fat headers, architectures present on only one side and
duplicate architectures (paired by ordinal).  For every matched slice the
module distinguishes:

* reference rewrites inside the allowed path-bearing load commands and the
  layout shifts their size changes cause;
* segment content edits that the layout shifts cannot explain, located to
  byte ranges on both files;
* code signature presence, coverage and byte content changes;
* missing evidence: absent or duplicate slices, malformed data and layout
  changes that do not follow from the rewritten commands.

All located findings carry both whole-file (fat) and slice-relative byte
intervals through :class:`ByteRange`.

The primary entry points are :func:`compare_files` for on-disk inputs and
:func:`compare_blobs` for in-memory data; :func:`parse_file` and
:func:`parse_bytes` expose the raw read-only slice views.  The module also
runs as ``python -m macholib.slice_diff BEFORE AFTER``.
