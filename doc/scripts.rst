Command-line tools
==================

python -m macholib find
-----------------------

Usage::

        $ python -mmacholib find dir...

Print the paths of all MachO binaries
in the specified directories.

python -m macholib standalone
-----------------------------

Usage::

        $ python -m macholib standalone appbundle...

Convert one or more application bundles into
standalone bundles. That is, copy all non-system
shared libraries and frameworks used by the bundle
into the bundle and rewrite load commands.

python -mmacholib dump
----------------------

Usage::

        $ python -mmacholib dump dir...

Prints information about all architectures in a
Mach-O file as well as all libraries it links
to.

python -mmacholib crypt
-----------------------

Usage::

        $ python -mmacholib crypt [--json] file...

Read-only audit of the encryption metadata in each slice of a Mach-O
file.  The audit does not attempt to decrypt anything.  For every
``LC_ENCRYPTION_INFO`` or ``LC_ENCRYPTION_INFO_64`` command it reports:

* the range declared by the load command;
* the ``LC_SEGMENT``/``LC_SEGMENT_64`` file ranges that cover it;
* the bytes that are actually present in the file.

``cryptoff`` and the segment ``fileoff`` values are slice-local.  The
report also shows the corresponding archive offsets, so the same local
range can be mapped to the different locations of the slices in a fat
file.  Each finding is classified as ``fully-visible``,
``declaration-only``, or ``contradictory``.  The ``evidence`` field
contains only ranges that are really present in the file.

Use ``--json`` for a machine-readable report.  The JSON report lists
``declared_local_range``, ``declared_archive_range``, matching
``segments``, ``saved_local_range``, ``saved_archive_range`` and the
actual ``evidence`` ranges for every slice.
