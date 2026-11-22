
python-registry
===============

Introduction
------------
python-registry is a pure Python library that provides read-only
access to Windows NT Registry files.
These include NTUSER.DAT, userdiff, and SAM. The interface is two-fold:
a high-level interface suitable for most tasks, and a low level
set of parsing objects and methods which may be used for advanced
study of the Windows NT Registry. This library is compatible with
Windows,Linux, and MacOS, making it accessible and functional
across all major operating systems.

Usage
-----

Most users will find the `Registry.Registry` module most appropriate.
The module exposes three classes: the `Registry`, the `RegistryKey`,
and the `RegistryValue`. The `Registry` organizes parsing and access
to the Windows Registry file. The `RegistryKey` is a convenient
interface into the tree-like structure of the Windows NT Registry.
A `RegistryKey` may have children `RegistryKeys`, and may also have
values associated with it. A `RegistryValue` can be thought of as
the tuple (name, datatype, value) associated with a `RegistryKey`.
python-registry supports all major datatypes, such as `RegSZ`,
`RegDWord`, and `RegBin`.

To open a Windows Registry file, its this easy:


    import sys
    from Registry import Registry
    
    reg = Registry.Registry(sys.argv[1])


Print all keys in a Registry


    def rec(key, depth=0):
        print "\t" * depth + key.path()
    
        for subkey in key.subkeys():
            rec(subkey, depth + 1)
    
    rec(reg.root())


Find a key and print all string values


    try:
        key = reg.open("SOFTWARE\\Microsoft\\Windows\\Current Version\\Run")
    except Registry.RegistryKeyNotFoundException:
        print "Couldn't find Run key. Exiting..."
        sys.exit(-1)
    
    for value in [v for v in key.values() \
                       if v.value_type() == Registry.RegSZ or \
                          v.value_type() == Registry.RegExpandSZ]:
        print "%s: %s" % (value.name(), value.value())


Advanced users who wish to study the structure of the Windows
Registry may find the `Registry.RegistryParse` module useful.
This module implements all known structures of the Windows Registry.

Wanted
------
  - Bug reports.
  - Feedback.

python-registry was originally developed to scratch one of
the author's itches.  Now he hopes it can be of use to
someone outside of his lonely NYC apartment.


License
-------
As of version 0.2.0, python-registry is released under the Apache 2.0 license.
Before that, python-registry was released under the GPLv3.


Sources
-------
Nearly all structure definitions used in python-registry
came from one of two sources:
1) WinReg.txt, by B.H., which may be accessed at:
   http://pogostick.net/~pnh/ntpasswd/WinReg.txt
2) The Windows NT Registry File Format version 0.4, by
   Timothy D. Morgan, which may be accessed at:
   https://docs.google.com/viewer?url=http%3A%2F%2Fsentinelchicken.com%2Fdata%2FTheWindowsNTRegistryFileFormat.pdf
Copies of these resources are included in the
`documentation/` directory of the python-registry source.


The source directory for python-registry contains a `sample/`
subdirectory that contains small programs that use python-registry.
For example, `regview.py` is a read-only clone of Microsoft Window's
Regedit, implemented in a few hundred lines.


Read-only evidence export
--------------------------

Delivery pipelines that hand registry values to other teams as plain JSON
values lose the on-disk context needed to tell a genuinely empty record apart
from an empty string whose terminator was repaired by a reader.  The
Registry.EvidenceExport module exports every value together with evidence
that a recipient can verify independently:

  * the key path and value name,
  * the declared data type (numeric code and symbolic name),
  * the declared/observed raw length, storage location (inline vs. data cell)
    and absolute file offset of the observed bytes,
  * the raw bytes as hex plus a SHA-256 digest for independent re-hashing,
  * the python-registry parsed view, kept separate from the evidence,
  * a restoration conclusion: restored for strings/numbers whose bytes
    re-encode exactly, empty_record for zero-length data, raw_carry
    for binary/structural data, and range_only when bad encoding, a
    missing terminator or a type/length mismatch means only the observed byte
    range can be asserted.

The exporter only opens the hive for reading::

    from Registry.EvidenceExport import export_evidence, export_evidence_json

    report = export_evidence("SOFTWARE")
    text = export_evidence_json("SOFTWARE")

A command line entry point is provided as well::

    python -m Registry.EvidenceExport SOFTWARE -o evidence.json

Synthetic hive generation
-------------------------

Registry.SyntheticHive is a self contained, write-only producer of minimal
single-HBIN hive images that the read-only parser can open again.  It exposes
the low level controls (exact raw bytes, declared length and inline storage)
needed to build forensic edge cases.  Two values can display identically after
parsing while still carrying different declared types or raw lengths::

    import struct
    from Registry.SyntheticHive import SyntheticHive
    from Registry import Registry
    from Registry.EvidenceExport import export_evidence
    import io

    builder = SyntheticHive("RootKey", "SYNTHETIC")
    builder.add_value("as_text", Registry.RegSZ,
                      u"42".encode("utf-16-le") + bytes([0, 0]))
    builder.add_value("as_dword", Registry.RegDWord, struct.pack("<I", 42))
    data = builder.build()
    report = export_evidence(io.BytesIO(data))

See tests/test_evidence_export.py for the round-trip scenarios, including
empty records, missing terminators, odd byte lengths and type/length
mismatches.
