
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


Value evidence and policy snapshots
-----------------------------------
Each RegistryValue can expose a per-value evidence view without changing
the legacy value() or raw_data() API:

    value = reg.root().value("AuditLevel")
    evidence = value.evidence()

    evidence.raw_data          # stored bytes, exactly as recorded
    evidence.raw_hex           # legacy-style hex display key
    evidence.type_marker       # effective numeric type marker
    evidence.type_name         # RegDWord, RegBigEndian, ...
    evidence.declared_length   # VK length declaration
    evidence.complete          # False when declaration is short or marker missing
    evidence.decoded           # same result as value.value()
    evidence.comparison_key    # includes type/declaration, not only hex
    evidence.report_comparison # display_key, evidence_key, and value_key

The evidence kind distinguishes:

  - big-endian: an explicit RegBigEndian integer
  - little-endian: an ordinary RegDWord/little-endian integer
  - incomplete: the value is still readable, but the VK declaration is
    shorter than the storage width or a four-byte inline value lacks the
    0x80000000 inline marker

Compare two snapshots with compare_evidence() or
RegistryValue.compare(). The status is unchanged,
representation_changed (the bytes were reinterpreted or re-encoded), or
value_changed (the stored bytes and decoded policy value both changed).

A four-policy fixture and an external comparison program are provided:

    python samples/compare_policy_evidence.py \
        tests/reg_samples/policy_evidence/baseline.hive \
        tests/reg_samples/policy_evidence/representation_change.hive

    python samples/compare_policy_evidence.py \
        tests/reg_samples/policy_evidence/baseline.hive \
        tests/reg_samples/policy_evidence/value_change.hive

The first command identifies AuditLevel as an evidence representation
change: the raw bytes remain 01000000 while the type marker changes from
RegDWord to RegBigEndian. The second identifies
LmCompatibilityLevel as a true policy value change. Regenerate the tiny
8 KiB hives with python tests/make_policy_evidence_hives.py.
