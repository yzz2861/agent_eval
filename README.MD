
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


User identity correlation
-------------------------
`Registry.Identity` is an additive, read-only layer that keeps three kinds of
identity information separate:

* mount notes and export names (`SourceKind.MOUNT_NOTE`);
* clues read from the hive itself (`SourceKind.HIVE`); and
* an explicitly supplied, independent SID cross-reference
  (`SourceKind.TRUSTED_SID_TABLE`).

The central forensic rule is enforced in code: **without a trusted SID table,
no unique user attribution is possible**.  The report can still show grouped
copies and provisional candidates, but `report.is_unique` is false,
`report.attribution` is `None`, and every per-hive attribution has `unique`
set to false.  Internal SIDs, mount paths and usernames never silently become
a final identity.

Usage
~~~~~
```python
from Registry.Identity import correlate_identities

report = correlate_identities(
    [
        {"data": site_ntuser_bytes, "evidence_id": "SITE",
         "mount_note": "C__Users_alice_NTUSER.DAT"},
        {"data": lab_ntuser_bytes, "evidence_id": "LAB",
         "mount_note": "/cases/42/C/Users/alice/NTUSER.DAT"},
    ],
    trusted_sid_table="sid-cross-reference.csv",
)

if report.is_unique:
    print(report.attribution["username"], report.attribution["sid"])
else:
    for identity in report.identities:
        print(identity.status.value, identity.sid, identity.username)
```

Inputs may be paths, bytes, file-like objects, parsed `Registry.Registry`
objects, or specification dictionaries.  Each specification accepts
`evidence_id`, `mount_note` (one note or a list), `label`, and one of
`path`, `data`, `bytes`, `raw`, `filelike`, `file`, or `registry`.

Hive-side extraction is conservative and covers the usual account clues:

* NTUSER/USRCLASS: `Volatile Environment`, `Environment`, Explorer
  `Shell Folders`, logon-user values and SID-named keys under
  `Protected Storage System Provider`;
* SAM: the machine SID, `Domains\Account\Users\Names`, RID keys with
  `V`/`F` values, and account SIDs reconstructed from machine SID + RID;
* SOFTWARE: `ProfileList` entries, profile paths, `Sid` values, last-logon
  and autologon values;
* SECURITY: `Policy\Accounts` SID keys; and
* SYSTEM: environment values that explicitly contain a user name.

Attribution status and provenance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Every clue carries `source`, `evidence_id`, `locator`, `confidence` and a
`group`.  The numeric `confidence_score` is retained alongside the label.
Typical ordering is: trusted table (authoritative), reconstructed SAM
account SID (high), profile/environment clues (high to medium), explicit
mount annotation (medium), path/export label (low), and free-form label
(unverified).

* Same display name with different SIDs remains visible as a
  `same_name_sid_conflict`; the SID candidates are not collapsed.
* A hive with no SID is marked with `sid_missing_evidence_ids`.  It is only
  resolved when the trusted table maps the name to exactly one SID, and the
  result records that the SID came from the table.
* Byte-identical copies are grouped as a `byte_identical` mirror.  Every copy
  keeps its own evidence id, path and mount notes; the copies are not two
  users.  Different bytes that carry the same SID and name are reported as a
  weaker `same_sid_and_name` mirror candidate.
* Default/system profiles (`Default`, `Public`, `SYSTEM`, service accounts,
  `DefaultAccount`, and their SIDs) are reported as `machine_default` and are
  never promoted to a human user attribution.
* A name-only ambiguity in the trusted table is reported as `ambiguous`; the
  resolver does not pick the first row.

Trusted SID table formats
~~~~~~~~~~~~~~~~~~~~~~~~~
CSV, TSV, JSON and plain text are accepted.  Column aliases include
`username`/`user`/`name`, `sid`/`user_sid`, `domain`, and `note`.
Headerless rows may be `user,sid`, `domain,user,sid`, or `sid user`.
JSON may be a list of records, a mapping from user name to SID, a mapping from
SID to user name, or an object with an `entries`/`users`/`table` list.

The table is used only when passed explicitly.  It is never auto-discovered
next to a hive, which keeps the provenance of the cross-reference clear.

CLI
~~~
```
python -m Registry.Identity --trusted-sid-table sid.csv --pretty SITE.DAT LAB.DAT
```
The command prints a JSON report.  `--require-unique` exits with status 3
when no unique user attribution exists.
