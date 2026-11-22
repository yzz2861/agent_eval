==========================
Directory evidence check
==========================

``olefile.check_directory_evidence`` is a read-only diagnostic for damaged or
repaired OLE2 directories.  It reads every 128-byte directory entry directly
and does not call ``append_kids`` or change the archive's ``kids``, ``used`` or
link fields.  This is useful when two sibling branches may have been connected
to the same physical directory entry.

For the root storage and every ordinary storage, the check reconstructs the
observed child tree and reports whether these conditions hold together:

* every reached SID is attributed to exactly one storage branch;
* the sibling tree is ordered by [MS-CFB]'s name length first and then
  case-insensitive name comparison;
* names are valid and unique (case-insensitively) among distinct child SIDs.

Each occurrence is kept separately, so a repeated physical SID and two
different SIDs that happen to share a name produce different conflicts:

* ``duplicate_ownership`` means the same SID is reached more than once, or
  from more than one storage;
* ``duplicate_name`` means two distinct SIDs under the same storage compare
  equal case-insensitively.

Conflicts include a minimal ``witness``: the smallest union of directed
directory links needed to demonstrate the contradiction.  Links are tuples of
``(source_sid, link, target_sid)``, where ``link`` is ``child``, ``left`` or
``right``.

Basic use
---------

.. code-block:: python

    import olefile

    with olefile.OleFileIO("repaired.doc") as ole:
        evidence = ole.check_directory_evidence()
        for parent in evidence.parents:
            print(parent.owner_sid, parent.owner_name, parent.status)
        for conflict in evidence.conflicts:
            print(conflict.kind, conflict.sids, conflict.witness)

The report has ``provable`` and ``needs_confirmation`` statuses.  A parent
status is ``provable`` only when its direct observed branch satisfies ownership,
ordering and naming.  ``evidence.minimal_witnesses`` returns all conflict
witnesses, while ``evidence.unclaimed`` lists active entries that no branch
reaches.

Testing a small directory
-------------------------

The check also accepts ``DirectoryEntrySnapshot`` records, which makes it
possible to test a hypothesis without modifying an OLE file:

.. code-block:: python

    S = olefile.DirectoryEntrySnapshot
    ROOT = olefile.STGTY_ROOT
    STORAGE = olefile.STGTY_STORAGE
    STREAM = olefile.STGTY_STREAM

    entries = [
        S(0, "Root Entry", ROOT, sid_child=3),
        S(1, "A", STORAGE, sid_child=2),
        S(2, "X", STREAM, sid_left=4),
        S(3, "B", STORAGE, sid_left=1, sid_child=2),
        S(4, "Y", STREAM),
    ]
    before = olefile.check_directory_evidence(entries)

In this example both ``A`` and ``B`` need confirmation: SID 2 (``X``) is
owned twice, and the sibling order inside each branch is also inconsistent.
Swapping the target of ``A.child`` with the target of ``X.left`` in a copy
reassigns ``Y`` to ``A`` while leaving ``B`` damaged:

.. code-block:: python

    after_entries = [
        entries[0],
        entries[1].replace(sid_child=4),
        entries[2].replace(sid_left=2),
        entries[3],
        entries[4],
    ]
    after = olefile.check_directory_evidence(after_entries)
    assert before.parent(1).status == "needs_confirmation"
    assert before.parent(3).status == "needs_confirmation"
    assert after.parent(1).status == "provable"
    assert after.parent(3).status == "needs_confirmation"

The change is confined to the analysis copy.  The original damaged relations,
including the cycle retained in branch ``B``, remain visible.
