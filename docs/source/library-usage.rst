Library usage
#############

Use the :py:class:`~pcapng.scanner.FileScanner` class to iterate over blocks
in a pcap-ng archive file, like this:

.. code-block:: python

    from pcapng import FileScanner

    with open('/tmp/mycapture.pcap') as fp:
        scanner = FileScanner(fp)
        for block in scanner:
            pass  # do something with the block...

Block types can be checked against blocks in :py:mod:`pcapng.blocks`.


Auditing reviewed comments
==========================

When sections from different captures are merged into one export, the
``opt_comment`` text is preserved but a merger may reorder whole
sections, so the text alone no longer proves which section, interface or
packet a human reviewer originally approved.

:py:mod:`pcapng.comment_audit` re-reads both files through the normal
scanner and binds every comment to a section, interface or packet scope.
Sections are matched by their packet content (so whole sections may be
reordered, and identical short captures are disambiguated by ordinal),
while packets are matched by interface id and a hash of the captured
bytes. Options unknown to the block schemas cannot be bound to a scope
and are reported separately as *unverifiable*.

.. code-block:: python

    from pcapng.comment_audit import audit_comments

    approved = [
        # scope, original section ordinal and the approved comment text;
        # interface_id / packet_index / comment_index narrow the scope.
        {"scope": "section", "section_index": 0, "text": "section note"},
        {"scope": "interface", "section_index": 0,
         "interface_id": 0, "text": "interface note"},
        {"scope": "packet", "section_index": 0, "interface_id": 0,
         "packet_index": 0, "comment_index": 0, "text": "packet note"},
    ]
    with open("original.pcapng", "rb") as original, open(
        "export.pcapng", "rb"
    ) as export:
        report = audit_comments(original, export, approved)

    report.all_verified            # True only if every entry re-binds
    report.find("packet note")     # where each text now lives
    report.unverifiable_options    # unknown options, never trusted

The same logic is available offline as a command line tool; it writes a
JSON report and exits non-zero if an entry cannot be re-verified or an
unknown option is present::

    python -m pcapng.comment_audit original.pcapng export.pcapng approved.json
