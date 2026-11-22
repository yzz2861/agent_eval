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

Read-only redaction review
##########################

Use :py:func:`pcapng.review.compare_files` to compare an original capture
with a redacted copy without modifying either input.  Approvals are scoped by
field domain and original packet identifier; interface numbers may be
reassigned without causing packet mismatches.  Findings carry the exact
original byte range of each reviewed change.

.. code-block:: python

    from pcapng.review import Approval, compare_files

    report = compare_files(
        "original.pcapng",
        "redacted.pcapng",
        approvals=[
            Approval(
                domain="packet",
                packet_id=17,
                field="opt_comment",
                action="delete",
            )
        ],
    )
    for finding in report.findings:
        print(finding.code, finding.original_range)
