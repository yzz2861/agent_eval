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

Preservation evidence for unknown blocks
========================================

When a file contains block types the library cannot decode, use the
read-only :py:func:`~pcapng.scan_unknown_blocks` entry point. It never
modifies the stream and returns a report describing each unknown block:
its owning section, declared length, the byte range that was actually
readable, and a digest of the recovered bytes. A truncated block is still
listed but flagged incomplete, and every section establishes its own byte
order instead of inheriting the previous one.

.. code-block:: python

    from pcapng import scan_unknown_blocks

    with open("/tmp/legacy-capture.pcapng", "rb") as fp:
        report = scan_unknown_blocks(fp)

    for evidence in report.unknown_blocks:
        print(evidence.section, hex(evidence.block_type),
              evidence.declared_length, evidence.readable_start,
              evidence.readable_end, evidence.digest,
              evidence.incomplete)
