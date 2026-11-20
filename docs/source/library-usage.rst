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


Probe handoff audits
====================

When a pcapng file is the concatenation of captures produced by several
probes, interface ids are only meaningful within their own section.  The
:py:mod:`pcapng.handoff` helpers therefore identify every interface by its
`(section index, interface id)` pair and never merge interfaces across
sections.

A typical audit reads the declared link type of every Interface Description
Block together with a few observable packet prefixes, flags interfaces that
share a human remark but disagree on their link type, and optionally compares
the result against a receiver-provided handoff checklist:

.. code-block:: python

    from pcapng import FileScanner
    from pcapng.handoff import (
        collect_interfaces,
        find_remark_conflicts,
        check_handoff,
        load_checklist,
    )

    with open('capture.pcapng', 'rb') as fp:
        records = collect_interfaces(FileScanner(fp))

    for record in records:
        print(record.label, record.link_type, record.remark)

    print(find_remark_conflicts(records))

    with open('checklist.ini') as checklist_fp:
        print(check_handoff(records, load_checklist(checklist_fp)))

Link types the library does not recognize are reported by numeric value
only: no name or packet structure is invented for an unfamiliar header.
The equivalent command-line report lives in
`examples/probe_handoff_audit.py`, and a matching two-probe sample can be
regenerated with `examples/generate_handoff_sample.py`.
