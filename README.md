python-evtx
===========

Introduction
------------

python-evtx is a pure Python parser for recent Windows Event Log files (those with the file extension ".evtx").  The module provides programmatic access to the File and Chunk headers, record templates, and event entries.  For example, you can use python-evtx to review the event logs of Windows 7 systems from a Mac or Linux workstation. The structure definitions and parsing strategies were heavily inspired by the work of Andreas Schuster and his Perl implementation "Parse-Evtx".

Background
----------
With the release of Windows Vista, Microsoft introduced an updated event log file format.  The format used in Windows XP was a circular buffer of record structures that each contained a list of strings.  A viewer resolved templates hosted in system library files and inserted the strings into appropriate positions.  The newer event log format is proprietary binary XML.  Unpacking chunks from an event log file from Windows 7 results in a complete XML document with a variable schema.  The changes helped Microsoft tune the file format to real-world uses of event logs, such as long running logs with hundreds of megabytes of data, and system independent template resolution.

Related Work
------------
Andreas Schuster released the first public description of the .evtx file format in 2007.  He is the author of the thorough document "Introducing the Microsoft Vista event log file format" that describes the motivation and details of the format.  Mr. Schuster also maintains the Perl implementation of a parser called "Parse-Evtx".  I referred to the source code of this library extensively during the development of python-evtx.

Joachim Metz also released a cross-platform, LGPL licensed C++ based parser in 2011.  His document "Windows XML Event Log (EVTX): Analysis of EVTX" provides a detailed description of the structures and context of newer event log files.

Dependencies
------------
python-evtx is a pure Python 3 module, so it works equally well across platforms like Windows, macOS, and Linux. 

python-evtx operates on event log files from Windows operating systems newer than Windows Vista.  These files typically have the file extension .evtx.  Version 5.09 of the `file` utility identifies such a file as "MS Vista Windows Event Log".  To manual confirm the file type, look for the ASCII string "ElfFile" in the first seven bytes:

    willi/evtx  » xxd -l 32 Security.evtx 
    0000000: 456c 6646 696c 6500 0000 0000 0000 0000  ElfFile.........
    0000010: d300 0000 0000 0000 375e 0000 0000 0000  ........7^......


Examples
--------
Provided with the parsing module `Evtx` are four scripts that mimic the tools distributed with Parse-Evtx.  `evtx_info.py` prints metadata about the event log and verifies the checksums of each chunk.  `evtx_templates.py` builds and prints the templates used throughout the event log. `evtx_dump.py` parses the event log and transforms the binary XML into a human readable ASCII XML format. Finally, `evtx_dump_json.py` parses event logs, similar to `evtx_dump.py` and transforms the binary XML into JSON with the added capability to output the JSON array to a file. 

Note the length of the `evtx_dump.py` script: its only 20 lines.  Now, review the contents and notice the complete implementation of the logic:

    print(e_views.XML_HEADER)
    print('<Events>')
    for record in log.records:
        print(record.xml())
    print('</Events>')  

Working with python-evtx is really easy!


Scoped Event Browsing
---------------------
`Evtx.Browser.EventBrowser` exposes an inclusive range of EVTX record numbers
while keeping record contents, fields, and summaries independently visible.
Cursors are authenticated, opaque, and bound to one browser's archive, role,
range, and policy generation. A cursor from another overlapping role window or
from before a range change is rejected.

The source provenance returned with each page is not subject to field
redaction. It identifies the original record numbers and byte offsets, allowing
an investigation lead to map a forwarded fragment back to the archive without
gaining access to fields that were not disclosed.

    from Evtx.Browser import EventBrowser

    with_key = "shared-receipt-key"
    duty = EventBrowser(
        "System.evtx",
        first_record=12049,
        last_record=12057,
        role="duty",
        page_size=4,
        field_visibility=("EventID", "Provider.Name", "TimeCreated.SystemTime"),
        summary_visibility=("total_count", "first_record_number", "last_record_number"),
        signing_key=with_key,
    )
    lead = EventBrowser(
        "System.evtx",
        first_record=12054,
        last_record=12062,
        role="lead",
        page_size=4,
        signing_key=with_key,
    )

    page = duty.page()
    assert page.source_range == (12049, 12052)
    assert page.provenance.scope_first_offset is not None
    next_page = duty.page(cursor=page.next_cursor)

    # Receipts remain verifiable after the browser moves to a new range.
    old_page = duty.page()
    old_receipt = old_page.receipt
    duty.set_range(12100, 12104)
    assert duty.verify(old_receipt)

    # Overlapping views have different query state even with the same key.
    try:
        lead.page(cursor=page.next_cursor)
    except Exception:
        pass  # InvalidCursor: the cursor belongs to the duty scope.

Use a stable `signing_key` when receipts must be verified by another process.
The default key is process-local and is suitable only for in-process verification.

Installation
------------
Updates to python-evtx are pushed to PyPi, so you can install the module using `pip`.  For example:

    pip install python-evtx

The source code for python-evtx is hosted at Github, and you may download, fork, and review it from this repository (http://www.github.com/williballenthin/python-evtx).  Please report issues or feature requests through Github's bug tracker associated with the project.

Development
-----------
For formatting, use isort:
    
    isort --length-sort --profile black --line-length=120 Evtx/ scripts/ tests/

and black:

    black --line-length=120 Evtx/ scripts/ tests/

For linting, use ruff:

    ruff check Evtx/ scripts/ tests/

Or use [just](https://github.com/casey/just) to run the linters:

    just lint

License
-------
python-evtx is licensed under the Apache License, Version 2.0.  This means it is freely available for use and modification in a personal and professional capacity.  

