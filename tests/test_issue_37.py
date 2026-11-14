import os

import pytest

import Evtx.Evtx as evtx
import Evtx.Views as e_views
from Evtx.Integrity import IntegrityStatus


def test_corrupt_ascii_example(data_path):
    """
    regression test demonstrating issue 37.

    Args:
      data_path (str): the file system path of the test directory.
    """
    # record number two contains a QNAME xml element
    # with an ASCII text value that is invalid ASCII:
    #
    #     000002E0:                                31 39 33 2E 31 2E            193.1.
    #     000002F0: 33 36 2E 31 32 31 30 2E  39 2E 31 35 2E 32 30 32  36.1210.9.15.202
    #     00000300: 01 62 2E 5F 64 6E 73 2D  73 64 2E 5F 75 64 70 2E  .b._dns-sd._udp.
    #     00000310: 40 A6 35 01 2E                                    @.5..
    #                  ^^ ^^ ^^
    #
    with pytest.raises(UnicodeDecodeError):
        with evtx.Evtx(os.path.join(data_path, "dns_log_malformed.evtx")) as log:
            for chunk in log.chunks():
                for record in chunk.records():
                    assert record.xml() is not None


def test_continue_parsing_after_corrupt_ascii(data_path):
    """
    regression test demonstrating issue 37.

    Args:
      data_path (str): the file system path of the test directory.
    """
    attempted = 0
    completed = 0
    failed = 0
    with evtx.Evtx(os.path.join(data_path, "dns_log_malformed.evtx")) as log:
        for chunk in log.chunks():
            for record in chunk.records():
                try:
                    attempted += 1
                    assert record.xml() is not None
                    completed += 1
                except UnicodeDecodeError:
                    failed += 1

    # this small log file has exactly five records.
    assert attempted == 5
    # the first record is valid.
    assert completed == 1
    # however the remaining four have corrupted ASCII strings,
    # which we are unable to decode.
    assert failed == 4


def test_recovery_mode_keeps_integrity_markers(data_path):
    """
    recovery mode never hides verification state behind clean XML: every
    record reachable through the marked file view carries an explicit
    EVTX-INTEGRITY comment, and records whose integrity layer fails also get
    an integrity attribute on the rendered element.
    """
    rendered = 0
    with evtx.Evtx(os.path.join(data_path, "dns_log_malformed.evtx")) as log:
        for chunk in log.chunks():
            for record in chunk.records():
                report = record.integrity()
                record_xml = e_views.evtx_record_xml_view_marked(record)
                assert record_xml.startswith("<!-- EVTX-INTEGRITY:")
                if report.ok():
                    assert "status=ok" in record_xml
                else:
                    assert report.status() in (IntegrityStatus.RECOVERABLE, IntegrityStatus.STRUCTURAL)
                    assert "status={}".format(report.status().value) in record_xml
                rendered += 1
    assert rendered == 5


def test_integrity_report_is_json_serializable(data_path):
    import json

    with evtx.Evtx(os.path.join(data_path, "dns_log_malformed.evtx")) as log:
        for record in log.records():
            # the JSON envelope must exist even when the payload XML cannot be
            # rendered due to the malformed ASCII bytes (issue 37).
            view = e_views.evtx_record_integrity_dict(record)
            encoded = json.dumps(view)
            assert "_integrity" in encoded
            assert view["_integrity"]["status"] in ("ok", "recoverable", "structural")
