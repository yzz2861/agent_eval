import os

import pytest

import Evtx.Evtx as evtx
import Evtx.Views as e_views


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
    # by default, the corrupt bytes are replaced with U+FFFD so that one
    # bad field cannot truncate the whole event...
    with evtx.Evtx(os.path.join(data_path, "dns_log_malformed.evtx")) as log:
        for chunk in log.chunks():
            for record in chunk.records():
                assert record.xml() is not None

    # ...while strict mode rejects the corrupt strings.
    with evtx.Evtx(os.path.join(data_path, "dns_log_malformed.evtx")) as log:
        with pytest.raises(UnicodeDecodeError):
            for chunk in log.chunks():
                for record in chunk.records():
                    e_views.evtx_record_xml_view(record, strict=True)


def test_continue_parsing_after_corrupt_ascii(data_path):
    """
    regression test demonstrating issue 37.

    Args:
      data_path (str): the file system path of the test directory.
    """
    with evtx.Evtx(os.path.join(data_path, "dns_log_malformed.evtx")) as log:
        # in the default, repairing mode, all five records render,
        # and the corrupt fields are visibly replaced with U+FFFD.
        rendered = [record.xml() for chunk in log.chunks() for record in chunk.records()]
        assert len(rendered) == 5
        assert any("\ufffd" in xml for xml in rendered)

    # in strict mode, the corrupt records are rejected instead.
    attempted = 0
    completed = 0
    failed = 0
    with evtx.Evtx(os.path.join(data_path, "dns_log_malformed.evtx")) as log:
        for chunk in log.chunks():
            for record in chunk.records():
                try:
                    attempted += 1
                    assert e_views.evtx_record_xml_view(record, strict=True) is not None
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
