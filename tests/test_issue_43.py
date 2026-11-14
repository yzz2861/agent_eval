import os

import pytest

import Evtx.Evtx as evtx
import Evtx.Views as e_views


def get_record_by_num(log, record_num):
    for record in log.records():
        if record.record_num() == record_num:
            return record
    raise KeyError(record_num)


def test_issue_43(data_path):
    """
    regression test demonstrating issue 43.

    Args:
      data_path (str): the file system path of the test directory.
    """
    with evtx.Evtx(os.path.join(data_path, "issue_43.evtx")) as log:
        bad_rec = get_record_by_num(log, 508)
        # by default, the corrupt UTF-16 string is replaced with U+FFFD,
        # so one bad field cannot truncate the whole event...
        assert "\ufffd" in bad_rec.xml()
        # ...while strict mode rejects the record.
        with pytest.raises(UnicodeDecodeError):
            _ = e_views.evtx_record_xml_view(bad_rec, strict=True)
