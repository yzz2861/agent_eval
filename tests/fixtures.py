import os
import mmap
import os.path
import contextlib

import pytest

from mutated_evtx import (
    make_bad_record_magic,
    make_corrupt_chunk,
    make_cross_chunk_reference,
    make_duplicate_offset,
    make_out_of_order,
    make_overlapping,
    make_record_number_regression,
    make_slack_pseudo_record,
    make_timestamp_regression,
    make_truncated_chunk,
    make_zero_length_record,
)


def system_path():
    """
    fetch the file system path of the system.evtx test file.

    Returns:
      str: the file system path of the test file.
    """
    cd = os.path.dirname(__file__)
    datadir = os.path.join(cd, "data")
    systempath = os.path.join(datadir, "system.evtx")
    return systempath


@pytest.fixture
def system():
    """
    yields the contents of the system.evtx test file.
    the returned value is a memory map of the contents,
     so it acts pretty much like a byte string.

    Returns:
      mmap.mmap: the contents of the test file.
    """
    p = system_path()
    with open(p, "rb") as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
            yield buf


def security_path():
    """
    fetch the file system path of the security.evtx test file.

    Returns:
      str: the file system path of the test file.
    """
    cd = os.path.dirname(__file__)
    datadir = os.path.join(cd, "data")
    secpath = os.path.join(datadir, "security.evtx")
    return secpath


@pytest.fixture
def security():
    """
    yields the contents of the security.evtx test file.
    the returned value is a memory map of the contents,
     so it acts pretty much like a byte string.

    Returns:
      mmap.mmap: the contents of the test file.
    """
    p = security_path()
    with open(p, "rb") as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
            yield buf


@pytest.fixture
def data_path():
    """
    fetch the file system path of the directory containing test files.

    Returns:
      str: the file system path of the test directory.
    """
    cd = os.path.dirname(__file__)
    datadir = os.path.join(cd, "data")
    return datadir


def _issue_38_bytes():
    datadir = os.path.join(os.path.dirname(__file__), "data")
    with open(os.path.join(datadir, "issue_38.evtx"), "rb") as handle:
        return handle.read()


@pytest.fixture
def issue_38_bytes():
    return _issue_38_bytes()


@pytest.fixture
def overlapping_evtx(issue_38_bytes):
    return make_overlapping(issue_38_bytes)


@pytest.fixture
def out_of_order_evtx(issue_38_bytes):
    return make_out_of_order(issue_38_bytes)


@pytest.fixture
def slack_pseudo_record_evtx(issue_38_bytes):
    return make_slack_pseudo_record(issue_38_bytes)


@pytest.fixture
def truncated_evtx(issue_38_bytes):
    return make_truncated_chunk(issue_38_bytes)


@pytest.fixture
def zero_length_evtx(issue_38_bytes):
    return make_zero_length_record(issue_38_bytes)


@pytest.fixture
def duplicate_offset_evtx(issue_38_bytes):
    return make_duplicate_offset(issue_38_bytes)


@pytest.fixture
def cross_chunk_evtx(issue_38_bytes):
    return make_cross_chunk_reference(issue_38_bytes)


@pytest.fixture
def corrupt_chunk_evtx(issue_38_bytes):
    return make_corrupt_chunk(issue_38_bytes)


@pytest.fixture
def bad_record_magic_evtx(issue_38_bytes):
    return make_bad_record_magic(issue_38_bytes)


@pytest.fixture
def record_number_regression_evtx(issue_38_bytes):
    return make_record_number_regression(issue_38_bytes)


@pytest.fixture
def timestamp_regression_evtx(issue_38_bytes):
    return make_timestamp_regression(issue_38_bytes)
