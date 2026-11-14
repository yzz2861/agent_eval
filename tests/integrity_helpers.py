import os

import Evtx.Evtx as evtx
from Evtx.Integrity import IntegrityStatus

CHUNK_SIZE = 0x10000
FILE_HEADER_SIZE = 0x1000
CHUNK_HEADER_SIZE = 0x200
FILE_HEADER_CHECKSUM_OFFSET = 0x7C
CHUNK_HEADER_CHECKSUM_OFFSET = 0x7C
CHUNK_DATA_CHECKSUM_OFFSET = 0x34
CHUNK_NEXT_RECORD_OFFSET = 0x30
TEMPLATE_TABLE_OFFSET = 0x180


def load_evtx_bytes(data_path, name):
    with open(os.path.join(data_path, name), "rb") as f:
        return bytearray(f.read())


def write_tmp_evtx(tmp_path, data, name="mutated.evtx"):
    path = tmp_path / name
    with open(str(path), "wb") as f:
        f.write(bytes(data))
    return str(path)


def chunk_offset(chunk_index):
    return FILE_HEADER_SIZE + (chunk_index * CHUNK_SIZE)


def first_record_absolute_offset(data, chunk_index=0):
    """Return the absolute file offset of the first record of a chunk."""
    return chunk_offset(chunk_index) + CHUNK_HEADER_SIZE


def open_integrity(path, recover=True):
    return evtx.Evtx(path, recover=recover)


def statuses(report):
    return {check.check.value: check.status.value for check in report.checks}


def get_check(report, check_type):
    for check in report.checks:
        if check.check == check_type:
            return check
    raise KeyError(check_type)


def all_ok(report):
    return report.status() == IntegrityStatus.OK and not report.failures()
