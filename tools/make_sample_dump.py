#!/usr/bin/env python3
"""
Build a small synthetic minidump for the "thread never woke up" postmortem drill.

Streams emitted side by side:
  - ThreadListStream     (type 3)  : plain enumeration at dump time
  - ThreadExListStream   (type 8)  : extended enumeration
  - ThreadInfoListStream (type 17) : query-based info incl. create/exit times

Baked-in scenario:
  - Thread 0x1A2C is the worker under investigation. It is suspended
    (SuspendCount=1) in both enumerations, but its Priority disagrees
    between ThreadList (8) and ThreadExList (9).
  - ThreadInfoList carries TWO records for 0x1A2C: an older one flagged
    EXITED_THREAD with a non-zero ExitTime (a previous incarnation whose
    thread id was later reused), and a current one created after that
    exit, still running.
  - Thread 0x1A30 is healthy and consistent across all sources.
  - Thread 0x1A44 only exists as an ERROR_THREAD placeholder in
    ThreadInfoList: nothing beyond the id is trustworthy.
"""
import os
import struct
import sys
from datetime import datetime, timedelta, timezone

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime(dt):
	return int((dt - EPOCH_1601).total_seconds() * 10_000_000)


ERROR_THREAD = 0x00000001
WRITING_THREAD = 0x00000002
EXITED_THREAD = 0x00000004
INVALID_CONTEXT = 0x00000010

NORMAL_PRIORITY_CLASS = 0x00000020


def loc_desc(data_size, rva):
	return struct.pack('<II', data_size, rva)


def mem_desc(start, data_size, rva):
	return struct.pack('<Q', start) + loc_desc(data_size, rva)


def thread_entry(tid, suspend, prio_class, prio, teb, stack_start, stack_size, stack_rva, ctx_rva):
	return struct.pack('<IIIIQ', tid, suspend, prio_class, prio, teb) \
		+ mem_desc(stack_start, stack_size, stack_rva) \
		+ loc_desc(0, ctx_rva)


def thread_ex_entry(tid, suspend, prio_class, prio, teb, stack_start, stack_size, stack_rva, ctx_rva):
	return thread_entry(tid, suspend, prio_class, prio, teb, stack_start, stack_size, stack_rva, ctx_rva) \
		+ mem_desc(0, 0, 0)


def thread_info_entry(tid, flags, error, exit_status, create, exit_, kernel, user, start, affinity):
	return struct.pack('<IIIIQQQQQQ', tid, flags, error, exit_status,
					   create, exit_, kernel, user, start, affinity)


def build_sample(path):
	t0 = datetime(2026, 11, 22, 14, 0, 0, tzinfo=timezone.utc)
	t_old_create = t0
	t_old_exit = t0 + timedelta(minutes=37)
	t_cur_create = t0 + timedelta(minutes=41)
	t_dump = t0 + timedelta(minutes=58)

	thread_list = struct.pack('<I', 2)
	thread_list += thread_entry(0x1A2C, 1, NORMAL_PRIORITY_CLASS, 8, 0x7FFDE000, 0x12F000, 0x1000, 0, 0)
	thread_list += thread_entry(0x1A30, 0, NORMAL_PRIORITY_CLASS, 10, 0x7FFDD000, 0x22F000, 0x1000, 0, 0)

	thread_ex_list = struct.pack('<I', 2)
	thread_ex_list += thread_ex_entry(0x1A2C, 1, NORMAL_PRIORITY_CLASS, 9, 0x7FFDE000, 0x12F000, 0x1000, 0, 0)
	thread_ex_list += thread_ex_entry(0x1A30, 0, NORMAL_PRIORITY_CLASS, 10, 0x7FFDD000, 0x22F000, 0x1000, 0, 0)

	ti_header = struct.pack('<III', 12, 64, 4)
	ti_entries = b''
	ti_entries += thread_info_entry(0x1A2C, EXITED_THREAD, 0, 0,
									filetime(t_old_create), filetime(t_old_exit),
									1_250_000, 3_400_000, 0x7FF610000000, 0xF)
	ti_entries += thread_info_entry(0x1A2C, 0, 0, 0x103,
									filetime(t_cur_create), 0,
									800_000, 2_100_000, 0x7FF610000000, 0xF)
	ti_entries += thread_info_entry(0x1A30, WRITING_THREAD, 0, 0x103,
									filetime(t0), 0,
									500_000, 900_000, 0x7FF610001000, 0xF)
	ti_entries += thread_info_entry(0x1A44, ERROR_THREAD | INVALID_CONTEXT, 0x80070005, 0,
									0, 0, 0, 0, 0, 0)
	thread_info_list = ti_header + ti_entries

	streams = [
		(3, thread_list),
		(8, thread_ex_list),
		(17, thread_info_list),
	]

	header_size = 32
	dir_size = 12 * len(streams)
	rva = header_size + dir_size
	directories = b''
	body = b''
	for stype, data in streams:
		directories += struct.pack('<I', stype) + loc_desc(len(data), rva)
		body += data
		rva += len(data)

	flags = 0x00000100 | 0x00001000
	header = b'MDMP'
	header += struct.pack('<HHIIII', 0xA793, 0, len(streams), header_size, 0,
						  int(t_dump.timestamp()))
	header += struct.pack('<I', flags)
	header += b'\x00' * (header_size - len(header))

	with open(path, 'wb') as f:
		f.write(header + directories + body)
	return path


if __name__ == '__main__':
	out = sys.argv[1] if len(sys.argv) > 1 else os.path.join('samples', 'thread_reuse_sample.dmp')
	os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
	build_sample(out)
	print('sample written to %s' % out)
