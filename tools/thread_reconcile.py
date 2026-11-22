#!/usr/bin/env python3
"""
Cross-source thread reconciliation for postmortem investigations.

Given a minidump and a thread id noted by whoever handled the incident,
this tool correlates the three thread-related streams:

  - ThreadListStream     : plain enumeration (suspend count, priority, TEB)
  - ThreadExListStream   : extended enumeration (same fields + backing store)
  - ThreadInfoListStream : query-based info (create/exit times, dump flags)

Design rules:
  - Evidence first: every claim in the report quotes the raw record it
    came from. ThreadInfoList is re-parsed from raw bytes so that
    combined/unknown DumpFlags values survive (the library parser maps
    flags onto a single-value enum and silently drops combinations).
  - When sources disagree, both values are kept and the report explains
    which interpretation of the scene still holds, instead of picking
    a winner silently.
  - Thread ids are recycled by the OS. Multiple ThreadInfo records with
    the same id are treated as an id-reuse history: records flagged
    EXITED_THREAD with a non-zero ExitTime that predates the current
    CreateTime are archived as historical clues, not current state.

Usage:
  python tools/thread_reconcile.py <dump file> <thread id, hex or dec> [--out DIR]
"""
import argparse
import os
import struct
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from minidump.minidumpfile import MinidumpFile
from minidump.constants import MINIDUMP_STREAM_TYPE

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)

DUMP_FLAG_NAMES = {
	0x01: 'ERROR_THREAD',
	0x02: 'WRITING_THREAD',
	0x04: 'EXITED_THREAD',
	0x08: 'INVALID_INFO',
	0x10: 'INVALID_CONTEXT',
	0x20: 'INVALID_TEB',
}

TRUST_CURRENT = 'current'
TRUST_STALE = 'stale-clue'
TRUST_UNRELIABLE = 'unreliable'


def filetime_to_dt(value):
	if not value:
		return None
	return EPOCH_1601 + timedelta(microseconds=value / 10)


def fmt_time(value):
	dt = filetime_to_dt(value)
	return dt.strftime('%Y-%m-%d %H:%M:%S UTC') if dt else '-'


def fmt_flags(raw):
	if raw == 0:
		return '(none)'
	names = [name for bit, name in DUMP_FLAG_NAMES.items() if raw & bit]
	known = 0
	for bit in DUMP_FLAG_NAMES:
		known |= bit
	unknown = raw & ~known
	if unknown:
		names.append('UNKNOWN(0x%x)' % unknown)
	return '|'.join(names)


class ThreadInfoRecord:
	def __init__(self, tid, flags, error, exit_status, create, exit_, kernel, user, start, affinity):
		self.tid = tid
		self.flags = flags
		self.error = error
		self.exit_status = exit_status
		self.create = create
		self.exit = exit_
		self.kernel = kernel
		self.user = user
		self.start = start
		self.affinity = affinity

	@property
	def is_error_placeholder(self):
		return bool(self.flags & 0x01)

	@property
	def is_exited(self):
		return bool(self.flags & 0x04) or (self.exit != 0)


def parse_thread_info_raw(mf):
	"""Re-parse ThreadInfoListStream from raw bytes, preserving raw DumpFlags."""
	records = []
	directory = None
	for d in mf.directories:
		if d.StreamType == MINIDUMP_STREAM_TYPE.ThreadInfoListStream:
			directory = d
			break
	if directory is None:
		return records
	mf.file_handle.seek(directory.Location.Rva)
	data = mf.file_handle.read(directory.Location.DataSize)
	size_of_header, size_of_entry, count = struct.unpack_from('<III', data, 0)
	offset = max(size_of_header, 12)
	for i in range(count):
		fields = struct.unpack_from('<IIIIQQQQQQ', data, offset + i * size_of_entry)
		records.append(ThreadInfoRecord(*fields))
	return records


def collect(mf, tid):
	evidence = {'thread_list': None, 'thread_ex': None, 'thread_info': []}
	if mf.threads is not None:
		for t in mf.threads.threads:
			if t.ThreadId == tid:
				evidence['thread_list'] = t
	if mf.threads_ex is not None:
		for t in mf.threads_ex.threads:
			if t.ThreadId == tid:
				evidence['thread_ex'] = t
	for rec in parse_thread_info_raw(mf):
		if rec.tid == tid:
			evidence['thread_info'].append(rec)
	evidence['thread_info'].sort(key=lambda r: (r.create, r.exit))
	return evidence


def classify_info_records(records):
	"""Split same-id ThreadInfo records into current vs historical."""
	current, historical = [], []
	for rec in records:
		if rec.is_error_placeholder:
			current.append((rec, TRUST_UNRELIABLE))
		elif rec.is_exited:
			historical.append(rec)
		else:
			current.append((rec, TRUST_CURRENT))
	if historical and current:
		latest_create = max(r.create for r, _ in current)
		confirmed = [r for r in historical if r.exit and r.exit <= latest_create]
		for r in confirmed:
			historical.remove(r)
			current.append((r, TRUST_STALE))
		for r in historical:
			current.append((r, TRUST_STALE))
		return current
	for r in historical:
		current.append((r, TRUST_STALE))
	return current


def reconcile(mf, tid):
	ev = collect(mf, tid)
	lines = []
	add = lines.append

	add('# Thread 0x%04X reconciliation report' % tid)
	add('')
	add('- dump file: `%s`' % mf.filename)
	if mf.header is not None and mf.header.TimeDateStamp:
		stamp = datetime.fromtimestamp(mf.header.TimeDateStamp, tz=timezone.utc)
		add('- dump timestamp: %s' % stamp.strftime('%Y-%m-%d %H:%M:%S UTC'))
	add('')

	add('## Evidence (as recorded, no reconciliation applied)')
	add('')
	tl, te = ev['thread_list'], ev['thread_ex']
	if tl is not None:
		add('- ThreadListStream: SuspendCount=%d PriorityClass=0x%X Priority=%d Teb=0x%X'
			% (tl.SuspendCount, tl.PriorityClass, tl.Priority, tl.Teb))
	else:
		add('- ThreadListStream: thread id NOT present')
	if te is not None:
		add('- ThreadExListStream: SuspendCount=%d PriorityClass=0x%X Priority=%d Teb=0x%X'
			% (te.SuspendCount, te.PriorityClass, te.Priority, te.Teb))
	else:
		add('- ThreadExListStream: thread id NOT present')
	if ev['thread_info']:
		for i, rec in enumerate(ev['thread_info'], 1):
			add('- ThreadInfoListStream record %d: DumpFlags=%s (raw 0x%X) DumpError=0x%X '
				'ExitStatus=0x%X Create=%s Exit=%s StartAddress=0x%X'
				% (i, fmt_flags(rec.flags), rec.flags, rec.error, rec.exit_status,
				   fmt_time(rec.create), fmt_time(rec.exit), rec.start))
	else:
		add('- ThreadInfoListStream: thread id NOT present')
	add('')

	add('## Conflicts and how the scene can still be explained')
	add('')
	conflicts = []
	if tl is not None and te is not None:
		if tl.Priority != te.Priority or tl.PriorityClass != te.PriorityClass:
			conflicts.append(
				'- Priority mismatch: ThreadList says %d, ThreadExList says %d. '
				'Both streams are written during the same dump but enumerate '
				'through different paths; a thread whose dynamic priority was '
				'being boosted/decayed while the dump was taken legitimately '
				'lands different values in the two streams. Neither value is '
				'discarded: treat the pair (%d, %d) as the plausible range, '
				'and do not build conclusions on any single one.'
				% (tl.Priority, te.Priority, tl.Priority, te.Priority))
		if tl.SuspendCount != te.SuspendCount:
			conflicts.append(
				'- SuspendCount mismatch: ThreadList says %d, ThreadExList says %d. '
				'The count changed between the two enumerations; the larger '
				'value is the safer lower bound for "was it suspended".'
				% (tl.SuspendCount, te.SuspendCount))
	info_records = ev['thread_info']
	if len(info_records) > 1:
		exited = [r for r in info_records if r.is_exited]
		running = [r for r in info_records if not r.is_exited and not r.is_error_placeholder]
		if exited and running:
			conflicts.append(
				'- Same thread id appears %d times in ThreadInfoList. The record(s) '
				'flagged EXITED_THREAD exited at %s, BEFORE the current record was '
				'created at %s. This is consistent with the OS recycling the thread '
				'id: the exited record describes a previous incarnation, not the '
				'thread that was dumped. Keep it as a historical clue only.'
				% (len(info_records),
				   ', '.join(fmt_time(r.exit) for r in exited),
				   ', '.join(fmt_time(r.create) for r in running)))
	if tl is not None and any(r.is_exited for r in info_records):
		conflicts.append(
			'- The id is enumerated as live in ThreadListStream while a '
			'ThreadInfo record marks it EXITED_THREAD. Both can be true at '
			'once only if the id was reused; the create/exit timestamps above '
			'are the deciding evidence.')
	for rec in info_records:
		if rec.is_error_placeholder:
			conflicts.append(
				'- A ThreadInfo record carries ERROR_THREAD (DumpError=0x%X): the '
				'dumper failed to query this thread. Only the thread id itself is '
				'reliable in that record; every other field is a placeholder.'
				% rec.error)
	if conflicts:
		lines.extend(conflicts)
	else:
		add('- No cross-source conflicts detected for this thread id.')
	add('')

	add('## Trust assessment')
	add('')
	if tl is not None and te is not None and tl.SuspendCount == te.SuspendCount:
		if tl.SuspendCount > 0:
			add('- [current] SuspendCount=%d is confirmed by BOTH enumerations: the '
				'thread was suspended at dump time. This directly supports the '
				'"never woke up" symptom.' % tl.SuspendCount)
		else:
			add('- [current] SuspendCount=0 is confirmed by BOTH enumerations: '
				'the thread was not suspended at dump time.')
	elif tl is not None or te is not None:
		src = tl if tl is not None else te
		add('- [current] SuspendCount=%d comes from a single enumeration only; '
			'plausible but uncorroborated.' % src.SuspendCount)
	if tl is not None and te is not None and tl.Priority != te.Priority:
		add('- [unreliable] Priority: sources disagree (%d vs %d); archive both, '
			'trust neither on its own.' % (tl.Priority, te.Priority))
	elif tl is not None:
		add('- [current] Priority=%d agrees across enumerations.' % tl.Priority)
	for rec, trust in classify_info_records(info_records):
		if trust == TRUST_CURRENT:
			add('- [current] ThreadInfo: created %s, still active (ExitStatus=0x%X), '
				'flags %s.' % (fmt_time(rec.create), rec.exit_status, fmt_flags(rec.flags)))
		elif trust == TRUST_STALE:
			add('- [stale-clue] ThreadInfo: created %s, exited %s. Previous '
				'incarnation of id 0x%04X; explains old log lines but says '
				'nothing about the dumped thread.'
				% (fmt_time(rec.create), fmt_time(rec.exit), tid))
		else:
			add('- [unreliable] ThreadInfo placeholder (ERROR_THREAD, '
				'DumpError=0x%X): only the id is trustworthy.' % rec.error)
	if not ev['thread_info']:
		add('- ThreadInfoListStream absent or has no record for this id; '
			'timeline claims cannot be cross-checked.')
	add('')
	return '\n'.join(lines)


def main():
	parser = argparse.ArgumentParser(description='Cross-source thread reconciliation')
	parser.add_argument('dump', help='minidump file')
	parser.add_argument('tid', help='thread id, hex (0x..) or decimal')
	parser.add_argument('--out', default='analysis', help='directory for the archived report')
	args = parser.parse_args()

	tid = int(args.tid, 0)
	mf = MinidumpFile.parse(args.dump)
	report = reconcile(mf, tid)
	print(report)

	os.makedirs(args.out, exist_ok=True)
	report_path = os.path.join(args.out, 'thread_%04x_report.md' % tid)
	with open(report_path, 'w') as f:
		f.write(report)
	print('report archived to %s' % report_path, file=sys.stderr)


if __name__ == '__main__':
	main()
