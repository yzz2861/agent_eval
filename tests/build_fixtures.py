#!/usr/bin/env python3
#
# Generates the synthetic minidump fixtures used by the retention planner
# tests. The dumps are built from raw bytes so that fixture creation stays
# fully offline and independent of the Windows capture APIs.
#
import os
import struct

from minidump.constants import MINIDUMP_STREAM_TYPE, MINIDUMP_TYPE

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
HEADER_SIZE = 32
DIRECTORY_ENTRY_SIZE = 12

# Four virtual memory segments shared (in terms of VA layout) by both dumps.
MEMORY_SEGMENTS = [
	(0x10000, 0x1000, b"FAULT" + b"\x00" * (0x1000 - 5)),
	(0x20000, 0x2000, b"STACK-DATA" + b"\x00" * (0x2000 - 10)),
	(0x30000, 0x4000, b"HEAP" + b"\x00" * (0x4000 - 4)),
	(0x40000, 0x800, b"UNUSED" + b"\x00" * (0x800 - 6)),
]


def _memory_list_stream(blobs, data_blob, data_base_rva):
	# MINIDUMP_MEMORY_LIST: count then one descriptor (VA 8, size 4, rva 4).
	blob = struct.pack("<I", len(MEMORY_SEGMENTS))
	rva = data_base_rva
	for start, size, _payload in MEMORY_SEGMENTS:
		blob += struct.pack("<QII", start, size, rva)
		rva += size
	blobs.append((MINIDUMP_STREAM_TYPE.MemoryListStream, blob))
	data_blob.append(b"".join(payload for _start, _size, payload in MEMORY_SEGMENTS))


def _memory64_list_stream(blobs, data_blob, data_base_rva):
	# MINIDUMP_MEMORY64_LIST: count, base rva, then (VA, size) pairs. The
	# backing bytes are stored consecutively starting at BaseRva.
	blob = struct.pack("<QQ", len(MEMORY_SEGMENTS), data_base_rva)
	for start, size, _payload in MEMORY_SEGMENTS:
		blob += struct.pack("<QQ", start, size)
	blobs.append((MINIDUMP_STREAM_TYPE.Memory64ListStream, blob))
	data_blob.append(b"".join(payload for _start, _size, payload in MEMORY_SEGMENTS))


def _exception_stream(blobs):
	# MINIDUMP_EXCEPTION_STREAM: thread id, alignment, exception record,
	# thread context location descriptor.
	exception_code = 0xC0000005  # EXCEPTION_ACCESS_VIOLATION
	exception_address = 0x10040  # lands inside the first memory segment
	record = struct.pack(
		"<IIQQII",
		exception_code,
		0,                  # ExceptionFlags
		0,                  # ExceptionRecord
		exception_address,
		2,                  # NumberParameters
		0,                  # alignment
	)
	record += struct.pack("<15Q", 1, 0x10040, *([0] * 13))
	blob = struct.pack("<II", 4242, 0)
	blob += record
	blob += struct.pack("<II", 0, 0)  # no separate thread context blob
	blobs.append((MINIDUMP_STREAM_TYPE.ExceptionStream, blob))


def _comment_stream(blobs):
	text = "retention-planner-fixture".encode("utf-16-le")
	blob = struct.pack("<I", len(text)) + text
	blobs.append((MINIDUMP_STREAM_TYPE.CommentStreamW, blob))


def _system_info_stream(blobs):
	# Minimal MINIDUMP_SYSTEM_INFO enough for the parser to accept the file.
	blob = struct.pack(
		"<HHHBBHIIII",
		9,      # ProcessorArchitecture (AMD64)
		6,      # ProcessorLevel
		1,      # ProcessorRevision
		1,      # NumberOfProcessors (low byte)
		0,      # ProductType
		0,      # MajorVersion/MinorVersion padding handled below
		0,      # MajorVersion
		0,      # MinorVersion
		0,      # BuildNumber
		0,      # PlatformId
	)
	blob += struct.pack("<I", 0)  # CSDVersionRva
	blob += struct.pack("<H", 0)  # SuiteMask
	blob += struct.pack("<H", 0)  # Reserved2
	blobs.append((MINIDUMP_STREAM_TYPE.SystemInfoStream, blob))


def build_dump(path, use_memory64):
	blobs = []
	data_blob = []
	_exception_stream(blobs)
	_system_info_stream(blobs)
	_comment_stream(blobs)
	if use_memory64:
		# Reserve space for header + directory + stream blobs to place data.
		_memory64_list_stream(blobs, data_blob, 0)
	else:
		_memory_list_stream(blobs, data_blob, 0)

	stream_count = len(blobs)
	directory_rva = HEADER_SIZE
	data_size = sum(len(chunk) for chunk in data_blob)
	stream_area_size = sum(len(blob) for _stream_type, blob in blobs)
	data_base_rva = HEADER_SIZE + stream_count * DIRECTORY_ENTRY_SIZE + stream_area_size

	# Patch descriptors that reference the data region.
	patched = []
	for stream_type, blob in blobs:
		if stream_type == MINIDUMP_STREAM_TYPE.Memory64ListStream:
			blob = struct.pack("<QQ", len(MEMORY_SEGMENTS), data_base_rva)
			blob += b"".join(struct.pack("<QQ", start, size) for start, size, _ in MEMORY_SEGMENTS)
		elif stream_type == MINIDUMP_STREAM_TYPE.MemoryListStream:
			blob = struct.pack("<I", len(MEMORY_SEGMENTS))
			rva = data_base_rva
			for start, size, _payload in MEMORY_SEGMENTS:
				blob += struct.pack("<QII", start, size, rva)
				rva += size
		patched.append((stream_type, blob))

	header = b"MDMP"
	header += struct.pack("<HH", 0xA793, 0)  # Version, ImplementationVersion
	header += struct.pack("<I", stream_count)
	header += struct.pack("<I", directory_rva)
	header += struct.pack("<I", 0)  # CheckSum
	header += struct.pack("<I", 0)  # TimeDateStamp (reserved in modern layout)
	header += struct.pack("<I", 0)  # reserved padding field
	header += struct.pack("<I", MINIDUMP_TYPE.MiniDumpNormal.value)  # Flags
	assert len(header) == HEADER_SIZE

	directory = b""
	cursor = HEADER_SIZE + stream_count * DIRECTORY_ENTRY_SIZE
	stream_bytes = b""
	for stream_type, blob in patched:
		directory += struct.pack("<III", stream_type.value, len(blob), cursor)
		stream_bytes += blob
		cursor += len(blob)

	with open(path, "wb") as handle:
		handle.write(header)
		handle.write(directory)
		handle.write(stream_bytes)
		for chunk in data_blob:
			handle.write(chunk)


def write_catalog(catalog_dir, include_cache_reading):
	os.makedirs(catalog_dir, exist_ok=True)
	exception_spec = {
		"analysis_id": "exception-conclusion",
		"description": "Crash exception code and faulting address conclusion",
		"readings": [
			{
				"name": "exception-stream-reading",
				"required_streams": [
					"ExceptionStream",
					["MemoryListStream", "Memory64ListStream"],
				],
				"required_ranges": [
					{"start": "0x10000", "size": 0x1000, "label": "faulting page"},
				],
				"from_cache": False,
			},
			{
				"name": "cached-exception-reading",
				"required_streams": [
					"ExceptionStream",
					["MemoryListStream", "Memory64ListStream"],
				],
				"required_ranges": [
					{"start": "0x10000", "size": 0x1000, "label": "faulting page"},
				],
				"from_cache": True,
			},
		],
	}
	stack_spec = {
		"analysis_id": "stack-scan",
		"description": "Additional stack memory scan beyond the exception conclusion",
		"readings": [
			{
				"name": "stack-range-reading",
				"required_streams": [
					["MemoryListStream", "Memory64ListStream"],
				],
				"required_ranges": [
					{"start": "0x20000", "size": 0x2000, "label": "stack page"},
					{"start": "0x30000", "size": 0x2000, "label": "heap prefix"},
				],
				"from_cache": False,
			},
		],
	}
	import json
	with open(os.path.join(catalog_dir, "01_exception.json"), "w", encoding="utf-8") as handle:
		json.dump(exception_spec, handle, indent=2)
	with open(os.path.join(catalog_dir, "02_stack_scan.json"), "w", encoding="utf-8") as handle:
		json.dump(stack_spec, handle, indent=2)


def main():
	catalog_mini = os.path.join(FIXTURE_DIR, "catalog_mini")
	catalog_full = os.path.join(FIXTURE_DIR, "catalog_full")
	mini_path = os.path.join(FIXTURE_DIR, "sample_mini.dmp")
	full_path = os.path.join(FIXTURE_DIR, "sample_full.dmp")
	build_dump(mini_path, use_memory64=False)
	build_dump(full_path, use_memory64=True)
	write_catalog(catalog_mini, True)
	write_catalog(catalog_full, True)
	print("fixtures written to %s" % FIXTURE_DIR)


if __name__ == "__main__":
	main()
