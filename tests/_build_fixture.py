import io

from minidump.constants import MINIDUMP_STREAM_TYPE, MINIDUMP_TYPE
from minidump.header import MinidumpHeader
from minidump.directory import MINIDUMP_DIRECTORY
from minidump.common_structs import MINIDUMP_LOCATION_DESCRIPTOR
from minidump.streams.SystemInfoStream import (
	MINIDUMP_SYSTEM_INFO,
	PROCESSOR_ARCHITECTURE,
	PRODUCT_TYPE,
	PLATFORM_ID,
)


SEG1_VA = 0x1000
SEG1_DATA = bytes(range(0x01, 0x09))
SEG2_VA = 0x2000
SEG2_DATA = bytes(range(0x11, 0x19))
ALIAS_VA = 0x5000

FILL = 0xEE

APPROVED_RANGES = [
	(SEG1_VA, SEG1_VA + len(SEG1_DATA)),
	(SEG2_VA, SEG2_VA + len(SEG2_DATA)),
]


def _system_info_bytes():
	info = MINIDUMP_SYSTEM_INFO()
	info.ProcessorArchitecture = PROCESSOR_ARCHITECTURE.AMD64
	info.ProcessorLevel = 6
	info.ProcessorRevision = 0
	info.NumberOfProcessors = 1
	info.ProductType = PRODUCT_TYPE.VER_NT_WORKSTATION
	info.MajorVersion = 10
	info.MinorVersion = 0
	info.BuildNumber = 19045
	info.PlatformId = PLATFORM_ID.VER_PLATFORM_WIN32_NT.value
	info.CSDVersionRva = 0
	info.SuiteMask = 0
	info.Reserved2 = 0
	info.ProcessorFeatures = [0, 0]
	return info.to_bytes()


def build_minidump_bytes():
	segments = [
		(SEG1_VA, SEG1_DATA),
		(SEG2_VA, SEG2_DATA),
		# Aliased mapping: different VA, same backing bytes as segment 1.
		(ALIAS_VA, SEG1_DATA),
	]

	header_size = 32
	number_of_streams = 3
	directory_rva = header_size
	directory_size = number_of_streams * 12

	# Stream data is laid out after the directory.
	module_list_rva = directory_rva + directory_size
	module_list_bytes = (0).to_bytes(4, byteorder="little")

	memory_list_rva = module_list_rva + len(module_list_bytes)
	memory_list_size = 4 + len(segments) * 16

	payload_rva = memory_list_rva + memory_list_size
	total_payload = sum(len(payload) for _, payload in segments)
	sysinfo_bytes = _system_info_bytes()
	sysinfo_rva = payload_rva + total_payload

	descriptor_records = []
	next_rva = payload_rva
	for va, payload in segments:
		descriptor_records.append((va, len(payload), next_rva))
		next_rva += len(payload)

	# The on-disk MINIDUMP_MEMORY_DESCRIPTOR is 16 bytes: 8-byte VA followed
	# by an 8-byte MINIDUMP_LOCATION_DESCRIPTOR (DataSize, Rva).
	memory_list_bytes = len(segments).to_bytes(4, byteorder="little")
	for va, size, rva in descriptor_records:
		memory_list_bytes += va.to_bytes(8, byteorder="little")
		memory_list_bytes += size.to_bytes(4, byteorder="little")
		memory_list_bytes += rva.to_bytes(4, byteorder="little")

	def directory(stream_type, data_size, rva):
		location = MINIDUMP_LOCATION_DESCRIPTOR()
		location.DataSize = data_size
		location.Rva = rva
		entry = MINIDUMP_DIRECTORY()
		entry.StreamType = stream_type
		entry.Location = location
		return entry

	buffer = io.BytesIO()
	header = MinidumpHeader()
	header.Signature = "MDMP"
	header.Version = 0xA793
	header.ImplementationVersion = 0
	header.NumberOfStreams = number_of_streams
	header.StreamDirectoryRva = directory_rva
	header.CheckSum = 0
	header.TimeDateStamp = 0
	header.Flags = MINIDUMP_TYPE.MiniDumpNormal
	buffer.write(header.to_bytes())
	# MINIDUMP_HEADER is 32 bytes; the library serializer omits the trailing 4.
	buffer.write(bytes(4))

	buffer.write(directory(MINIDUMP_STREAM_TYPE.ModuleListStream, len(module_list_bytes), module_list_rva).to_bytes())
	buffer.write(directory(MINIDUMP_STREAM_TYPE.SystemInfoStream, len(sysinfo_bytes), sysinfo_rva).to_bytes())
	buffer.write(directory(MINIDUMP_STREAM_TYPE.MemoryListStream, len(memory_list_bytes), memory_list_rva).to_bytes())

	buffer.write(module_list_bytes)
	buffer.write(memory_list_bytes)
	for _, payload in segments:
		buffer.write(payload)
	buffer.write(sysinfo_bytes)

	return buffer.getvalue()
