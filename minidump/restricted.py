#!/usr/bin/env python3
#
# Read-only, hand-off-able view over an approved set of virtual address
# ranges of a minidump.
#
# The forensics side keeps the original minidump file.  This view only
# materializes the bytes that fall inside the approved address list, so the
# resulting object can be handed to an external expert together with its
# serialized form without exposing any other evidence.
#

import io


class RestrictedViewError(Exception):
	"""Base class for errors raised by the restricted view."""
	pass


class RestrictedRangeError(RestrictedViewError):
	"""
	Raised when a read starts outside every approved range.

	On purpose the message only references the approved ranges and never the
	requested (and therefore undisclosed) address or any other dump metadata.
	"""
	pass


class RestrictedReadResult:
	"""
	Outcome of a restricted read.

	``data`` always has exactly the requested length.  Positions whose byte is
	not part of the disclosure are filled with ``fill`` and the same positions
	are marked ``False`` in ``available`` / in ``mask``.
	"""
	def __init__(self, address, size, data, available, fill=0x00):
		self.address = address
		self.size = size
		self.data = data
		self.available = available
		self.fill = fill

	@property
	def mask(self):
		"""Byte-wise availability mask: ``1`` disclosed, ``0`` missing."""
		return bytes(1 if ok else 0 for ok in self.available)

	@property
	def missing_ranges(self):
		"""Virtual address ranges (start, end) whose bytes are not disclosed."""
		ranges = []
		start = None
		for index, ok in enumerate(self.available):
			if not ok and start is None:
				start = self.address + index
			elif ok and start is not None:
				ranges.append((start, self.address + index))
				start = None
		if start is not None:
			ranges.append((start, self.address + len(self.available)))
		return ranges

	@property
	def is_complete(self):
		return all(self.available)

	def __bytes__(self):
		return self.data

	def __len__(self):
		return self.size

	def __eq__(self, other):
		if not isinstance(other, RestrictedReadResult):
			return NotImplemented
		return (
			self.address == other.address
			and self.data == other.data
			and self.available == other.available
			and self.fill == other.fill
		)

	def __repr__(self):
		return (
			"RestrictedReadResult(address=%s, size=%d, disclosed=%d, missing=%d)"
			% (
				hex(self.address),
				self.size,
				sum(self.available),
				len(self.available) - sum(self.available),
			)
		)


class _DisclosedBlock:
	"""One contiguous chunk of bytes copied out of the minidump."""
	def __init__(self, start, data, evidence_key):
		self.start = start
		self.end = start + len(data)
		self.data = data
		self.evidence_key = evidence_key


class RestrictedMinidumpView:
	"""
	Read-only view limited to an approved list of virtual address ranges.

	``approved_ranges`` is an iterable of ``(start, end)`` pairs (end
	exclusive).  Only the intersection of those ranges and the memory actually
	present in the minidump is copied into the view at construction time; the
	underlying file handle is never retained, so the view is safe to hand over
	and serialize.
	"""

	MAGIC = b'RDMP'
	VERSION = 1

	def __init__(self, approved_ranges, fill=0x00):
		self._approved_ranges = self._normalize_ranges(approved_ranges)
		self.fill = fill
		self._blocks = []
		self._evidence_keys = set()

	# ------------------------------------------------------------------ #
	# Construction
	# ------------------------------------------------------------------ #
	@staticmethod
	def _normalize_ranges(ranges):
		normalized = []
		for start, end in ranges:
			if end < start:
				raise RestrictedViewError(
					'Invalid approved range: end %s is below start %s'
					% (hex(end), hex(start))
				)
			if end == start:
				continue
			normalized.append((start, end))
		normalized.sort()

		merged = []
		for start, end in normalized:
			if merged and start <= merged[-1][1]:
				if end > merged[-1][1]:
					merged[-1] = (merged[-1][0], end)
			else:
				merged.append((start, end))
		return merged

	def _record_block(self, start, data, evidence_key):
		if not data:
			return
		self._blocks.append(_DisclosedBlock(start, data, evidence_key))
		self._evidence_keys.add(evidence_key)

	def _finalize_blocks(self):
		self._blocks.sort(key=lambda block: block.start)

		# Adjacent pieces produced by the segment/range clipping are stitched
		# together, but only when they originate from the same evidence.
		merged = []
		for block in self._blocks:
			if (
				merged
				and merged[-1].end == block.start
				and merged[-1].evidence_key == block.evidence_key
			):
				previous = merged.pop()
				self._evidence_keys.discard(previous.evidence_key)
				block = _DisclosedBlock(
					previous.start,
					previous.data + block.data,
					previous.evidence_key,
				)
			merged.append(block)
			self._evidence_keys.add(block.evidence_key)
		self._blocks = merged

	def _collect_overlaps(self, reader):
		"""Compute the approved/present overlaps without reading any bytes."""
		segments = list(reader.memory_segments)
		overlaps = []
		for approved_start, approved_end in self._approved_ranges:
			for segment in segments:
				overlap_start = max(approved_start, segment.start_virtual_address)
				overlap_end = min(approved_end, segment.end_virtual_address)
				if overlap_start >= overlap_end:
					continue

				size = overlap_end - overlap_start
				# The evidence key identifies the underlying bytes inside the
				# minidump file.  Several virtual segments may point at the
				# same key (aliased mappings); disclosure is still decided by
				# the approved virtual addresses, so an unapproved alias can
				# never pull in extra bytes.
				offset_in_segment = overlap_start - segment.start_virtual_address
				evidence_key = (
					segment.start_file_address + offset_in_segment,
					segment.start_file_address + offset_in_segment + size,
				)
				overlaps.append(
					(segment, overlap_start, size, evidence_key)
				)
		return overlaps

	@classmethod
	def from_reader(cls, reader, approved_ranges, fill=0x00):
		"""Build a view from a synchronous ``MinidumpFileReader``."""
		view = cls(approved_ranges, fill=fill)
		overlaps = view._collect_overlaps(reader)
		for segment, overlap_start, size, evidence_key in overlaps:
			data = segment.read(overlap_start, size, reader.file_handle)
			view._record_block(overlap_start, data, evidence_key)
		view._finalize_blocks()
		return view

	@classmethod
	async def from_async_reader(cls, reader, approved_ranges, fill=0x00):
		"""Build a view from an ``AMinidumpFileReader``."""
		view = cls(approved_ranges, fill=fill)
		overlaps = view._collect_overlaps(reader)
		for segment, overlap_start, size, evidence_key in overlaps:
			data = await segment.aread(
				overlap_start, size, reader.file_handle
			)
			view._record_block(overlap_start, data, evidence_key)
		view._finalize_blocks()
		return view

	# ------------------------------------------------------------------ #
	# Public metadata
	# ------------------------------------------------------------------ #
	@property
	def approved_ranges(self):
		"""The merged, read-only list of approved virtual address ranges."""
		return list(self._approved_ranges)

	@property
	def disclosed_ranges(self):
		"""Ranges for which bytes could actually be copied out of the dump."""
		return [(block.start, block.end) for block in self._blocks]

	@property
	def evidence_keys(self):
		"""
		Underlying-evidence identifiers backing the disclosed bytes.

		Two blocks share the same underlying evidence when their keys are
		equal; the disclosure restriction still follows the virtual addresses
		that were approved.
		"""
		return set(self._evidence_keys)

	def is_approved(self, address):
		for start, end in self._approved_ranges:
			if start <= address < end:
				return True
		return False

	# ------------------------------------------------------------------ #
	# Reads
	# ------------------------------------------------------------------ #
	def _read_core(self, address, size):
		if size < 0:
			raise RestrictedViewError('Read size must not be negative')
		if size == 0:
			return RestrictedReadResult(address, 0, b'', [], fill=self.fill)

		if not self.is_approved(address):
			# Deliberately only quote the approved ranges in the error text.
			rendered = ', '.join(
				'%s-%s' % (hex(start), hex(end))
				for start, end in self._approved_ranges
			)
			raise RestrictedRangeError(
				'Read starts outside the approved disclosure ranges: %s'
				% rendered
			)

		request_end = address + size
		data = bytearray(bytes([self.fill]) * size)
		available = [False] * size

		for block in self._blocks:
			if block.end <= address or block.start >= request_end:
				continue
			copy_start = max(address, block.start)
			copy_end = min(request_end, block.end)
			dst = copy_start - address
			src = copy_start - block.start
			length = copy_end - copy_start
			data[dst:dst + length] = block.data[src:src + length]
			for index in range(dst, dst + length):
				available[index] = True

		return RestrictedReadResult(
			address, size, bytes(data), available, fill=self.fill
		)

	def read(self, address, size):
		"""Synchronous read; identical byte result to :meth:`aread`."""
		return self._read_core(address, size)

	async def aread(self, address, size):
		"""Asynchronous counterpart of :meth:`read` with the same semantics."""
		return self._read_core(address, size)

	# ------------------------------------------------------------------ #
	# Hand-off serialization (no original minidump required to reload)
	# ------------------------------------------------------------------ #
	def to_bytes(self):
		buffer = io.BytesIO()
		buffer.write(self.MAGIC)
		buffer.write(self.VERSION.to_bytes(2, byteorder='little', signed=False))
		buffer.write(self.fill.to_bytes(1, byteorder='little', signed=False))
		buffer.write(len(self._approved_ranges).to_bytes(4, byteorder='little'))
		for start, end in self._approved_ranges:
			buffer.write(start.to_bytes(8, byteorder='little'))
			buffer.write(end.to_bytes(8, byteorder='little'))
		buffer.write(len(self._blocks).to_bytes(4, byteorder='little'))
		for block in self._blocks:
			buffer.write(block.start.to_bytes(8, byteorder='little'))
			buffer.write(len(block.data).to_bytes(8, byteorder='little'))
			key_start, key_end = block.evidence_key
			buffer.write(key_start.to_bytes(8, byteorder='little'))
			buffer.write(key_end.to_bytes(8, byteorder='little'))
			buffer.write(block.data)
		return buffer.getvalue()

	@classmethod
	def from_bytes(cls, payload):
		buffer = io.BytesIO(payload)
		magic = buffer.read(4)
		if magic != cls.MAGIC:
			raise RestrictedViewError('Bad restricted view signature')
		version = int.from_bytes(buffer.read(2), byteorder='little')
		if version != cls.VERSION:
			raise RestrictedViewError(
				'Unsupported restricted view version %d' % version
			)
		fill = buffer.read(1)[0]
		range_count = int.from_bytes(buffer.read(4), byteorder='little')
		approved_ranges = []
		for _ in range(range_count):
			start = int.from_bytes(buffer.read(8), byteorder='little')
			end = int.from_bytes(buffer.read(8), byteorder='little')
			approved_ranges.append((start, end))

		view = cls(approved_ranges, fill=fill)
		block_count = int.from_bytes(buffer.read(4), byteorder='little')
		for _ in range(block_count):
			start = int.from_bytes(buffer.read(8), byteorder='little')
			size = int.from_bytes(buffer.read(8), byteorder='little')
			key_start = int.from_bytes(buffer.read(8), byteorder='little')
			key_end = int.from_bytes(buffer.read(8), byteorder='little')
			data = buffer.read(size)
			view._record_block(start, data, (key_start, key_end))
		view._finalize_blocks()
		return view
