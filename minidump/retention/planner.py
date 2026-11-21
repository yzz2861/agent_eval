#!/usr/bin/env python3
#
# Offline evidence retention planner for crash dump cleanup.
#
# The planner never performs network IO and never executes the recorded
# analyses. It only reads a local minidump and the local stream catalog that
# describes which evidence each candidate reading needs for recomputation,
# then classifies every fragment of the dump as RETAINED or CLEANABLE.
#
import os
from dataclasses import dataclass, field
from typing import List, Optional

from minidump.minidumpfile import MinidumpFile
from minidump.constants import MINIDUMP_STREAM_TYPE

from minidump.retention.catalog import RetentionCatalogError, load_catalog, parse_address


class RetentionPlanningError(Exception):
	pass


# Structural fragments are needed to open the file and to resolve the
# stream directory, so they can never be released.
HEADER_FRAGMENT_ID = "header"
DIRECTORY_FRAGMENT_ID = "stream-directory"


def stream_fragment_id(stream_type):
	return "stream:%s" % stream_type.name


def memory_fragment_id(kind, index):
	return "memory:%s[%d]" % (kind, index)


@dataclass
class Fragment:
	"""A cleanable unit inside the dump file.

	Stream fragments cover a directory entry backing bytes. Memory fragments
	cover a single memory segment from the MemoryList / Memory64List stream.
	"""
	fragment_id: str
	kind: str
	file_offset: int
	file_size: int
	start_virtual_address: Optional[int] = None
	end_virtual_address: Optional[int] = None
	parent_fragment_id: Optional[str] = None
	stream_type: Optional[MINIDUMP_STREAM_TYPE] = None
	retained: bool = False
	reasons: List["RetentionReason"] = field(default_factory=list)


@dataclass
class RetentionReason:
	"""Why a fragment must be retained."""
	analysis_id: str
	reading_id: str
	source: str
	cached: bool

	def to_dict(self):
		return {
			"analysis_id": self.analysis_id,
			"reading_id": self.reading_id,
			"source": self.source,
			"cached": self.cached,
		}


@dataclass
class RetentionPlan:
	"""The full retention decision for one dump file."""
	dump_path: str
	fragments: List[Fragment]

	def fragment(self, fragment_id):
		for fragment in self.fragments:
			if fragment.fragment_id == fragment_id:
				return fragment
		raise KeyError(fragment_id)

	def retained_fragments(self):
		return [fragment for fragment in self.fragments if fragment.retained]

	def cleanable_fragments(self):
		return [fragment for fragment in self.fragments if not fragment.retained]

	def retained_ids(self):
		return {fragment.fragment_id for fragment in self.retained_fragments()}

	def cleanable_ids(self):
		return {fragment.fragment_id for fragment in self.fragments if not fragment.retained}

	def extra_retained_against(self, other_plan):
		"""Fragments this plan retains but ``other_plan`` does not.

		Used to show which original segments an additional analysis keeps
		beyond a baseline plan (for example an exception-only retention set).
		"""
		baseline = other_plan.retained_ids()
		return [
			fragment for fragment in self.retained_fragments()
			if fragment.fragment_id not in baseline
		]

	def to_dict(self):
		return {
			"dump_path": self.dump_path,
			"retained": [self._fragment_to_dict(fragment) for fragment in self.retained_fragments()],
			"cleanable": [self._fragment_to_dict(fragment) for fragment in self.cleanable_fragments()],
		}

	@staticmethod
	def _fragment_to_dict(fragment):
		data = {
			"fragment_id": fragment.fragment_id,
			"kind": fragment.kind,
			"file_offset": fragment.file_offset,
			"file_size": fragment.file_size,
			"reasons": [reason.to_dict() for reason in fragment.reasons],
		}
		if fragment.start_virtual_address is not None:
			data["start_virtual_address"] = fragment.start_virtual_address
			data["end_virtual_address"] = fragment.end_virtual_address
		if fragment.stream_type is not None:
			data["stream_type"] = fragment.stream_type.name
		if fragment.parent_fragment_id is not None:
			data["parent_fragment_id"] = fragment.parent_fragment_id
		return data


class RetentionPlanner:
	"""Builds retention plans from local dumps and local catalogs.

	All inputs are paths on disk. The catalog is the "stream directory" used
	to recompute the analyses; a cached reading does not remove the evidence
	requirement because the original ranges must still support recomputation.
	"""

	def __init__(self, dump_path, catalog_dir, selected_analyses=None):
		self.dump_path = dump_path
		self.catalog_dir = catalog_dir
		self.selected_analyses = list(selected_analyses) if selected_analyses else None
		self.minidump = None
		self.analyses = []
		self._fragments = []
		self._fragments_by_id = {}
		self._stream_fragments = {}

	def plan(self):
		self._load_inputs()
		self._enumerate_fragments()
		self._retain_structure()
		for analysis in self.analyses:
			for reading in analysis.readings:
				self._apply_reading(analysis, reading)
		return RetentionPlan(dump_path=os.path.abspath(self.dump_path), fragments=self._fragments)

	def _load_inputs(self):
		if not os.path.isfile(self.dump_path):
			raise RetentionPlanningError("Dump file does not exist: %s" % self.dump_path)
		if not os.path.isdir(self.catalog_dir):
			raise RetentionPlanningError(
				"Stream catalog directory does not exist: %s" % self.catalog_dir
			)
		try:
			self.minidump = MinidumpFile.parse(self.dump_path)
		except Exception as exc:
			raise RetentionPlanningError("Failed to parse dump %s: %s" % (self.dump_path, exc))
		try:
			self.analyses = load_catalog(self.catalog_dir)
		except RetentionCatalogError as exc:
			raise RetentionPlanningError("Invalid stream catalog: %s" % exc)
		available = {analysis.analysis_id for analysis in self.analyses}
		if self.selected_analyses is not None:
			unknown = [name for name in self.selected_analyses if name not in available]
			if unknown:
				raise RetentionPlanningError(
					"Unknown analysis id(s) in catalog: %s" % ", ".join(sorted(unknown))
				)
			chosen = set(self.selected_analyses)
			self.analyses = [
				analysis for analysis in self.analyses
				if analysis.analysis_id in chosen
			]

	def _add_fragment(self, fragment):
		if fragment.fragment_id in self._fragments_by_id:
			raise RetentionPlanningError("Duplicate fragment id: %s" % fragment.fragment_id)
		self._fragments.append(fragment)
		self._fragments_by_id[fragment.fragment_id] = fragment

	def _enumerate_fragments(self):
		header = self.minidump.header
		self._add_fragment(Fragment(
			fragment_id=HEADER_FRAGMENT_ID,
			kind="header",
			file_offset=0,
			file_size=32,
		))
		self._add_fragment(Fragment(
			fragment_id=DIRECTORY_FRAGMENT_ID,
			kind="directory",
			file_offset=header.StreamDirectoryRva,
			file_size=len(self.minidump.directories) * 12,
		))

		for directory in self.minidump.directories:
			stream_type = directory.StreamType
			fragment = Fragment(
				fragment_id=stream_fragment_id(stream_type),
				kind="stream",
				file_offset=directory.Location.Rva,
				file_size=directory.Location.DataSize,
				stream_type=stream_type,
			)
			self._add_fragment(fragment)
			self._stream_fragments[stream_type] = fragment

		self._enumerate_memory_segments(
			MINIDUMP_STREAM_TYPE.MemoryListStream,
			self.minidump.memory_segments,
			"memory-list",
		)
		self._enumerate_memory_segments(
			MINIDUMP_STREAM_TYPE.Memory64ListStream,
			self.minidump.memory_segments_64,
			"memory64-list",
		)

	def _enumerate_memory_segments(self, stream_type, memory_list, kind):
		if memory_list is None:
			return
		parent_id = stream_fragment_id(stream_type)
		for index, segment in enumerate(memory_list.memory_segments):
			self._add_fragment(Fragment(
				fragment_id=memory_fragment_id(kind, index),
				kind="memory",
				file_offset=segment.start_file_address,
				file_size=segment.size,
				start_virtual_address=segment.start_virtual_address,
				end_virtual_address=segment.end_virtual_address,
				parent_fragment_id=parent_id,
			))

	def _retain_structure(self):
		for fragment_id in (HEADER_FRAGMENT_ID, DIRECTORY_FRAGMENT_ID):
			self._retain(
				fragment_id,
				RetentionReason(
					analysis_id="<structure>",
					reading_id="<structure>",
					source="structural fragment required to open the dump",
					cached=False,
				),
			)

	def _apply_reading(self, analysis, reading):
		for stream_set in reading.required_streams:
			self._require_stream_set(analysis, reading, stream_set)
		for memory_range in reading.required_ranges:
			self._require_memory_range(analysis, reading, memory_range)

	def _require_stream_set(self, analysis, reading, stream_set):
		if not stream_set:
			return
		present = [name for name in stream_set if self._find_stream_fragment(name) is not None]
		if not present:
			raise RetentionPlanningError(
				"Reading %s/%s requires stream(s) %s, none are present in %s"
				% (
					analysis.analysis_id,
					reading.name,
					"|".join(stream_set),
					self.dump_path,
				)
			)
		# A stream set lists equivalent alternatives; the alternatives present
		# in this dump are the evidence that must survive to recompute it.
		for stream_name in present:
			fragment = self._find_stream_fragment(stream_name)
			self._retain(
				fragment.fragment_id,
				RetentionReason(
					analysis_id=analysis.analysis_id,
					reading_id=reading.name,
					source="required stream %s" % stream_name,
					cached=reading.from_cache,
				),
			)

	def _find_stream_fragment(self, stream_name):
		try:
			stream_type = MINIDUMP_STREAM_TYPE[stream_name]
		except KeyError:
			raise RetentionPlanningError("Unknown stream type in catalog: %s" % stream_name)
		return self._stream_fragments.get(stream_type)

	def _require_memory_range(self, analysis, reading, memory_range):
		start = parse_address(memory_range.start)
		end = memory_range.end
		if end <= start:
			raise RetentionPlanningError(
				"Reading %s/%s declares an empty/inverted memory range 0x%x-0x%x"
				% (analysis.analysis_id, reading.name, start, end)
			)
		description = memory_range.label or "memory range"
		matches = [
			fragment for fragment in self._fragments
			if fragment.kind == "memory"
			and fragment.start_virtual_address < end
			and fragment.end_virtual_address > start
		]
		if not matches:
			raise RetentionPlanningError(
				"Reading %s/%s requires %s 0x%x-0x%x but no memory segment covers it in %s"
				% (
					analysis.analysis_id,
					reading.name,
					description,
					start,
					end,
					self.dump_path,
				)
			)
		for fragment in matches:
			# A cached reading still produced its conclusion from the original
			# bytes; caching never releases the underlying evidence.
			self._retain(
				fragment.fragment_id,
				RetentionReason(
					analysis_id=analysis.analysis_id,
					reading_id=reading.name,
					source="%s 0x%x-0x%x" % (description, start, end),
					cached=reading.from_cache,
				),
			)
			self._retain(
				fragment.parent_fragment_id,
				RetentionReason(
					analysis_id=analysis.analysis_id,
					reading_id=reading.name,
					source="backing stream for retained memory segment %s" % fragment.fragment_id,
					cached=reading.from_cache,
				),
			)

	def _retain(self, fragment_id, reason):
		if fragment_id is None:
			raise RetentionPlanningError("Cannot retain an unnamed fragment")
		fragment = self._fragments_by_id.get(fragment_id)
		if fragment is None:
			raise RetentionPlanningError("Unknown fragment id: %s" % fragment_id)
		fragment.retained = True
		existing = {
			(reason_item.analysis_id, reason_item.reading_id, reason_item.source)
			for reason_item in fragment.reasons
		}
		key = (reason.analysis_id, reason.reading_id, reason.source)
		if key not in existing:
			fragment.reasons.append(reason)


def build_plan(dump_path, catalog_dir, selected_analyses=None):
	"""Convenience wrapper returning a ready-made :class:`RetentionPlan`."""
	return RetentionPlanner(dump_path, catalog_dir, selected_analyses).plan()
