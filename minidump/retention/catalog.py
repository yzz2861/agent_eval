#!/usr/bin/env python3
#
# Offline analysis-catalog loading for the retention planner.
#
# A catalog is a directory of JSON files.  Each file describes one analysis
# item together with every candidate reading that can recompute its results.
# Nothing in this module performs any IO beyond reading local files.
#
import json
import os


class RetentionCatalogError(Exception):
	pass


class CandidateReading:
	def __init__(self, name, required_streams=None, required_ranges=None, from_cache=False):
		self.name = name
		self.required_streams = list(required_streams or [])
		self.required_ranges = list(required_ranges or [])
		self.from_cache = from_cache

	def to_dict(self):
		return {
			'name': self.name,
			'from_cache': self.from_cache,
			'required_streams': list(self.required_streams),
			'required_ranges': [r.to_dict() for r in self.required_ranges],
		}


class AnalysisSpec:
	def __init__(self, analysis_id, description, readings):
		self.analysis_id = analysis_id
		self.description = description
		self.readings = list(readings)

	def to_dict(self):
		return {
			'analysis_id': self.analysis_id,
			'description': self.description,
			'readings': [r.to_dict() for r in self.readings],
		}


class RequiredMemoryRange:
	def __init__(self, start, size, label=''):
		self.start = int(start)
		self.size = int(size)
		self.end = self.start + self.size
		self.label = label

	def to_dict(self):
		return {
			'start': '0x%x' % self.start,
			'size': self.size,
			'end': '0x%x' % self.end,
			'label': self.label,
		}


def _parse_address(value):
	if isinstance(value, int):
		return value
	if isinstance(value, str):
		return int(value, 16 if value.lower().startswith('0x') else 10)
	raise RetentionCatalogError('Address must be an int or string, got %r' % value)


def _parse_stream_requirement(entry):
	if isinstance(entry, str):
		return [entry]
	if isinstance(entry, list) and entry and all(isinstance(item, str) for item in entry):
		return list(entry)
	raise RetentionCatalogError('required_streams entries must be a stream name or a non-empty list of stream names, got %r' % entry)


def _parse_reading(raw):
	if not isinstance(raw, dict) or 'name' not in raw:
		raise RetentionCatalogError('Each reading must be an object containing a "name" field')
	streams = []
	for entry in raw.get('required_streams', []):
		streams.append(_parse_stream_requirement(entry))
	ranges = []
	for raw_range in raw.get('required_ranges', []):
		if not isinstance(raw_range, dict) or 'start' not in raw_range or 'size' not in raw_range:
			raise RetentionCatalogError('Each required range needs "start" and "size"')
		ranges.append(RequiredMemoryRange(
			_parse_address(raw_range['start']),
			_parse_address(raw_range['size']),
			raw_range.get('label', ''),
		))
	return CandidateReading(
		name=raw['name'],
		required_streams=streams,
		required_ranges=ranges,
		from_cache=bool(raw.get('from_cache', False)),
	)


def parse_analysis_spec(raw):
	if not isinstance(raw, dict):
		raise RetentionCatalogError('Analysis specification must be a JSON object')
	analysis_id = raw.get('analysis_id')
	if not analysis_id or not isinstance(analysis_id, str):
		raise RetentionCatalogError('Analysis specification requires a string "analysis_id"')
	readings_raw = raw.get('readings')
	if not isinstance(readings_raw, list) or not readings_raw:
		raise RetentionCatalogError('Analysis %s needs at least one candidate reading' % analysis_id)
	readings = [_parse_reading(item) for item in readings_raw]
	return AnalysisSpec(analysis_id, raw.get('description', ''), readings)


def load_catalog(catalog_dir):
	if not os.path.isdir(catalog_dir):
		raise RetentionCatalogError('Catalog directory does not exist: %s' % catalog_dir)
	specs = []
	for filename in sorted(os.listdir(catalog_dir)):
		if not filename.endswith('.json'):
			continue
		path = os.path.join(catalog_dir, filename)
		with open(path, 'r', encoding='utf-8') as handle:
			try:
				raw = json.load(handle)
			except json.JSONDecodeError as error:
				raise RetentionCatalogError('Invalid JSON in %s: %s' % (path, error))
		specs.append(parse_analysis_spec(raw))
	if not specs:
		raise RetentionCatalogError('No analysis specifications (*.json) found in %s' % catalog_dir)
	return specs


# Public alias used by the planner while keeping the private helper name above.
parse_address = _parse_address
