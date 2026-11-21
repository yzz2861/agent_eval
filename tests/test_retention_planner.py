#!/usr/bin/env python3
#
# Tests for the offline evidence retention planner. The same scenarios are
# exercised against both fixture dumps: one carrying a MemoryListStream and
# one carrying a Memory64ListStream.
#
import json
import os
import subprocess
import sys

import pytest

from minidump.retention import (
	RetentionPlanningError,
	build_plan,
	format_diff,
	format_plan,
)
from minidump.retention.catalog import load_catalog

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
MINI_DUMP = os.path.join(FIXTURE_DIR, "sample_mini.dmp")
FULL_DUMP = os.path.join(FIXTURE_DIR, "sample_full.dmp")
MINI_CATALOG = os.path.join(FIXTURE_DIR, "catalog_mini")
FULL_CATALOG = os.path.join(FIXTURE_DIR, "catalog_full")

DUMP_CASES = [
	pytest.param(MINI_DUMP, MINI_CATALOG, "memory-list", id="memory-list"),
	pytest.param(FULL_DUMP, FULL_CATALOG, "memory64-list", id="memory64-list"),
]


def _memory_id(kind, index):
	return "memory:%s[%d]" % (kind, index)


@pytest.mark.parametrize("dump_path,catalog_dir,kind", DUMP_CASES)
def test_catalog_loads_both_analyses(dump_path, catalog_dir, kind):
	analyses = load_catalog(catalog_dir)
	assert {spec.analysis_id for spec in analyses} == {
		"exception-conclusion",
		"stack-scan",
	}
	exception = next(spec for spec in analyses if spec.analysis_id == "exception-conclusion")
	assert [reading.name for reading in exception.readings] == [
		"exception-stream-reading",
		"cached-exception-reading",
	]
	assert exception.readings[0].from_cache is False
	assert exception.readings[1].from_cache is True


@pytest.mark.parametrize("dump_path,catalog_dir,kind", DUMP_CASES)
def test_exception_only_plan_retains_faulting_page(dump_path, catalog_dir, kind):
	plan = build_plan(dump_path, catalog_dir, ["exception-conclusion"])

	assert "header" in plan.retained_ids()
	assert "stream-directory" in plan.retained_ids()
	assert "stream:ExceptionStream" in plan.retained_ids()
	assert _memory_id(kind, 0) in plan.retained_ids()

	cleanable = plan.cleanable_ids()
	for index in (1, 2, 3):
		assert _memory_id(kind, index) in cleanable
	assert "stream:SystemInfoStream" in cleanable
	assert "stream:CommentStreamW" in cleanable

	faulting = plan.fragment(_memory_id(kind, 0))
	sources = {reason.source for reason in faulting.reasons}
	assert any("faulting page" in source for source in sources)
	# Both the live and the cached readings demand the same original bytes.
	assert {reason.cached for reason in faulting.reasons} == {True, False}


@pytest.mark.parametrize("dump_path,catalog_dir,kind", DUMP_CASES)
def test_backing_memory_stream_is_retained(dump_path, catalog_dir, kind):
	plan = build_plan(dump_path, catalog_dir, ["exception-conclusion"])
	stream_name = "stream:MemoryListStream" if kind == "memory-list" else "stream:Memory64ListStream"
	stream_fragment = plan.fragment(stream_name)
	assert stream_fragment.retained is True
	parent_ids = {
		plan.fragment(fragment_id).parent_fragment_id
		for fragment_id in plan.retained_ids()
		if fragment_id.startswith("memory:")
	}
	assert stream_name in parent_ids


@pytest.mark.parametrize("dump_path,catalog_dir,kind", DUMP_CASES)
def test_extra_analysis_keeps_additional_original_segments(dump_path, catalog_dir, kind):
	baseline = build_plan(dump_path, catalog_dir, ["exception-conclusion"])
	extended = build_plan(
		dump_path,
		catalog_dir,
		["exception-conclusion", "stack-scan"],
	)

	extra = extended.extra_retained_against(baseline)
	extra_ids = {fragment.fragment_id for fragment in extra}
	assert extra_ids == {_memory_id(kind, 1), _memory_id(kind, 2)}

	# The baseline-cleanable segments become retained for concrete reasons.
	stack_fragment = extended.fragment(_memory_id(kind, 1))
	assert any("stack page" in reason.source for reason in stack_fragment.reasons)
	heap_fragment = extended.fragment(_memory_id(kind, 2))
	assert any("heap prefix" in reason.source for reason in heap_fragment.reasons)

	# The untouched fourth segment stays cleanable in both plans.
	assert _memory_id(kind, 3) in extended.cleanable_ids()
	assert baseline.extra_retained_against(extended) == []

	rendered = format_diff(baseline, extended)
	assert _memory_id(kind, 1) in rendered
	assert _memory_id(kind, 2) in rendered
	assert "stack page" in rendered


def _write_catalog(catalog_dir, spec):
	os.makedirs(catalog_dir, exist_ok=True)
	with open(os.path.join(catalog_dir, "analysis.json"), "w", encoding="utf-8") as handle:
		json.dump(spec, handle)


def test_cached_reading_does_not_release_original_range(tmp_path):
	# A catalog whose only reading is served from cache. The original faulting
	# page must still be retained so the conclusion can be recomputed.
	catalog_dir = tmp_path / "cached-only"
	_write_catalog(catalog_dir, {
		"analysis_id": "cached-only-analysis",
		"description": "Conclusion currently available from cache only",
		"readings": [
			{
				"name": "cached-reading",
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
	})
	plan = build_plan(MINI_DUMP, str(catalog_dir))
	faulting = plan.fragment("memory:memory-list[0]")
	assert faulting.retained is True
	assert all(reason.cached is True for reason in faulting.reasons)
	assert plan.fragment("stream:MemoryListStream").retained is True
	assert plan.fragment("memory:memory-list[1]").retained is False


def test_missing_memory_coverage_raises(tmp_path):
	catalog_dir = tmp_path / "uncovered"
	_write_catalog(catalog_dir, {
		"analysis_id": "uncovered-analysis",
		"description": "Points at a VA no segment contains",
		"readings": [
			{
				"name": "uncovered-reading",
				"required_streams": [["MemoryListStream", "Memory64ListStream"]],
				"required_ranges": [
					{"start": "0x90000", "size": 0x1000, "label": "phantom page"},
				],
				"from_cache": False,
			},
		],
	})
	with pytest.raises(RetentionPlanningError, match="no memory segment covers"):
		build_plan(MINI_DUMP, str(catalog_dir))


def test_missing_required_stream_raises(tmp_path):
	catalog_dir = tmp_path / "missing-stream"
	_write_catalog(catalog_dir, {
		"analysis_id": "module-analysis",
		"description": "Needs a stream the fixture does not contain",
		"readings": [
			{
				"name": "module-reading",
				"required_streams": ["ModuleListStream"],
				"required_ranges": [],
				"from_cache": False,
			},
		],
	})
	with pytest.raises(RetentionPlanningError, match="none are present"):
		build_plan(MINI_DUMP, str(catalog_dir))


def test_unknown_analysis_id_raises():
	with pytest.raises(RetentionPlanningError, match="Unknown analysis id"):
		build_plan(MINI_DUMP, MINI_CATALOG, ["does-not-exist"])


def test_missing_dump_or_catalog_raises(tmp_path):
	with pytest.raises(RetentionPlanningError, match="Dump file does not exist"):
		build_plan(str(tmp_path / "nope.dmp"), MINI_CATALOG)
	with pytest.raises(RetentionPlanningError, match="catalog directory does not exist"):
		build_plan(MINI_DUMP, str(tmp_path / "no-catalog"))


def test_plan_dict_and_text_rendering_are_complete():
	plan = build_plan(MINI_DUMP, MINI_CATALOG, ["exception-conclusion"])
	data = plan.to_dict()
	assert os.path.abspath(MINI_DUMP) == data["dump_path"]
	assert {entry["fragment_id"] for entry in data["retained"]} == plan.retained_ids()
	assert {entry["fragment_id"] for entry in data["cleanable"]} == plan.cleanable_ids()
	text = format_plan(plan)
	assert "RETAINED" in text and "CLEANABLE" in text
	assert "memory:memory-list[0]" in text


def test_planner_runs_without_network(tmp_path):
	# Spawn the CLI in a subprocess and forbid all socket creation to prove
	# the planner is purely offline.
	probe = tmp_path / "offline_probe.py"
	probe.write_text(
		"import socket\n"
		"def deny(*args, **kwargs):\n"
		"    raise RuntimeError(\"network access is forbidden\")\n"
		"socket.socket = deny\n"
		"socket.create_connection = deny\n"
		"from minidump.retention.__main__ import run\n"
		"raise SystemExit(run())\n",
		encoding="utf-8",
	)
	env = dict(os.environ)
	repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
	result = subprocess.run(
		[
			sys.executable,
			str(probe),
			MINI_DUMP,
			MINI_CATALOG,
			"--analysis",
			"exception-conclusion",
		],
		capture_output=True,
		text=True,
		env=env,
	)
	assert result.returncode == 0, result.stderr
	assert "RETAINED" in result.stdout
	assert "RuntimeError" not in result.stderr


def test_cli_json_output():
	env = dict(os.environ)
	repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
	result = subprocess.run(
		[
			sys.executable,
			"-m",
			"minidump.retention",
			MINI_DUMP,
			MINI_CATALOG,
			"--analysis",
			"exception-conclusion",
			"--json",
		],
		capture_output=True,
		text=True,
		env=env,
	)
	assert result.returncode == 0, result.stderr
	payload = json.loads(result.stdout)
	assert "retained" in payload and "cleanable" in payload
	assert any(entry["fragment_id"] == "memory:memory-list[0]" for entry in payload["retained"])
