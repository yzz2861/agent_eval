#!/usr/bin/env python3
#
# Human readable rendering of a :class:`RetentionPlan`.
#
from minidump.retention.planner import RetentionPlan


def _hex_or_none(value):
	if value is None:
		return "-"
	return "0x%x" % value


def _format_reason(reason):
	cached = " [cached]" if reason.cached else ""
	return "%s/%s: %s%s" % (
		reason.analysis_id,
		reason.reading_id,
		reason.source,
		cached,
	)


def format_plan(plan):
	lines = []
	lines.append("Retention plan for %s" % plan.dump_path)
	lines.append("=" * 72)

	retained = plan.retained_fragments()
	cleanable = plan.cleanable_fragments()
	lines.append("Retained fragments: %d" % len(retained))
	lines.append("Cleanable fragments: %d" % len(cleanable))
	lines.append("")

	lines.append("RETAINED")
	lines.append("-" * 72)
	for fragment in retained:
		lines.append(
			"  %s (offset=%s size=%d va=%s-%s)"
			% (
				fragment.fragment_id,
				_hex_or_none(fragment.file_offset),
				fragment.file_size,
				_hex_or_none(fragment.start_virtual_address),
				_hex_or_none(fragment.end_virtual_address),
			)
		)
		for reason in fragment.reasons:
			lines.append("      - %s" % _format_reason(reason))
	lines.append("")

	lines.append("CLEANABLE")
	lines.append("-" * 72)
	for fragment in cleanable:
		lines.append(
			"  %s (offset=%s size=%d va=%s-%s)"
			% (
				fragment.fragment_id,
				_hex_or_none(fragment.file_offset),
				fragment.file_size,
				_hex_or_none(fragment.start_virtual_address),
				_hex_or_none(fragment.end_virtual_address),
			)
		)
	return "\n".join(lines)


def format_diff(baseline_plan, extended_plan):
	"""Show which original fragments the extended plan keeps additionally."""
	extra = extended_plan.extra_retained_against(baseline_plan)
	lines = []
	lines.append("Extra fragments retained beyond the baseline plan")
	lines.append("=" * 72)
	if not extra:
		lines.append("(none)")
		return "\n".join(lines)
	for fragment in extra:
		lines.append(
			"  %s (offset=%s size=%d va=%s-%s)"
			% (
				fragment.fragment_id,
				_hex_or_none(fragment.file_offset),
				fragment.file_size,
				_hex_or_none(fragment.start_virtual_address),
				_hex_or_none(fragment.end_virtual_address),
			)
		)
		for reason in fragment.reasons:
			lines.append("      - %s" % _format_reason(reason))
	return "\n".join(lines)
