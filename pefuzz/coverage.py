"""Lightweight coverage tracer for pefile directory parsing.

The tracer counts, for one parse run, how often each data-directory parser
is entered and how deeply the recursive resource parser nests.  These
counts give an objective "deep directory reached" signal instead of relying
on line-level coverage of a third-party module.
"""

import sys
from dataclasses import dataclass, field


DIRECTORY_PARSERS = {
    "parse_export_directory": "EXPORT",
    "parse_import_directory": "IMPORT",
    "parse_resources_directory": "RESOURCE",
    "parse_exceptions_directory": "EXCEPTION",
    "parse_relocations_directory": "BASERELOC",
    "parse_debug_directory": "DEBUG",
    "parse_directory_tls": "TLS",
    "parse_directory_load_config": "LOAD_CONFIG",
    "parse_directory_bound_imports": "BOUND_IMPORT",
    "parse_delay_import_directory": "DELAY_IMPORT",
}


@dataclass
class CoverageReport:
    directory_hits: dict = field(default_factory=dict)
    resource_max_depth: int = 0
    resource_calls: int = 0
    distinct_directories: int = 0

    def reached_at_least_depth(self, depth):
        return self.resource_max_depth >= depth

    def explain(self):
        parts = [
            name + "=" + str(self.directory_hits.get(name, 0))
            for name in sorted(set(self.directory_hits))
        ]
        parts.append("resource_max_depth=" + str(self.resource_max_depth))
        parts.append("distinct_directories=" + str(self.distinct_directories))
        return ", ".join(parts)



class DirectoryCoverage:
    """Context manager that counts directory-parser call events."""

    def __init__(self):
        self.report = CoverageReport()
        self._resource_depth = 0
        self._previous_trace = None

    def _on_call(self, frame, event, arg):
        if frame.f_globals.get("__name__") != "pefile":
            return None
        func_name = frame.f_code.co_name
        if func_name in DIRECTORY_PARSERS:
            label = DIRECTORY_PARSERS[func_name]
            self.report.directory_hits[label] = (
                self.report.directory_hits.get(label, 0) + 1
            )
        if func_name == "parse_resources_directory":
            self.report.resource_calls += 1
            level = frame.f_locals.get("level", 0)
            self._resource_depth = max(self._resource_depth, level)
        return self._on_call

    def __enter__(self):
        self._previous_trace = sys.gettrace()
        sys.settrace(self._on_call)
        return self

    def __exit__(self, exc_type, exc, tb):
        sys.settrace(self._previous_trace)
        self.report.resource_max_depth = self._resource_depth
        hits = {
            name: count
            for name, count in self.report.directory_hits.items()
            if count > 0
        }
        self.report.directory_hits = hits
        self.report.distinct_directories = len(hits)
        return False


def measure(parse_callable):
    """Run a zero-argument parse callable and return ``(result, report)``."""
    with DirectoryCoverage() as tracer:
        result = parse_callable()
    return result, tracer.report
