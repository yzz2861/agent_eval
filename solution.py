"""Conventional solution entry point re-exporting the archive engine."""

from _archive_compat import setup_module

setup_module(globals(), __name__)
