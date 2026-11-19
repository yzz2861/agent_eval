"""Synthetic registry hive construction helpers for offline plugin tests.

The builders in this package emit minimal but spec-compliant REGF hive files
(4 KB header + hbin cells) so tests can craft exact multi-control-set material
without depending on captured Windows hives or on any Windows host.
"""
