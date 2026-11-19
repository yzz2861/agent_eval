# SPDX-License-Identifier: Apache-2.0
"""Sensitive-data exposure through diagnostic log statements.

This package implements the B616/B617 plugin tests.  The heavy lifting
(configuration parsing, intra-procedural taint tracking and sink detection)
lives in :mod:`bandit.plugins.sensitive_log.engine`; the decorated entry
points are kept in :mod:`bandit.plugins.sensitive_log.sensitive_log`.
"""
