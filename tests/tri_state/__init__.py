"""Offline property tests for the approval system's tri-state YAML contract.

This package is intentionally dependency-free (no Hypothesis, no network):
it ships its own deterministic generator and shrinker so it can run in a
sealed evaluation environment.
"""

