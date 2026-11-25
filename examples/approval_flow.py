"""Synthetic approval runtime used by the async approval examples.

This module stands in for the library-side API surface that the
B705 (async_approval_toctou) check reasons about.  Three kinds of
APIs are provided:

- ``check_approval``  -- obtain an approval decision from the shared,
  short-term approval state (取得批准).
- ``freeze_approval`` -- freeze a decision into a local snapshot that
  stays valid across coroutine switches (冻结批准).
- ``publish``         -- perform the real publish side effect (实际发布).
"""

_SHARED_APPROVALS = {}


def check_approval(topic):
    """Read the current shared approval decision for ``topic``."""
    return _SHARED_APPROVALS.get(topic, False)


def freeze_approval(decision):
    """Pin a decision into a local snapshot immune to later updates."""
    return bool(decision)


def publish(topic, payload):
    """Perform the actual publish side effect."""
    return (topic, payload)
