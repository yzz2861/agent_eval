"""Synthetic entry module: release and test entries share helpers.

Nothing here executes at import time; the module only defines functions so
the scanner can compare a release call chain with a test call chain that
uses the very same shared helpers under unittest.mock.patch.
"""
from unittest import mock

import mock_patch_shared_helpers as shared_helpers
from mock_patch_shared_helpers import check_permission as verify_permission

_DYNAMIC_TARGET = "mock_patch_shared_helpers.check_permission"


def _shared_pipeline(action, subject):
    # Shared helper used by both the release and the test entry.
    if verify_permission(action, subject):
        return shared_helpers.audit_trail(action)
    return []


def release_entry(action, subject):
    with mock.patch("mock_patch_shared_helpers.check_permission"):
        return _shared_pipeline(action, subject)


@mock.patch("mock_patch_shared_helpers.check_permission")
def release_entry_decorated(fake_permission, action, subject):
    return _shared_pipeline(action, subject)


def release_entry_dynamic(action, subject):
    with mock.patch(_DYNAMIC_TARGET):
        return _shared_pipeline(action, subject)


def test_release_entry(action, subject):
    # Test entry shares the helper but is not a configured release entry,
    # so patching the decision function here is expected and not reported.
    with mock.patch("mock_patch_shared_helpers.check_permission"):
        return _shared_pipeline(action, subject)
