"""Synthetic shared package holding helpers and the protected decision.

This module only defines callables; importing it performs no work. Test
helpers were moved here so that release and test entry points can share
them, which is exactly what makes mock.patch scopes in shared code risky.
"""


def check_permission(action, subject):
    """Protected authorization decision; release must use the real one."""
    return subject is not None and action in ("deploy", "rollback")


def make_fake_permission(allowed=True):
    """Test helper: build a stand-in decision function."""

    def fake_permission(action, subject):
        return allowed

    return fake_permission


def audit_trail(action):
    return ["audit:" + action]


def run_pipeline(action, subject):
    if check_permission(action, subject):
        return audit_trail(action)
    return []
