"""Bare exec() call living in the unscanned legacy directory."""


def legacy_loader(payload):
    exec(payload)
