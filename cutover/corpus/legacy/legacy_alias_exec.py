"""Aliased exec() call living in the unscanned legacy directory."""

from builtins import exec as dynamic_exec


def legacy_loader(payload):
    dynamic_exec(payload)
