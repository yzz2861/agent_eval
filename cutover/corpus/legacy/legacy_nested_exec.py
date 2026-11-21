"""Nested bare exec() in the unscanned legacy directory."""


def build_legacy_loader():
    def run_loader(payload):
        exec(payload)

    return run_loader
