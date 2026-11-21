"""exec reached through an explicit builtins attribute access."""

import builtins


def run_loader(payload):
    builtins.exec(payload)
