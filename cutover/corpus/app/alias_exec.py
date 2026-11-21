"""exec imported under an alias and called through the alias."""

from builtins import exec as dynamic_exec


def run_loader(payload):
    dynamic_exec(payload)
