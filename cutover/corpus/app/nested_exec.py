"""Bare exec() nested inside an inner function.

B102 follows the call at any scope depth, while the replacement X901 only
inspects shallow-scope calls, so this file is a syntax-coverage gap.
"""


def build_loader():
    def run_loader(payload):
        exec(payload)

    return run_loader
