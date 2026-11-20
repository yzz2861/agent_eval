"""Sandbox-safe test runner.

pytest walks parent directories while computing its rootdir, but the local
sandbox denies access to every parent of the workspace. This runner imports
the pytest-style test module directly and executes its functions, so the
suite remains runnable inside the restricted environment. On a normal machine
``python -m pytest tests`` works unchanged.
"""

from __future__ import annotations

import inspect
import sys
import tempfile
import traceback

from delay_evidence.loader import load_bytes
from delay_evidence.make_samples import (
    SAMPLE_A_SPECS,
    SAMPLE_B_SPECS,
)
from delay_evidence.sample_builder import build_sample

import tests.test_delay_evidence as suite


class _Fixtures:
    def __init__(self):
        image_a, _ = build_sample(SAMPLE_A_SPECS)
        image_b, _ = build_sample(SAMPLE_B_SPECS)
        self.sample_a_bytes = image_a
        self.sample_b_bytes = image_b
        self.loaded_a = load_bytes(image_a, source="sample_a")
        self.loaded_b = load_bytes(image_b, source="sample_b")


def main():
    fixtures = _Fixtures()
    functions = [
        (name, member)
        for name, member in inspect.getmembers(suite, inspect.isfunction)
        if name.startswith("test_")
    ]
    failures = []
    for name, function in tests_order(functions):
        kwargs = build_kwargs(function, fixtures)
        try:
            function(**kwargs)
            print("PASS", name)
        except Exception:  # noqa: BLE001
            failures.append((name, traceback.format_exc()))
            print("FAIL", name)
    if failures:
        for name, trace in failures:
            print("-" * 60)
            print(trace)
        print("%d failed, %d passed" % (len(failures), len(functions) - len(failures)))
        return 1
    print("all %d tests passed" % len(functions))
    return 0


def tests_order(functions):
    return sorted(functions, key=lambda item: item[1].__code__.co_firstlineno)


def build_kwargs(function, fixtures):
    params = inspect.signature(function).parameters
    kwargs = {}
    if "tmp_path" in params:
        kwargs["tmp_path"] = tempfile.mkdtemp()
    for name in params:
        if hasattr(fixtures, name):
            kwargs[name] = getattr(fixtures, name)
    return kwargs


if __name__ == "__main__":
    sys.exit(main())
