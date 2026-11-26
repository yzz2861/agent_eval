"""Root compatibility entry point for direct imports/execution."""

# ruff: noqa: F403
from securesystemslib.independence_check import *
from securesystemslib.independence_sample import main

if __name__ == "__main__":
    raise SystemExit(main())
