#!/usr/bin/env python
"""Compatibility entry point for the EVTX slot/activity audit."""

try:
    from .evtx_activity import main
except ImportError:  # pragma: no cover - direct script execution
    from evtx_activity import main


if __name__ == "__main__":
    raise SystemExit(main())
