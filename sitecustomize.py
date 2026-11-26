"""Best-effort import hook for direct ``python``/``unittest`` invocation."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import _archive_compat

    _archive_compat.install_finder()
except Exception:  # pragma: no cover - startup compatibility only
    pass
