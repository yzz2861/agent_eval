"""Backward-compatible import path for generated-source provenance."""
from .provenance import *     # noqa: F401,F403
from .provenance import __getattr__     # noqa: F401
