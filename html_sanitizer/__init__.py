import contextlib
import importlib


__version__ = "2.7.0"


with contextlib.suppress(ImportError):
    from .sanitizer import *  # noqa: F403
from .sanitizer import Sanitizer


_PREVIEW_EXPORTS = {
    "DiffEntry",
    "NodeOutcome",
    "PolicyDecision",
    "PolicyPreview",
    "compare_policies",
    "preview",
    "preview_html",
    "preview_policy",
    "policy_preview",
    "sanitize_preview",
}


def __getattr__(name):
    if name in _PREVIEW_EXPORTS:
        module = importlib.import_module(".preview", __name__)

        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [  # noqa: F405
    "Sanitizer",
    "DiffEntry",
    "NodeOutcome",
    "PolicyDecision",
    "PolicyPreview",
    "compare_policies",
    "preview",
    "preview_html",
    "preview_policy",
    "policy_preview",
    "sanitize_preview",
]
