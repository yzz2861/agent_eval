import contextlib


__version__ = "2.7.0"


with contextlib.suppress(ImportError):
    from .sanitizer import *  # noqa: F403

with contextlib.suppress(ImportError):
    from .fragments import (  # noqa: F401
        FragmentIssue,
        FragmentMergeResult,
        FragmentReference,
        merge_fragments,
        sanitize_fragments,
    )
