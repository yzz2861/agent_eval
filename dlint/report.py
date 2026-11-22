#!/usr/bin/env python

"""Compatibility import surface for Dlint report normalization."""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from .scope import (  # noqa: F401
    ReportAudit,
    ReportItems,
    ReportScope,
    ReportItem,
    audit,
    audit_report,
    audit_report_items,
    audit_scope,
    check_report,
    classify_report,
    eligible_report_items,
    eligible_versions,
    summarize_report,
)


if __name__ == "__main__":
    import sys
    from .scope import main

    sys.exit(main())


from .scope import *  # noqa: F401,F403
from .scope import __all__  # noqa: F401
