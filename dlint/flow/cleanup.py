#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from .resource import (  # noqa F401
    AnalysisConfig,
    ExitEvidence,
    FunctionEvidence,
    analyze_function,
    analyze_module,
    collect_evidence,
)
