#!/usr/bin/env python

"""Compatibility import surface for Python version helpers."""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from .scope import (  # noqa: F401
    PythonVersion,
    SUPPORTED_PYTHON_VERSIONS,
    SyntaxResult,
    TargetVersion,
    can_parse,
    check_source,
    is_supported,
    is_syntax_supported,
    normalize_version,
    parse_source,
    parse_version,
    supported_versions,
    syntax_supported,
    version_string,
)


from .scope import *  # noqa: F401,F403
from .scope import __all__  # noqa: F401
