# Copyright (c) 2008-2012 testtools developers. See LICENSE for details.

import warnings

from testtools.matchers.test import TestMatchersInterface

warnings.warn(
    "This module is deprecated for removal",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "TestMatchersInterface",
]
