# -*- coding: utf-8 -*-

from __future__ import absolute_import

from .filetype import *  # noqa
from .helpers import *  # noqa
from .handoff import (
    HandoffError,
    HandoffIntegrityError,
    HandoffNotFound,
    HandoffObject,
    HandoffRegistry,
    HandoffStateError,
    RecognitionSummary,
    fingerprint_bytes,
    fingerprint_file,
)
from .match import *  # noqa

# Current package semver version
__version__ = version = '1.2.0'
