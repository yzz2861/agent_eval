# -*- coding: utf-8 -*-

from __future__ import absolute_import

from .filetype import *  # noqa
from .helpers import *  # noqa
from .match import *  # noqa
from .quarantine import QuarantineError, QuarantineSizeError  # noqa
from .quarantine import QuarantinedFile, quarantine  # noqa

# Current package semver version
__version__ = version = '1.2.0'
