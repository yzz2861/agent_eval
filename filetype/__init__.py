# -*- coding: utf-8 -*-

from __future__ import absolute_import

from .filetype import *  # noqa
from .helpers import *  # noqa
from .match import *  # noqa
from .routing import (  # noqa
    ALLOW,
    QUARANTINE,
    NEED_MORE,
    MATCHED,
    PENDING,
    ELIMINATED,
    MagicMatcher,
    Candidate,
    Consumer,
    RoutingDecision,
    route,
    collect_candidates,
    allowed_types,
)

# Current package semver version
__version__ = version = '1.2.0'
