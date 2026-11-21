# -*- coding: utf-8 -*-

from __future__ import absolute_import

from .filetype import *  # noqa
from .helpers import *  # noqa
from .match import *  # noqa

# Current package semver version
__version__ = version = '1.2.0'

_IMPACT_EXPORTS = frozenset((
    "assess", "assess_impact", "compare", "compare_registries",
    "compare_routing", "analyze", "analyze_impact", "impact_report",
    "render_markdown", "render_text",
))


def __getattr__(name):
    """Lazily exposes the impact assessment helpers."""
    if name in _IMPACT_EXPORTS:
        from . import impact
        return getattr(impact, name)
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
