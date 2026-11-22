"""Jinja is a template engine written in pure Python. It provides a
non-XML syntax that supports inline expressions and an optional
sandboxed environment.
"""

from __future__ import annotations

import typing as t

from .bccache import BytecodeCache as BytecodeCache
from .bccache import FileSystemBytecodeCache as FileSystemBytecodeCache
from .bccache import MemcachedBytecodeCache as MemcachedBytecodeCache
from .capabilities import Capability as Capability
from .capabilities import CapabilityApproval as CapabilityApproval
from .capabilities import CapabilityChangeList as CapabilityChangeList
from .capabilities import CapabilityManifest as CapabilityManifest
from .capabilities import CapabilityPolicy as CapabilityPolicy
from .capabilities import CapabilityReview as CapabilityReview
from .environment import Environment as Environment
from .environment import Template as Template
from .exceptions import CapabilityError as CapabilityError
from .exceptions import CapabilityNotApproved as CapabilityNotApproved
from .exceptions import CapabilityReviewError as CapabilityReviewError
from .exceptions import CapabilityReviewRequired as CapabilityReviewRequired
from .exceptions import TemplateAssertionError as TemplateAssertionError
from .exceptions import TemplateError as TemplateError
from .exceptions import TemplateNotFound as TemplateNotFound
from .exceptions import TemplateRuntimeError as TemplateRuntimeError
from .exceptions import TemplatesNotFound as TemplatesNotFound
from .exceptions import TemplateSyntaxError as TemplateSyntaxError
from .exceptions import UnapprovedCapability as UnapprovedCapability
from .exceptions import UnapprovedDynamicCall as UnapprovedDynamicCall
from .exceptions import UndefinedError as UndefinedError
from .loaders import BaseLoader as BaseLoader
from .loaders import ChoiceLoader as ChoiceLoader
from .loaders import DictLoader as DictLoader
from .loaders import FileSystemLoader as FileSystemLoader
from .loaders import FunctionLoader as FunctionLoader
from .loaders import ModuleLoader as ModuleLoader
from .loaders import PackageLoader as PackageLoader
from .loaders import PrefixLoader as PrefixLoader
from .runtime import ChainableUndefined as ChainableUndefined
from .runtime import DebugUndefined as DebugUndefined
from .runtime import make_logging_undefined as make_logging_undefined
from .runtime import StrictUndefined as StrictUndefined
from .runtime import Undefined as Undefined
from .sandbox import review_capabilities as review_capabilities
from .utils import clear_caches as clear_caches
from .utils import is_undefined as is_undefined
from .utils import pass_context as pass_context
from .utils import pass_environment as pass_environment
from .utils import pass_eval_context as pass_eval_context
from .utils import select_autoescape as select_autoescape


def __getattr__(name: str) -> t.Any:
    if name == "__version__":
        import importlib.metadata
        import warnings

        warnings.warn(
            "The `__version__` attribute is deprecated and will be removed in"
            " Jinja 3.3. Use feature detection or"
            ' `importlib.metadata.version("jinja2")` instead.',
            DeprecationWarning,
            stacklevel=2,
        )
        return importlib.metadata.version("jinja2")

    raise AttributeError(name)
