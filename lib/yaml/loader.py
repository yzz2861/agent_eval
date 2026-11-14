
__all__ = ['BaseLoader', 'FullLoader', 'SafeLoader', 'Loader', 'UnsafeLoader',
        'UnsafeUnlimitedSafeLoader']

from .reader import *
from .scanner import *
from .parser import *
from .composer import *
from .constructor import *
from .resolver import *
from .limits import ResourceLimits


class _BudgetedLoader:

    def _init_budgeted_components(self, stream, resource_limits, constructor):
        if resource_limits is None:
            resource_limits = self.default_resource_limits()
        Reader.__init__(self, stream, resource_limits)
        Scanner.__init__(self, resource_limits)
        Parser.__init__(self)
        Composer.__init__(self, resource_limits)
        constructor.__init__(self, resource_limits)

    @classmethod
    def default_resource_limits(cls):
        return ResourceLimits()


class BaseLoader(_BudgetedLoader, Reader, Scanner, Parser, Composer,
        BaseConstructor, BaseResolver):

    def __init__(self, stream, resource_limits=None):
        self._init_budgeted_components(
                stream, resource_limits, BaseConstructor)
        BaseResolver.__init__(self)

class FullLoader(_BudgetedLoader, Reader, Scanner, Parser, Composer,
        FullConstructor, Resolver):

    def __init__(self, stream, resource_limits=None):
        self._init_budgeted_components(
                stream, resource_limits, FullConstructor)
        Resolver.__init__(self)

class SafeLoader(_BudgetedLoader, Reader, Scanner, Parser, Composer,
        SafeConstructor, Resolver):

    def __init__(self, stream, resource_limits=None):
        self._init_budgeted_components(
                stream, resource_limits, SafeConstructor)
        Resolver.__init__(self)

class Loader(_BudgetedLoader, Reader, Scanner, Parser, Composer,
        Constructor, Resolver):

    def __init__(self, stream, resource_limits=None):
        self._init_budgeted_components(
                stream, resource_limits, Constructor)
        Resolver.__init__(self)

# UnsafeLoader is the same as Loader (which is and was always unsafe on
# untrusted input). Use of either Loader or UnsafeLoader should be rare, since
# FullLoad should be able to load almost all YAML safely. Loader is left intact
# to ensure backwards compatibility.
class UnsafeLoader(_BudgetedLoader, Reader, Scanner, Parser, Composer,
        Constructor, Resolver):

    def __init__(self, stream, resource_limits=None):
        self._init_budgeted_components(
                stream, resource_limits, Constructor)
        Resolver.__init__(self)


class UnsafeUnlimitedSafeLoader(SafeLoader):
    """SafeLoader variant with every resource budget disabled.

    The name is deliberately explicit: parsing untrusted input with this
    loader restores the historical, unbounded memory behaviour and allows
    anchor bombs or deeply nested documents to exhaust available memory.
    Only use it with trusted streams that legitimately exceed the default
    budgets.
    """

    @classmethod
    def default_resource_limits(cls):
        return ResourceLimits.unlimited()
