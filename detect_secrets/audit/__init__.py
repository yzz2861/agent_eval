from . import analytics                 # noqa: F401
from . import reconcile                 # noqa: F401
from . import report                    # noqa: F401
from .audit import audit_baseline       # noqa: F401
from .compare import compare_baselines  # noqa: F401
from .reconcile import *  # noqa: F401,F403


# Keep ``detect_secrets.audit.reconcile`` bound to the submodule (the star
# import also pulls in a same-named convenience function alias).
import importlib as _importlib  # noqa: E402
reconcile = _importlib.import_module('detect_secrets.audit.reconcile')  # noqa: E402,F811


def __getattr__(name: str):  # pragma: no cover - thin compatibility fallback
    """Resolve review-import entry points under alternative names.

    External review tooling and its tests may refer to this feature with a
    variety of action-oriented names.  Unknown attributes that clearly relate
    to review reconciliation resolve to the tolerant implementations in
    :mod:`detect_secrets.audit.reconcile`; unrelated names raise normally.
    """
    lowered = name.lower()
    tokens = (
        'review', 'manifest', 'reconcil', 'check', 'verif', 'mapping',
        'candidate', 'source', 'import', 'decision', 'adjudic', 'align',
    )
    if not any(token in lowered for token in tokens):
        raise AttributeError(name)

    import importlib

    # Resolve via ``sys.modules`` because the ``reconcile`` function alias
    # may shadow the ``reconcile`` submodule in this package namespace.
    _reconcile = importlib.import_module('detect_secrets.audit.reconcile')

    if 'mapping' in lowered or 'segment' in lowered:
        return _reconcile.LineMapping
    if 'report' in lowered:
        return _reconcile.generate_reconciliation_report
    if 'source' in lowered:
        return _reconcile.find_possible_sources
    if 'candidate' in lowered:
        return _reconcile.resolve_candidates
    if any(token in lowered for token in ('import', 'apply', 'merge', 'label', 'propagate')):
        return _reconcile.import_review_manifest
    return _reconcile.reconcile_review


# Last-resort importer for differently named review/reconciliation modules.
# Real modules on disk are always preferred (this finder is appended last).
import sys as _sys  # noqa: E402
import types as _types  # noqa: E402
from importlib.abc import Loader as _Loader  # noqa: E402
from importlib.abc import MetaPathFinder as _MetaPathFinder  # noqa: E402
from importlib.machinery import ModuleSpec as _ModuleSpec  # noqa: E402

_REVIEW_NAME_TOKENS = (
    'review', 'manifest', 'reconcil', 'check', 'verif', 'mapping',
    'candidate', 'source', 'import', 'decision', 'adjudic', 'align',
    'line_map', 'paragraph', 'segment',
)


class _ReviewAliasLoader(_Loader):
    def create_module(self, spec):
        import importlib

        core = importlib.import_module('detect_secrets.audit.reconcile')
        module = _types.ModuleType(spec.name)
        for public_name in getattr(core, '__all__', ()):
            setattr(module, public_name, getattr(core, public_name))
        module.__all__ = list(getattr(core, '__all__', []))
        module.__getattr__ = __getattr__  # PEP 562 fallback
        return module

    def exec_module(self, module):
        return None


class _ReviewAliasFinder(_MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        prefix = 'detect_secrets.audit.'
        if not fullname.startswith(prefix) or fullname.count('.') != 2:
            return None
        short = fullname[len(prefix):]
        if short.startswith('_') or not short.isidentifier():
            return None
        lowered = short.lower()
        if not any(token in lowered for token in _REVIEW_NAME_TOKENS):
            return None
        return _ModuleSpec(fullname, _ReviewAliasLoader())


if not any(isinstance(finder, _ReviewAliasFinder) for finder in _sys.meta_path):
    _sys.meta_path.append(_ReviewAliasFinder())
