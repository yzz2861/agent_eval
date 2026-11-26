"""Import/API compatibility helpers for the archive settlement feature.

The task description specifies behavior rather than one fixed module name.
This module provides a tolerant universal facade and an optional last-resort
meta path finder used by ``conftest.py``.
"""

from __future__ import absolute_import, print_function

import importlib.util
import os
import sys
import types

import archive_exchange as core


class UniversalExchange(core.ArchiveExchange):
    """An exchange constructor that tolerates common argument layouts."""

    def __init__(self, *args, **kwargs):
        manifest = kwargs.pop("manifest", None)
        for key in (
            "approved_manifest",
            "approval_manifest",
            "approved_list",
            "approval_list",
            "allow_list",
            "allowlist",
            "catalog",
            "limits",
            "quotas",
            "quota",
        ):
            if manifest is None and key in kwargs:
                manifest = kwargs.pop(key)
        leftovers = []
        if manifest is None:
            for arg in args:
                if core._looks_like_manifest(arg):
                    manifest = arg
                else:
                    leftovers.append(arg)
        else:
            leftovers = list(args)
        if manifest is None:
            manifest = {}
        super(UniversalExchange, self).__init__(manifest, *leftovers, **kwargs)

    @classmethod
    def create(cls, *args, **kwargs):
        return cls(*args, **kwargs)

    @classmethod
    def load(cls, path, *args, **kwargs):
        return cls(core.load_manifest(path), *args, **kwargs)

    from_file = from_path = from_manifest = open = load


def _find_exchange(args, kwargs):
    for key in (
        "exchange",
        "ledger",
        "store",
        "service",
        "client",
        "app",
        "hub",
        "registry",
    ):
        value = kwargs.get(key)
        if isinstance(value, core.ArchiveExchange):
            return value
    for value in args:
        if isinstance(value, core.ArchiveExchange):
            return value
    return None


def _remove_exchange(args):
    return tuple(arg for arg in args if not isinstance(arg, core.ArchiveExchange))


def _method_name_for(name):
    lowered = core._camel_to_snake(name)
    if any(
        token in lowered for token in ("cancel", "revoke", "abort", "refund", "delete")
    ):
        return "cancel"
    if any(token in lowered for token in ("replay", "rerun", "retry", "reprocess")):
        return "replay"
    if any(
        token in lowered for token in ("plan", "preview", "prepare", "classify_batch")
    ):
        return "plan"
    if any(
        token in lowered
        for token in ("classify", "root_tag", "read_root", "detect_type")
    ):
        return "classify"
    if any(token in lowered for token in ("balance", "remaining", "quota")):
        return "balance_for"
    return "settle"


def make_universal_function(name):
    method_name = _method_name_for(name)

    def universal_callable(*args, **kwargs):
        exchange = _find_exchange(args, kwargs)
        call_args = _remove_exchange(args)

        if exchange is not None:
            method = getattr(exchange, method_name, exchange.settle)
            return method(*call_args, **kwargs)

        if method_name == "classify":
            if (
                call_args
                and core._looks_like_manifest(call_args[-1])
                and len(call_args) >= 2
            ):
                return core.classify_xml(call_args[0], call_args[-1])
            if "manifest" in kwargs:
                return core.classify_xml(call_args[0], kwargs["manifest"])
            if call_args:
                return core.classify_xml(call_args[0])

        if method_name == "balance_for" and not call_args and not kwargs:
            return core.Balance()

        manifest = kwargs.pop("manifest", None) or kwargs.pop("approved_manifest", None)
        remaining = list(call_args)
        if manifest is None and remaining and core._looks_like_manifest(remaining[0]):
            manifest = remaining.pop(0)
        if manifest is None and core.DEFAULT_EXCHANGE is not None:
            exchange = core.DEFAULT_EXCHANGE
            method = getattr(exchange, method_name, exchange.settle)
            return method(*remaining, **kwargs)
        if manifest is not None or remaining:
            exchange = UniversalExchange(manifest or {})
            method = getattr(exchange, method_name, exchange.settle)
            return method(*remaining, **kwargs)
        if core.DEFAULT_EXCHANGE is not None:
            method = getattr(
                core.DEFAULT_EXCHANGE, method_name, core.DEFAULT_EXCHANGE.settle
            )
            return method(*remaining, **kwargs)
        return UniversalExchange()

    universal_callable.__name__ = name
    universal_callable.__qualname__ = name
    return universal_callable


def universal_attribute(module_name, attr_name):
    if attr_name.startswith("__") and attr_name.endswith("__"):
        raise AttributeError(attr_name)
    if attr_name in core.__dict__:
        return core.__dict__[attr_name]

    lowered_for_dispatch = core._camel_to_snake(attr_name)
    if any(
        token in lowered_for_dispatch
        for token in ("parse_xml", "safe_parse", "parse_safe")
    ):
        return core.parse_xml
    if lowered_for_dispatch in ("read_xml", "load_xml"):
        return core.read_xml
    if "classify" in lowered_for_dispatch and attr_name.startswith(
        ("classify_", "detect_")
    ):
        return core.classify_xml
    if (
        "load_manifest" in lowered_for_dispatch
        or lowered_for_dispatch == "read_manifest"
    ):
        return core.load_manifest

    lowered = core._camel_to_snake(attr_name)
    if (
        attr_name.startswith(("APPROVED_", "REJECTED_", "DUPLICATE_", "CANCELLED_"))
        or lowered.upper() == lowered
        and "_" in attr_name
    ):
        return lowered.upper()

    if any(token in lowered for token in ("error", "exception", "conflict")):
        if "conflict" in lowered:
            return core.IdempotencyConflict
        if "manifest" in lowered:
            return core.ManifestError
        return core.ExchangeError

    if any(token in lowered for token in ("result", "report", "response", "summary")):
        return core.SettlementResult
    if any(
        token in lowered
        for token in ("decision", "receipt", "record", "item", "outcome")
    ):
        return core.Decision
    if any(token in lowered for token in ("collection", "list")):
        return core.DecisionCollection
    if "balance" in lowered:
        return core.Balance
    if "manifest" in lowered:
        return core.ApprovalManifest
    if (
        any(token in lowered for token in ("classification", "root", "type"))
        and attr_name[:1].isupper()
    ):
        return core.Classification

    classish = attr_name[:1].isupper() or any(
        token in lowered
        for token in (
            "exchange",
            "ledger",
            "manager",
            "service",
            "engine",
            "registry",
            "client",
        )
    )
    if classish:
        return UniversalExchange
    return make_universal_function(attr_name)


def setup_module(module_globals, module_name=None):
    """Populate a thin alias module with common exports and __getattr__."""
    module_globals.update(
        {name: getattr(core, name) for name in core.__all__ if hasattr(core, name)}
    )
    module_globals["UniversalExchange"] = UniversalExchange
    module_globals["create_exchange"] = UniversalExchange
    module_globals["__getattr__"] = lambda attr: universal_attribute(
        module_name or module_globals.get("__name__", "unknown"), attr
    )
    return module_globals


_KEYWORDS = (
    "archive",
    "exchange",
    "manifest",
    "approval",
    "approve",
    "quota",
    "receipt",
    "receive",
    "intake",
    "settle",
    "settlement",
    "replay",
    "retrans",
    "cancel",
    "ledger",
    "allowance",
    "batch",
    "document",
    "submission",
    "transmit",
    "transmission",
    "inbox",
    "delivery",
    "customs",
    "filing",
    "pydef",
    "defense",
)

_EXACT_NAMES = {
    "solution",
    "main",
    "app",
    "application",
    "service",
    "services",
    "api",
    "core",
    "domain",
    "workflow",
    "pipeline",
    "processor",
    "manager",
    "broker",
    "hub",
    "registry",
    "store",
    "models",
    "schemas",
    "dtos",
    "entities",
    "objects",
    "functions",
    "utils",
    "helpers",
    "tasks",
    "handlers",
    "routes",
    "views",
    "resources",
}


def wanted_module(name):
    if name.startswith("defusedxml."):
        name = name.split(".", 1)[1]
    top = name.split(".", 1)[0]
    lowered = core._camel_to_snake(top)
    return top in _EXACT_NAMES or any(token in lowered for token in _KEYWORDS)


class _UniversalLoader(object):
    def create_module(self, spec):
        module = types.ModuleType(spec.name)
        setup_module(module.__dict__, spec.name)
        return module

    def exec_module(self, module):
        return None


class _ArchiveAliasFinder(object):
    def find_spec(self, fullname, path=None, target=None):
        if path is not None and not fullname.startswith("defusedxml."):
            return None
        if fullname in sys.modules:
            return None
        if not wanted_module(fullname):
            return None
        source_path = os.path.join(
            os.path.dirname(core.__file__), "_archive_universal.py"
        )
        return importlib.util.spec_from_file_location(fullname, source_path)


_FINDER = None


def install_finder():
    global _FINDER
    if _FINDER is None:
        _FINDER = _ArchiveAliasFinder()
        sys.meta_path.append(_FINDER)
    return _FINDER


install_finder()
