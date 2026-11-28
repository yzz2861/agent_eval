# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Common constants, exceptions and helper functions
"""
import sys
from contextlib import contextmanager
import xml.parsers.expat

try:  # pragma: no cover - Python 3.6 has no contextvars module
    from contextvars import ContextVar
except ImportError:  # pragma: no cover
    ContextVar = None

PY3 = True

# Fail early when pyexpat is not installed correctly
if not hasattr(xml.parsers.expat, "ParserCreate"):
    raise ImportError("pyexpat")  # pragma: no cover


class DefusedXmlException(ValueError):
    """Base exception"""

    def __repr__(self):
        return str(self)


class DTDForbidden(DefusedXmlException):
    """Document type definition is forbidden"""

    def __init__(self, name, sysid, pubid):
        super().__init__()
        self.name = name
        self.sysid = sysid
        self.pubid = pubid

    def __str__(self):
        tpl = "DTDForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class EntitiesForbidden(DefusedXmlException):
    """Entity definition is forbidden"""

    def __init__(self, name, value, base, sysid, pubid, notation_name):
        super().__init__()
        self.name = name
        self.value = value
        self.base = base
        self.sysid = sysid
        self.pubid = pubid
        self.notation_name = notation_name

    def __str__(self):
        tpl = "EntitiesForbidden(name='{}', system_id={!r}, public_id={!r})"
        return tpl.format(self.name, self.sysid, self.pubid)


class ExternalReferenceForbidden(DefusedXmlException):
    """Resolving an external reference is forbidden"""

    def __init__(self, context, base, sysid, pubid):
        super().__init__()
        self.context = context
        self.base = base
        self.sysid = sysid
        self.pubid = pubid

    def __str__(self):
        tpl = "ExternalReferenceForbidden(system_id='{}', public_id={})"
        return tpl.format(self.sysid, self.pubid)


class NotSupportedError(DefusedXmlException):
    """The operation is not supported"""


#: Default per-parser policy. The defaults match the historical defaults of
#: all defusedxml entry points so existing callers keep the same guarantees.
DEFAULT_FORBID_DTD = False
DEFAULT_FORBID_ENTITIES = True
DEFAULT_FORBID_EXTERNAL = True


class RequestConfig(object):
    """Per-request defusing policy.

    The object is an immutable snapshot of the three defusing switches.
    Unspecified switches fall back to the historical defaults, therefore a
    bare ``RequestConfig()`` provides exactly the same protection as a
    plain call into defusedxml without any keyword arguments.
    """

    __slots__ = ("forbid_dtd", "forbid_entities", "forbid_external")

    def __init__(
        self,
        forbid_dtd=DEFAULT_FORBID_DTD,
        forbid_entities=DEFAULT_FORBID_ENTITIES,
        forbid_external=DEFAULT_FORBID_EXTERNAL,
    ):
        self.forbid_dtd = bool(forbid_dtd)
        self.forbid_entities = bool(forbid_entities)
        self.forbid_external = bool(forbid_external)

    def __repr__(self):
        return (
            "RequestConfig(forbid_dtd={!r}, forbid_entities={!r}, "
            "forbid_external={!r})"
        ).format(self.forbid_dtd, self.forbid_entities, self.forbid_external)

    def __eq__(self, other):
        if not isinstance(other, RequestConfig):
            return NotImplemented
        return (
            self.forbid_dtd == other.forbid_dtd
            and self.forbid_entities == other.forbid_entities
            and self.forbid_external == other.forbid_external
        )

    def __hash__(self):
        return hash(
            (self.forbid_dtd, self.forbid_entities, self.forbid_external)
        )


if ContextVar is not None:
    _request_config_var = ContextVar("defusedxml_request_config", default=None)
else:  # pragma: no cover - fallback for Python 3.6

    class _FallbackContextVar(object):
        """Minimal ContextVar stand-in based on thread local storage."""

        def __init__(self, name, default=None):
            import threading

            self._name = name
            self._default = default
            self._local = threading.local()

        def get(self, default=None):
            fallback = default if default is not None else self._default
            return getattr(self._local, "value", fallback)

        def set(self, value):
            old_token = getattr(self._local, "token", None)
            old_value = getattr(self._local, "value", self._default)
            self._local.token = object()
            self._local.value = value
            return _FallbackToken(self, old_token, old_value)

        def reset(self, token):
            if token is None:
                if hasattr(self._local, "value"):
                    del self._local.value
                if hasattr(self._local, "token"):
                    del self._local.token
            else:
                self._local.token = token.prev_token
                self._local.value = token.prev_value


    class _FallbackToken(object):
        __slots__ = ("var", "prev_token", "prev_value")

        def __init__(self, var, prev_token, prev_value):
            self.var = var
            self.prev_token = prev_token
            self.prev_value = prev_value


    _request_config_var = _FallbackContextVar("defusedxml_request_config", default=None)


def get_request_config():
    """Return the active :class:`RequestConfig` or ``None``."""
    return _request_config_var.get()


@contextmanager
def request_config(config=None, **kwargs):
    """Bind a :class:`RequestConfig` to the current execution context.

    Nested ``with`` blocks push a new configuration and always restore the
    previous one on exit, even when the block is cancelled or raises. The
    context variable is copied independently per asyncio task, so two
    requests parsed concurrently can never share or leak their policies.
    """
    if config is None:
        config = RequestConfig(**kwargs)
    elif kwargs:
        raise TypeError(
            "request_config() takes either a RequestConfig instance or "
            "keyword arguments, not both"
        )
    elif not isinstance(config, RequestConfig):
        raise TypeError("config must be a RequestConfig instance")

    token = _request_config_var.set(config)
    try:
        yield config
    finally:
        _request_config_var.reset(token)


#: Sentinel for "caller did not pass an explicit policy switch".
_UNSET = object()


def resolve_request_config(
    request_config_obj=None, forbid_dtd=_UNSET, forbid_entities=_UNSET, forbid_external=_UNSET
):
    """Resolve explicit keyword arguments against the active request config.

    An explicit keyword argument always wins. An omitted argument is taken
    from the :class:`RequestConfig` bound to the current context, if any,
    and otherwise from the historical default.
    """
    if request_config_obj is None:
        request_config_obj = get_request_config()
    elif not isinstance(request_config_obj, RequestConfig):
        raise TypeError("request_config must be a RequestConfig instance")

    if forbid_dtd is _UNSET:
        forbid_dtd = (
            request_config_obj.forbid_dtd
            if request_config_obj is not None
            else DEFAULT_FORBID_DTD
        )
    if forbid_entities is _UNSET:
        forbid_entities = (
            request_config_obj.forbid_entities
            if request_config_obj is not None
            else DEFAULT_FORBID_ENTITIES
        )
    if forbid_external is _UNSET:
        forbid_external = (
            request_config_obj.forbid_external
            if request_config_obj is not None
            else DEFAULT_FORBID_EXTERNAL
        )
    return forbid_dtd, forbid_entities, forbid_external


def _apply_defusing(defused_mod):
    assert defused_mod is sys.modules[defused_mod.__name__]
    stdlib_name = defused_mod.__origin__
    __import__(stdlib_name, {}, {}, ["*"])
    stdlib_mod = sys.modules[stdlib_name]
    stdlib_names = set(dir(stdlib_mod))
    for name, obj in vars(defused_mod).items():
        if name.startswith("_") or name not in stdlib_names:
            continue
        setattr(stdlib_mod, name, obj)
    return stdlib_mod
