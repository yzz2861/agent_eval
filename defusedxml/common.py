# defusedxml
#
# Copyright (c) 2013-2020 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Common constants, exceptions and helper functions"""

from __future__ import absolute_import

import sys
import re
import xml.parsers.expat

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


class ExpansionPolicy(object):
    """Limits for safe expansion of internal general entities."""

    def __init__(
        self,
        enabled=True,
        max_entity_declarations=10000,
        max_expansion_size=10 * 1024 * 1024,
        max_entity_depth=100,
        max_entity_value_size=1024 * 1024,
        max_document_expansion=100 * 1024 * 1024,
    ):
        self.enabled = bool(enabled)
        self.max_entity_declarations = self._check_limit(
            max_entity_declarations, "max_entity_declarations"
        )
        self.max_expansion_size = self._check_limit(max_expansion_size, "max_expansion_size")
        self.max_entity_depth = self._check_limit(max_entity_depth, "max_entity_depth")
        self.max_entity_value_size = self._check_limit(
            max_entity_value_size, "max_entity_value_size"
        )
        self.max_document_expansion = self._check_limit(
            max_document_expansion, "max_document_expansion"
        )

    @staticmethod
    def _check_limit(value, name):
        if value is None or isinstance(value, int) and value >= 0:
            return value
        raise ValueError("{} must be a non-negative integer or None".format(name))

    def create_state(self):
        return _EntityExpansionState(self)


class EntityExpansionExceeded(DefusedXmlException):
    """An entity expansion limit was exceeded."""

    def __init__(self, limit_name, limit, current, entity_name=None):
        super().__init__()
        self.limit_name = limit_name
        self.limit = limit
        self.current = current
        self.entity_name = entity_name

    def __str__(self):
        if self.entity_name is None:
            return "{}(limit={}, current={})".format(
                self.__class__.__name__, self.limit, self.current
            )
        return "{}(entity_name={!r}, limit={}, current={})".format(
            self.__class__.__name__, self.entity_name, self.limit, self.current
        )


def _entity_byte_size(value):
    if value is None:
        return 0
    if isinstance(value, bytes):
        return len(value)
    return len(value.encode("utf-8"))


_GENERAL_ENTITY_REFERENCE = re.compile(r"&([A-Za-z_][A-Za-z0-9_.-]*);")


class _EntityExpansionState(object):
    def __init__(self, policy):
        self.policy = policy
        self.reset()

    def reset(self):
        self.declaration_count = 0
        self.document_expansion = 0
        self.entities = {}
        self.pending_declarations = {}

    def entity_declared(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        if is_parameter_entity or value is None or notation_name is not None:
            raise EntitiesForbidden(name, value, base, sysid, pubid, notation_name)

        self.declaration_count += 1
        limit = self.policy.max_entity_declarations
        if limit is not None and self.declaration_count > limit:
            raise EntityExpansionExceeded(
                "max_entity_declarations", limit, self.declaration_count, name
            )

        value_size = _entity_byte_size(value)
        limit = self.policy.max_entity_value_size
        if limit is not None and value_size > limit:
            raise EntityExpansionExceeded("max_entity_value_size", limit, value_size, name)

        self.pending_declarations[name] = (value, value_size)

    def finalize_declarations(self):
        for name, (value, value_size) in self.pending_declarations.items():
            expansion_size, depth = self._measure(value, name)
            limit = self.policy.max_expansion_size
            if limit is not None and expansion_size > limit:
                raise EntityExpansionExceeded("max_expansion_size", limit, expansion_size, name)
            limit = self.policy.max_entity_depth
            if limit is not None and depth > limit:
                raise EntityExpansionExceeded("max_entity_depth", limit, depth, name)
            expanded_value = self._expand(value)
            self.entities[name] = (
                value,
                value_size,
                expansion_size,
                depth,
                expanded_value,
            )
        self.pending_declarations = {}

    def reference(self, name):
        try:
            value, value_size, expansion_size, depth, expanded_value = self.entities[name]
        except KeyError:
            return None
        limit = self.policy.max_document_expansion
        self.document_expansion += expansion_size
        if limit is not None and self.document_expansion > limit:
            raise EntityExpansionExceeded(
                "max_document_expansion", limit, self.document_expansion, name
            )
        return expanded_value

    def count_raw_entities(self, data):
        if data is None:
            return
        if isinstance(data, str):
            text = data
        else:
            text = data.decode("utf-8")
        entity_names = self._attribute_entity_names(text)
        for entity_name in entity_names:
            self.reference(entity_name)

    @staticmethod
    def _attribute_entity_names(text):
        quote = None
        attribute_start = 0
        for index, character in enumerate(text):
            if quote is None and character == ">":
                break
            if quote is None:
                if character in ("'", '"'):
                    quote = character
                    attribute_start = index + 1
            elif character == quote:
                attribute = text[attribute_start:index]
                for match in _GENERAL_ENTITY_REFERENCE.finditer(attribute):
                    yield match.group(1)
                quote = None

    def _expand(self, value):
        def replace(match):
            name = match.group(1)
            try:
                return self.entities[name][4]
            except KeyError:
                try:
                    return self._expand(self.pending_declarations[name][0])
                except KeyError:
                    pass
            return match.group(0)

        return _GENERAL_ENTITY_REFERENCE.sub(replace, value)

    def _measure(self, value, name, seen=None):
        if seen is None:
            seen = set()
        if name in seen:
            raise EntityExpansionExceeded(
                "max_entity_depth",
                (
                    self.policy.max_entity_depth
                    if self.policy.max_entity_depth is not None
                    else len(seen) + 1
                ),
                len(seen) + 1,
                name,
            )
        seen.add(name)
        value_size = 0
        depth = 1
        pattern = _GENERAL_ENTITY_REFERENCE
        cursor = 0
        for match in pattern.finditer(value):
            value_size += _entity_byte_size(value[cursor : match.start()])
            cursor = match.end()
            referenced_name = match.group(1)
            try:
                referenced = self.entities[referenced_name]
            except KeyError:
                try:
                    referenced = self.pending_declarations[referenced_name]
                except KeyError:
                    continue
            child_value_size, child_depth = self._measure(referenced[0], referenced_name, seen)
            value_size += child_value_size
            depth = max(depth, child_depth + 1)
        seen.remove(name)
        value_size += _entity_byte_size(value[cursor:])
        return value_size, depth


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
