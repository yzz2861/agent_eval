# defusedxml
#
# Copyright (c) 2013 by Christian Heimes <christian@python.org>
# Licensed to PSF under a Contributor Agreement.
# See https://www.python.org/psf/license for licensing details.
"""Defused xmlrpclib

Also defuses gzip bomb
"""
from __future__ import print_function, absolute_import

import io

from .common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden
from ._expat_policy import ExpatPolicyHandler
from .policy import BACKEND_XMLRPC, XMLSecurityPolicy

__origin__ = "xmlrpc.client"
from xmlrpc.client import ExpatParser
from xmlrpc import client as xmlrpc_client
from xmlrpc import server as xmlrpc_server
from xmlrpc.client import gzip_decode as _orig_gzip_decode
from xmlrpc.client import GzipDecodedResponse as _OrigGzipDecodedResponse

try:
    import gzip
except ImportError:  # pragma: no cover
    gzip = None


# Limit maximum request size to prevent resource exhaustion DoS
# Also used to limit maximum amount of gzip decoded data in order to prevent
# decompression bombs
# A value of -1 or smaller disables the limit
MAX_DATA = 30 * 1024 * 1024  # 30 MB


def defused_gzip_decode(data, limit=None):
    """gzip encoded data -> unencoded data

    Decode data using the gzip content encoding as described in RFC 1952
    """
    if not gzip:  # pragma: no cover
        raise NotImplementedError
    if limit is None:
        limit = MAX_DATA
    f = io.BytesIO(data)
    gzf = gzip.GzipFile(mode="rb", fileobj=f)
    try:
        if limit < 0:  # no limit
            decoded = gzf.read()
        else:
            decoded = gzf.read(limit + 1)
    except IOError:  # pragma: no cover
        raise ValueError("invalid data")
    f.close()
    gzf.close()
    if limit >= 0 and len(decoded) > limit:
        raise ValueError("max gzipped payload length exceeded")
    return decoded


class DefusedGzipDecodedResponse(gzip.GzipFile if gzip else object):
    """a file-like object to decode a response encoded with the gzip
    method, as described in RFC 1952.
    """

    def __init__(self, response, limit=None):
        # response doesn't support tell() and read(), required by
        # GzipFile
        if not gzip:  # pragma: no cover
            raise NotImplementedError
        self.limit = limit = limit if limit is not None else MAX_DATA
        if limit < 0:  # no limit
            data = response.read()
            self.readlength = None
        else:
            data = response.read(limit + 1)
            self.readlength = 0
        if limit >= 0 and len(data) > limit:
            raise ValueError("max payload length exceeded")
        self.stringio = io.BytesIO(data)
        super().__init__(mode="rb", fileobj=self.stringio)

    def read(self, n):
        if self.limit >= 0:
            left = self.limit - self.readlength
            n = min(n, left + 1)
            data = gzip.GzipFile.read(self, n)
            self.readlength += len(data)
            if self.readlength > self.limit:
                raise ValueError("max payload length exceeded")
            return data
        else:
            return super().read(n)

    def close(self):
        super().close()
        self.stringio.close()


class DefusedExpatParser(ExpatParser):
    def __init__(
        self,
        target,
        forbid_dtd=False,
        forbid_entities=True,
        forbid_external=True,
        policy=None,
    ):
        super().__init__(target)
        if policy is not None and not isinstance(policy, XMLSecurityPolicy):
            raise TypeError(
                "policy must be an XMLSecurityPolicy instance, got {!r}".format(
                    type(policy).__name__
                )
            )
        self._policy = policy
        self._backend = BACKEND_XMLRPC
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external
        parser = self._parser
        if policy is not None:
            self.install_policy(parser)
        else:
            if self.forbid_dtd:
                parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
            if self.forbid_entities:
                parser.EntityDeclHandler = self.defused_entity_decl
                parser.UnparsedEntityDeclHandler = (
                    self.defused_unparsed_entity_decl
                )
            if self.forbid_external:
                parser.ExternalEntityRefHandler = (
                    self.defused_external_entity_ref_handler
                )

    # Shared XMLSecurityPolicy implementation.
    _position = ExpatPolicyHandler._position
    policy_start_doctype_decl = ExpatPolicyHandler.policy_start_doctype_decl
    policy_entity_decl = ExpatPolicyHandler.policy_entity_decl
    policy_unparsed_entity_decl = ExpatPolicyHandler.policy_unparsed_entity_decl
    policy_external_entity_ref_handler = (
        ExpatPolicyHandler.policy_external_entity_ref_handler
    )
    install_policy = ExpatPolicyHandler.install_policy

    def _raise(self, exc, policy_item):
        exc.backend = self._backend
        exc.policy_item = policy_item
        exc.position = self._position()
        raise exc

    def defused_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        raise DTDForbidden(name, sysid, pubid)

    def defused_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        raise EntitiesForbidden(name, value, base, sysid, pubid, notation_name)

    def defused_unparsed_entity_decl(self, name, base, sysid, pubid, notation_name):
        # expat 1.2
        raise EntitiesForbidden(name, None, base, sysid, pubid, notation_name)  # pragma: no cover

    def defused_external_entity_ref_handler(self, context, base, sysid, pubid):
        raise ExternalReferenceForbidden(context, base, sysid, pubid)


def monkey_patch():
    xmlrpc_client.FastParser = DefusedExpatParser
    xmlrpc_client.GzipDecodedResponse = DefusedGzipDecodedResponse
    xmlrpc_client.gzip_decode = defused_gzip_decode
    if xmlrpc_server:
        xmlrpc_server.gzip_decode = defused_gzip_decode


def unmonkey_patch():
    xmlrpc_client.FastParser = None
    xmlrpc_client.GzipDecodedResponse = _OrigGzipDecodedResponse
    xmlrpc_client.gzip_decode = _orig_gzip_decode
    if xmlrpc_server:
        xmlrpc_server.gzip_decode = _orig_gzip_decode


class _PolicyTarget:
    """Minimal xmlrpc parser target used by the unified policy entry."""

    def __init__(self):
        self._data = []

    def xml(self, encoding, standalone):
        pass

    def start(self, tag, attrs):
        self._data.append("<%s>" % tag)

    def data(self, text):
        self._data.append(text)

    def end(self, tag):
        self._data.append("</%s>" % tag)

    def __str__(self):
        return "".join(self._data)


def _as_bytes(text):
    if isinstance(text, str):
        return text.encode("utf-8")
    return text


def fromstring(text, policy=None, **legacy_kwargs):
    """Parse an in-memory document under an :class:`XMLSecurityPolicy`."""
    target = _PolicyTarget()
    parser = DefusedExpatParser(target, policy=policy, **legacy_kwargs)
    parser.feed(_as_bytes(text))
    parser.close()
    return target


def parse(source, policy=None, **legacy_kwargs):
    """Parse a filename or file object under an :class:`XMLSecurityPolicy`."""
    if hasattr(source, "read"):
        data = source.read()
    else:
        with open(source, "rb") as fp:
            data = fp.read()
    return fromstring(data, policy=policy, **legacy_kwargs)
