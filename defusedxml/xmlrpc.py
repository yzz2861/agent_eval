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

from .common import DTDForbidden, ParameterEntityForbidden
from .dtdscan import (
    DTDScanGuard,
    raise_entity_decl,
    raise_unparsed_entity_decl,
    raise_notation_decl,
    raise_external_reference,
)

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
    def __init__(self, target, forbid_dtd=False, forbid_entities=True, forbid_external=True):
        super().__init__(target)
        self.forbid_dtd = forbid_dtd
        self.forbid_entities = forbid_entities
        self.forbid_external = forbid_external
        self._dtd_depth = 0
        self._dtd_source = "internal_subset"
        self._dtd_guard = DTDScanGuard(
            forbid_dtd=forbid_dtd,
            forbid_entities=forbid_entities,
            forbid_external=forbid_external,
        )
        parser = self._parser
        parser.StartDoctypeDeclHandler = self.defused_start_doctype_decl
        parser.EndDoctypeDeclHandler = self.defused_end_doctype_decl
        parser.EntityDeclHandler = self.defused_entity_decl
        parser.UnparsedEntityDeclHandler = self.defused_unparsed_entity_decl
        parser.NotationDeclHandler = self.defused_notation_decl
        if self.forbid_entities:
            parser.DefaultHandler = self.defused_default_handler
        if self.forbid_external:
            parser.ExternalEntityRefHandler = self.defused_external_entity_ref_handler

    def _location(self):
        parser = self._parser
        try:
            return parser.CurrentLineNumber, parser.CurrentColumnNumber + 1
        except AttributeError:
            return None, None

    def feed(self, data):
        self._dtd_guard.update_flags(
            forbid_dtd=self.forbid_dtd,
            forbid_entities=self.forbid_entities,
            forbid_external=self.forbid_external,
        )
        buffered = self._dtd_guard.feed(data)
        if buffered is None:
            return
        self._parser.Parse(buffered, False)

    def close(self):
        pending = self._dtd_guard.finish()
        if pending is not None:
            self._parser.Parse(pending, False)
        super().close()

    def defused_start_doctype_decl(self, name, sysid, pubid, has_internal_subset):
        self._dtd_depth = 1
        self._dtd_source = "internal_subset" if has_internal_subset else "external_subset"
        if self.forbid_dtd:
            line, column = self._location()
            raise DTDForbidden(
                name,
                sysid,
                pubid,
                construct="doctype",
                depth=0,
                source="doctype",
                line=line,
                column=column,
            )

    def defused_end_doctype_decl(self):
        self._dtd_depth = 0

    def defused_default_handler(self, text):
        if self.forbid_entities and self._dtd_depth and text.strip().startswith("%"):
            name = text.strip()[1:-1]
            line, column = self._location()
            raise ParameterEntityForbidden(
                name,
                None,
                None,
                None,
                None,
                None,
                construct="parameter-entity-reference",
                depth=self._dtd_depth,
                source=self._dtd_source,
                line=line,
                column=column,
            )

    def defused_entity_decl(
        self, name, is_parameter_entity, value, base, sysid, pubid, notation_name
    ):
        line, column = self._location()
        raise_entity_decl(
            name,
            is_parameter_entity,
            value,
            base,
            sysid,
            pubid,
            notation_name,
            forbid_entities=self.forbid_entities,
            forbid_external=self.forbid_external,
            depth=max(self._dtd_depth, 1),
            source=self._dtd_source,
            line=line,
            column=column,
        )

    def defused_unparsed_entity_decl(self, name, base, sysid, pubid, notation_name):
        line, column = self._location()
        raise_unparsed_entity_decl(
            name,
            base,
            sysid,
            pubid,
            notation_name,
            forbid_entities=self.forbid_entities,
            forbid_external=self.forbid_external,
            depth=max(self._dtd_depth, 1),
            source=self._dtd_source,
            line=line,
            column=column,
        )

    def defused_notation_decl(self, name, base, sysid, pubid):
        line, column = self._location()
        raise_notation_decl(
            name,
            base,
            sysid,
            pubid,
            forbid_entities=self.forbid_entities,
            forbid_external=self.forbid_external,
            depth=max(self._dtd_depth, 1),
            source=self._dtd_source,
            line=line,
            column=column,
        )

    def defused_external_entity_ref_handler(self, context, base, sysid, pubid):
        line, column = self._location()
        raise_external_reference(
            context,
            base,
            sysid,
            pubid,
            depth=max(self._dtd_depth, 1),
            source=self._dtd_source,
            line=line,
            column=column,
        )


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
