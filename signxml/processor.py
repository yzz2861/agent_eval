from __future__ import annotations

import importlib.resources
import logging
import re
import threading
from functools import lru_cache
from typing import Any, ClassVar
from warnings import warn
from xml.etree import ElementTree as stdlibElementTree

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import Hash
from lxml import etree

from .algorithms import CanonicalizationMethod, DigestAlgorithm, digest_algorithm_implementations
from .exceptions import InvalidInput
from .util import namespaces

logger = logging.getLogger(__name__)

# Absolute URIs (any scheme such as file:, http:, https:, or protocol-relative //host) are never
# dereferenced, so that a malicious signature cannot induce local file reads or network requests.
_ABSOLUTE_URI_PATTERN = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*:|//)")

# Whitelist of supported XPointer expressions: id('ID') or an absolute path of element names with
# optional positional predicates (e.g. /root/child[2]).
_XPOINTER_ID_PATTERN = re.compile(r"id\('([^']*)'\)")
_XPOINTER_PATH_PATTERN = re.compile(r"(/[A-Za-z_][\w.-]*(\[[1-9][0-9]*\])?)+")

# Maximum number of location steps allowed in an XPointer path expression.
_MAX_XPOINTER_PATH_DEPTH = 10


@lru_cache
def get_schema(schema_file: str) -> etree.XMLSchema:
    pkg_name = "signxml.xades.schemas" if schema_file.startswith("XAdES") else "signxml.schemas"

    pkg_resources = importlib.resources.files(pkg_name)
    with pkg_resources.joinpath(schema_file).open("r") as schema_fh:
        return etree.XMLSchema(etree.parse(schema_fh))


class XMLProcessor:
    _schemas: ClassVar[list[Any]] = []
    _schemas_lock = threading.Lock()
    schema_files: ClassVar[list[str]] = []
    _default_parser, _parser = None, None

    @classmethod
    def schemas(cls):
        with cls._schemas_lock:
            if "_schemas" not in cls.__dict__:
                cls._schemas = [get_schema(schema_file) for schema_file in cls.schema_files]
        return cls._schemas

    @property
    def parser(self):
        if self._parser is None:
            if self._default_parser is None:
                self._default_parser = etree.XMLParser(resolve_entities=False)
            return self._default_parser
        return self._parser

    def _fromstring(self, xml_string, **kwargs):
        xml_node = etree.fromstring(xml_string, parser=self.parser, **kwargs)
        docinfo = etree.ElementTree(xml_node).docinfo
        if docinfo.internalDTD is not None or docinfo.externalDTD is not None:
            raise InvalidInput("DTD declarations are not supported in XML input")
        for entity in xml_node.iter(etree.Entity):
            raise InvalidInput("Entities are not supported in XML input")
        return xml_node

    def _tostring(self, xml_node, **kwargs):
        return etree.tostring(xml_node, **kwargs)

    def get_root(self, data):
        if isinstance(data, (str, bytes)):
            return self._fromstring(data)
        elif isinstance(data, stdlibElementTree.Element):
            # TODO: add debug level logging statement re: performance impact here
            return self._fromstring(stdlibElementTree.tostring(data, encoding="utf-8"))
        else:
            # Create a separate copy of the node so we can modify the tree and avoid any c14n inconsistencies from
            # namespaces propagating from parent nodes. The lxml docs recommend using copy.deepcopy for this, but it
            # doesn't seem to preserve namespaces. It would be nice to find a less heavy-handed way of doing this.
            return self._fromstring(self._tostring(data))


class XMLSignatureProcessor(XMLProcessor):
    schema_files: ClassVar[list[str]] = ["xmldsig1-schema.xsd"]

    # See https://tools.ietf.org/html/rfc5656
    # ec.SECT* curves have been de-registered due to CVE-2026-26007
    # (https://github.com/pyca/cryptography/security/advisories/GHSA-r6ph-v2qm-q3c2)
    # List of disabled curves:
    # "urn:oid:1.3.132.0.1": ec.SECT163K1,
    # "urn:oid:1.3.132.0.26": ec.SECT233K1,
    # "urn:oid:1.3.132.0.27": ec.SECT233R1,
    # "urn:oid:1.3.132.0.16": ec.SECT283R1,
    # "urn:oid:1.3.132.0.36": ec.SECT409K1,
    # "urn:oid:1.3.132.0.37": ec.SECT409R1,
    # "urn:oid:1.3.132.0.38": ec.SECT571K1
    known_ecdsa_curves: ClassVar[dict[str, ec.EllipticCurve]] = {
        "urn:oid:1.2.840.10045.3.1.7": ec.SECP256R1(),
        "urn:oid:1.3.132.0.34": ec.SECP384R1(),
        "urn:oid:1.3.132.0.35": ec.SECP521R1(),
        "urn:oid:1.2.840.10045.3.1.1": ec.SECP192R1(),
        "urn:oid:1.3.132.0.33": ec.SECP224R1(),
    }
    known_ecdsa_curve_oids: ClassVar[dict[str, str]] = {curve.name: oid for oid, curve in known_ecdsa_curves.items()}

    excise_empty_xmlns_declarations = False
    """
    Deprecated compatibility option with no effect on canonicalization. Setting it to ``True`` emits a
    :class:`DeprecationWarning` when canonicalizing. Empty default namespace declarations are preserved where required.
    """

    id_attributes: tuple[str, ...] = ("Id", "ID", "id", "xml:id")

    def _get_digest(self, data, algorithm: DigestAlgorithm):
        algorithm_implementation = digest_algorithm_implementations[algorithm]()
        hasher = Hash(algorithm=algorithm_implementation)
        hasher.update(data)
        return hasher.finalize()

    def _find(self, element, query, require=True, xpath=""):
        namespace = "ds"
        if ":" in query:
            namespace, _, query = query.partition(":")
        expression = f"{xpath}{namespace}:{query}"
        result = element.find(expression, namespaces=namespaces)

        if require and result is None:
            raise InvalidInput(f"Expected to find XML element {query} in {element.tag} using XPath {expression}")
        return result

    def _findall(self, element, query, xpath=""):
        namespace = "ds"
        if ":" in query:
            namespace, _, query = query.partition(":")
        return element.findall(f"{xpath}{namespace}:{query}", namespaces=namespaces)

    def _c14n(self, nodes, algorithm: CanonicalizationMethod, inclusive_ns_prefixes=None):
        exclusive, with_comments = False, False

        if algorithm.value.startswith("http://www.w3.org/2001/10/xml-exc-c14n#"):
            exclusive = True
        if algorithm.value.endswith("#WithComments"):
            with_comments = True

        if not isinstance(nodes, list):
            nodes = [nodes]

        c14n = b""
        for node in nodes:
            if not exclusive:
                # Reparse as a standalone document to avoid lxml's subtree namespace resets.
                # XML serialization preserves inherited namespace bindings, including unused ones.
                node = self._fromstring(self._tostring(node, with_tail=False))
            c14n += etree.tostring(
                node,
                method="c14n",
                exclusive=exclusive,
                with_comments=with_comments,
                inclusive_ns_prefixes=inclusive_ns_prefixes,
            )
        if self.excise_empty_xmlns_declarations is True:
            warn(
                "excise_empty_xmlns_declarations is deprecated and has no effect; remove this setting.",
                DeprecationWarning,
                stacklevel=2,
            )
        logger.debug("Canonicalized string (exclusive=%s, with_comments=%s): %s", exclusive, with_comments, c14n)
        return c14n

    def _resolve_reference(self, doc_root, reference, uri_resolver=None):
        uri = reference.get("URI")
        if uri is None:
            raise InvalidInput("References without URIs are not supported")
        elif uri == "":
            return doc_root
        elif uri.startswith("#"):
            return self._resolve_same_document_reference(doc_root, uri)
        elif _ABSOLUTE_URI_PATTERN.match(uri):
            raise InvalidInput(f"External reference URI is not allowed: {uri}")
        elif uri_resolver is None:
            raise InvalidInput(f"External URI dereferencing is not configured: {uri}")
        else:
            result = uri_resolver(uri)
            if result is None:
                raise InvalidInput(f"Unable to resolve reference URI: {uri}")
            return result

    def _resolve_same_document_reference(self, doc_root, uri):
        if uri.startswith("#xpointer("):
            return self._resolve_xpointer(doc_root, uri)
        return self._resolve_id_reference(doc_root, uri, uri.lstrip("#"))

    def _resolve_id_reference(self, doc_root, uri, id_value):
        for id_attribute in self.id_attributes:
            xpath_query = f"//*[@*[local-name() = '{id_attribute}']=$uri]"
            results = doc_root.xpath(xpath_query, uri=id_value)
            if len(results) > 1:
                raise InvalidInput(f"Ambiguous reference URI {uri} resolved to {len(results)} nodes")
            elif len(results) == 1:
                return results[0]
        raise InvalidInput(f"Unable to resolve reference URI: {uri}")

    def _resolve_xpointer(self, doc_root, uri):
        expression = uri[len("#xpointer(") :]
        if not expression.endswith(")"):
            raise InvalidInput(f"Unsupported XPointer reference: {uri}")
        expression = expression[:-1]
        id_match = _XPOINTER_ID_PATTERN.fullmatch(expression)
        if id_match is not None:
            return self._resolve_id_reference(doc_root, uri, id_match.group(1))
        if _XPOINTER_PATH_PATTERN.fullmatch(expression) is None:
            raise InvalidInput(f"XPointer expression is not in the supported whitelist: {uri}")
        if expression.count("/") > _MAX_XPOINTER_PATH_DEPTH:
            raise InvalidInput(
                f"XPointer path exceeds the maximum supported depth of {_MAX_XPOINTER_PATH_DEPTH}: {uri}"
            )
        results = doc_root.xpath(expression)
        if len(results) > 1:
            raise InvalidInput(f"Ambiguous reference URI {uri} resolved to {len(results)} nodes")
        elif len(results) == 0:
            raise InvalidInput(f"Unable to resolve reference URI: {uri}")
        return results[0]
