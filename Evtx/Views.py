#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from __future__ import absolute_import

import json
import re
import xml.sax.saxutils

import Evtx.Nodes as e_nodes
from .Integrity import IntegrityStatus

XML_HEADER = '<?xml version="1.1" encoding="utf-8" standalone="yes" ?>\n'
INTEGRITY_NS = "http://python-evtx/integrity"
INTEGRITY_ATTR = "integrity:status"
INTEGRITY_DETAIL_ATTR = "integrity:detail"


class UnexpectedElementException(Exception):
    def __init__(self, msg):
        super(UnexpectedElementException, self).__init__(msg)


# ref: https://www.w3.org/TR/xml11/#charsets
RESTRICTED_CHARS = re.compile("[\x01-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]")


def escape_attr(s):
    """
    escape the given string such that it can be placed in an XML attribute, like:

        <foo bar='$value'>

    Args:
      s (str): the string to escape.

    Returns:
      str: the escaped string.
    """
    esc = xml.sax.saxutils.quoteattr(s)
    esc = esc.encode("ascii", "xmlcharrefreplace").decode("ascii")
    esc = RESTRICTED_CHARS.sub("", esc)
    return esc


def escape_value(s):
    """
    escape the given string such that it can be placed in an XML value location, like:

        <foo>
          $value
        </foo>

    Args:
      s (str): the string to escape.

    Returns:
      str: the escaped string.
    """
    esc = xml.sax.saxutils.escape(s)
    esc = esc.encode("ascii", "xmlcharrefreplace").decode("ascii")
    esc = RESTRICTED_CHARS.sub("", esc)
    return esc


# ref: https://www.w3.org/TR/xml/#NT-NameStartChar
# but we are going to require a even stricter subset.
NAME_PATTERN = re.compile(r"[a-zA-Z_][a-zA-Z_\-]*")


def validate_name(s):
    """
    ensure the given name can be used as an XML entity name, such as tag or attribute name.

    Args:
      s (str): the string to validate.

    Raises:
      RuntimeError: if the string is not suitable to be an XML name.
    """
    if not NAME_PATTERN.match(s):
        raise RuntimeError("invalid xml name: %s" % (s))
    return s


def render_root_node_with_subs(root_node, subs):
    """
    render the given root node using the given substitutions into XML.

    Args:
      root_node (e_nodes.RootNode): the node to render.
      subs (list[str]): the substitutions that maybe included in the XML.

    Returns:
      str: the rendered XML document.
    """

    def rec(node, acc):
        if isinstance(node, e_nodes.EndOfStreamNode):
            pass  # intended
        elif isinstance(node, e_nodes.OpenStartElementNode):
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, e_nodes.AttributeNode):
                    acc.append(" ")
                    acc.append(validate_name(child.attribute_name().string()))
                    acc.append('="')
                    # TODO: should use xml.sax.saxutils.quoteattr here
                    # but to do so, we'd need to ensure we're not double-quoting this value.
                    rec(child.attribute_value(), acc)
                    acc.append('"')
            acc.append(">")
            for child in node.children():
                rec(child, acc)
            acc.append("</")
            acc.append(validate_name(node.tag_name()))
            acc.append(">\n")
        elif isinstance(node, e_nodes.CloseStartElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.ValueNode):
            acc.append(escape_value(node.children()[0].string()))
        elif isinstance(node, e_nodes.AttributeNode):
            pass  # intended
        elif isinstance(node, e_nodes.CDataSectionNode):
            acc.append("<![CDATA[")
            # TODO: is this correct escaping???
            acc.append(escape_value(node.cdata()))
            acc.append("]]>")
        elif isinstance(node, e_nodes.EntityReferenceNode):
            acc.append(escape_value(node.entity_reference()))
        elif isinstance(node, e_nodes.ProcessingInstructionTargetNode):
            acc.append(escape_value(node.processing_instruction_target()))
        elif isinstance(node, e_nodes.ProcessingInstructionDataNode):
            acc.append(escape_value(node.string()))
        elif isinstance(node, e_nodes.TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, e_nodes.NormalSubstitutionNode):
            sub = subs[node.index()]

            if isinstance(sub, e_nodes.BXmlTypeNode):
                sub = render_root_node(sub.root())
            else:
                sub = escape_value(sub.string())

            acc.append(sub)
        elif isinstance(node, e_nodes.ConditionalSubstitutionNode):
            sub = subs[node.index()]

            if isinstance(sub, e_nodes.BXmlTypeNode):
                sub = render_root_node(sub.root())
            else:
                sub = escape_value(sub.string())

            acc.append(sub)
        elif isinstance(node, e_nodes.StreamStartNode):
            pass  # intended

    acc = []
    for c in root_node.template().children():
        rec(c, acc)
    return "".join(acc)


def render_root_node(root_node):
    subs = []
    for sub in root_node.substitutions():
        if isinstance(sub, str):
            raise RuntimeError("string sub?")

        if sub is None:
            raise RuntimeError("null sub?")

        subs.append(sub)

    return render_root_node_with_subs(root_node, subs)


def evtx_record_xml_view(record, cache=None):
    """
    render the given record into an XML document.

    Args:
      record (Evtx.Record): the record to render.

    Returns:
      str: the rendered XML document.
    """
    return render_root_node(record.root())


def _first_failure(report):
    for check in report.checks:
        if check.status != IntegrityStatus.OK:
            return check
    return None


def integrity_comment(record):
    """
    build an XML comment that cannot be silently dropped by evidence tooling.

    The comment states the layered integrity status and, when verification
    failed, the first failing check with expected/actual values and scope.

    Args:
      record (Evtx.Record): the record to render.

    Returns:
      str: an XML comment such as
      ``<!-- EVTX-INTEGRITY: status=ok; ... -->``.
    """
    report = record.integrity()
    status = report.status().value
    parts = ["EVTX-INTEGRITY: status={}".format(status)]
    parts.append("chunk={}".format(record.chunk_index()))
    parts.append("record={}".format(record.record_num()))
    failure = _first_failure(report)
    if failure is not None:
        parts.append("check={}".format(failure.check.value))
        parts.append("algorithm={}".format(failure.algorithm))
        parts.append("scope={}".format(json.dumps([list(rng) for rng in failure.scope])))
        parts.append("expected={}".format(failure.expected))
        parts.append("actual={}".format(failure.actual))
        parts.append("detail={}".format(failure.detail))
    # comments must not contain the double-hyphen sequence
    return "<!-- " + " | ".join(parts).replace("--", "- -") + " -->"


def evtx_record_xml_view_marked(record, cache=None):
    """
    render a record into XML with a non-ignorable integrity marker.

    A leading XML comment always carries the layered status so consumers can
    distinguish verified evidence from recovery-mode output.  When the record
    is not fully verified, the root element additionally receives an
    ``integrity:status`` attribute and a namespace declaration.

    Args:
      record (Evtx.Record): the record to render.

    Returns:
      str: the marked XML document (without the XML declaration).
    """
    report = record.integrity()
    comment = integrity_comment(record)
    try:
        rendered = evtx_record_xml_view(record, cache=cache)
    except Exception as exc:
        # the integrity marker must survive an un-renderable payload; emit
        # a replacement element instead of silently dropping the record.
        failure = escape_attr(str(exc))
        rendered = (
            '<Event xmlns:integrity="{ns}" {status_attr}="{status}" '
            '{detail_attr}="unrenderable payload: {failure}"></Event>'
        ).format(
            ns=INTEGRITY_NS,
            status_attr=INTEGRITY_ATTR,
            status=report.status().value,
            detail_attr=INTEGRITY_DETAIL_ATTR,
            failure=failure,
        )
        return comment + "\n" + rendered
    if report.ok():
        return comment + "\n" + rendered

    failure = _first_failure(report)
    detail = escape_attr(failure.detail if failure is not None else report.status().value)
    marker = (' xmlns:integrity="{ns}" {status_attr}="{status}" {detail_attr}={detail}').format(
        ns=INTEGRITY_NS,
        status_attr=INTEGRITY_ATTR,
        status=report.status().value,
        detail_attr=INTEGRITY_DETAIL_ATTR,
        detail=detail,
    )
    # inject the attributes on the opening root element only
    if rendered.startswith("<"):
        gt = rendered.find(">")
        if gt != -1:
            rendered = rendered[:gt] + marker + rendered[gt:]
    return comment + "\n" + rendered


def evtx_record_integrity_dict(record):
    """
    return a JSON-serializable integrity envelope for a record.

    Args:
      record (Evtx.Record): the record to describe.

    Returns:
      dict: keys prefixed with underscore so they never collide with event
      fields.  Includes overall status, chunk/record coordinates and every
      check with expected/actual values, algorithm and fixed scope.
    """
    report = record.integrity()
    return {
        "_integrity": {
            "status": report.status().value,
            "chunk": record.chunk_index(),
            "record_number": record.record_num(),
            "checks": [check.to_dict() for check in report.checks],
        }
    }


def evtx_record_json_view(record, data=None):
    """
    render a record as a JSON object with an embedded integrity envelope.

    Args:
      record (Evtx.Record): the record to render.
      data (dict|None): optional parsed event payload, for example produced
        with xmltodict.  When omitted, only the integrity envelope and the
        raw XML are returned, so the helper works without extra dependencies.

    Returns:
      dict: a JSON-serializable object whose ``_integrity`` key cannot be
      confused with normal event data.
    """
    envelope = evtx_record_integrity_dict(record)
    if data is not None:
        envelope.update(data)
    else:
        try:
            envelope["_xml"] = evtx_record_xml_view(record)
        except Exception as exc:
            # keep the integrity envelope even when the payload cannot render
            envelope["_xml_error"] = str(exc)
    return envelope


def evtx_chunk_xml_view(chunk):
    """
    Generate XML representations of the records in an EVTX chunk.

    Does not include the XML <?xml... header.
    Records are ordered by chunk.records()

    Args:
      chunk (Evtx.Chunk): the chunk to render.

    Yields:
      tuple[str, Evtx.Record]: the rendered XML document and the raw record.
    """
    for record in chunk.records():
        record_str = evtx_record_xml_view_marked(record)
        yield record_str, record


def evtx_file_xml_view(file_header):
    """
    Generate XML representations of the records in an EVTX file.

    Does not include the XML <?xml... header.
    Records are ordered by file_header.chunks(), and then by chunk.records()

    Args:
      chunk (Evtx.FileHeader): the file header to render.

    Yields:
      tuple[str, Evtx.Record]: the rendered XML document and the raw record.
    """
    for chunk in file_header.chunks():
        for record in chunk.records():
            record_str = evtx_record_xml_view_marked(record)
            yield record_str, record


def evtx_template_readable_view(root_node, cache=None):
    def rec(node, acc):
        if isinstance(node, e_nodes.EndOfStreamNode):
            pass  # intended
        elif isinstance(node, e_nodes.OpenStartElementNode):
            acc.append("<")
            acc.append(node.tag_name())
            for child in node.children():
                if isinstance(child, e_nodes.AttributeNode):
                    acc.append(" ")
                    acc.append(child.attribute_name().string())
                    acc.append('="')
                    rec(child.attribute_value(), acc)
                    acc.append('"')
            acc.append(">")
            for child in node.children():
                rec(child, acc)
            acc.append("</")
            acc.append(node.tag_name())
            acc.append(">\n")
        elif isinstance(node, e_nodes.CloseStartElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseEmptyElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.CloseElementNode):
            pass  # intended
        elif isinstance(node, e_nodes.ValueNode):
            acc.append(node.children()[0].string())
        elif isinstance(node, e_nodes.AttributeNode):
            pass  # intended
        elif isinstance(node, e_nodes.CDataSectionNode):
            acc.append("<![CDATA[")
            acc.append(node.cdata())
            acc.append("]]>")
        elif isinstance(node, e_nodes.EntityReferenceNode):
            acc.append(node.entity_reference())
        elif isinstance(node, e_nodes.ProcessingInstructionTargetNode):
            acc.append(node.processing_instruction_target())
        elif isinstance(node, e_nodes.ProcessingInstructionDataNode):
            acc.append(node.string())
        elif isinstance(node, e_nodes.TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, e_nodes.NormalSubstitutionNode):
            acc.append("[Normal Substitution(index={}, type={})]".format(node.index(), node.type()))
        elif isinstance(node, e_nodes.ConditionalSubstitutionNode):
            acc.append("[Conditional Substitution(index={}, type={})]".format(node.index(), node.type()))
        elif isinstance(node, e_nodes.StreamStartNode):
            pass  # intended

    acc = []
    for c in root_node.template().children():
        rec(c, acc)
    return "".join(acc)
