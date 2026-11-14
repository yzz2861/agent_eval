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

import Evtx.Nodes as e_nodes
import Evtx.Sanitizers as e_sanitizers

XML_HEADER = '<?xml version="1.1" encoding="utf-8" standalone="yes" ?>\n'


class UnexpectedElementException(Exception):
    def __init__(self, msg):
        super(UnexpectedElementException, self).__init__(msg)


# kept for backwards compatibility; the canonical definitions live in Evtx.Sanitizers.
RESTRICTED_CHARS = e_sanitizers.RESTRICTED_CHARS
NAME_PATTERN = e_sanitizers.NAME_PATTERN
validate_name = e_sanitizers.validate_name


def escape_attr(s):
    """
    escape the given string such that it can be placed in a double-quoted
    XML attribute, like:

        <foo bar="$value">

    the returned value does not include the surrounding quotes.

    Args:
      s (str): the string to escape.

    Returns:
      str: the escaped string.
    """
    return e_sanitizers.escape_attr(s)


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
    return e_sanitizers.escape_text(s)


def render_root_node_with_subs(root_node, subs, strict=None, _depth=0):
    """
    render the given root node using the given substitutions into XML.

    Args:
      root_node (e_nodes.RootNode): the node to render.
      subs (list[str]): the substitutions that maybe included in the XML.
      strict (bool|None): if given, reject invalid strings instead of
        repairing them with U+FFFD. defaults to the process-wide setting.
      _depth (int): internal recursion depth, for the render depth budget.

    Returns:
      str: the rendered XML document.
    """

    def rec(node, acc, depth):
        if depth > e_sanitizers.MAX_RENDER_DEPTH:
            raise UnexpectedElementException("render depth budget of {} exceeded".format(e_sanitizers.MAX_RENDER_DEPTH))
        if isinstance(node, e_nodes.EndOfStreamNode):
            pass  # intended
        elif isinstance(node, e_nodes.OpenStartElementNode):
            acc.append("<")
            acc.append(validate_name(node.tag_name()))
            for child in node.children():
                if isinstance(child, e_nodes.AttributeNode):
                    acc.append(" ")
                    acc.append(validate_name(child.attribute_name().string()))
                    acc.append('="')
                    rec_attribute_value(child.attribute_value(), acc, depth)
                    acc.append('"')
            acc.append(">")
            for child in node.children():
                rec(child, acc, depth + 1)
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
            acc.append(e_sanitizers.escape_text(node.children()[0].string(), strict=strict))
        elif isinstance(node, e_nodes.AttributeNode):
            pass  # intended
        elif isinstance(node, e_nodes.CDataSectionNode):
            acc.append("<![CDATA[")
            acc.append(e_sanitizers.escape_cdata(node.cdata(), strict=strict))
            acc.append("]]>")
        elif isinstance(node, e_nodes.CharacterReferenceNode):
            acc.append(e_sanitizers.escape_text(chr(node.entity()), strict=strict))
        elif isinstance(node, e_nodes.EntityReferenceNode):
            acc.append("&")
            acc.append(validate_name(node.entity_reference_name()))
            acc.append(";")
        elif isinstance(node, e_nodes.ProcessingInstructionTargetNode):
            acc.append("<?")
            acc.append(validate_name(node.processing_instruction_target_name()))
        elif isinstance(node, e_nodes.ProcessingInstructionDataNode):
            data = node.processing_instruction_data()
            if data:
                acc.append(" ")
                acc.append(e_sanitizers.escape_processing_instruction_data(data, strict=strict))
            acc.append("?>")
        elif isinstance(node, e_nodes.TemplateInstanceNode):
            raise UnexpectedElementException("TemplateInstanceNode")
        elif isinstance(node, e_nodes.NormalSubstitutionNode):
            sub = subs[node.index()]

            if isinstance(sub, e_nodes.BXmlTypeNode):
                sub = render_root_node(sub.root(), strict=strict, _depth=depth + 1)
            else:
                sub = e_sanitizers.escape_text(sub.string(), strict=strict)

            acc.append(sub)
        elif isinstance(node, e_nodes.ConditionalSubstitutionNode):
            sub = subs[node.index()]

            if isinstance(sub, e_nodes.BXmlTypeNode):
                sub = render_root_node(sub.root(), strict=strict, _depth=depth + 1)
            else:
                sub = e_sanitizers.escape_text(sub.string(), strict=strict)

            acc.append(sub)
        elif isinstance(node, e_nodes.StreamStartNode):
            pass  # intended

    def rec_attribute_value(node, acc, depth):
        if isinstance(node, e_nodes.ValueNode):
            acc.append(e_sanitizers.escape_attr(node.children()[0].string(), strict=strict))
        elif isinstance(node, (e_nodes.NormalSubstitutionNode, e_nodes.ConditionalSubstitutionNode)):
            sub = subs[node.index()]
            if isinstance(sub, e_nodes.BXmlTypeNode):
                sub = render_root_node(sub.root(), strict=strict, _depth=depth + 1)
                acc.append(e_sanitizers.escape_attr(sub, strict=strict))
            else:
                acc.append(e_sanitizers.escape_attr(sub.string(), strict=strict))
        else:
            raise UnexpectedElementException("unexpected attribute value node: {!r}".format(node))

    acc = []
    for c in root_node.template().children():
        rec(c, acc, _depth)
    return "".join(acc)


def render_root_node(root_node, strict=None, _depth=0):
    subs = []
    for sub in root_node.substitutions():
        if isinstance(sub, str):
            raise RuntimeError("string sub?")

        if sub is None:
            raise RuntimeError("null sub?")

        subs.append(sub)

    return render_root_node_with_subs(root_node, subs, strict=strict, _depth=_depth)


def evtx_record_xml_view(record, cache=None, strict=None):
    """
    render the given record into an XML document.

    Args:
      record (Evtx.Record): the record to render.
      cache: unused, kept for backwards compatibility.
      strict (bool|None): if given, reject invalid strings instead of
        repairing them with U+FFFD. defaults to the process-wide setting.

    Returns:
      str: the rendered XML document.
    """
    if strict is None:
        return render_root_node(record.root())
    with e_sanitizers.strict_mode(strict):
        return render_root_node(record.root(), strict=strict)


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
        record_str = evtx_record_xml_view(record)
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
            record_str = evtx_record_xml_view(record)
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
