"""
Structure-aware model of the RTF subset used by oletools.rtfobj.

The model mirrors the semantics of oletools.rtfobj.RtfParser:

* curly braces delimit groups and drive a group-level stack;
* a control word listed in rtfobj.DESTINATION_CONTROL_WORDS opens a
  destination that stays open until the enclosing group is closed;
* the backslash-bin control word consumes a fixed number of raw bytes
  (including an optional delimiting space) instead of ordinary text;
* everything else is a control word, control symbol or text run.

Parsing an RTF document into the model and serialising the model back is
guaranteed to reproduce the original bytes.  Mutators therefore operate on
syntactic units (groups, destinations, bin entries and hexadecimal fragments)
instead of flipping random bytes, which keeps every variant explainable
through its transformation chain.
"""

import re

from .. import rtfobj


_RE_CONTROL_WORD = rtfobj.re_control_word
_RE_CONTROL_SYMBOL = rtfobj.re_control_symbol
_RE_TEXT = rtfobj.re_text

# RtfParser.parse() inspects at most 254 bytes when matching a control word.
_CROP_SIZE = 254


class Node(object):
    """Base class for every syntactic unit."""

    kind = "node"

    def render(self):
        """Return the RTF bytes produced by this node."""
        raise NotImplementedError


class TextNode(Node):
    """A run of plain text (may contain hexadecimal digits)."""

    kind = "text"

    def __init__(self, data):
        self.data = bytes(data)

    def render(self):
        return self.data

    def __repr__(self):
        return "TextNode(%r)" % (self.data,)


class ControlWordNode(Node):
    """A control word such as backslash-objdata or backslash-bin16."""

    kind = "control_word"

    def __init__(self, name, param, delimiter=b""):
        # control word name without leading backslash (e.g. b"bin")
        self.name = bytes(name)
        # signed integer parameter as raw bytes, or None when absent
        self.param = None if param is None else bytes(param)
        # raw delimiter emitted after the control word (usually a space)
        self.delimiter = bytes(delimiter)

    @property
    def is_destination(self):
        return self.name in rtfobj.DESTINATION_CONTROL_WORDS

    def int_param(self, default=None):
        if self.param is None:
            return default
        return int(self.param)

    def render(self):
        param = b"" if self.param is None else self.param
        return b"\\" + self.name + param + self.delimiter

    def __repr__(self):
        return "ControlWordNode(%r, %r, %r)" % (
            self.name, self.param, self.delimiter)


class ControlSymbolNode(Node):
    """A control symbol rendered verbatim."""

    kind = "control_symbol"

    def __init__(self, raw):
        self.raw = bytes(raw)

    def render(self):
        return self.raw

    def __repr__(self):
        return "ControlSymbolNode(%r)" % (self.raw,)


class BinNode(Node):
    """A backslash-bin entry with its length token and raw binary payload."""

    kind = "bin"

    def __init__(self, length_token, payload, leading_space=False,
                 truncated=False):
        # decimal length as encoded in the document (kept verbatim so that
        # contradictory lengths can be represented faithfully)
        self.length_token = bytes(length_token)
        # raw bytes consumed as binary data
        self.payload = bytes(payload)
        # whether the optional delimiting space before data was present
        self.leading_space = leading_space
        # True when the declared length runs past the end of the document
        self.truncated = truncated

    @property
    def declared_length(self):
        return int(self.length_token)

    @property
    def length_contradiction(self):
        """True when the encoded length does not match the available bytes."""
        return self.truncated or len(self.payload) != self.declared_length

    def render(self):
        space = b" " if self.leading_space else b""
        return b"\\bin" + self.length_token + space + self.payload

    def __repr__(self):
        return "BinNode(len=%r, payload=%d bytes, truncated=%r)" % (
            self.length_token, len(self.payload), self.truncated)


class GroupNode(Node):
    """A brace-delimited group containing child nodes."""

    kind = "group"

    def __init__(self, children=None):
        self.children = [] if children is None else list(children)

    @property
    def destination(self):
        """Name of the destination opened in this group, if any."""
        for child in self.children:
            if isinstance(child, ControlWordNode) and child.is_destination:
                return child.name
        return None

    def render(self):
        out = [b"{"]
        out.extend(child.render() for child in self.children)
        out.append(b"}")
        return b"".join(out)

    def __repr__(self):
        return "GroupNode(dest=%r, %d children)" % (
            self.destination, len(self.children))


class DocumentNode(GroupNode):
    """Virtual root representing the whole document (no surrounding braces)."""

    kind = "document"

    def render(self):
        return b"".join(child.render() for child in self.children)

    def __repr__(self):
        return "DocumentNode(%d children)" % len(self.children)


class RtfModelParser(object):
    """Parse RTF bytes into a DocumentNode.

    The scanner follows oletools.rtfobj.RtfParser.parse closely so the
    resulting tree reflects the same grouping, destination and backslash-bin
    boundaries that the extraction parser uses.
    """

    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)
        self.index = 0

    def parse(self):
        document = DocumentNode()
        self._parse_children(document, at_eof=True)
        return document

    def _parse_children(self, group, at_eof=False):
        data = self.data
        while self.index < self.size:
            char = data[self.index:self.index + 1]
            if char == b"{":
                self.index += 1
                child = GroupNode()
                group.children.append(child)
                self._parse_children(child)
                continue
            if char == b"}":
                self.index += 1
                if not at_eof:
                    return
                # Unmatched closing brace at top level: keep it as text so the
                # round trip remains byte-exact.
                group.children.append(TextNode(b"}"))
                continue
            if char == b"\\":
                node = self._parse_backslash()
                if node is not None:
                    group.children.append(node)
                    continue
            match = _RE_TEXT.match(data, self.index)
            if match:
                group.children.append(TextNode(match.group()))
                self.index = match.end()
                continue
            # Defensive fallback: consume one byte so progress is guaranteed.
            group.children.append(TextNode(char))
            self.index += 1

    def _parse_backslash(self):
        data = self.data
        cropped = data[self.index:self.index + _CROP_SIZE] + b" "
        match = _RE_CONTROL_WORD.match(cropped)
        if match:
            name = match.group(1)
            param = match.group(2) if len(match.groups()) > 1 else None
            consumed = len(match.group())
            delimiter = b""
            if data[self.index + consumed:self.index + consumed + 1] == b" ":
                delimiter = b" "
            if name == b"bin":
                # RtfParser._bin owns the optional space, so do not consume it
                # as part of the generic control word token here.
                self.index += consumed
                return self._parse_bin(param)
            self.index += consumed + len(delimiter)
            return ControlWordNode(name, param, delimiter)
        match = _RE_CONTROL_SYMBOL.match(data, self.index)
        if match:
            node = ControlSymbolNode(match.group())
            self.index = match.end()
            return node
        return None

    def _parse_bin(self, param):
        data = self.data
        leading_space = False
        # RtfParser._bin ignores one optional space before the binary payload.
        if data[self.index:self.index + 1] == b" ":
            leading_space = True
            self.index += 1
        if param is None:
            # backslash-bin without an argument: rtfobj reads zero bytes.
            return BinNode(b"0", b"", leading_space)
        declared = int(param)
        if declared < 0:
            # Negative lengths are normalised to zero by rtfobj; keep the
            # original token so the contradictory state stays reproducible.
            return BinNode(param, b"", leading_space, truncated=True)
        end = self.index + declared
        payload = data[self.index:min(self.size, end)]
        truncated = end > self.size
        self.index = min(self.size, end)
        return BinNode(param, payload, leading_space, truncated)


def parse_rtf(data):
    """Parse RTF bytes into a DocumentNode."""
    return RtfModelParser(data).parse()


def render(node):
    """Serialise a node back to RTF bytes."""
    return node.render()


def walk(node):
    """Yield every node in the tree (depth first, parents before children)."""
    yield node
    for child in getattr(node, "children", ()):
        for descendant in walk(child):
            yield descendant


def walk_with_parent(node, parent=None):
    """Yield (parent, node) tuples for every node in the tree."""
    yield parent, node
    for child in getattr(node, "children", ()):
        for pair in walk_with_parent(child, node):
            yield pair


def find_groups(node, destination=None):
    """Find groups, optionally restricted to a given destination name."""
    result = []
    for candidate in walk(node):
        if isinstance(candidate, GroupNode):
            if destination is None or candidate.destination == destination:
                result.append(candidate)
    return result


def find_objdata_groups(node):
    """Return every group whose destination is backslash-objdata."""
    return find_groups(node, b"objdata")


def find_bin_nodes(node):
    """Return every BinNode in the tree."""
    return [candidate for candidate in walk(node)
            if isinstance(candidate, BinNode)]


def find_hex_fragments(node):
    """Return text nodes that carry at least one hexadecimal digit pair."""
    fragments = []
    for candidate in walk(node):
        if isinstance(candidate, TextNode) and re.search(
                br"[0-9A-Fa-f]{2}", candidate.data):
            fragments.append(candidate)
    return fragments
