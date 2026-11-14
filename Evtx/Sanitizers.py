#!/usr/bin/python
#    This file is part of python-evtx.
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
"""
A single, auditable chain for turning BinXML string bytes into safe XML text.

The chain has two halves that share one character boundary:

  1. decoding (bytes -> str): decode_utf16le() and decode_string() replace
     truncated UTF-16 code units and unpaired surrogates with U+FFFD
     (or reject them in strict mode), and enforce a length budget.
  2. escaping (str -> XML): sanitize_chars() replaces NUL and other
     XML-forbidden control characters with U+FFFD (or rejects them in
     strict mode), and the escape_*() functions quote the XML markup
     characters appropriate for each context: text, attribute, CDATA,
     processing-instruction data, and names.

Legal Unicode (emoji, combining characters, non-BMP code points) passes
through unchanged, so escaped output can be parsed back to equivalent text.
"""

from __future__ import absolute_import

import re
import logging
import contextlib

logger = logging.getLogger(__name__)

# budgets that bound the resources a malicious or corrupt record can consume.
# a single decoded string may not exceed this many characters.
MAX_STRING_CHARS = 1 << 20
# rendering may not nest elements (or nested BXml substitutions) deeper than this.
MAX_RENDER_DEPTH = 256

REPLACEMENT_CHARACTER = "\ufffd"


class InvalidStringError(ValueError):
    """
    Base exception for strings that cannot be made safe for XML output.
    """


class StringBudgetExceededError(InvalidStringError):
    """
    A string declared more characters than the configured budget allows.
    """


class DisallowedCharacterError(InvalidStringError):
    """
    A string contains characters that may not appear in XML output,
    and strict mode is enabled so they cannot be replaced.
    """


_strict = False


def set_strict(flag):
    """
    set the process-wide default strictness for decoding and escaping.

    when strict, invalid strings raise instead of being repaired with U+FFFD.

    Args:
      flag (bool): True to reject invalid strings, False to repair them.
    """
    global _strict
    _strict = bool(flag)


def is_strict():
    """
    Returns:
      bool: the process-wide default strictness.
    """
    return _strict


@contextlib.contextmanager
def strict_mode(flag=True):
    """
    context manager that temporarily sets the process-wide strictness.

    Args:
      flag (bool): the strictness to use within the with-block.
    """
    global _strict
    previous = _strict
    _strict = bool(flag)
    try:
        yield
    finally:
        _strict = previous


def _resolve_strict(strict):
    return _strict if strict is None else strict


def check_string_budget(num_chars):
    """
    ensure a string of the given length is within the configured budget.

    Args:
      num_chars (int): the number of characters (or bytes, for 8-bit strings).

    Raises:
      StringBudgetExceededError: if the length exceeds MAX_STRING_CHARS.
    """
    if num_chars > MAX_STRING_CHARS:
        raise StringBudgetExceededError(
            "string of {} characters exceeds budget of {}".format(num_chars, MAX_STRING_CHARS)
        )


def decode_utf16le(data, strict=None):
    """
    decode UTF-16-LE bytes from a BinXML string into text.

    truncated final code units and unpaired surrogates are replaced with
    U+FFFD (and logged), unless strict mode rejects them with
    UnicodeDecodeError.

    Args:
      data (bytes): the raw string bytes.
      strict (bool|None): override the process-wide strictness.

    Returns:
      str: the decoded string.

    Raises:
      StringBudgetExceededError: if the data exceeds the length budget.
      UnicodeDecodeError: in strict mode, if the data is not valid UTF-16.
    """
    strict = _resolve_strict(strict)
    check_string_budget((len(data) + 1) // 2)
    try:
        return data.decode("utf-16-le", "strict")
    except UnicodeDecodeError as e:
        if strict:
            raise
        logger.warning("invalid UTF-16 in BinXML string (%s); replacing invalid sequences with U+FFFD", e)
        return data.decode("utf-16-le", "replace")


def decode_string(data, strict=None):
    """
    decode 8-bit (ASCII) bytes from a BinXML string into text.

    non-ASCII bytes are replaced with U+FFFD (and logged), unless strict
    mode rejects them with UnicodeDecodeError.

    Args:
      data (bytes): the raw string bytes.
      strict (bool|None): override the process-wide strictness.

    Returns:
      str: the decoded string.

    Raises:
      StringBudgetExceededError: if the data exceeds the length budget.
      UnicodeDecodeError: in strict mode, if the data is not ASCII.
    """
    strict = _resolve_strict(strict)
    check_string_budget(len(data))
    try:
        return data.decode("ascii", "strict")
    except UnicodeDecodeError as e:
        if strict:
            raise
        logger.warning("non-ASCII bytes in BinXML string (%s); replacing with U+FFFD", e)
        return data.decode("ascii", "replace")


# characters that may never appear in XML output:
#   - NUL and the C0 controls except \t \n \r
#   - the C1 controls (discouraged by XML 1.1)
#   - unpaired UTF-16 surrogates (cannot be encoded as UTF-8)
# ref: https://www.w3.org/TR/xml11/#charsets
RESTRICTED_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f\ud800-\udfff]")


def sanitize_chars(s, strict=None):
    """
    replace NUL, restricted control characters, and lone surrogates with
    U+FFFD, logging how many were replaced so the repair is auditable.

    Args:
      s (str): the decoded string.
      strict (bool|None): override the process-wide strictness.

    Returns:
      str: the sanitized string.

    Raises:
      DisallowedCharacterError: in strict mode, if restricted characters are present.
    """
    strict = _resolve_strict(strict)
    bad = RESTRICTED_CHARS.findall(s)
    if not bad:
        return s
    if strict:
        raise DisallowedCharacterError(
            "string contains restricted character(s): {}".format(", ".join(hex(ord(c)) for c in bad))
        )
    logger.warning(
        "replacing %d restricted character(s) in BinXML string: %s",
        len(bad),
        ", ".join(hex(ord(c)) for c in bad),
    )
    return RESTRICTED_CHARS.sub(REPLACEMENT_CHARACTER, s)


# ref: https://www.w3.org/TR/xml/#NT-NameStartChar
# but we require a stricter subset, matched against the whole name.
NAME_PATTERN = re.compile(r"[a-zA-Z_][a-zA-Z0-9_.:\-]*\Z")


def validate_name(s):
    """
    ensure the given name can be used as an XML entity name, such as a tag
    or attribute name. names cannot be escaped, so invalid ones are rejected.

    Args:
      s (str): the string to validate.

    Returns:
      str: the validated name.

    Raises:
      RuntimeError: if the string is not suitable to be an XML name.
    """
    if not NAME_PATTERN.match(s):
        raise RuntimeError("invalid xml name: %s" % (s))
    return s


def escape_text(s, strict=None):
    """
    escape a decoded string for XML text content, like:

        <foo>$value</foo>

    escapes & < > and turns \r into a character reference so the text
    survives an XML parse round-trip (parsers normalize literal \r to \n).

    Args:
      s (str): the decoded string.
      strict (bool|None): override the process-wide strictness.

    Returns:
      str: the escaped string.
    """
    s = sanitize_chars(s, strict=strict)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\r", "&#xD;")


def escape_attr(s, strict=None):
    """
    escape a decoded string for a double-quoted XML attribute value, like:

        <foo bar="$value">

    escapes & < > " and turns \t \n \r into character references so the
    value survives an XML parse round-trip (parsers normalize them to spaces).

    Args:
      s (str): the decoded string.
      strict (bool|None): override the process-wide strictness.

    Returns:
      str: the escaped string, without surrounding quotes.
    """
    s = sanitize_chars(s, strict=strict)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\t", "&#x9;")
        .replace("\n", "&#xA;")
        .replace("\r", "&#xD;")
    )


def escape_cdata(s, strict=None):
    """
    escape a decoded string for a CDATA section, like:

        <![CDATA[$value]]>

    CDATA content cannot contain "]]>" and character references are not
    expanded there, so "]]>" and \r are split across adjacent CDATA
    sections instead of being escaped.

    Args:
      s (str): the decoded string.
      strict (bool|None): override the process-wide strictness.

    Returns:
      str: the escaped string.
    """
    s = sanitize_chars(s, strict=strict)
    s = s.replace("]]>", "]]]]><![CDATA[>")
    s = s.replace("\r", "]]>&#xD;<![CDATA[")
    return s


def escape_processing_instruction_data(s, strict=None):
    """
    escape a decoded string for processing-instruction data, which ends at
    the first "?>". there is no way to represent "?>" inside PI data, so it
    is made harmless.

    Args:
      s (str): the decoded string.
      strict (bool|None): override the process-wide strictness.

    Returns:
      str: the escaped string.
    """
    s = sanitize_chars(s, strict=strict)
    return s.replace("?>", "?&gt;")
