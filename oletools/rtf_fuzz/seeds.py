"""
Benign, fully synthetic seed corpus for the structure-aware RTF fuzzer.

Every payload is generated in-memory and contains harmless marker bytes only;
no Office document, executable or external sample is ever opened.  The OLE 1.0
object structure follows MS-OLEDS so that oletools.oleobj.OleObject can
parse it, but the embedded data is just an ASCII marker string.
"""

import binascii
import struct

from . import model


# A harmless, recognisable marker used as the embedded object body.  The bytes
# stay in the printable ASCII range and contain no executable content.
DEFAULT_MARKER = b"FUZZ-HARMLESS-OBJECT-" + bytes(bytearray(range(1, 33)))


def _length_prefixed_string(text):
    """Build an OLE1.0 length-prefixed ANSI string (including NUL)."""
    body = bytes(text) + b"\x00"
    return struct.pack("<I", len(body)) + body


def build_ole1_object(class_name=b"FuzzHarmless", marker=None):
    """Return a minimal, valid, embedded OLE 1.0 object (MS-OLEDS 2.2).

    The object parses successfully through
    :class:`oletools.oleobj.OleObject` while its embedded data is only an
    inert ASCII marker.
    """
    if marker is None:
        marker = DEFAULT_MARKER
    class_name = bytes(class_name)
    parts = [
        struct.pack("<I", 0x00000002),       # OLE version
        struct.pack("<I", 0x00000002),       # format id = embedded
        _length_prefixed_string(class_name),
        _length_prefixed_string(b"fuzz-topic"),
        _length_prefixed_string(b"fuzz-item"),
        struct.pack("<I", len(marker)),      # native data size
        marker,
    ]
    return b"".join(parts)


def wrap_rtf_object(payload, destination=b"objdata", prefix=b"",
                    suffix=b""):
    """Wrap an encoded object payload into a minimal object-bearing RTF doc."""
    return (b"\\rtf1\\ansi{\\object\\objemb{\\*\\objclass Fuzz}"
            + b"{\\" + bytes(destination) + b" " + bytes(prefix)
            + bytes(payload) + bytes(suffix) + b"}}")


def hex_encode(payload):
    """Hex-encode a payload the way an RTF objdata destination stores it."""
    return binascii.hexlify(bytes(payload))


def bin_encode(payload, leading_space=True):
    """Build a backslash-bin token carrying a raw payload."""
    space = b" " if leading_space else b""
    return b"\\bin" + str(len(payload)).encode("ascii") + space + payload


def build_seed_documents(payload=None):
    """Return a dict of named, semantically equivalent seed documents.

    Every seed embeds the same harmless OLE object but through a different
    legal encoding, so the valid-sample oracle can assert byte-identical
    extracted objects across encodings.
    """
    if payload is None:
        payload = build_ole1_object()
    hexed = hex_encode(payload)
    half = len(hexed) // 2
    seeds = {}
    seeds["hex_plain"] = wrap_rtf_object(hexed)
    seeds["hex_split_ws"] = wrap_rtf_object(
        hexed[:half] + b"\\r\\n " + hexed[half:])
    seeds["hex_split_group"] = wrap_rtf_object(
        hexed[:half] + b"{\\*\\zzz qqq}" + hexed[half:])
    seeds["hex_apostrophe"] = wrap_rtf_object(
        hexed[:4] + b"\\'00" + hexed[4:])
    seeds["bin_single"] = wrap_rtf_object(bin_encode(payload))
    chunk = max(1, len(payload) // 3)
    pieces = []
    for index in range(0, len(payload), chunk):
        pieces.append(bin_encode(payload[index:index + chunk]))
    seeds["bin_multi"] = wrap_rtf_object(b"".join(pieces))
    byte_split = len(payload) // 2
    seeds["mixed_hex_bin"] = wrap_rtf_object(
        hexed[:byte_split * 2]
        + bin_encode(payload[byte_split:]))
    return seeds


def default_seed_corpus():
    """Return (payload, {name: document_bytes}) for the default corpus."""
    payload = build_ole1_object()
    return payload, build_seed_documents(payload)
