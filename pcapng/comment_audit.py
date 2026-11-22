"""
Offline verification of reviewed ``opt_comment`` annotations.

When two pcapng sections are merged into a single export, the comment
*text* is preserved but the surrounding blocks can be reordered, copied
or rewritten.  Text alone therefore cannot prove that a human-reviewed
comment still points at the same section, interface and packet that were
originally approved.

This module re-reads both the original capture and the exported capture
through the normal :class:`~pcapng.scanner.FileScanner` read path and
binds every ``opt_comment`` option (option code 1) to one of three
scopes:

* :data:`SCOPE_SECTION` -- comment on a Section Header Block;
* :data:`SCOPE_INTERFACE` -- comment on an Interface Description Block;
* :data:`SCOPE_PACKET` -- comment on a packet block (EPB, SPB or the
  obsolete Packet Block).

Sections are recognised by their packet content rather than by file
position, so whole sections may be reordered or appear more than once.
Packets inside a section are recognised by a hash of the captured bytes
plus their ordinal position, which keeps duplicate comment text and
duplicate packets distinguishable.

Options unknown to the block schemas cannot be bound to any reviewed
scope; they are reported separately as *unverifiable* instead of being
silently trusted.
"""

import hashlib
import json
import struct

from pcapng import blocks
from pcapng._compat import namedtuple
from pcapng.exceptions import CommentAuditError
from pcapng.scanner import FileScanner

#: Comment attached to a Section Header Block.
SCOPE_SECTION = "section"
#: Comment attached to an Interface Description Block.
SCOPE_INTERFACE = "interface"
#: Comment attached to a packet block.
SCOPE_PACKET = "packet"

VALID_SCOPES = (SCOPE_SECTION, SCOPE_INTERFACE, SCOPE_PACKET)

#: The approved comment was found in the export at its original scope.
STATUS_VERIFIED = "verified"
#: The approved comment could no longer be bound to its original scope.
STATUS_UNVERIFIED = "unverified"
#: An option not covered by the approved entries was encountered.
STATUS_UNVERIFIABLE = "unverifiable"

#: The option code of ``opt_comment``, common to every option-bearing block.
OPT_COMMENT_CODE = 1


class PacketFingerprint(namedtuple("PacketFingerprint", ("interface_id", "digest"))):
    """Content-based identity of a single packet block."""

    __slots__ = ()

    def to_dict(self):
        return {"interface_id": self.interface_id, "digest": self.digest}


class CommentBinding(
    namedtuple(
        "CommentBinding",
        (
            "scope",
            "section_index",
            "interface_id",
            "packet_index",
            "comment_index",
            "block_index",
            "text",
        ),
    )
):
    """A single ``opt_comment`` bound to a concrete block scope.

    ``interface_id`` and ``packet_index`` are ``None`` when they do not
    apply to the scope.  ``comment_index`` is the ordinal of the comment
    among the comments of its owning block, which keeps blocks carrying
    repeated comment text unambiguous.
    """

    __slots__ = ()

    def to_dict(self):
        return {
            "scope": self.scope,
            "section_index": self.section_index,
            "interface_id": self.interface_id,
            "packet_index": self.packet_index,
            "comment_index": self.comment_index,
            "block_index": self.block_index,
            "text": self.text,
        }


class ApprovedComment(
    namedtuple(
        "ApprovedComment",
        (
            "scope",
            "section_index",
            "interface_id",
            "packet_index",
            "comment_index",
            "text",
        ),
    )
):
    """A comment entry that a human reviewer approved on the original."""

    __slots__ = ()

    @classmethod
    def from_dict(cls, data):
        try:
            scope = data["scope"]
            section_index = data["section_index"]
            text = data["text"]
        except KeyError as exc:
            raise CommentAuditError(
                "approved entry is missing required field: {0}".format(exc.args[0])
            )
        if scope not in VALID_SCOPES:
            raise CommentAuditError("unknown comment scope: {0!r}".format(scope))
        return cls(
            scope=scope,
            section_index=section_index,
            interface_id=data.get("interface_id"),
            packet_index=data.get("packet_index"),
            comment_index=data.get("comment_index", 0),
            text=text,
        )


class CommentAuditResult(
    namedtuple("CommentAuditResult", ("approved", "status", "binding", "reason"))
):
    """Outcome of checking one approved comment."""

    __slots__ = ()

    @property
    def verified(self):
        return self.status == STATUS_VERIFIED

    def to_dict(self):
        data = {
            "scope": self.approved.scope,
            "section_index": self.approved.section_index,
            "interface_id": self.approved.interface_id,
            "packet_index": self.approved.packet_index,
            "comment_index": self.approved.comment_index,
            "text": self.approved.text,
            "status": self.status,
        }
        data["found"] = self.binding.to_dict() if self.binding else None
        if self.reason is not None:
            data["reason"] = self.reason
        return data


class UnverifiableOption(
    namedtuple(
        "UnverifiableOption",
        (
            "section_index",
            "block_kind",
            "block_index",
            "option_code",
            "raw_value",
        ),
    )
):
    """An option that cannot be tied back to an approved comment scope."""

    __slots__ = ()

    def to_dict(self):
        return {
            "section_index": self.section_index,
            "block_kind": self.block_kind,
            "block_index": self.block_index,
            "option_code": self.option_code,
            "raw_value_hex": self.raw_value.hex(),
            "status": STATUS_UNVERIFIABLE,
        }


# ---------------------------------------------------------------------------
# Scanning helpers: bind comments to section / interface / packet scopes
# ---------------------------------------------------------------------------

def _iter_blocks(stream):
    """Yield ``(block_index, block, section_index)`` from a pcapng stream."""
    section_index = -1
    for block_index, block in enumerate(FileScanner(stream)):
        if isinstance(block, blocks.SectionHeader):
            section_index += 1
        yield block_index, block, section_index


def _block_scope(block):
    if isinstance(block, blocks.SectionHeader):
        return SCOPE_SECTION
    if isinstance(block, blocks.InterfaceDescription):
        return SCOPE_INTERFACE
    if isinstance(block, blocks.BasePacketBlock):
        return SCOPE_PACKET
    return None


def _block_kind(block):
    return type(block).__name__


def _block_comments(block):
    """Return the decoded ``opt_comment`` values carried by a block."""
    options = getattr(block, "options", None)
    if options is None or OPT_COMMENT_CODE not in options.data:
        return []
    return list(options.get_all("opt_comment"))


def _unknown_options(block):
    """Return ``[(option_code, raw_value), ...]`` for unknown options."""
    options = getattr(block, "options", None)
    if options is None:
        return []
    found = []
    for code, values in options.data.items():
        if code in options.schema:
            continue
        for value in values:
            found.append((code, bytes(value)))
    return found


class PacketPosition(
    namedtuple(
        "PacketPosition",
        ("interface_id", "packet_index", "block_index", "fingerprint"),
    )
):
    """A packet located inside a section, independent of its comments."""

    __slots__ = ()


class SectionIndex(object):
    """Content-based index of one section packets, comments and options."""

    __slots__ = (
        "section_index",
        "signature",
        "packets",
        "bindings",
        "unknown_options",
    )

    def __init__(self, section_index, signature, packets, bindings, unknown_options):
        self.section_index = section_index
        self.signature = signature
        self.packets = packets
        self.bindings = bindings
        self.unknown_options = unknown_options


def _packet_fingerprint(block):
    """Identify a packet by interface id and the captured packet data."""
    hasher = hashlib.sha256()
    hasher.update(struct.pack("<I", int(block.interface_id)))
    hasher.update(bytes(block.packet_data))
    return PacketFingerprint(
        interface_id=int(block.interface_id),
        digest=hasher.hexdigest(),
    )


def build_section_index(stream):
    """
    Build a content-based index of every section in a pcapng stream.

    A section is identified by the ordered fingerprints of the packets it
    contains. Two sections carrying identical packet data share a
    signature, so repeated sections are disambiguated by ordinal among
    equal signatures. Each section also records its bound comments and any
    unknown option.

    :param stream: a readable binary pcapng stream.
    :returns: a dict keyed by the section ordinal, with SectionIndex
        values.
    """
    sections = {}
    current = None
    packet_counters = {}
    for block_index, block, section_index in _iter_blocks(stream):
        if isinstance(block, blocks.SectionHeader):
            current = SectionIndex(
                section_index=section_index,
                signature=(),
                packets=[],
                bindings=[],
                unknown_options=[],
            )
            sections[section_index] = current
            packet_counters = {}

        for code, raw in _unknown_options(block):
            current.unknown_options.append(
                UnverifiableOption(
                    section_index=section_index,
                    block_kind=_block_kind(block),
                    block_index=block_index,
                    option_code=code,
                    raw_value=raw,
                )
            )

        scope = _block_scope(block)
        packet_index = None
        if isinstance(block, blocks.BasePacketBlock):
            key = (section_index, block.interface_id)
            packet_index = packet_counters.get(key, 0)
            packet_counters[key] = packet_index + 1
            fingerprint = _packet_fingerprint(block)
            current.packets.append(
                PacketPosition(
                    interface_id=fingerprint.interface_id,
                    packet_index=packet_index,
                    block_index=block_index,
                    fingerprint=fingerprint,
                )
            )

        if scope is None:
            continue
        for comment_index, text in enumerate(_block_comments(block)):
            current.bindings.append(
                CommentBinding(
                    scope=scope,
                    section_index=section_index,
                    interface_id=getattr(block, "interface_id", None),
                    packet_index=packet_index,
                    comment_index=comment_index,
                    block_index=block_index,
                    text=text,
                )
            )

    for section in sections.values():
        section.signature = tuple(
            (position.interface_id, position.fingerprint.digest)
            for position in section.packets
        )
    return sections


def extract_comment_index(stream):
    """
    Read a pcapng stream and index every human-reviewed comment.

    Comments are bound to the section, interface and packet scopes in
    stream order. The result is a flat list of :class:`CommentBinding`
    objects across all sections.

    :param stream: a readable binary pcapng stream.
    :returns: a list of :class:`CommentBinding` objects.
    """
    index = build_section_index(stream)
    bindings = []
    for section_index in sorted(index):
        bindings.extend(index[section_index].bindings)
    return bindings


def extract_unverifiable_options(stream):
    """
    Collect every option whose code is unknown to the block schemas.

    Such options cannot be proven to belong to a reviewed comment scope
    and are reported as unverifiable rather than trusted.

    :param stream: a readable binary pcapng stream.
    :returns: a list of :class:`UnverifiableOption` objects.
    """
    index = build_section_index(stream)
    items = []
    for section_index in sorted(index):
        items.extend(index[section_index].unknown_options)
    return items


def match_sections(original_sections, export_sections):
    """
    Map original section ordinals onto export section ordinals.

    Sections are matched by their content signature. Whole sections may
    therefore be reordered; when two sections share a signature (for
    example an empty section, or a duplicated short capture), the nth
    original section with that signature is matched to the nth export
    section with the same signature.

    :raises CommentAuditError: if the export is missing a section that is
        present in the original.
    :returns: a dict ``{original_section_index: export_section_index}``.
    """
    export_by_signature = {}
    for export_section_index in sorted(export_sections):
        signature = export_sections[export_section_index].signature
        export_by_signature.setdefault(signature, []).append(export_section_index)

    seen = {}
    mapping = {}
    for original_section_index in sorted(original_sections):
        signature = original_sections[original_section_index].signature
        occurrence = seen.get(signature, 0)
        candidates = export_by_signature.get(signature, ())
        if occurrence >= len(candidates):
            raise CommentAuditError(
                "export is missing section {0} with signature {1!r}".format(
                    original_section_index, signature
                )
            )
        mapping[original_section_index] = candidates[occurrence]
        seen[signature] = occurrence + 1
    return mapping


class AuditReport(
    namedtuple(
        "AuditReport",
        ("results", "unverifiable_options", "section_mapping"),
    )
):
    """Result of auditing an export against the approved original."""

    __slots__ = ()

    @property
    def all_verified(self):
        return all(result.verified for result in self.results)

    def find(self, text, scope=None):
        """Return the verified bindings whose comment text equals ``text``."""
        found = []
        for result in self.results:
            if not result.verified or result.approved.text != text:
                continue
            if scope is not None and result.approved.scope != scope:
                continue
            found.append(result.binding)
        return found

    def to_dict(self):
        return {
            "all_verified": self.all_verified,
            "section_mapping": dict(self.section_mapping),
            "results": [result.to_dict() for result in self.results],
            "unverifiable_options": [
                option.to_dict() for option in self.unverifiable_options
            ],
        }


def _binding_key(binding):
    return (
        binding.scope,
        binding.section_index,
        binding.interface_id,
        binding.packet_index,
        binding.comment_index,
        binding.text,
    )


def _approved_key(approved, export_section_index):
    return (
        approved.scope,
        export_section_index,
        approved.interface_id,
        approved.packet_index,
        approved.comment_index,
        approved.text,
    )


def _validate_approved(approved, original_index):
    section = original_index.get(approved.section_index)
    if section is None:
        raise CommentAuditError(
            "approved entry references unknown original section {0}".format(
                approved.section_index
            )
        )
    wanted = (
        approved.scope,
        approved.section_index,
        approved.interface_id,
        approved.packet_index,
        approved.comment_index,
        approved.text,
    )
    for binding in section.bindings:
        if _binding_key(binding) == wanted:
            return
    raise CommentAuditError(
        "approved entry has no matching comment in the original: {0!r}".format(
            wanted
        )
    )


def audit_comments(original_stream, export_stream, approved_entries):
    """
    Verify that approved comments survived an export at their scope.

    :param original_stream:
        readable binary pcapng stream of the original, pre-merge capture.
    :param export_stream:
        readable binary pcapng stream of the merged/reordered export.
    :param approved_entries:
        iterable of :class:`ApprovedComment` objects (or plain dicts that
        :meth:`ApprovedComment.from_dict` accepts) naming the comments a
        human reviewer approved on the original.
    :returns: an :class:`AuditReport`.
    :raises CommentAuditError: if an approved entry cannot be located in
        the original or the export is missing one of the original
        sections.
    """
    approved = [
        entry if isinstance(entry, ApprovedComment)
        else ApprovedComment.from_dict(entry)
        for entry in approved_entries
    ]
    original_index = build_section_index(original_stream)
    export_index = build_section_index(export_stream)

    for entry in approved:
        _validate_approved(entry, original_index)

    mapping = match_sections(original_index, export_index)

    export_bindings = {}
    for export_section_index in sorted(export_index):
        for binding in export_index[export_section_index].bindings:
            export_bindings.setdefault(_binding_key(binding), binding)

    results = []
    for entry in approved:
        export_section_index = mapping[entry.section_index]
        key = _approved_key(entry, export_section_index)
        binding = export_bindings.get(key)
        if binding is None:
            results.append(
                CommentAuditResult(
                    approved=entry,
                    status=STATUS_UNVERIFIED,
                    binding=None,
                    reason=(
                        "no comment with the same text and scope was found "
                        "in the exported section"
                    ),
                )
            )
        else:
            results.append(
                CommentAuditResult(
                    approved=entry,
                    status=STATUS_VERIFIED,
                    binding=binding,
                    reason=None,
                )
            )

    unverifiable = []
    for export_section_index in sorted(export_index):
        unverifiable.extend(export_index[export_section_index].unknown_options)

    return AuditReport(
        results=results,
        unverifiable_options=unverifiable,
        section_mapping=mapping,
    )


def _build_arg_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Offline audit of human-reviewed pcapng opt_comment annotations "
            "after two sections are merged into one export."
        )
    )
    parser.add_argument(
        "original",
        type=lambda name: open(name, "rb"),
        help="path to the original, pre-merge pcapng capture",
    )
    parser.add_argument(
        "export",
        type=lambda name: open(name, "rb"),
        help="path to the merged/reordered pcapng export",
    )
    parser.add_argument(
        "approved",
        type=lambda name: open(name, "rb"),
        help=(
            "JSON file listing the caller-approved comments; each entry needs "
            "scope, section_index and text, plus interface_id/packet_index/"
            "comment_index as appropriate for the scope"
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="write the JSON audit report here instead of to stdout",
    )
    return parser


def main(argv=None):
    """Command-line entry point; returns a process exit code."""
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    with args.original, args.export, args.approved:
        approved_entries = json.loads(
            args.approved.read().decode("utf-8")
        )
        report = audit_comments(args.original, args.export, approved_entries)

    payload = json.dumps(report.to_dict(), indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w") as out:
            out.write(payload)
            out.write("\n")
    else:
        print(payload)
    return 0 if report.all_verified and not report.unverifiable_options else 1


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main())
