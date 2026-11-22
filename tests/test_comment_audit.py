"""
Tests for the offline audit of reviewed ``opt_comment`` annotations.

The scenario mirrors a joint incident investigation: two short captures
(each using interface 0) are merged into one export, whole sections are
reordered and comment text may be duplicated. The audit must still prove
which section, interface and packet every approved comment points at.
"""

import io
import json
import struct

import pytest

import pcapng.blocks as blocks
from pcapng import FileScanner, FileWriter
from pcapng.comment_audit import (
    SCOPE_INTERFACE,
    SCOPE_PACKET,
    SCOPE_SECTION,
    STATUS_UNVERIFIABLE,
    STATUS_UNVERIFIED,
    STATUS_VERIFIED,
    ApprovedComment,
    CommentAuditError,
    audit_comments,
    build_section_index,
    extract_comment_index,
    extract_unverifiable_options,
    main,
    match_sections,
)


def build_section(section_comment, interface_comment, packets, packet_comments=None):
    """Serialize one section with one interface 0 and the given packets."""
    packet_comments = packet_comments or {}
    shb = blocks.SectionHeader(
        endianness="<",
        options={"opt_comment": section_comment},
    )
    shb.new_member(
        blocks.InterfaceDescription,
        link_type=1,
        snaplen=0,
        options={"opt_comment": interface_comment},
    )
    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    for packet_index, payload in enumerate(packets):
        packet = shb.new_member(blocks.EnhancedPacket, interface_id=0)
        packet.packet_data = payload
        for text in packet_comments.get(packet_index, ()):
            packet.options.add("opt_comment", text)
        writer.write_block(packet)
    return stream.getvalue()


def joined(*chunks):
    return b"".join(chunks)


def _pad4(data):
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def _option(code, value):
    return struct.pack("<HH", code, len(value)) + _pad4(value)


def _raw_block(block_type, body):
    padded = _pad4(body)
    total = 12 + len(padded)
    header = struct.pack("<II", block_type, total)
    footer = struct.pack("<I", total)
    return header + padded + footer


def raw_shb(comment=None, unknown=None):
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    if comment:
        body += _option(1, comment.encode("utf-8"))
    if unknown:
        body += _option(unknown[0], unknown[1])
    body += struct.pack("<I", 0)
    return _raw_block(0x0A0D0D0A, body)


def raw_idb():
    body = struct.pack("<HHI", 1, 0, 0) + struct.pack("<I", 0)
    return _raw_block(0x00000001, body)


def raw_epb(packet, comment=None, unknown=None):
    body = struct.pack("<III", 0, 0, 0)
    body += struct.pack("<II", len(packet), len(packet)) + _pad4(packet)
    if comment:
        body += _option(1, comment.encode("utf-8"))
    if unknown:
        body += _option(unknown[0], unknown[1])
    body += struct.pack("<I", 0)
    return _raw_block(0x00000006, body)


# ---------------------------------------------------------------------------
# Indexing: comments are bound to section / interface / packet scopes
# ---------------------------------------------------------------------------

def test_index_binds_all_three_scopes():
    capture = build_section(
        "section note",
        "interface note",
        [b"packet-one", b"packet-two"],
        packet_comments={0: ["packet note"]},
    )
    index = build_section_index(io.BytesIO(capture))
    assert sorted(index) == [0]

    bindings = index[0].bindings
    by_scope = {}
    for binding in bindings:
        by_scope.setdefault(binding.scope, []).append(binding)

    section_binding = by_scope[SCOPE_SECTION][0]
    assert section_binding.text == "section note"
    assert section_binding.interface_id is None
    assert section_binding.packet_index is None

    interface_binding = by_scope[SCOPE_INTERFACE][0]
    assert interface_binding.text == "interface note"
    assert interface_binding.interface_id == 0

    packet_binding = by_scope[SCOPE_PACKET][0]
    assert packet_binding.text == "packet note"
    assert packet_binding.interface_id == 0
    assert packet_binding.packet_index == 0
    assert packet_binding.comment_index == 0


def test_packet_index_counts_per_interface_and_section():
    capture = joined(
        build_section("a", "ia", [b"a1", b"a2"], {0: ["c"], 1: ["c"]}),
        build_section("b", "ib", [b"b1"], {0: ["c"]}),
    )
    bindings = [
        binding
        for binding in extract_comment_index(io.BytesIO(capture))
        if binding.scope == SCOPE_PACKET
    ]
    assert [(binding.section_index, binding.packet_index) for binding in bindings] == [
        (0, 0),
        (0, 1),
        (1, 0),
    ]


# ---------------------------------------------------------------------------
# Section matching: content identity survives whole-section reordering
# ---------------------------------------------------------------------------

@pytest.fixture
def two_section_capture():
    section_a = build_section(
        "section-A",
        "iface-A",
        [b"aaaa-1", b"aaaa-2"],
        packet_comments={0: ["packet note A"]},
    )
    section_b = build_section(
        "section-B",
        "iface-B",
        [b"bbbb-1"],
        packet_comments={0: ["packet note B"]},
    )
    return section_a, section_b


def test_section_signature_ignores_position_and_comments(two_section_capture):
    section_a, section_b = two_section_capture
    original = build_section_index(io.BytesIO(joined(section_a, section_b)))
    reordered = build_section_index(io.BytesIO(joined(section_b, section_a)))

    assert original[0].signature == reordered[1].signature
    assert original[1].signature == reordered[0].signature
    assert original[0].signature != original[1].signature


def test_match_sections_maps_reordered_sections(two_section_capture):
    section_a, section_b = two_section_capture
    original = build_section_index(io.BytesIO(joined(section_a, section_b)))
    reordered = build_section_index(io.BytesIO(joined(section_b, section_a)))

    mapping = match_sections(original, reordered)
    assert mapping == {0: 1, 1: 0}


def test_match_sections_disambiguates_duplicate_sections_by_ordinal():
    section = build_section("dup", "iface", [b"shared"])
    original = build_section_index(io.BytesIO(joined(section, section)))
    reordered = build_section_index(io.BytesIO(joined(section, section)))

    assert match_sections(original, reordered) == {0: 0, 1: 1}


def test_match_sections_reports_missing_section():
    section_a = build_section("a", "ia", [b"a1"])
    section_b = build_section("b", "ib", [b"b1"])
    original = build_section_index(io.BytesIO(joined(section_a, section_b)))
    truncated = build_section_index(io.BytesIO(section_b))

    with pytest.raises(CommentAuditError, match="missing section"):
        match_sections(original, truncated)


# ---------------------------------------------------------------------------
# End-to-end audit across a reordered, merged export
# ---------------------------------------------------------------------------

def test_audit_finds_comment_moved_to_another_section(two_section_capture):
    section_a, section_b = two_section_capture
    original = io.BytesIO(joined(section_a, section_b))
    export = io.BytesIO(joined(section_b, section_a))

    approved = [
        ApprovedComment(
            scope=SCOPE_SECTION, section_index=0, interface_id=None,
            packet_index=None, comment_index=0, text="section-A",
        ),
        ApprovedComment(
            scope=SCOPE_INTERFACE, section_index=0, interface_id=0,
            packet_index=None, comment_index=0, text="iface-A",
        ),
        ApprovedComment(
            scope=SCOPE_PACKET, section_index=0, interface_id=0,
            packet_index=0, comment_index=0, text="packet note A",
        ),
        ApprovedComment(
            scope=SCOPE_SECTION, section_index=1, interface_id=None,
            packet_index=None, comment_index=0, text="section-B",
        ),
    ]
    report = audit_comments(original, export, approved)

    assert report.section_mapping == {0: 1, 1: 0}
    assert report.all_verified
    assert [result.status for result in report.results] == [
        STATUS_VERIFIED,
        STATUS_VERIFIED,
        STATUS_VERIFIED,
        STATUS_VERIFIED,
    ]

    moved_packet = report.find("packet note A", scope=SCOPE_PACKET)
    assert len(moved_packet) == 1
    assert moved_packet[0].section_index == 1
    assert moved_packet[0].interface_id == 0
    assert moved_packet[0].packet_index == 0

    moved_section = report.find("section-A", scope=SCOPE_SECTION)
    assert moved_section[0].section_index == 1


def test_audit_accepts_plain_dict_entries(two_section_capture):
    section_a, section_b = two_section_capture
    report = audit_comments(
        io.BytesIO(joined(section_a, section_b)),
        io.BytesIO(joined(section_b, section_a)),
        [
            {"scope": SCOPE_INTERFACE, "section_index": 1,
             "interface_id": 0, "text": "iface-B"},
        ],
    )
    assert report.all_verified
    assert report.results[0].binding.section_index == 0


def test_duplicate_comment_text_remains_separately_queryable():
    capture = build_section(
        "sec",
        "iface",
        [b"packet-one", b"packet-two"],
        packet_comments={0: ["same text"], 1: ["same text"]},
    )
    approved = [
        {"scope": SCOPE_PACKET, "section_index": 0, "interface_id": 0,
         "packet_index": 0, "comment_index": 0, "text": "same text"},
        {"scope": SCOPE_PACKET, "section_index": 0, "interface_id": 0,
         "packet_index": 1, "comment_index": 0, "text": "same text"},
    ]
    report = audit_comments(
        io.BytesIO(capture), io.BytesIO(capture), approved
    )

    assert report.all_verified
    found = report.find("same text", scope=SCOPE_PACKET)
    assert [binding.packet_index for binding in found] == [0, 1]


def test_repeated_comments_on_one_block_keep_comment_ordinal():
    capture = build_section(
        "sec",
        "iface",
        [b"packet-one"],
        packet_comments={0: ["repeat", "repeat"]},
    )
    bindings = [
        binding
        for binding in extract_comment_index(io.BytesIO(capture))
        if binding.scope == SCOPE_PACKET
    ]
    assert [binding.comment_index for binding in bindings] == [0, 1]

    approved = [
        {"scope": SCOPE_PACKET, "section_index": 0, "interface_id": 0,
         "packet_index": 0, "comment_index": 1, "text": "repeat"},
    ]
    report = audit_comments(
        io.BytesIO(capture), io.BytesIO(capture), approved
    )
    assert report.all_verified
    assert report.results[0].binding.comment_index == 1


def test_dropped_comment_is_unverified():
    original = build_section(
        "sec",
        "iface",
        [b"packet-one", b"packet-two"],
        packet_comments={0: ["reviewed note"], 1: ["reviewed note"]},
    )
    export = build_section(
        "sec",
        "iface",
        [b"packet-one", b"packet-two"],
        packet_comments={1: ["reviewed note"]},
    )
    approved = [
        {"scope": SCOPE_PACKET, "section_index": 0, "interface_id": 0,
         "packet_index": 0, "comment_index": 0, "text": "reviewed note"},
    ]
    report = audit_comments(
        io.BytesIO(original), io.BytesIO(export), approved
    )
    assert not report.all_verified
    result = report.results[0]
    assert result.status == STATUS_UNVERIFIED
    assert result.binding is None
    assert result.reason


# ---------------------------------------------------------------------------
# Unknown options are flagged as unverifiable, never trusted
# ---------------------------------------------------------------------------

def test_unknown_options_are_reported_as_unverifiable():
    capture = joined(
        raw_shb(comment="section note", unknown=(0x1234, b"mystery")),
        raw_idb(),
        raw_epb(
            b"packet-one",
            comment="packet note",
            unknown=(0x04D2, b""),
        ),
        raw_epb(b"packet-two"),
    )
    # The capture must still parse through the normal scanner path.
    assert [type(block).__name__ for block in FileScanner(io.BytesIO(capture))] == [
        "SectionHeader",
        "InterfaceDescription",
        "EnhancedPacket",
        "EnhancedPacket",
    ]

    unverifiable = extract_unverifiable_options(io.BytesIO(capture))
    assert len(unverifiable) == 2
    shb_option, packet_option = unverifiable
    assert shb_option.option_code == 0x1234
    assert shb_option.raw_value == b"mystery"
    assert shb_option.to_dict()["status"] == STATUS_UNVERIFIABLE
    assert packet_option.option_code == 0x04D2
    assert packet_option.block_kind == "EnhancedPacket"
    assert packet_option.raw_value == b"\x01\x02\x03"


def test_audit_keeps_verified_comments_and_flags_unknown_options():
    capture = joined(
        raw_shb(comment="section note", unknown=(0x1234, b"mystery")),
        raw_idb(),
        raw_epb(b"packet-one", comment="packet note"),
    )
    approved = [
        {"scope": SCOPE_SECTION, "section_index": 0, "text": "section note"},
        {"scope": SCOPE_PACKET, "section_index": 0, "interface_id": 0,
         "packet_index": 0, "comment_index": 0, "text": "packet note"},
    ]
    report = audit_comments(
        io.BytesIO(capture), io.BytesIO(capture), approved
    )
    assert report.all_verified
    assert len(report.unverifiable_options) == 1
    payload = report.to_dict()
    assert payload["unverifiable_options"][0]["option_code"] == 0x1234


# ---------------------------------------------------------------------------
# Input validation and command line entry point
# ---------------------------------------------------------------------------

def test_approved_entry_must_exist_in_original():
    capture = build_section("sec", "iface", [b"packet-one"])
    with pytest.raises(CommentAuditError, match="no matching comment"):
        audit_comments(
            io.BytesIO(capture),
            io.BytesIO(capture),
            [{"scope": SCOPE_SECTION, "section_index": 0, "text": "absent"}],
        )


def test_approved_entry_rejects_unknown_section():
    capture = build_section("sec", "iface", [b"packet-one"])
    with pytest.raises(CommentAuditError, match="unknown original section"):
        audit_comments(
            io.BytesIO(capture),
            io.BytesIO(capture),
            [{"scope": SCOPE_SECTION, "section_index": 9, "text": "sec"}],
        )


def test_approved_entry_rejects_unknown_scope():
    with pytest.raises(CommentAuditError, match="unknown comment scope"):
        ApprovedComment.from_dict(
            {"scope": "frame", "section_index": 0, "text": "x"}
        )


def test_cli_reports_json_and_exit_code(tmp_path):
    section_a = build_section("section-A", "iface-A", [b"aaaa-1"])
    section_b = build_section("section-B", "iface-B", [b"bbbb-1"])
    original_path = tmp_path / "original.pcapng"
    export_path = tmp_path / "export.pcapng"
    approved_path = tmp_path / "approved.json"
    output_path = tmp_path / "report.json"

    original_path.write_bytes(joined(section_a, section_b))
    export_path.write_bytes(joined(section_b, section_a))
    approved_path.write_text(
        json.dumps(
            [
                {"scope": SCOPE_SECTION, "section_index": 0,
                 "text": "section-A"},
                {"scope": SCOPE_INTERFACE, "section_index": 1,
                 "interface_id": 0, "text": "iface-B"},
            ]
        )
    )

    exit_code = main(
        [
            str(original_path),
            str(export_path),
            str(approved_path),
            "-o",
            str(output_path),
        ]
    )
    assert exit_code == 0
    report = json.loads(output_path.read_text())
    assert report["all_verified"] is True
    assert report["section_mapping"] == {"0": 1, "1": 0}
    assert report["unverifiable_options"] == []


def test_cli_exit_code_nonzero_with_unverifiable_option(tmp_path):
    capture = joined(
        raw_shb(comment="section note", unknown=(0x1234, b"mystery")),
        raw_idb(),
        raw_epb(b"packet-one"),
    )
    original_path = tmp_path / "original.pcapng"
    export_path = tmp_path / "export.pcapng"
    approved_path = tmp_path / "approved.json"
    original_path.write_bytes(capture)
    export_path.write_bytes(capture)
    approved_path.write_text(
        json.dumps(
            [{"scope": SCOPE_SECTION, "section_index": 0,
              "text": "section note"}]
        )
    )

    exit_code = main(
        [str(original_path), str(export_path), str(approved_path)]
    )
    assert exit_code == 1
