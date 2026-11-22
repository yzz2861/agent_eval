import io

import pcapng.blocks as blocks
from pcapng import FileWriter
from pcapng.review import Approval, compare, compare_files


def build(order, packets, recv=None):
    shb = blocks.SectionHeader(endianness="<")
    idbs = {}
    for name in order:
        idb = shb.new_member(
            blocks.InterfaceDescription,
            link_type=1,
            snaplen=65535,
            options={"if_name": name},
        )
        idbs[name] = idb
    out = io.BytesIO()
    writer = FileWriter(out, shb)
    for packet in packets:
        options = {}
        if "packetid" in packet:
            options["epb_packetid"] = packet["packetid"]
        if "comment" in packet:
            options["opt_comment"] = packet["comment"]
        if "hash" in packet:
            options["epb_hash"] = [(0, packet["hash"])]
        block = shb.new_member(
            blocks.EnhancedPacket,
            interface_id=idbs[packet["interface"]].interface_id,
            timestamp_high=0,
            timestamp_low=packet["timestamp"],
            packet_len=packet.get("packet_len", len(packet["data"])),
            packet_data=packet["data"],
            options=options,
        )
        writer.write_block(block)
    if recv:
        for name, value in recv.items():
            block = shb.new_member(
                blocks.InterfaceStatistics,
                interface_id=idbs[name].interface_id,
                timestamp_high=0,
                timestamp_low=0,
                options={"isb_ifrecv": value},
            )
            writer.write_block(block)
    return out.getvalue()


def test_approved_comment_deletion_and_silent_hash_change():
    original = build(
        ["alpha", "beta"],
        [
            {
                "interface": "beta",
                "packetid": 1,
                "timestamp": 100,
                "data": b"AAAA",
                "comment": "secret one",
                "hash": b"good-one",
            },
            {
                "interface": "alpha",
                "packetid": 2,
                "timestamp": 200,
                "data": b"BBBB",
                "comment": "secret two",
                "hash": b"good-two",
            },
        ],
        {"alpha": 1, "beta": 1},
    )
    redacted = build(
        ["beta", "alpha"],
        [
            {
                "interface": "beta",
                "packetid": 1,
                "timestamp": 100,
                "data": b"AAAA",
                "hash": b"good-one",
            },
            {
                "interface": "alpha",
                "packetid": 2,
                "timestamp": 200,
                "data": b"BBBB",
                "comment": "secret two",
                "hash": b"evil-two",
            },
        ],
        {"alpha": 1, "beta": 1},
    )
    approvals = [
        Approval(domain="packet", packet_id=1, field="opt_comment", action="delete")
    ]
    report = compare_files(original, redacted, approvals=approvals)

    approved = [
        finding
        for finding in report.findings
        if finding.field == "opt_comment"
    ]
    assert len(approved) == 1
    assert approved[0].approved is True
    assert approved[0].packet_id == 1
    assert approved[0].code == "approved_redaction"
    assert b"secret one" in original[slice(*approved[0].original_range)]

    changed = [finding for finding in report.findings if finding.field == "epb_hash"]
    assert len(changed) == 1
    assert changed[0].approved is False
    assert changed[0].packet_id == 2
    assert changed[0].code == "preservation_field_changed"
    assert b"good-two" in original[slice(*changed[0].original_range)]
    assert report.ok is False
    assert report.violations == changed
    assert len(report.violations) == 1
    assert not any(finding.field == "interface_id" for finding in report.findings)


def test_interface_renumbering_alone_is_not_a_change():
    original = build(
        ["alpha", "beta"],
        [
            {
                "interface": "alpha",
                "packetid": 10,
                "timestamp": 1,
                "data": b"one",
                "comment": "keep",
                "hash": b"one",
            },
            {
                "interface": "beta",
                "packetid": 11,
                "timestamp": 2,
                "data": b"two",
                "comment": "keep",
                "hash": b"two",
            },
        ],
        {"alpha": 1, "beta": 1},
    )
    redacted = build(
        ["beta", "alpha"],
        [
            {
                "interface": "beta",
                "packetid": 11,
                "timestamp": 2,
                "data": b"two",
                "comment": "keep",
                "hash": b"two",
            },
            {
                "interface": "alpha",
                "packetid": 10,
                "timestamp": 1,
                "data": b"one",
                "comment": "keep",
                "hash": b"one",
            },
        ],
        {"alpha": 1, "beta": 1},
    )
    report = compare(original, redacted)
    assert report.findings == []
    assert report.ok is True


def test_retained_observation_counts_are_checked_after_packet_removal():
    original = build(
        ["alpha"],
        [
            {"interface": "alpha", "packetid": 1, "timestamp": 1, "data": b"AA"},
            {"interface": "alpha", "packetid": 2, "timestamp": 2, "data": b"BB"},
        ],
        {"alpha": 2},
    )
    redacted = build(
        ["alpha"],
        [{"interface": "alpha", "packetid": 1, "timestamp": 1, "data": b"AA"}],
        {"alpha": 2},
    )
    report = compare_files(original, redacted)
    assert len(report.by_code("packet_removed")) == 1
    overclaims = report.by_code("count_overclaim")
    assert len(overclaims) == 1
    assert overclaims[0].field == "isb_ifrecv"
    assert overclaims[0].approved is False
    assert b"\x04\x00" in original[slice(*overclaims[0].original_range)]


def test_approval_accepts_tuple_and_read_only_streams():
    original = build(
        ["alpha"],
        [
            {
                "interface": "alpha",
                "packetid": 7,
                "timestamp": 1,
                "data": b"AA",
                "comment": "remove",
            }
        ],
    )
    redacted = build(
        ["alpha"],
        [{"interface": "alpha", "packetid": 7, "timestamp": 1, "data": b"AA"}],
    )
    approval = Approval(("packet", 7, "opt_comment", "delete"))
    original_stream = io.BytesIO(original)
    original_stream.seek(3)
    report = compare_files(original_stream, io.BytesIO(redacted), approvals=[approval])
    assert original_stream.tell() == 3
    assert report.ok is True
    assert len(report.approved) == 1
