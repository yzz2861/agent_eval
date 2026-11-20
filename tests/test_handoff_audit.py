import io

from pcapng import FileScanner, FileWriter
from pcapng.blocks import (
    EnhancedPacket,
    InterfaceDescription,
    SectionHeader,
    SimplePacket,
)
from pcapng.constants.link_types import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
)
from pcapng.handoff import (
    check_handoff,
    collect_interfaces,
    find_remark_conflicts,
    link_type_name,
    load_checklist,
    observe_prefix,
)

EGRESS_REMARK = "出口"


def _ethernet_packet():
    return (
        b"\x00\x1b\x44\x11\x22\x33"
        + b"\x00\x1b\x44\xaa\xbb\xcc"
        + b"\x08\x00"
        + b"\x45"
        + b"\x00" * 45
    )


def _sll_packet():
    return (
        b"\x00\x00"  # packet type
        + b"\x00\x01"  # ARPHRD_ETHER
        + b"\x00\x06"  # address length
        + b"\x00\x1b\x44\xaa\xbb\xcc\x00\x00"  # 8-byte address
        + b"\x08\x00"  # protocol
        + b"\x45"
        + b"\x00" * 45
    )


def _build_section(link_type, remark, packet):
    shb = SectionHeader(options={"shb_hardware": "probe"})
    shb.new_member(
        InterfaceDescription,
        link_type=link_type,
        snaplen=65535,
        options={"if_name": "if0", "if_description": remark},
    )
    return shb, [packet, packet]


def _write_sections(sections):
    stream = io.BytesIO()
    for shb, packets in sections:
        writer = FileWriter(stream, shb)
        for packet in packets:
            epb = shb.new_member(EnhancedPacket)
            epb.packet_data = packet
            writer.write_block(epb)
    stream.seek(0)
    return stream


def _two_probe_stream():
    first = _build_section(LINKTYPE_ETHERNET, EGRESS_REMARK, _ethernet_packet())
    second = _build_section(LINKTYPE_LINUX_SLL, EGRESS_REMARK, _sll_packet())
    return _write_sections([first, second])


def test_each_section_keeps_own_interface_identity():
    records = collect_interfaces(FileScanner(_two_probe_stream()))

    assert len(records) == 2
    # Both probes numbered their interface 0; the section prefix keeps
    # the two identities distinct instead of merging them.
    assert [record.label for record in records] == [
        "section 0 / interface 0",
        "section 1 / interface 0",
    ]
    assert [record.section_index for record in records] == [0, 1]
    assert {record.interface_id for record in records} == {0}
    assert {record.remark for record in records} == {EGRESS_REMARK}


def test_declared_link_types_are_reported_per_section():
    records = collect_interfaces(FileScanner(_two_probe_stream()))

    assert records[0].link_type == LINKTYPE_ETHERNET
    assert records[0].link_type_known is True
    assert records[1].link_type == LINKTYPE_LINUX_SLL
    assert records[1].link_type_known is True
    assert records[0].packet_count == 2
    assert records[1].packet_count == 2


def test_packet_prefix_corroborates_declared_link_type():
    eth = observe_prefix(LINKTYPE_ETHERNET, _ethernet_packet())
    assert eth["rule"] == "Ethernet frame header"
    assert eth["fields"]["destination_mac"] == "00:1b:44:11:22:33"
    assert eth["fields"]["ethertype"] == "0x0800"
    assert eth["fields"]["ethertype_name"] == "IPv4"

    sll = observe_prefix(LINKTYPE_LINUX_SLL, _sll_packet())
    assert sll["rule"] == "Linux cooked capture header (16 bytes)"
    assert sll["fields"]["arphrd_type"] == 1
    assert sll["fields"]["address_length"] == 6
    assert sll["fields"]["protocol"] == "0x0800"
    assert sll["fields"]["protocol_name"] == "IPv4"


def test_shared_remark_conflict_names_each_original_interface():
    records = collect_interfaces(FileScanner(_two_probe_stream()))
    conflicts = find_remark_conflicts(records)

    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict["remark"] == EGRESS_REMARK
    assert conflict["link_types"] == [LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL]

    labels = [record.label for record in conflict["interfaces"]]
    assert labels == ["section 0 / interface 0", "section 1 / interface 0"]


def test_same_remark_same_link_type_is_not_a_conflict():
    first = _build_section(LINKTYPE_ETHERNET, EGRESS_REMARK, _ethernet_packet())
    second = _build_section(LINKTYPE_ETHERNET, EGRESS_REMARK, _ethernet_packet())
    records = collect_interfaces(FileScanner(_write_sections([first, second])))

    assert find_remark_conflicts(records) == []


def test_unknown_link_type_only_reports_known_facts():
    unknown_value = 0xFF01
    assert link_type_name(unknown_value) is None

    observed = observe_prefix(unknown_value, b"\x01\x02\x03\x04" + b"some-bytes")
    assert observed["rule"] is None
    assert observed["complete"] is False
    # Only the raw leading bytes are exposed; no structure is invented.
    assert observed["raw_hex"].startswith("0x01020304")

    shb = SectionHeader()
    shb.new_member(
        InterfaceDescription,
        link_type=unknown_value,
        snaplen=0,
        options={"if_description": EGRESS_REMARK},
    )
    epb = shb.new_member(EnhancedPacket)
    epb.packet_data = b"\x01\x02\x03\x04" + b"payload"
    stream = _write_sections([(shb, [epb.packet_data])])

    records = collect_interfaces(FileScanner(stream))
    assert len(records) == 1
    record = records[0]
    assert record.link_type == unknown_value
    assert record.link_type_known is False
    assert record.prefixes[0]["rule"] is None


def test_truncated_packet_does_not_manufacture_a_prefix():
    short_eth = b"\x00\x1b\x44\x11"
    observed = observe_prefix(LINKTYPE_ETHERNET, short_eth)
    assert observed["rule"] is None
    assert observed["complete"] is False
    assert observed["raw_hex"] == "0x001b4411"


def test_checklist_detects_mismatch_and_accepts_match():
    records = collect_interfaces(FileScanner(_two_probe_stream()))

    checklist = {
        "section 0 / interface 0": LINKTYPE_ETHERNET,
        "section 1 / interface 0": LINKTYPE_ETHERNET,
    }
    mismatches = check_handoff(records, checklist)
    assert len(mismatches) == 1
    assert mismatches[0]["record"].label == "section 1 / interface 0"
    assert mismatches[0]["expected"] == LINKTYPE_ETHERNET

    matching = {
        "section 0 / interface 0": LINKTYPE_ETHERNET,
        "section 1 / interface 0": LINKTYPE_LINUX_SLL,
    }
    assert check_handoff(records, matching) == []


def test_load_checklist_ignores_entries_without_link_type():
    text = "\n".join(
        [
            "[section 0 / interface 0]",
            "link_type = 1",
            "[section 1 / interface 0]",
            "note = no link type promised",
        ]
    ) + "\n"
    checklist = load_checklist(io.StringIO(text))
    assert checklist == {"section 0 / interface 0": 1}


def test_simple_packet_is_attributed_to_section_interface_zero():
    # SPBs carry no interface id and always belong to interface 0.
    shb = SectionHeader()
    shb.new_member(
        InterfaceDescription,
        link_type=LINKTYPE_ETHERNET,
        snaplen=65535,
        options={"if_description": EGRESS_REMARK},
    )
    packet = (
        b"\x00\x1b\x44\x11\x22\x33"
        + b"\x00\x1b\x44\xaa\xbb\xcc"
        + b"\x08\x00"
        + b"\x00" * 20
    )
    stream = io.BytesIO()
    writer = FileWriter(stream, shb)
    spb = shb.new_member(SimplePacket)
    spb.packet_data = packet
    writer.write_block(spb)
    stream.seek(0)

    records = collect_interfaces(FileScanner(stream))
    assert len(records) == 1
    assert records[0].label == "section 0 / interface 0"
    assert records[0].packet_count == 1
    assert records[0].prefixes[0]["rule"] == "Ethernet frame header"


def test_generated_sample_file_round_trips():
    # The checked-in sample is the spliced two-probe capture described in
    # examples/generate_handoff_sample.py.
    with open("test_data/two_probe_egress.ntar", "rb") as stream:
        records = collect_interfaces(FileScanner(stream))

    assert len(records) == 2
    assert [record.remark for record in records] == [EGRESS_REMARK, EGRESS_REMARK]
    assert [record.link_type for record in records] == [
        LINKTYPE_ETHERNET,
        LINKTYPE_LINUX_SLL,
    ]
    conflict = find_remark_conflicts(records)
    assert len(conflict) == 1
    assert [r.label for r in conflict[0]["interfaces"]] == [
        "section 0 / interface 0",
        "section 1 / interface 0",
    ]
