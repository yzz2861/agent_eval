#!/usr/bin/env python
"""
Generate the spliced two-probe pcapng sample used by the handoff audit
tests and documentation.

Both probes wrote the same human remark ("出口" / egress) into their
Interface Description Block, but they captured on different link layers:

* section 0, interface 0: LINKTYPE_ETHERNET (1), plain Ethernet frames;
* section 1, interface 0: LINKTYPE_LINUX_SLL (113), Linux cooked capture,
  i.e. a 16-byte cooked header instead of an Ethernet header.

The resulting file is a byte-level concatenation of the two sections,
matching how the headquarters received the merged capture.
"""

from __future__ import print_function

import sys

from pcapng import FileWriter
from pcapng.blocks import EnhancedPacket, InterfaceDescription, SectionHeader
from pcapng.constants.link_types import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL

EGRESS_REMARK = "出口"


def _ethernet_packet():
    dst = b"\x00\x1b\x44\x11\x22\x33"
    src = b"\x00\x1b\x44\xaa\xbb\xcc"
    ethertype = b"\x08\x00"
    payload = b"\x45" + b"\x00" * 45
    return dst + src + ethertype + payload


def _linux_sll_packet():
    packet_type = b"\x00\x00"
    arphrd = b"\x00\x01"
    address_length = b"\x00\x06"
    # The address field is always 8 bytes, zero-padded to the address length.
    address = b"\x00\x1b\x44\xaa\xbb\xcc" + b"\x00\x00"
    protocol = b"\x08\x00"  # at offset 14, after the 8-byte address
    payload = b"\x45" + b"\x00" * 45
    return packet_type + arphrd + address_length + address + protocol + payload


def build_ethernet_section():
    shb = SectionHeader(
        options={
            "shb_hardware": "probe-a",
            "shb_userappl": "generate_handoff_sample.py",
        }
    )
    shb.new_member(
        InterfaceDescription,
        link_type=LINKTYPE_ETHERNET,
        snaplen=65535,
        options={"if_name": "eth0", "if_description": EGRESS_REMARK},
    )
    return shb, [_ethernet_packet(), _ethernet_packet()]


def build_sll_section():
    shb = SectionHeader(
        options={
            "shb_hardware": "probe-b",
            "shb_userappl": "generate_handoff_sample.py",
        }
    )
    shb.new_member(
        InterfaceDescription,
        link_type=LINKTYPE_LINUX_SLL,
        snaplen=65535,
        options={"if_name": "any", "if_description": EGRESS_REMARK},
    )
    return shb, [_linux_sll_packet(), _linux_sll_packet()]


def write_section(stream, shb, packets):
    writer = FileWriter(stream, shb)
    for packet in packets:
        epb = shb.new_member(EnhancedPacket)
        epb.packet_data = packet
        writer.write_block(epb)


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("usage: generate_handoff_sample.py OUTPUT.pcapng", file=sys.stderr)
        return 2

    output_path = argv[0]
    with open(output_path, "wb") as stream:
        shb, packets = build_ethernet_section()
        write_section(stream, shb, packets)
        shb, packets = build_sll_section()
        write_section(stream, shb, packets)

    print("wrote {0}".format(output_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
