"""
Offline cross-checking of probe handoff checklists against pcapng files.

The pcapng files inspected here may be concatenations of several sections,
each produced by a different probe.  Interface ids are only meaningful
*within* their own section, so every interface in the report is identified
by its ``(section index, interface id)`` pair rather than by the raw id.

Only facts that can be read directly from the blocks are reported:

* the link type declared in each Interface Description Block;
* a small set of well-known packet prefixes observable in the captured
  packets.

Link types the library does not know about, and link types whose packet
prefix we do not have rules for, are reported conservatively -- we never
guess the meaning of an unfamiliar header.
"""

from collections import OrderedDict

from pcapng.blocks import (
    EnhancedPacket,
    InterfaceDescription,
    SectionHeader,
    SimplePacket,
)
from pcapng.constants import link_types


# First bytes that can be observed in packet data for a handful of well
# understood link types.  Each entry maps a link type to the expected
# fixed-size prefix; anything not listed here is left untouched and reported
# as raw bytes only.
#
# The rules intentionally cover only link layers whose prefix format is
# stable and documented on https://www.tcpdump.org/linktypes.html.
PREFIX_RULES = OrderedDict(
    [
        (
            link_types.LINKTYPE_ETHERNET,
            {
                "name": "Ethernet frame header",
                "min_length": 14,
            },
        ),
        (
            link_types.LINKTYPE_NULL,
            {
                "name": "BSD null/loopback address family (4 bytes)",
                "min_length": 4,
            },
        ),
        (
            link_types.LINKTYPE_LOOP,
            {
                "name": "OpenBSD loopback address family (4 bytes)",
                "min_length": 4,
            },
        ),
        (
            link_types.LINKTYPE_RAW,
            {
                "name": "raw IP packet",
                "min_length": 1,
            },
        ),
        (
            link_types.LINKTYPE_LINUX_SLL,
            {
                "name": "Linux cooked capture header (16 bytes)",
                "min_length": 16,
            },
        ),
    ]
)

# Ethernet ethertypes worth naming in a report.  Only the two IP variants
# are needed to corroborate an "IP over Ethernet" capture condition.
_ETHERTYPE_NAMES = {
    0x0800: "IPv4",
    0x86DD: "IPv6",
}

# Address family values used by the NULL / LOOP loopback link types.
# Values differ between host byte order variants, so both are listed.
_AF_INET_VALUES = {2, 0x02000000}  # host order / byte-swapped AF_INET
_AF_INET6_VALUES = {24, 28, 0x18000000, 0x1C000000}


def link_type_name(link_type):
    """
    Return the registered description for a link type, or ``None`` if the
    value is not one the library knows about.
    """
    try:
        return link_types.LINKTYPE_DESCRIPTIONS[link_type]
    except KeyError:
        return None


def _clean_option(value):
    """Strip the trailing NUL some capture tools append to string options."""
    if isinstance(value, str):
        return value.rstrip("\x00")
    return value


def _interface_remark(idb):
    """
    The human-facing interface note is taken from ``if_description``,
    falling back to ``if_name`` when no description is present.
    """
    options = idb.options
    for key in ("if_description", "if_name"):
        try:
            return _clean_option(options[key])
        except KeyError:
            continue
    return None


def _format_mac(data):
    return ":".join("{0:02x}".format(b) for b in data)


def _format_hex(data):
    return "0x" + "".join("{0:02x}".format(b) for b in data)


def observe_prefix(link_type, packet_data):
    """
    Inspect the first bytes of a captured packet.

    Returns a dict describing the observable prefix when the link type has
    a known, stable header format.  For unfamiliar link types or truncated
    packets a dict carrying only the raw leading bytes is returned, so the
    caller never fabricates structure that is not actually known.
    """
    observed = {
        "raw_hex": _format_hex(packet_data[:16]),
        "length": len(packet_data),
        "rule": None,
        "fields": OrderedDict(),
        "complete": False,
    }

    rule = PREFIX_RULES.get(link_type)
    if rule is None or len(packet_data) < rule["min_length"]:
        return observed

    observed["rule"] = rule["name"]
    observed["complete"] = True

    if link_type == link_types.LINKTYPE_ETHERNET:
        observed["fields"]["destination_mac"] = _format_mac(packet_data[0:6])
        observed["fields"]["source_mac"] = _format_mac(packet_data[6:12])
        ethertype = int.from_bytes(packet_data[12:14], "big")
        observed["fields"]["ethertype"] = "0x{0:04x}".format(ethertype)
        observed["fields"]["ethertype_name"] = _ETHERTYPE_NAMES.get(
            ethertype, "unknown"
        )

    elif link_type in (link_types.LINKTYPE_NULL, link_types.LINKTYPE_LOOP):
        # The 4-byte family value is stored in the capture host's byte
        # order; record the raw value plus the most common interpretation.
        family_le = int.from_bytes(packet_data[0:4], "little")
        family_be = int.from_bytes(packet_data[0:4], "big")
        observed["fields"]["value_le"] = family_le
        observed["fields"]["value_be"] = family_be
        if family_le in _AF_INET_VALUES or family_be in _AF_INET_VALUES:
            observed["fields"]["interpretation"] = "IPv4"
        elif family_le in _AF_INET6_VALUES or family_be in _AF_INET6_VALUES:
            observed["fields"]["interpretation"] = "IPv6"
        else:
            observed["fields"]["interpretation"] = "unknown address family"

    elif link_type == link_types.LINKTYPE_RAW:
        observed["fields"]["ip_version_nibble"] = packet_data[0] >> 4

    elif link_type == link_types.LINKTYPE_LINUX_SLL:
        observed["fields"]["packet_type"] = int.from_bytes(
            packet_data[0:2], "big"
        )
        observed["fields"]["arphrd_type"] = int.from_bytes(
            packet_data[2:4], "big"
        )
        observed["fields"]["address_length"] = int.from_bytes(
            packet_data[4:6], "big"
        )
        observed["fields"]["address"] = _format_hex(packet_data[6:14])
        protocol = int.from_bytes(packet_data[14:16], "big")
        observed["fields"]["protocol"] = "0x{0:04x}".format(protocol)
        observed["fields"]["protocol_name"] = _ETHERTYPE_NAMES.get(
            protocol, "unknown"
        )

    return observed


class InterfaceRecord(object):
    """Everything that can be observed about one interface in a section."""

    __slots__ = (
        "section_index",
        "interface_id",
        "remark",
        "link_type",
        "link_type_name",
        "snaplen",
        "packet_count",
        "prefixes",
    )

    def __init__(self, section_index, interface_id, idb):
        self.section_index = section_index
        self.interface_id = interface_id
        self.remark = _interface_remark(idb)
        self.link_type = idb.link_type
        self.link_type_name = link_type_name(idb.link_type)
        self.snaplen = idb.snaplen
        self.packet_count = 0
        self.prefixes = []

    @property
    def label(self):
        """Stable identity of an interface inside the concatenated file."""
        return "section {0} / interface {1}".format(
            self.section_index, self.interface_id
        )

    @property
    def link_type_known(self):
        return self.link_type_name is not None

    def add_packet(self, packet_data):
        self.packet_count += 1
        if len(self.prefixes) < 3:
            self.prefixes.append(
                observe_prefix(self.link_type, packet_data)
            )


def collect_interfaces(scanner):
    """
    Walk a :class:`~pcapng.scanner.FileScanner` and return one
    :class:`InterfaceRecord` per Interface Description Block, keeping each
    section's interface numbering independent.
    """
    records = []
    section_index = -1

    for block in scanner:
        if isinstance(block, SectionHeader):
            section_index += 1
            continue

        if isinstance(block, InterfaceDescription):
            records.append(
                InterfaceRecord(section_index, block.interface_id, block)
            )

        elif isinstance(block, (EnhancedPacket, SimplePacket)):
            record = _find_record(
                records, section_index, block.interface_id
            )
            if record is not None:
                record.add_packet(bytes(block.packet_data))

    return records


def _find_record(records, section_index, interface_id):
    for record in records:
        if (
            record.section_index == section_index
            and record.interface_id == interface_id
        ):
            return record
    return None


def find_remark_conflicts(records):
    """
    Group interfaces sharing the same human-facing remark and flag the
    groups whose declared link types do not agree.

    Returns a list of dicts, one per conflicting remark, naming every
    original interface involved.
    """
    groups = OrderedDict()
    for record in records:
        if record.remark is None:
            continue
        groups.setdefault(record.remark, []).append(record)

    conflicts = []
    for remark, members in groups.items():
        link_types_seen = {member.link_type for member in members}
        if len(members) > 1 and len(link_types_seen) > 1:
            conflicts.append(
                {
                    "remark": remark,
                    "interfaces": list(members),
                    "link_types": sorted(link_types_seen),
                }
            )
    return conflicts


def check_handoff(records, checklist):
    """
    Compare the observed interfaces against a handoff checklist.

    ``checklist`` maps the interface label (``"section N / interface M"``)
    to the link type the receiving side was promised, as an integer.  The
    returned list contains one mismatch entry per interface whose declared
    link type differs from the checklist; interfaces absent from the
    checklist (or listed with an unknown value) are left alone.
    """
    mismatches = []
    for record in records:
        if record.label not in checklist:
            continue
        expected = checklist[record.label]
        if not isinstance(expected, int):
            continue
        if expected != record.link_type:
            mismatches.append(
                {
                    "record": record,
                    "expected": expected,
                    "expected_name": link_type_name(expected),
                }
            )
    return mismatches


def load_checklist(stream):
    """
    Load a handoff checklist from an ini-like text stream.

    Expected layout, one line per interface::

        [section 0 / interface 0]
        link_type = 1

    Unknown sections / keys are ignored, so an unfamiliar probe entry never
    causes the audit itself to fail.
    """
    import configparser

    parser = configparser.ConfigParser()
    parser.read_file(stream)
    checklist = {}
    for label in parser.sections():
        try:
            value = parser.getint(label, "link_type")
        except (configparser.NoOptionError, ValueError):
            continue
        checklist[label.strip()] = value
    return checklist
