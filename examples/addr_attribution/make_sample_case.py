"""Generate a sample migration case: two domain pcaps plus custodian CSVs.

Layout produced under the output directory:
  domain-a.pcap    mirror of the old-site broadcast domain
  domain-b.pcap    mirror of the new-site broadcast domain
  devices.csv      custodian device inventory
  maintenance.csv  custodian maintenance windows

The case embeds all four report situations:
  10.0.0.5   confirmed in BOTH domains (SRV-01 old, SRV-02 new, the
             new-side observation falls inside SRV-02's maintenance window)
  10.0.0.9   conflict inside domain-a only (CLI-07 and ROGUE-13 both
             confirm it); located by packet sequence numbers
  10.0.0.7   only ARP who-has requests seen on the domain-b mirror;
             reported as requests-only, never an ownership confirmation
"""

import os
import socket
import sys

import dpkt

TS0 = 1700000000.0  # 2023-11-14T22:13:20Z

MAC_SRV01 = '02:00:00:00:01:01'
MAC_SRV02 = '02:00:00:00:02:02'
MAC_CLI07 = '02:00:00:00:07:07'
MAC_ROGUE = '02:00:00:00:13:13'
MAC_CLIENT = '02:00:00:00:99:99'

DEVICES_CSV = (
    'device_id,mac,ip\n'
    'SRV-01,%s,10.0.0.5\n'
    'SRV-02,%s,10.0.0.5\n'
    'CLI-07,%s,10.0.0.9\n'
    'ROGUE-13,%s,\n'
    'MON-99,%s,\n'
) % (MAC_SRV01, MAC_SRV02, MAC_CLI07, MAC_ROGUE, MAC_CLIENT)

MAINTENANCE_CSV = (
    'device_id,start,end\n'
    'SRV-02,%s,%s\n'
) % (TS0 + 100, TS0 + 200)


def _mac(text):
    return bytes(int(part, 16) for part in text.split(':'))


def arp_reply(src_mac, src_ip, dst_ip):
    arp = dpkt.arp.ARP(
        op=dpkt.arp.ARP_OP_REPLY,
        sha=_mac(src_mac), spa=socket.inet_aton(src_ip),
        tha=b'\x00' * 6, tpa=socket.inet_aton(dst_ip))
    return dpkt.ethernet.Ethernet(
        src=_mac(src_mac), dst=b'\xff' * 6, data=arp)


def arp_request(src_mac, target_ip, src_ip='0.0.0.0'):
    arp = dpkt.arp.ARP(
        op=dpkt.arp.ARP_OP_REQUEST,
        sha=_mac(src_mac), spa=socket.inet_aton(src_ip),
        tha=b'\x00' * 6, tpa=socket.inet_aton(target_ip))
    return dpkt.ethernet.Ethernet(
        src=_mac(src_mac), dst=b'\xff' * 6, data=arp)


def ip_packet(src_mac, src_ip, dst_ip):
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip), dst=socket.inet_aton(dst_ip),
        p=dpkt.ip.IP_PROTO_ICMP,
        data=dpkt.icmp.ICMP(type=dpkt.icmp.ICMP_ECHO,
                            data=dpkt.icmp.ICMP.Echo(id=1, seq=1,
                                                     data=b'ping')))
    return dpkt.ethernet.Ethernet(
        src=_mac(src_mac), dst=b'\xff' * 6, data=ip)


def write_pcap(path, frames):
    with open(path, 'wb') as fh:
        writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        for ts, pkt in frames:
            writer.writepkt(pkt, ts=ts)


def build(outdir):
    os.makedirs(outdir, exist_ok=True)

    domain_a = [
        # 10.0.0.5 confirmed by SRV-01 on the old site.
        (TS0 + 1, arp_reply(MAC_SRV01, '10.0.0.5', '10.0.0.1')),
        (TS0 + 2, ip_packet(MAC_SRV01, '10.0.0.5', '10.0.0.1')),
        # 10.0.0.9 conflict on this side: CLI-07 then ROGUE-13.
        (TS0 + 3, arp_reply(MAC_CLI07, '10.0.0.9', '10.0.0.1')),
        (TS0 + 4, ip_packet(MAC_CLI07, '10.0.0.9', '10.0.0.1')),
        (TS0 + 5, arp_reply(MAC_ROGUE, '10.0.0.9', '10.0.0.1')),
        (TS0 + 6, ip_packet(MAC_ROGUE, '10.0.0.9', '10.0.0.1')),
    ]
    domain_b = [
        # A monitor request for 10.0.0.7: interest only, no owner.
        (TS0 + 110, arp_request(MAC_CLIENT, '10.0.0.7')),
        (TS0 + 111, arp_request(MAC_CLIENT, '10.0.0.7')),
        # 10.0.0.5 confirmed by SRV-02 inside its maintenance window.
        (TS0 + 120, arp_reply(MAC_SRV02, '10.0.0.5', '10.0.2.1')),
        (TS0 + 121, ip_packet(MAC_SRV02, '10.0.0.5', '10.0.2.1')),
    ]

    write_pcap(os.path.join(outdir, 'domain-a.pcap'), domain_a)
    write_pcap(os.path.join(outdir, 'domain-b.pcap'), domain_b)
    with open(os.path.join(outdir, 'devices.csv'), 'w') as fh:
        fh.write(DEVICES_CSV)
    with open(os.path.join(outdir, 'maintenance.csv'), 'w') as fh:
        fh.write(MAINTENANCE_CSV)
    return outdir


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'sample_case'
    build(target)
    print('sample case written to %s' % target)
