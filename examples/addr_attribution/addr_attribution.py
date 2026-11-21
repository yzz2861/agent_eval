"""Attribute IP addresses to devices across isolated broadcast domains.

Scenario: after a datacenter migration the same address may briefly be used
by different devices in two isolated broadcast domains.  This tool reads
offline pcap files (one per mirror / broadcast domain) with dpkt, joins the
device inventory and maintenance windows provided by the evidence custodian,
and constrains address ownership using only visible layer-2 relationships.

Rules implemented:

* Confirmation needs response-side evidence.  A mirror sees less traffic
  than the original interface, so absence of traffic proves nothing, and an
  address that is only ever *requested* (ARP who-has target, IP destination)
  is NOT confirmed to belong to anyone.
* Confirmed ownership comes from the address speaking for itself: ARP
  is-at replies and IP packets sourced from the address, both tied to the
  sender MAC.
* If an address has valid observations in both domains, the report keeps
  both sides.
* If one side (domain) shows the address confirmed by more than one MAC,
  that side is reported as a conflict and located by packet sequence
  numbers (1-based frame numbers inside that domain's pcap).
"""

import argparse
import csv
import json
import socket
import sys
from collections import defaultdict
from datetime import datetime

import dpkt


def mac_to_str(mac):
    return ':'.join('%02x' % b for b in mac)


def ip_to_str(ip):
    return socket.inet_ntoa(ip)


def parse_time(value):
    """Accept epoch seconds or ISO 8601 timestamps."""
    value = value.strip()
    try:
        return float(value)
    except ValueError:
        pass
    return datetime.fromisoformat(value).timestamp()


class Evidence(object):
    """One visible layer-2 fact about an address, tied to a frame number."""

    __slots__ = ('frame_no', 'ts', 'kind', 'ip', 'mac')

    def __init__(self, frame_no, ts, kind, ip, mac):
        self.frame_no = frame_no
        self.ts = ts
        self.kind = kind
        self.ip = ip
        self.mac = mac


def iter_evidence(path):
    """Yield Evidence for every ARP / IPv4 frame in an offline pcap.

    Kinds:
      arp_reply   - ARP is-at: sender claims (spa -> sha); confirms ownership
      ip_src      - IPv4 packet sourced from the address; confirms ownership
      arp_request - ARP who-has target; interest only, never confirmation
      ip_dst      - IPv4 packet destined to the address; interest only
    """
    with open(path, 'rb') as fh:
        reader = dpkt.pcap.Reader(fh)
        for frame_no, (ts, buf) in enumerate(reader, start=1):
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
            payload = eth.data
            if isinstance(payload, dpkt.arp.ARP):
                spa = ip_to_str(payload.spa)
                tpa = ip_to_str(payload.tpa)
                sha = mac_to_str(payload.sha)
                if payload.op == dpkt.arp.ARP_OP_REPLY:
                    yield Evidence(frame_no, ts, 'arp_reply', spa, sha)
                elif payload.op == dpkt.arp.ARP_OP_REQUEST:
                    yield Evidence(frame_no, ts, 'arp_request', tpa, sha)
            elif isinstance(payload, dpkt.ip.IP):
                src = ip_to_str(payload.src)
                dst = ip_to_str(payload.dst)
                eth_src = mac_to_str(eth.src)
                yield Evidence(frame_no, ts, 'ip_src', src, eth_src)
                yield Evidence(frame_no, ts, 'ip_dst', dst, eth_src)


CONFIRM_KINDS = ('arp_reply', 'ip_src')
INTEREST_KINDS = ('arp_request', 'ip_dst')


def load_devices(path):
    """Custodian device inventory: device_id,mac,ip (ip may be blank)."""
    devices = {}
    with open(path, newline='') as fh:
        for row in csv.DictReader(fh):
            mac = row['mac'].strip().lower()
            devices[mac] = {
                'device_id': row['device_id'].strip(),
                'ip': (row.get('ip') or '').strip(),
            }
    return devices


def load_maintenance(path):
    """Custodian maintenance windows: device_id,start,end."""
    windows = []
    if not path:
        return windows
    with open(path, newline='') as fh:
        for row in csv.DictReader(fh):
            windows.append({
                'device_id': row['device_id'].strip(),
                'start': parse_time(row['start']),
                'end': parse_time(row['end']),
            })
    return windows


def in_maintenance(device_id, ts, windows):
    return any(w['device_id'] == device_id and w['start'] <= ts <= w['end']
               for w in windows)


def _summarize_owner(mac, evidences, devices, windows):
    device = devices.get(mac)
    device_id = device['device_id'] if device else None
    frames = [e.frame_no for e in evidences]
    return {
        'mac': mac,
        'device_id': device_id or 'unknown',
        'frames': frames,
        'first_frame': frames[0],
        'last_frame': frames[-1],
        'first_seen': evidences[0].ts,
        'last_seen': evidences[-1].ts,
        'evidence_kinds': sorted({e.kind for e in evidences}),
        'in_maintenance': bool(device_id) and any(
            in_maintenance(device_id, e.ts, windows) for e in evidences),
    }


def analyze(pcaps, devices, windows):
    """Build the attribution report.

    pcaps: {domain_name: pcap_path}
    devices: output of load_devices
    windows: output of load_maintenance
    """
    # address -> domain -> {'confirm': {mac: [Evidence]}, 'interest': [...]}
    observations = defaultdict(
        lambda: defaultdict(lambda: {'confirm': defaultdict(list),
                                     'interest': []}))
    for domain, path in pcaps.items():
        for ev in iter_evidence(path):
            slot = observations[ev.ip][domain]
            if ev.kind in CONFIRM_KINDS:
                slot['confirm'][ev.mac].append(ev)
            else:
                slot['interest'].append(ev)

    report = {'domains': sorted(pcaps), 'addresses': {}}
    for ip in sorted(observations, key=socket.inet_aton):
        domains_seen = observations[ip]
        entry = {'domains': {}, 'status': 'unconfirmed', 'conflicts': []}
        confirmed_domains = []
        for domain in sorted(domains_seen):
            slot = domains_seen[domain]
            owners = []
            for mac in sorted(slot['confirm']):
                owners.append(_summarize_owner(
                    mac, slot['confirm'][mac], devices, windows))
            interest_frames = sorted(e.frame_no for e in slot['interest'])
            domain_entry = {'confirmed_owners': owners}
            if interest_frames:
                domain_entry['requests_only'] = {
                    'frames': interest_frames,
                    'note': 'requests seen by the monitor are not '
                            'ownership confirmation',
                }
            entry['domains'][domain] = domain_entry
            if owners:
                confirmed_domains.append(domain)
                if len(owners) > 1:
                    entry['conflicts'].append({
                        'domain': domain,
                        'owners': [o['mac'] for o in owners],
                        'frames': {o['mac']: o['frames'] for o in owners},
                        'during_maintenance': any(o['in_maintenance']
                                                  for o in owners),
                    })
        if entry['conflicts']:
            entry['status'] = 'conflict'
        elif len(confirmed_domains) > 1:
            entry['status'] = 'both_domains'
        elif confirmed_domains:
            entry['status'] = 'confirmed'
        entry['confirmed_domains'] = confirmed_domains
        report['addresses'][ip] = entry
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Attribute addresses to devices across isolated '
                    'broadcast domains using offline pcaps.')
    parser.add_argument('--pcap', action='append', required=True,
                        metavar='DOMAIN=PATH',
                        help='offline pcap for one broadcast domain '
                             '(repeatable)')
    parser.add_argument('--devices', required=True,
                        help='custodian CSV: device_id,mac,ip')
    parser.add_argument('--maintenance',
                        help='custodian CSV: device_id,start,end')
    parser.add_argument('-o', '--output', help='write JSON report here '
                                               '(default: stdout)')
    args = parser.parse_args(argv)

    pcaps = {}
    for spec in args.pcap:
        domain, _, path = spec.partition('=')
        if not path:
            parser.error('--pcap expects DOMAIN=PATH, got %r' % spec)
        pcaps[domain] = path

    report = analyze(pcaps, load_devices(args.devices),
                     load_maintenance(args.maintenance))
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, 'w') as fh:
            fh.write(text + '\n')
    else:
        sys.stdout.write(text + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
