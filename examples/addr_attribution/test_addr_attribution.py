import os

import pytest

import addr_attribution as aa
import make_sample_case as case


@pytest.fixture
def report(tmp_path):
    outdir = str(tmp_path / 'case')
    case.build(outdir)
    pcaps = {
        'domain-a': os.path.join(outdir, 'domain-a.pcap'),
        'domain-b': os.path.join(outdir, 'domain-b.pcap'),
    }
    devices = aa.load_devices(os.path.join(outdir, 'devices.csv'))
    windows = aa.load_maintenance(os.path.join(outdir, 'maintenance.csv'))
    return aa.analyze(pcaps, devices, windows)


def test_both_domains_kept(report):
    entry = report['addresses']['10.0.0.5']
    assert entry['status'] == 'both_domains'
    assert entry['confirmed_domains'] == ['domain-a', 'domain-b']
    owner_a = entry['domains']['domain-a']['confirmed_owners'][0]
    owner_b = entry['domains']['domain-b']['confirmed_owners'][0]
    assert owner_a['device_id'] == 'SRV-01'
    assert owner_b['device_id'] == 'SRV-02'
    assert owner_a['frames'] == [1, 2]
    assert owner_b['frames'] == [3, 4]


def test_maintenance_window_annotated(report):
    owner_b = report['addresses']['10.0.0.5']['domains']['domain-b'][
        'confirmed_owners'][0]
    assert owner_b['in_maintenance'] is True
    owner_a = report['addresses']['10.0.0.5']['domains']['domain-a'][
        'confirmed_owners'][0]
    assert owner_a['in_maintenance'] is False


def test_one_sided_conflict_located_by_frame_numbers(report):
    entry = report['addresses']['10.0.0.9']
    assert entry['status'] == 'conflict'
    assert len(entry['conflicts']) == 1
    conflict = entry['conflicts'][0]
    assert conflict['domain'] == 'domain-a'
    assert conflict['frames'][case.MAC_CLI07] == [3, 4]
    assert conflict['frames'][case.MAC_ROGUE] == [5, 6]
    assert 'domain-b' not in entry['domains']


def test_requests_only_is_not_confirmation(report):
    entry = report['addresses']['10.0.0.7']
    assert entry['status'] == 'unconfirmed'
    assert entry['confirmed_domains'] == []
    domain_b = entry['domains']['domain-b']
    assert domain_b['confirmed_owners'] == []
    assert domain_b['requests_only']['frames'] == [1, 2]


def test_unknown_device_marked(report):
    entry = report['addresses']['10.0.0.9']
    owners = {o['mac']: o['device_id']
              for o in entry['domains']['domain-a']['confirmed_owners']}
    assert owners[case.MAC_CLI07] == 'CLI-07'
    assert owners[case.MAC_ROGUE] == 'ROGUE-13'


def test_cli(tmp_path, capsys):
    outdir = str(tmp_path / 'case')
    case.build(outdir)
    rc = aa.main([
        '--pcap', 'domain-a=%s' % os.path.join(outdir, 'domain-a.pcap'),
        '--pcap', 'domain-b=%s' % os.path.join(outdir, 'domain-b.pcap'),
        '--devices', os.path.join(outdir, 'devices.csv'),
        '--maintenance', os.path.join(outdir, 'maintenance.csv'),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"10.0.0.5"' in out
    assert '"both_domains"' in out
