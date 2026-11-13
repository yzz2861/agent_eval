import os
import struct
import pytest

from ssh_audit.auditconf import AuditConf
from ssh_audit.banner import Banner
from ssh_audit.evidence import EvidenceModel
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.protocol import Protocol
from ssh_audit.readbuf import ReadBuf
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexparty import SSH2_KexParty
from ssh_audit.ssh_audit import audit
from ssh_audit.writebuf import WriteBuf


# pylint: disable=line-too-long,attribute-defined-outside-init
class TestSSH2:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.OutputBuffer = OutputBuffer
        self.protocol = Protocol
        self.ssh2_kex = SSH2_Kex
        self.ssh2_kexparty = SSH2_KexParty
        self.rbuf = ReadBuf
        self.wbuf = WriteBuf
        self.audit = audit
        self.AuditConf = AuditConf

    def _conf(self):
        conf = self.AuditConf('localhost', 22)
        conf.colors = False
        conf.batch = True
        conf.verbose = True
        conf.ssh1 = False
        conf.ssh2 = True
        conf.skip_rate_test = True
        return conf

    @classmethod
    def _create_ssh2_packet(cls, payload):
        padding = -(len(payload) + 5) % 8
        if padding < 4:
            padding += 8
        plen = len(payload) + padding + 1
        pad_bytes = b'\x00' * padding
        data = struct.pack('>Ib', plen, padding) + payload + pad_bytes
        return data

    def _kex_payload(self):
        w = self.wbuf()
        w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        w.write_list(['bogus_kex1', 'bogus_kex2'])  # We use a bogus kex, otherwise the host key tests will kick off and fail.
        w.write_list(['ssh-rsa', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'])
        w.write_list(['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc'])
        w.write_list(['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc'])
        w.write_list(['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'])
        w.write_list(['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'])
        w.write_list(['none', 'zlib@openssh.com'])
        w.write_list(['none', 'zlib@openssh.com'])
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        return w.write_flush()

    def _kex_payload_with_gss(self):
        w = self.wbuf()
        w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        w.write_list(['gss-gex-sha1-dZuIebMjgUqaxvbF7hDbAw==', 'gss-gex-sha1-vz8J1E9PzLr8b1K+0remTg==', 'gss-group14-sha1-dZuIebMjgUqaxvbF7hDbAw==', 'gss-group14-sha1-vz8J1E9PzLr8b1K+0remTg==', 'gss-group14-sha256-dZuIebMjgUqaxvbF7hDbAw==', 'gss-group14-sha256-vz8J1E9PzLr8b1K+0remTg==', 'gss-group16-sha512-dZuIebMjgUqaxvbF7hDbAw==', 'gss-group16-sha512-vz8J1E9PzLr8b1K+0remTg==', 'gss-group18-sha512-dZuIebMjgUqaxvbF7hDbAw==', 'gss-group18-sha512-vz8J1E9PzLr8b1K+0remTg==', 'gss-group1-sha1-dZuIebMjgUqaxvbF7hDbAw==', 'gss-group1-sha1-vz8J1E9PzLr8b1K+0remTg==', 'gss-curve448-sha512-XXX', 'gss-nistp256-sha256-RANDOMCHARSTOTESTWILDCARDMATCHING'])
        w.write_list(['ssh-ed25519'])
        w.write_list(['chacha20-poly1305@openssh.com'])
        w.write_list(['chacha20-poly1305@openssh.com'])
        w.write_list(['hmac-sha2-512-etm@openssh.com'])
        w.write_list(['hmac-sha2-512-etm@openssh.com'])
        w.write_list(['none', 'zlib@openssh.com'])
        w.write_list(['none', 'zlib@openssh.com'])
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        return w.write_flush()

    def test_kex_read(self):
        kex = self.ssh2_kex.parse(self.OutputBuffer, self._kex_payload())
        assert kex is not None
        assert kex.cookie == b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        assert kex.kex_algorithms == ['bogus_kex1', 'bogus_kex2']
        assert kex.key_algorithms == ['ssh-rsa', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519']
        assert kex.client is not None
        assert kex.server is not None
        assert kex.client.encryption == ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc']
        assert kex.server.encryption == ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc']
        assert kex.client.mac == ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1']
        assert kex.server.mac == ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1']
        assert kex.client.compression == ['none', 'zlib@openssh.com']
        assert kex.server.compression == ['none', 'zlib@openssh.com']
        assert kex.client.languages == ['']
        assert kex.server.languages == ['']
        assert kex.follows is False
        assert kex.unused == 0

    def _get_empty_kex(self, cookie=None):
        kex_algs, key_algs = [], []
        enc, mac, compression, languages = [], [], ['none'], []
        cli = self.ssh2_kexparty(enc, mac, compression, languages)
        enc, mac, compression, languages = [], [], ['none'], []
        srv = self.ssh2_kexparty(enc, mac, compression, languages)
        if cookie is None:
            cookie = os.urandom(16)
        kex = self.ssh2_kex(self.OutputBuffer, cookie, kex_algs, key_algs, cli, srv, 0)
        return kex

    def _get_kex_variat1(self):
        cookie = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        kex = self._get_empty_kex(cookie)
        kex.kex_algorithms.append('bogus_kex1')
        kex.kex_algorithms.append('bogus_kex2')
        kex.key_algorithms.append('ssh-rsa')
        kex.key_algorithms.append('rsa-sha2-512')
        kex.key_algorithms.append('rsa-sha2-256')
        kex.key_algorithms.append('ssh-ed25519')
        kex.server.encryption.append('chacha20-poly1305@openssh.com')
        kex.server.encryption.append('aes128-ctr')
        kex.server.encryption.append('aes192-ctr')
        kex.server.encryption.append('aes256-ctr')
        kex.server.encryption.append('aes128-gcm@openssh.com')
        kex.server.encryption.append('aes256-gcm@openssh.com')
        kex.server.encryption.append('aes128-cbc')
        kex.server.encryption.append('aes192-cbc')
        kex.server.encryption.append('aes256-cbc')
        kex.server.mac.append('umac-64-etm@openssh.com')
        kex.server.mac.append('umac-128-etm@openssh.com')
        kex.server.mac.append('hmac-sha2-256-etm@openssh.com')
        kex.server.mac.append('hmac-sha2-512-etm@openssh.com')
        kex.server.mac.append('hmac-sha1-etm@openssh.com')
        kex.server.mac.append('umac-64@openssh.com')
        kex.server.mac.append('umac-128@openssh.com')
        kex.server.mac.append('hmac-sha2-256')
        kex.server.mac.append('hmac-sha2-512')
        kex.server.mac.append('hmac-sha1')
        kex.server.compression.append('zlib@openssh.com')
        for a in kex.server.encryption:
            kex.client.encryption.append(a)
        for a in kex.server.mac:
            kex.client.mac.append(a)
        for a in kex.server.compression:
            if a == 'none':
                continue
            kex.client.compression.append(a)
        return kex

    def test_key_payload(self):
        kex1 = self._get_kex_variat1()
        kex2 = self.ssh2_kex.parse(self.OutputBuffer, self._kex_payload())
        assert kex1.payload == kex2.payload

    def test_ssh2_server_simple(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        w = self.wbuf()
        w.write_byte(self.protocol.MSG_KEXINIT)
        w.write(self._kex_payload())
        vsocket.rdata.append(b'SSH-2.0-OpenSSH_7.3 ssh-audit-test\r\n')
        vsocket.rdata.append(self._create_ssh2_packet(w.write_flush()))
        output_spy.begin()
        out = self.OutputBuffer()
        self.audit(out, self._conf())
        out.write()
        lines = output_spy.flush()
        assert len(lines) == 74

    def test_ssh2_server_invalid_first_packet(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        w = self.wbuf()
        w.write_byte(self.protocol.MSG_KEXINIT + 1)
        vsocket.rdata.append(b'SSH-2.0-OpenSSH_7.3 ssh-audit-test\r\n')
        vsocket.rdata.append(self._create_ssh2_packet(w.write_flush()))
        output_spy.begin()
        out = self.OutputBuffer()
        ret = self.audit(out, self._conf())
        out.write()
        assert ret != 0
        lines = output_spy.flush()
        assert len(lines) == 4
        assert 'unknown message' in lines[-1]

    def test_ssh2_gss_kex(self, output_spy, virtual_socket):
        '''Ensure that GSS kex algorithms are properly parsed.'''

        vsocket = virtual_socket
        w = self.wbuf()
        w.write_byte(self.protocol.MSG_KEXINIT)
        w.write(self._kex_payload_with_gss())  # Use the kex with GSS algorithms.
        vsocket.rdata.append(b'SSH-2.0-OpenSSH_7.3 ssh-audit-test\r\n')
        vsocket.rdata.append(self._create_ssh2_packet(w.write_flush()))
        output_spy.begin()
        out = self.OutputBuffer()
        self.audit(out, self._conf())
        out.write()
        lines = output_spy.flush()

        # Ensure that none of the lines are reported as "unknown algorithm".
        for line in lines:
            assert line.find('unknown algorithm') == -1

    def _get_kex_with_algorithms(self, kex_algs, key_algs=None, enc=None, mac=None):
        '''Builds an SSH2_Kex from explicit algorithm lists for capability/evidence testing.'''
        key_algs = key_algs if key_algs is not None else ['ssh-ed25519', 'rsa-sha2-512']
        enc = enc if enc is not None else ['chacha20-poly1305@openssh.com', 'aes256-ctr', 'aes128-gcm@openssh.com']
        mac = mac if mac is not None else ['hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com']
        srv = self.ssh2_kexparty(list(enc), list(mac), ['none'], [])
        cli = self.ssh2_kexparty(list(enc), list(mac), ['none'], [])
        return self.ssh2_kex(self.OutputBuffer, b'\x00' * 16, list(kex_algs), list(key_algs), cli, srv, 0)

    def _model(self, banner_text, kex):
        software = Software.parse(Banner.parse(banner_text))
        return EvidenceModel(software, kex).to_dict()

    def test_capabilities_derived_from_observed_algorithms(self):
        '''The capability window is derived from observed algorithm introduction/removal versions, not from the banner.'''
        kex = self._get_kex_with_algorithms(['curve25519-sha256', 'diffie-hellman-group14-sha256'], ['rsa-sha2-512', 'ssh-ed25519'])
        evidence = self._model('SSH-2.0-OpenSSH_9.6p1', kex)
        observation = evidence['capability_observation']
        # curve25519-sha256 was introduced in 7.4, which is the newest introduction among the observed set.
        assert observation['since_version'] == '7.4'
        assert observation['observed_counts'] == {'kex': 2, 'key': 2, 'enc': 3, 'mac': 2}
        # Every mapped algorithm (2 kex + 2 host-key + 3 ciphers + 2 MACs) is reported as an evidence item.
        assert len(observation['algorithms']) == 9

    def test_backfilled_version_requires_multiple_capability_features(self):
        '''A high version claim combined with several removed algorithms across multiple categories is flagged as back-filled.'''
        kex = self._get_kex_with_algorithms(
            ['curve25519-sha256', 'diffie-hellman-group1-sha1'],
            ['ssh-ed25519', 'ssh-dss'],
            ['aes128-ctr', '3des-cbc'],
            ['hmac-sha2-256', 'hmac-md5', 'hmac-md5-96'])
        evidence = self._model('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5', kex)
        assert evidence['status'] == EvidenceModel.BACKFILL_SUSPECTED
        assert evidence['backfill_score'] >= evidence['backfill_threshold']
        behind = evidence['capability_observation']['features_behind']
        assert len(behind) >= evidence['backfill_min_features']
        assert len({item['type'] for item in behind}) >= 2
        ids = [item['id'] for item in evidence['evidence']]
        assert 'backfilled_version' in ids
        assert 'legacy_feature' in ids
        assert any(item['severity'] == 'fail' for item in evidence['evidence'])

    def test_single_legacy_algorithm_does_not_trigger_backfill(self):
        '''A single legacy algorithm (sparse/missing-feature case) must stay a conflict, not a back-fill finding.'''
        kex = self._get_kex_with_algorithms(['diffie-hellman-group1-sha1'], ['ssh-ed25519'], ['aes128-ctr'], ['hmac-sha2-256'])
        evidence = self._model('SSH-2.0-OpenSSH_9.6p1', kex)
        assert evidence['status'] == EvidenceModel.CONFLICT
        assert len(evidence['capability_observation']['features_behind']) == 1
        assert 'backfilled_version' not in [item['id'] for item in evidence['evidence']]

    def test_backport_with_new_algorithms_is_not_misflagged(self):
        '''A low version claim that gains a newer algorithm via a vendor back-port is reported but never upgraded to a safe version.'''
        kex = self._get_kex_with_algorithms(['curve25519-sha256', 'sntrup761x25519-sha512@openssh.com'], ['ssh-ed25519'])
        evidence = self._model('SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3', kex)
        assert evidence['status'] == EvidenceModel.FORWARD_FEATURES_ON_OLD_CLAIM
        assert evidence['backfill_score'] == 0
        ahead = evidence['capability_observation']['features_ahead']
        assert any(item['algorithm'] == 'sntrup761x25519-sha512@openssh.com' for item in ahead)
        ids = [item['id'] for item in evidence['evidence']]
        assert 'backported_feature' in ids
        assert 'backfilled_version' not in ids

    def test_genuine_modern_build_is_consistent(self):
        '''A modern build whose observed modern markers match its claim is consistent and produces no conflict evidence.'''
        kex = self._get_kex_with_algorithms(
            ['curve25519-sha256', 'ext-info-s', 'sntrup761x25519-sha512@openssh.com'],
            ['ssh-ed25519', 'sk-ssh-ed25519@openssh.com'])
        evidence = self._model('SSH-2.0-OpenSSH_9.6p1', kex)
        assert evidence['status'] == EvidenceModel.CONSISTENT
        assert evidence['capability_observation']['features_behind'] == []
        assert 'backfilled_version' not in [item['id'] for item in evidence['evidence']]

    def test_capability_only_observation(self):
        '''Without a banner, the model still reports an observation derived purely from the KEX.'''
        kex = self._get_kex_with_algorithms(['curve25519-sha256'], ['ssh-ed25519'])
        evidence = EvidenceModel(None, kex).to_dict()
        assert evidence['status'] == EvidenceModel.CAPABILITY_ONLY
        assert evidence['version_claim'] is None
        assert evidence['capability_observation']['since_version'] == '7.4'
        assert kex.capability_evidence()['status'] == EvidenceModel.CAPABILITY_ONLY

    def test_evidence_items_are_serializable_and_sorted_stable(self):
        '''Evidence items always carry the documented keys and survive JSON serialization.'''
        import json
        kex = self._get_kex_with_algorithms(['diffie-hellman-group1-sha1'], ['ssh-dss'], ['3des-cbc'], ['hmac-md5', 'hmac-md5-96'])
        evidence = self._model('SSH-2.0-OpenSSH_9.6p1', kex)
        for item in evidence['evidence']:
            assert 'id' in item and 'severity' in item and 'message' in item
        serialized = json.dumps(evidence)
        assert 'backfilled_version' in serialized
