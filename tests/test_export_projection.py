"""外发投影入口的行为测试。

覆盖：本地认证裁剪、归属未知阻断、裁剪后失去自签阻断、验签失败阻断、
原始接收顺序审计，以及冻结样本原件 / 外发副本的双份重读。
"""

import json

import pytest

from pgpy import PGPKey, PGPUID
from pgpy.constants import (
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SignatureType,
)
from pgpy.packet.types import MPI

from export_projection import (
    BLOCK_REASONS,
    ExportBlocked,
    build_export_projection,
    export_public_key,
)
from export_projection.projection import (
    is_exportable,
    normalize_boolean_subpackets,
    serialize_transferable_public_key,
)
from export_projection.sample import freeze_sample
from export_projection.inspect import reread_frozen_sample


USAGE = {KeyFlags.Certify, KeyFlags.Sign}
HASHES = [HashAlgorithm.SHA256]


def _new_key(name, email):
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    key.add_uid(
        PGPUID.new(name, email=email),
        usage=USAGE,
        hashes=HASHES,
    )
    return key


@pytest.fixture()
def owner():
    return _new_key('Owner', 'owner@example.com')


@pytest.fixture()
def certifier():
    return _new_key('Known Certifier', 'ca@partner.example')


@pytest.fixture()
def stranger():
    return _new_key('Stranger', 'stranger@elsewhere.example')


def test_local_only_certification_is_dropped_but_kept_out_of_export(owner, certifier):
    uid = owner.userids[0]
    uid |= certifier.certify(uid, SignatureType.Positive_Cert, exportable=True)
    uid |= certifier.certify(uid, SignatureType.Generic_Cert, exportable=False)

    result = build_export_projection(owner, certifiers=[certifier])
    audit = result.audit.as_dict()

    verdicts = [(s.attribution, s.verdict, s.reason)
                for s in result.audit.uids[0].signatures]
    assert ('SELF', 'KEEP', None) in verdicts
    assert (certifier.fingerprint.keyid, 'KEEP', None) in verdicts
    assert (certifier.fingerprint.keyid, 'DROP', 'LOCAL_ONLY') in verdicts

    reparsed, _ = PGPKey.from_blob(result.armored)
    exported_sigs = reparsed.userids[0]._signatures
    assert all(is_exportable(s) for s in exported_sigs)
    assert len(exported_sigs) == 2
    assert 'PRIVATE' not in result.armored


def test_unattributed_signature_blocks_projection(owner, stranger):
    uid = owner.userids[0]
    uid |= stranger.certify(uid, SignatureType.Generic_Cert, exportable=True)

    with pytest.raises(ExportBlocked) as excinfo:
        build_export_projection(owner, certifiers=[])

    reasons = [s.reason for s in excinfo.value.audit.uids[0].signatures]
    assert BLOCK_REASONS.UNATTRIBUTED.value in reasons

    # 非严格模式：剔除带未知归属的 UID，而不是把签名静默带出去。
    result = build_export_projection(owner, certifiers=[], strict=False)
    assert result.retained_uids() == []
    assert result.audit.blocked[0].reason == BLOCK_REASONS.UNATTRIBUTED.value


def test_unverifiable_third_party_certification_is_blocked(owner, certifier):
    uid = owner.userids[0]
    signature = certifier.certify(uid, SignatureType.Generic_Cert, exportable=True)
    original_mpi = int(signature._signature.signature.md_mod_n)
    signature._signature.signature.md_mod_n = MPI(original_mpi ^ 0x01)
    uid |= signature

    with pytest.raises(ExportBlocked) as excinfo:
        build_export_projection(owner, certifiers=[certifier], strict=True)

    reasons = {entry.reason for entry in excinfo.value.audit.blocked}
    assert BLOCK_REASONS.UNVERIFIABLE.value in reasons


def test_uid_with_only_local_selfsig_is_blocked(owner):
    owner.add_uid(
        PGPUID.new('Internal Only', email='intra@intranet.local'),
        usage=USAGE,
        hashes=HASHES,
        exportable=False,
    )

    with pytest.raises(ExportBlocked) as excinfo:
        build_export_projection(owner, strict=True)

    blocked = excinfo.value.audit.blocked
    assert any(entry.reason == BLOCK_REASONS.SELF_SIG_MISSING.value for entry in blocked)


def test_received_order_is_preserved_in_audit(owner, certifier):
    uid = owner.userids[0]
    uid |= certifier.certify(uid, SignatureType.Casual_Cert, exportable=True)
    uid |= certifier.certify(uid, SignatureType.Generic_Cert, exportable=False)

    result = build_export_projection(owner, certifiers=[certifier])
    records = result.audit.uids[0].signatures
    assert [record.order for record in records] == [0, 1, 2]
    assert [record.verdict for record in records] == ['KEEP', 'KEEP', 'DROP']


def test_audit_never_carries_signature_payload(owner, certifier):
    uid = owner.userids[0]
    local = certifier.certify(uid, SignatureType.Generic_Cert, exportable=False)
    uid |= local

    result = build_export_projection(owner, certifiers=[certifier])
    serialized = json.dumps(result.audit.as_dict())
    local_bytes = bytes(local)
    # 被裁签名的任何字节片段都不得出现在审计或外发副本里。
    assert local_bytes.hex() not in serialized
    assert local_bytes.hex() not in result.armored.encode('latin-1').hex()


def test_normalize_boolean_subpackets_roundtrip(owner, certifier):
    uid = owner.userids[0]
    uid |= certifier.certify(uid, SignatureType.Positive_Cert, exportable=True)

    reparsed, _ = PGPKey.from_blob(serialize_transferable_public_key(owner))
    third_party = [
        s for s in reparsed.userids[0]._signatures
        if s.signer == certifier.fingerprint.keyid
    ][0]
    # 归一化前命中 PGPy 解析 bug：状态被写到普通属性 bool 上。
    assert 'bool' in next(iter(
        third_party._signature.subpackets['ExportableCertification']
    )).__dict__
    normalize_boolean_subpackets(third_party)
    assert is_exportable(third_party) is True


def test_frozen_sample_dual_reread(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    paths = freeze_sample()

    with open(paths['audit'], encoding='utf-8') as handle:
        audit = json.load(handle)
    assert audit['blocked'][0]['reason'] == BLOCK_REASONS.SELF_SIG_MISSING.value

    view = reread_frozen_sample()
    original_uids = {u['uid']: u['certifications'] for u in view['original']['uids']}
    export_uids = {u['uid']: u['certifications'] for u in view['export']['uids']}

    # 原件承认普通 UID 与本地 UID，且普通 UID 上挂着一条本地认证。
    assert len(original_uids) == 2
    scopes = {c['scope'] for c in original_uids['Alice Public <alice@public.example>']}
    assert scopes == {'public', 'local-only'}

    # 外发副本只承认普通 UID，且全部为公开认证。
    assert list(export_uids) == ['Alice Public <alice@public.example>']
    assert all(c['scope'] == 'public'
               for c in export_uids['Alice Public <alice@public.example>'])


def test_export_public_key_helper_returns_armor_and_audit(owner, certifier):
    uid = owner.userids[0]
    uid |= certifier.certify(uid, SignatureType.Positive_Cert, exportable=True)

    armored, audit = export_public_key(owner, certifiers=[certifier])
    assert armored.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----')
    assert audit['fingerprint'] == str(owner.fingerprint)
    assert audit['uids'][0]['kept'] is True
