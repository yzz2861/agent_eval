"""冻结一份用于演示外发投影的公钥小样本。

样本固定使用 RSA-2048，覆盖三类材料：

* 普通 UID（``Alice Public ...``）：持有可导出的自签和合作伙伴公开认证，
  外加一条仅内部使用的本地认证，用于演示“裁剪但不阻断”；
* 本地 UID（``Ops Internal Only ...``）：自签本身被标记为不可导出，
  裁剪后失去必要自签，用于演示阻断依据；
* 合作伙伴认证者密钥（``Partner CA ...``）：作为“可公开认证”来源随样本冻结。

生成结果写入 :data:`SAMPLE_DIR`，原件与外发副本各自落盘，便于发布人
重新加载后核对两份材料分别承认哪些身份。
"""

import json
import os
from datetime import datetime, timedelta, timezone

from pgpy import PGPKey, PGPUID
from pgpy.constants import (
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SignatureType,
)

from .projection import build_export_projection, serialize_transferable_public_key

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          'frozen_sample')

ORIGINAL_PATH = os.path.join(SAMPLE_DIR, 'original_internal.asc')
PARTNER_PATH = os.path.join(SAMPLE_DIR, 'partner_certifier.asc')
EXPORT_PATH = os.path.join(SAMPLE_DIR, 'public_export.asc')
AUDIT_PATH = os.path.join(SAMPLE_DIR, 'projection_audit.json')

KEY_USAGE = {KeyFlags.Certify, KeyFlags.Sign}
HASHES = [HashAlgorithm.SHA256]

# 固定自签时间，保证原件里 UID 的接收顺序可复现：
# PGPy 按自签时间倒序存放 UID，普通 UID 使用更晚的时间即可排在首位。
BASE_TIME = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
PUBLIC_UID_TIME = BASE_TIME + timedelta(hours=2)
LOCAL_UID_TIME = BASE_TIME + timedelta(hours=1)


def _new_primary_key(name, email):
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    key.add_uid(
        PGPUID.new(name, email=email),
        usage=KEY_USAGE,
        hashes=HASHES,
    )
    return key


def build_sample():
    """构造样本密钥组，返回 ``(内部私钥, 合作伙伴私钥, 非严格投影结果)``。

    返回私钥只是为了让测试能继续在内存里追加签名；落盘文件只包含公钥材料。
    """
    internal = _new_primary_key('Alice Public', 'alice@public.example')
    partner = _new_primary_key('Partner CA', 'ca@partner.example')

    # 第二个 UID 的自签显式标记为不可导出：裁剪后该 UID 失去必要自签。
    internal.add_uid(
        PGPUID.new('Ops Internal Only', 'internal-only', 'ops@intranet.local'),
        usage=KEY_USAGE,
        hashes=HASHES,
        exportable=False,
        created=LOCAL_UID_TIME,
    )

    # 把普通 UID 的自签时间显式推后，确保它在原件里排第一。
    public_selfsig = internal.get_uid('Alice Public').selfsig
    public_selfsig._signature.subpackets['h_CreationTime'][-1].created = PUBLIC_UID_TIME
    for uid in internal._uids:
        internal._uids.resort(uid)

    public_uid = internal.get_uid('Alice Public')

    # 可公开的第三方认证：随外发副本保留。
    public_uid |= partner.certify(
        public_uid,
        SignatureType.Positive_Cert,
        exportable=True,
        created=PUBLIC_UID_TIME + timedelta(minutes=1),
    )

    # 仅内部使用的第三方认证：必须裁剪，且其内容不得出现在副本中。
    public_uid |= partner.certify(
        public_uid,
        SignatureType.Generic_Cert,
        exportable=False,
        created=PUBLIC_UID_TIME + timedelta(minutes=2),
    )

    result = build_export_projection(internal, certifiers=[partner], strict=False)
    return internal, partner, result


def freeze_sample():
    """生成样本并把原件、认证者、外发副本和审计 JSON 写到磁盘。"""
    internal, partner, result = build_sample()

    os.makedirs(SAMPLE_DIR, exist_ok=True)
    with open(ORIGINAL_PATH, 'w', encoding='utf-8') as handle:
        handle.write(serialize_transferable_public_key(internal, include_local=True))
    with open(PARTNER_PATH, 'w', encoding='utf-8') as handle:
        handle.write(str(partner.pubkey))
    with open(EXPORT_PATH, 'w', encoding='utf-8') as handle:
        handle.write(result.armored)
    with open(AUDIT_PATH, 'w', encoding='utf-8') as handle:
        json.dump(result.audit.as_dict(), handle, indent=2, ensure_ascii=False)
        handle.write('\n')

    return {
        'original': ORIGINAL_PATH,
        'certifier': PARTNER_PATH,
        'export': EXPORT_PATH,
        'audit': AUDIT_PATH,
    }


if __name__ == '__main__':
    paths = freeze_sample()
    for label, path in sorted(paths.items()):
        print('{0}: {1}'.format(label, path))
