"""显式外发投影核心逻辑。

本模块不依赖 PGPy 序列化时对非导出签名的隐式过滤，而是显式遍历公钥上的
每个 UID 及其绑定签名，逐条决定“保留 / 裁剪 / 阻断”，并把判定依据固定在
审计对象里，供发布人事前核对。

归属判定
--------
每条绑定签名的签发者 key id 会和以下两个来源比较：

* 被投影主键自身（自签）；
* 调用方显式提供的“可公开认证者”公钥集合（第三方认证）。

两者都匹配不上的签名归属未知，默认直接阻断投影，而不是静默保留或丢弃。

内容隔离
--------
被裁掉的仅本地认证不会被复制进投影密钥；审计记录里只保存类型、归属等
元数据，刻意不保存签名的字节、notation 正文或任何子包负载。

第三方认证在保留前会用随附的认证者公钥实际验签：通不过验签的认证同样
视为归属不可信而阻断，避免“key id 对得上但签名本身无效”的材料外发。
"""

import base64
from collections import OrderedDict
from copy import copy
from enum import Enum

from pgpy import PGPKey, PGPUID
from pgpy.constants import SignatureType
from pgpy.types import PGPObject


class BlockReason(str, Enum):
    """组件被阻断的原因码。"""

    LOCAL_ONLY = 'LOCAL_ONLY'
    """签名被标记为仅本地使用（不可导出），必须裁掉。"""

    UNATTRIBUTED = 'UNATTRIBUTED'
    """签名签发者既不是主键自身，也不在可公开认证者集合中，归属未知。"""

    UNVERIFIABLE = 'UNVERIFIABLE'
    """签名虽能归属到登记的认证者，但用其公钥验签失败，不允许外发。"""

    SELF_SIG_MISSING = 'SELF_SIG_MISSING'
    """裁剪后该 UID 不再持有可导出的自签，失去发布所需的自证。"""

    USER_ATTRIBUTE = 'USER_ATTRIBUTE'
    """当前投影入口只接受普通 UID，用户属性（照片等）不予外发。"""


# 供外部代码做稳定引用，同时在文档/报错里复用同一份原因码。
BLOCK_REASONS = BlockReason

# 标识“自签”归属，区别于具体第三方认证者的 key id。
SELF = 'SELF'
LOCAL = 'LOCAL'


def normalize_boolean_subpackets(signature):
    """修正 PGPy 解析 Boolean 子包时的状态写错位问题。

    PGPy 的 Boolean 解析器把负载写到一个并不存在的 self.bool 属性上，
    真正的 bflag 永远停在初值 False。命中该 bug 时实例上会多出一个普通
    属性 bool，保存着线上真实布尔值；本函数把它搬回 bflag，使后续序列化
    与属性访问恢复 RFC 4880 语义。对解析正常的签名幂等。
    """
    for packet in signature._signature.subpackets:
        if packet.__class__.__name__ in ("ExportableCertification", "Revocable"):
            if "bool" in packet.__dict__:
                packet.bflag = bool(packet.__dict__.pop("bool"))
    return signature


def is_exportable(signature):
    """按 RFC 4880 5.2.3.11 判定签名是否可导出。

    缺少 ExportableCertification 子包时默认可导出；存在时先经
    normalize_boolean_subpackets 修正 PGPy 的解析错位，再读取布尔负载。
    """
    normalize_boolean_subpackets(signature)
    subpackets = signature._signature.subpackets
    if "ExportableCertification" not in subpackets:
        return True
    return bool(next(iter(subpackets["ExportableCertification"])).bflag)


class ExportBlocked(Exception):
    """投影因无法安全裁剪而整体失败。

    严格模式（默认）下，只要出现归属未知或 UID 失去自签的情况就抛出本异常；
    异常携带完整审计对象，但不包含任何被裁材料的字节内容。
    """

    def __init__(self, audit):
        self.audit = audit
        problems = [
            (component.uid, component.reason)
            for component in audit.blocked
        ]
        detail = '; '.join('{0}: {1}'.format(uid, reason) for uid, reason in problems)
        super().__init__('export projection blocked: {0}'.format(detail or 'unknown reason'))


class SignatureRecord(object):
    """单条绑定签名的审计记录（只含元数据，不含签名负载）。"""

    __slots__ = (
        'order', 'sigtype', 'signer_keyid', 'attribution',
        'exportable', 'verdict', 'reason',
    )

    def __init__(self, order, signature, attribution, verdict, reason=None):
        self.order = order
        self.sigtype = signature.type.name
        self.signer_keyid = signature.signer
        self.attribution = attribution
        self.exportable = is_exportable(signature)
        self.verdict = verdict
        self.reason = reason

    def as_dict(self):
        return {
            'order': self.order,
            'sigtype': self.sigtype,
            'signer_keyid': self.signer_keyid,
            'attribution': self.attribution,
            'exportable': self.exportable,
            'verdict': self.verdict,
            'reason': self.reason,
        }


class UidAudit(object):
    """单个 UID 的投影审计，按原始接收顺序保存签名判定。"""

    def __init__(self, index, uid):
        self.index = index
        self.uid = uid
        self.signatures = []
        self.retained = []
        self.dropped = []
        self.blocked = []
        self.reason = None
        self.kept = False

    def as_dict(self):
        return {
            'index': self.index,
            'uid': self.uid,
            'kept': self.kept,
            'reason': self.reason,
            'signatures': [record.as_dict() for record in self.signatures],
        }


class KeySignatureRecord(object):
    """主键顶层（直接作用于 key）签名的审计记录，同样只含元数据。"""

    __slots__ = ('order', 'sigtype', 'signer_keyid', 'attribution',
                 'exportable', 'verdict', 'reason')

    def __init__(self, order, signature, attribution, verdict, reason=None):
        self.order = order
        self.sigtype = signature.type.name
        self.signer_keyid = signature.signer
        self.attribution = attribution
        self.exportable = is_exportable(signature)
        self.verdict = verdict
        self.reason = reason

    def as_dict(self):
        return {
            'order': self.order,
            'sigtype': self.sigtype,
            'signer_keyid': self.signer_keyid,
            'attribution': self.attribution,
            'exportable': self.exportable,
            'verdict': self.verdict,
            'reason': self.reason,
        }


class ProjectionAudit(object):
    """整份公钥的投影审计，保留 UID 的原始接收顺序。"""

    def __init__(self, fingerprint):
        self.fingerprint = str(fingerprint)
        self.uids = []
        self.blocked = []
        self.key_signatures = []

    def as_dict(self):
        return OrderedDict([
            ('fingerprint', self.fingerprint),
            ('key_signatures', [record.as_dict() for record in self.key_signatures]),
            ('uids', [entry.as_dict() for entry in self.uids]),
            ('blocked', [
                {'uid': entry.uid, 'reason': entry.reason}
                for entry in self.blocked
            ]),
        ])


class ProjectionResult(object):
    """投影产物：投影公钥、ASCII 副本和审计对象。"""

    def __init__(self, key, audit):
        self.key = key
        self.audit = audit

    @property
    def armored(self):
        """:rtype: ``str`` 外发 ASCII-armored 公钥副本。"""
        return str(self.key)

    def retained_uids(self):
        return [entry.uid for entry in self.audit.uids if entry.kept]


def _keyid_index(certifiers):
    """把可公开认证者材料归一成 key id -> PGPKey 的索引。"""
    index = {}
    if certifiers is None:
        return index

    for material in certifiers:
        keys = [material] if isinstance(material, PGPKey) else list(_iter_keys(material))
        for key in keys:
            index[key.fingerprint.keyid] = key
            for subkey in key.subkeys.values():
                index.setdefault(subkey.fingerprint.keyid, key)
    return index


def _iter_keys(material):
    """支持把 PGPKeyring 或序列化 blob 作为认证者材料传入。"""
    if isinstance(material, PGPKey):
        yield material
        return

    if hasattr(material, 'keys') and callable(getattr(material, 'keys')):
        for key in material.keys():
            yield key
        return

    key, others = PGPKey.from_blob(material)
    yield key
    for other in others.values():
        yield other


def _attribute(signature, primary_keyid, certifier_index):
    """判定签名归属：自签 / 已登记第三方 / 未知。"""
    signer = signature.signer
    if signer == primary_keyid:
        return SELF
    if signer in certifier_index:
        return signer
    return None


def _is_self_signature(signature, primary_keyid):
    return (
        signature.signer == primary_keyid
        and signature.type in (
            SignatureType.Generic_Cert,
            SignatureType.Persona_Cert,
            SignatureType.Casual_Cert,
            SignatureType.Positive_Cert,
        )
    )


def _verify_certification(certifier_key, uid, signature):
    """用认证者公钥对 UID 绑定签名做实际验签。"""
    try:
        return bool(certifier_key.verify(uid, signature))
    except Exception:
        return False


def _project_key_signatures(audit, source, primary_keyid, certifier_index):
    """裁决直接作用于主键（非子键绑定、非内嵌）的顶层签名。

    本地签名裁剪、归属未知阻断；通过的签名以对象形式返回，供投影副本重建。
    """
    retained = []
    for order, signature in enumerate(
        sig for sig in source._signatures if not sig.embedded
    ):
        attribution = _attribute(signature, primary_keyid, certifier_index)

        if not is_exportable(signature):
            audit.key_signatures.append(KeySignatureRecord(
                order, signature,
                attribution if attribution is not None else LOCAL,
                verdict='DROP', reason=BlockReason.LOCAL_ONLY.value,
            ))
            continue

        if attribution is None:
            audit.key_signatures.append(KeySignatureRecord(
                order, signature, attribution=None,
                verdict='BLOCK', reason=BlockReason.UNATTRIBUTED.value,
            ))
            audit.blocked.append(_KeyLevelBlock(
                reason=BlockReason.UNATTRIBUTED.value,
                signer=signature.signer,
            ))
            continue

        if attribution != SELF:
            certifier = certifier_index[signature.signer]
            if not _verify_certification(certifier, source, signature):
                audit.key_signatures.append(KeySignatureRecord(
                    order, signature, attribution=attribution,
                    verdict='BLOCK', reason=BlockReason.UNVERIFIABLE.value,
                ))
                audit.blocked.append(_KeyLevelBlock(
                    reason=BlockReason.UNVERIFIABLE.value,
                    signer=signature.signer,
                ))
                continue

        audit.key_signatures.append(KeySignatureRecord(
            order, signature, attribution=attribution, verdict='KEEP',
        ))
        retained.append(signature)

    return retained


class _KeyLevelBlock(object):
    """顶层签名阻断在审计中的占位条目（没有对应 UID）。"""

    def __init__(self, reason, signer):
        self.uid = '<key-level signature by {0}>'.format(signer)
        self.reason = reason


def _project_uid(uid_entry, uid, primary_keyid, certifier_index):
    """对单个 UID 的绑定签名逐条裁决，返回该 UID 允许保留的签名列表。"""
    retained = []

    for order, signature in enumerate(uid._signatures):
        attribution = _attribute(signature, primary_keyid, certifier_index)

        if not is_exportable(signature):
            record = SignatureRecord(
                order, signature,
                attribution if attribution is not None else LOCAL,
                verdict='DROP',
                reason=BlockReason.LOCAL_ONLY.value,
            )
            uid_entry.signatures.append(record)
            uid_entry.dropped.append(record)
            continue

        if attribution is None:
            record = SignatureRecord(
                order, signature, attribution=None,
                verdict='BLOCK',
                reason=BlockReason.UNATTRIBUTED.value,
            )
            uid_entry.signatures.append(record)
            uid_entry.blocked.append(record)
            continue

        if attribution != SELF and not _verify_certification(
            certifier_index[signature.signer], uid, signature
        ):
            record = SignatureRecord(
                order, signature, attribution=attribution,
                verdict='BLOCK',
                reason=BlockReason.UNVERIFIABLE.value,
            )
            uid_entry.signatures.append(record)
            uid_entry.blocked.append(record)
            continue

        record = SignatureRecord(
            order, signature, attribution=attribution,
            verdict='KEEP',
        )
        uid_entry.signatures.append(record)
        retained.append(signature)

    return retained


def _build_projected_key(source, kept_uids, kept_key_signatures):
    """构造只含通过裁决的 UID 及其可导出签名的新公钥对象。

    通过 ``copy.copy`` 复制主键与子键，再用 PGPUID 自带的复制逻辑重建 UID，
    确保被裁签名的对象不会进入投影结果。
    """
    projected = PGPKey()
    projected._key = copy(source._key)

    for signature in kept_key_signatures:
        projected |= copy(signature)

    for subkey in source.subkeys.values():
        projected |= copy(subkey)

    for uid, signatures in kept_uids:
        uid_copy = PGPUID()
        uid_copy._uid = copy(uid._uid)
        for signature in signatures:
            uid_copy |= copy(signature)
        projected |= uid_copy

    return projected


def build_export_projection(public_key, certifiers=None, strict=True):
    """显式外发投影入口。

    :param public_key: 待发布的公钥（私钥会先取其公开半部分）。
    :type public_key: :py:obj:`pgpy.PGPKey`
    :param certifiers: 可公开认证者集合，元素可以是 :py:obj:`pgpy.PGPKey`、
                       :py:obj:`pgpy.PGPKeyring` 或序列化公钥 blob。
    :param strict: 出现归属未知或裁剪后失去自签时，``True`` 抛出
                   :class:`ExportBlocked`；``False`` 改为剔除问题 UID 并继续。
    :type strict: ``bool``
    :returns: :class:`ProjectionResult`
    :raises ExportBlocked: 严格模式下存在不可安全外发的组件。
    """
    if not isinstance(public_key, PGPKey):
        raise TypeError('public_key must be a PGPKey instance')

    source = public_key if public_key.is_public else public_key.pubkey
    certifier_index = _keyid_index(certifiers)
    primary_keyid = source.fingerprint.keyid
    audit = ProjectionAudit(source.fingerprint)

    kept_uids = []

    kept_key_signatures = _project_key_signatures(
        audit, source, primary_keyid, certifier_index
    )

    for index, uid in enumerate(source._uids):
        uid_text = uid.userid if uid.is_uid else '<user-attribute>'
        entry = UidAudit(index, uid_text)
        audit.uids.append(entry)

        if not uid.is_uid:
            entry.kept = False
            entry.reason = BlockReason.USER_ATTRIBUTE.value
            audit.blocked.append(entry)
            continue

        retained = _project_uid(entry, uid, primary_keyid, certifier_index)

        if entry.blocked:
            entry.kept = False
            entry.reason = entry.blocked[0].reason
            audit.blocked.append(entry)
            continue

        has_self_sig = any(
            _is_self_signature(signature, primary_keyid)
            for signature in retained
        )
        if not has_self_sig:
            entry.kept = False
            entry.reason = BlockReason.SELF_SIG_MISSING.value
            audit.blocked.append(entry)
            continue

        entry.kept = True
        entry.retained = retained
        kept_uids.append((uid, retained))

    if strict and audit.blocked:
        raise ExportBlocked(audit)

    projected = _build_projected_key(source, kept_uids, kept_key_signatures)
    return ProjectionResult(projected, audit)


def serialize_transferable_public_key(key, include_local=True):
    """显式序列化可传输公钥（RFC 4880 11.1）。

    PGPy 默认序列化会静默剥离不可导出签名；本函数按 packet 显式拼装，
    include_local=True 时连仅本地认证一并写出，用于内部原件留档与重新加载
    核对。返回 ASCII-armored 文本。
    """
    source = key if key.is_public else key.pubkey
    buf = bytearray(source._key.__bytearray__())
    for signature in source._signatures:
        if signature.embedded:
            continue
        if include_local or is_exportable(signature):
            normalize_boolean_subpackets(signature)
            buf += signature.__bytearray__()
    for uid in source._uids:
        buf += uid._uid.__bytearray__()
        for signature in uid._signatures:
            if include_local or is_exportable(signature):
                normalize_boolean_subpackets(signature)
                buf += signature.__bytearray__()
    for subkey in source.subkeys.values():
        buf += subkey.__bytearray__()
    payload = base64.b64encode(bytes(buf)).decode("latin-1")
    payload = chr(10).join(payload[i:i + 64] for i in range(0, len(payload), 64))
    crc = base64.b64encode(PGPObject.int_to_bytes(PGPKey.crc24(buf), 3)).decode("latin-1")
    return (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
        "\n"
        "{packet}\n"
        "={crc}\n"
        "-----END PGP PUBLIC KEY BLOCK-----\n"
    ).format(packet=payload, crc=crc)


def export_public_key(public_key, certifiers=None, strict=True):
    """便捷封装：返回外发 ASCII 文本与审计字典。"""
    result = build_export_projection(public_key, certifiers=certifiers, strict=strict)
    return result.armored, result.audit.as_dict()
