"""重新读取原件与外发副本，并排展示各自承认的身份与认证。

这个模块只做只读检查：从磁盘加载冻结的两份公钥材料，逐 UID 列出
自签与第三方认证，帮助发布人确认外发副本没有夹带仅本地使用的认证。
"""

from pgpy import PGPKey

from .projection import is_exportable
from .sample import EXPORT_PATH, ORIGINAL_PATH, PARTNER_PATH


def _load(path):
    key, _ = PGPKey.from_file(path)
    return key


def _is_exportable(signature):
    return is_exportable(signature)


def _describe_uid(uid, primary_keyid):
    certifications = []
    for signature in uid._signatures:
        if signature.signer == primary_keyid:
            attribution = 'self'
        else:
            attribution = 'third-party:{0}'.format(signature.signer)
        scope = 'public' if _is_exportable(signature) else 'local-only'
        certifications.append({
            'attribution': attribution,
            'scope': scope,
            'type': signature.type.name,
        })
    return {
        'uid': uid.userid,
        'certifications': certifications,
    }


def describe_key(key):
    """列出一把公钥承认的全部 UID 及其绑定认证的归属与可导出范围。"""
    primary_keyid = key.fingerprint.keyid
    return {
        'fingerprint': str(key.fingerprint),
        'uids': [_describe_uid(uid, primary_keyid) for uid in key.userids],
    }


def reread_frozen_sample():
    """重读冻结的原件与外发副本，返回两份材料的身份视图。"""
    original = _load(ORIGINAL_PATH)
    exported = _load(EXPORT_PATH)
    certifier = _load(PARTNER_PATH)
    return {
        'certifier_fingerprint': str(certifier.fingerprint),
        'original': describe_key(original),
        'export': describe_key(exported),
    }


def render_report(view):
    """把 :func:`reread_frozen_sample` 的结果渲染成可读文本。"""
    lines = []
    lines.append('registered public certifier: {0}'.format(view['certifier_fingerprint']))
    for label in ('original', 'export'):
        material = view[label]
        lines.append('')
        lines.append('== {0} ({1}) =='.format(label, material['fingerprint']))
        for uid_view in material['uids']:
            lines.append('UID: {0}'.format(uid_view['uid']))
            for certification in uid_view['certifications']:
                lines.append('  - [{0}] {1} {2}'.format(
                    certification['scope'],
                    certification['attribution'],
                    certification['type'],
                ))
    return '\n'.join(lines)


if __name__ == '__main__':
    print(render_report(reread_frozen_sample()))
