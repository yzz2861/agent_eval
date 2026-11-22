"""显式外发投影（public export projection）。

本包在 PGPy 之上提供一个明确的“对外发布”入口：把一份内部公钥材料投影成
可以离开内网的公共副本，并对每一个 UID 及其绑定签名给出保留 / 阻断依据。

设计要点：

* 仅内部使用的认证（``exportable=False``）一律不进入投影副本，审计记录只
  保留必要的归属元数据，绝不携带被裁签名的任何包内容。
* 归属无法判定的签名（签发者既不是主键自身，也不在随附材料中）直接阻断，
  避免把无法解释的认证带出去。
* 投影后失去必要自签的 UID 不允许发布；默认策略下整个投影失败，
  ``strict=False`` 时改为剔除该 UID 并在审计中记为阻断。
"""

from .projection import (
    BLOCK_REASONS,
    ExportBlocked,
    ProjectionAudit,
    ProjectionResult,
    build_export_projection,
    export_public_key,
)

__all__ = [
    'BLOCK_REASONS',
    'ExportBlocked',
    'ProjectionAudit',
    'ProjectionResult',
    'build_export_projection',
    'export_public_key',
]
