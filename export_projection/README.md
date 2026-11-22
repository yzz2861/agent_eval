PGPy 外发投影（Public Export Projection）
=========================================

本包在 PGPy 之上提供一个显式的对外发布入口，把内网公钥材料投影成可以
离开内网的公共副本，并对每个 UID 及其绑定签名逐条给出保留 / 裁剪 / 阻断
依据，而不是依赖 PGPy 序列化时对非导出签名的隐式过滤。

核心入口
--------

``export_projection.build_export_projection(public_key, certifiers=None, strict=True)``

* ``public_key``：待发布公钥（传私钥会自动取公开半部分，副本不含私钥）。
* ``certifiers``：可公开认证者集合，元素支持 ``PGPKey``、``PGPKeyring`` 或
  序列化公钥 blob。第三方认证只有能用这里的公钥实际验签通过才会保留。
* ``strict=True``（默认）：出现归属未知、验签失败或裁剪后失去自签时抛出
  :class:`~export_projection.ExportBlocked`；``strict=False`` 改为剔除问题
  UID / 签名并在审计里记为阻断，其余材料继续外发。

返回 :class:`~export_projection.ProjectionResult`，含投影公钥、ASCII 副本
（``.armored``）和完整审计（``.audit``）。

裁决规则（原因码见 ``BLOCK_REASONS``）
--------------------------------------

* ``LOCAL_ONLY``：签名带不可导出标记（RFC 4880 5.2.3.11），一律裁剪，
  且审计只保留类型 / 归属等元数据，绝不携带签名字节或子包负载。
* ``UNATTRIBUTED``：签发者既不是主键自身，也不在可公开认证者集合中，
  归属未知，默认阻断而非静默保留或丢弃。
* ``UNVERIFIABLE``：能归属到登记认证者但用其公钥验签失败，阻断。
* ``SELF_SIG_MISSING``：裁剪后该 UID 不再持有可导出的自签，失去发布
  所需的自证，阻断该 UID。
* ``USER_ATTRIBUTE``：当前入口只接受普通 UID，照片等用户属性不外发。

审计里每条签名都带 ``order`` 字段，对应它在原件中的接收顺序，便于把认证
归属对回具体 UID。

PGPy 兼容性说明
---------------

当前 PGPy 版本解析 ``Boolean`` 子包（``ExportableCertification`` /
``Revocable``）时会把负载写到一个并不存在的 ``self.bool`` 属性，导致重解析
后可导出性恒为 ``False``。:func:`export_projection.projection.normalize_boolean_subpackets`
会把误置的布尔值搬回正确的 ``bflag``，``is_exportable`` 与序列化均先经此
归一化，保证线上字节的真实语义被正确识别。

冻结小样本
----------

``python -m export_projection.sample`` 会在 ``frozen_sample/`` 写出：

* ``original_internal.asc``：内部原件，显式保留仅本地认证；
* ``partner_certifier.asc``：登记的可公开认证者公钥；
* ``public_export.asc``：外发投影副本；
* ``projection_audit.json``：逐 UID、逐签名的裁决审计。

``python -m export_projection.inspect`` 会重新加载原件与副本，并排展示两份
材料各自承认哪些身份、每条认证的归属与可导出范围。

测试
----

``tests/test_export_projection.py`` 覆盖本地认证裁剪、归属未知阻断、验签失败
阻断、失去自签阻断、接收顺序审计、审计无签名负载泄漏，以及冻结样本双份重读。
