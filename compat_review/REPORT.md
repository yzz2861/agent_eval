# 两代 CBOR 档案格式 — 离线兼容审查报告

日期: 2026-11-26 · 审查方式: 离线、只读 · 审查器: review.py(退出码 1 = 存在非 COMPATIBLE 组合)

## 输入工件(只读对照路径)

- 批准口径: compat_review/readers.json(调用方批准的读者描述,含签收号)
- 已解码对象: compat_review/objects/gen1.json、compat_review/objects/gen2.json
- 线格式对照: compat_review/objects/gen1.cbor、compat_review/objects/gen2.cbor
  (由 generate_objects.py 一次性生成;test_wire_matches_mirror 证明线格式解码结果与镜像逐字段一致)

审查过程不写入任何输入文件;旧签收(SO-2025-114、SO-2026-041)的覆盖范围不被延长,
边界外字段一律标记为"交接前须剥离",不视为已批准。

## 交接边界与结论(读者 x 对象)

| 读者(签收) | 对象 | 交接边界 | 边界外字段 | 结论 |
|---|---|---|---|---|
| legacy-archive-reader (SO-2025-114) | gen1 | title, created, owner, payload, tags | 无 | COMPATIBLE |
| legacy-archive-reader (SO-2025-114) | gen2 | title, created, owner, payload | summary, version, review_meta | **RE-REVIEW** |
| analytics-export-reader (SO-2026-041) | gen1 | title, created, owner | payload, tags | **INCOMPATIBLE** |
| analytics-export-reader (SO-2026-041) | gen2 | title, created, owner, summary, version | payload, review_meta | COMPATIBLE |

## 发现与归因(对象事实 vs 批准口径)

1. **payload 类别变更(legacy x gen2 → RE-REVIEW)**
   - 对象事实: gen2 中 payload 由字节串(opaque-bytes)变为文本(text)——解码值层面的实际变更。
   - 批准口径: SO-2025-114 将 payload 绑定到 opaque-bytes;重审义务来自该绑定,而非审查器新设规则。
   - 处置: 触发 legacy-archive-reader 读者域重审;新签收前,gen2 的 payload 不得按旧签收交付。
2. **version 必填缺失(analytics x gen1 → INCOMPATIBLE)**
   - 对象事实: gen1 不含 version 字段。批准口径: SO-2026-041 将其列为必填(count)。
   - 处置: gen1 不可交接给 analytics-export-reader;不补造字段、不放宽必填。
3. **边界外字段(summary/version/review_meta、payload/tags 等,依组合而定)**
   - 对象事实: 字段在对象中存在;批准口径: 不在该读者签收范围内。
   - 处置: 交接前剥离;存在本身不构成违规,但也不因实际存在而获得批准。
4. **tags 字段在 gen2 中移除**
   - 对象事实: gen2 无 tags。批准口径: SO-2025-114 中 tags 为可选,故不触发结论变化。

## 待核查(未知标签,不放行)

- tag(60001) @ $.review_meta(gen2): 未登记的私有标签,离线审查不推断其类别、不批准其交接,
  留待标签登记方核查。已登记标签仅 tag 1(时间戳)与 tag 55799(自描述,透明)。

## 验证(两条合法短对象)

test_compat_review.py 共 4 项,全部通过:

- **排列不变性**: {"a":1,"b":"x"} 与 {"b":"x","a":1} 两种键序分别编码为合法 CBOR,
  解码后逻辑形状相同,对同一读者描述的审查结论逐字段一致(COMPATIBLE,无发现)——
  更换排列顺序不制造审批变化。
- **同名类别变更**: b: "x" 改为 b: b"x"(text → opaque-bytes)后,
  审查结论由 COMPATIBLE 变为 RE-REVIEW,且发现精确定位到字段 b——
  同名字段改变逻辑类别会触发对应读者域重审。

## 复现

    .venv/bin/python compat_review/review.py
    cd compat_review && ../.venv/bin/python -m pytest test_compat_review.py --rootdir=. -p no:cacheprovider --confcutdir=.
