# 设备豁免迁移预览

这个示例把旧豁免分成两种授权基础：

- `basis: "device"`：CPE 只用于确认型号，真正放行的是 `device_ids` 中列出的资产 ID。
- `basis: "product"`：CPE 集合构成产品范围，范围内的新设备可以继续使用该规则。

`inheritances` 是显式的资产继承边。设备型批准只有在继承边带有 `evidence` 时才会转移；没有证据的继承边会生成 `inheritances`/`pending_review` 明细，不会因为同型号而自动批准。

运行完整预览：

```bash
python -m cpe.migration examples/migration_preview/input.json
```

单独定位同型号但从未获批的设备：

```bash
python -m cpe.migration examples/migration_preview/input.json --device EDGE-N-02
```

这台设备与 `EDGE-N-01` 的 CPE 完全相同，但不在 `LEGACY-EDGE-GROUP.device_ids` 中，因此预览给出 `cpe_match_without_device_approval`，而不是继承旧例外。
