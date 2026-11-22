# Metadata samples

两个样本均由 `tools/make_metadata_samples.py` 直接生成，不调用 C# 编译器或 CLR。

| 文件 | SHA-256 | 结论 |
|---|---|---|
| `readonly-overloads.dll` | `742499a1f4dcd85460cf57f4414c633b54c9467802e8b9be5a310de57f3530ae` | 无外部接口写访问器 |
| `write-overloads.dll` | `9e74504e2ff61ba2f35bc4d267abc19e5730f0236e7ee8d681ee958d005490d9` | 有外部接口写访问器 |

`readonly-overloads.dll`

- `IReadOnlyValue.Value`: getter only.
- `IValueWriter.Value`: getter + setter, used as a comparison contract.
- `ReadOnlyFacade` implements only `IReadOnlyValue` and contains three unrelated overloads named `set_Value`.

`write-overloads.dll`

- `WriteFacade`: implicit implementation.
- `ExplicitWriteFacade`: `MethodImpl` explicit override, private body.
- `InheritedWriteFacade`: implementation inherited from `BaseWriter`.
- All writers carry at least one unrelated same-name `set_Value` overload.

审计结果：

- `readonly-audit.md` / `readonly-audit.json`
- `write-audit.md` / `write-audit.json`

重新生成：

```bash
.venv/bin/python tools/make_metadata_samples.py
```
