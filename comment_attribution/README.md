# 批注离线归属分析

借 oletools 的格式识别（`oleid` + `ooxml.get_type`）与 OOXML 部件读取
（`ooxml.XmlParser`），以 `word/document.xml` 的批注锚点为入口，关联
作者、回复链与文档部件，输出离线归属表（Markdown + JSON）。

## 用法

```sh
.venv/bin/python comment_attribution/make_fixture.py          # 生成测试件
.venv/bin/python comment_attribution/comment_attribution.py \
    comment_attribution/fixtures/sample_comments.docx \
    --out-dir comment_attribution/out                          # 生成归属表
```

## 取证规则

- 局部 ID 不跨部件认人：`w:id` 只在单个部件内有意义；同名作者不合并，
  仅在部件内以 `(initials, paraId, durableId)` 区分。
- 删除过的对象标为历史证据：`comments.xml` 有记录但 `document.xml`
  无锚点的批注不参与现行归属。
- 缺一段引用不能给出肯定归属：`document.xml` 有锚点但 `comments.xml`
  无记录的锚点只报告事实，不下作者结论。
- 每行结论都列出支持它的源部件；`docProps/core.xml` 仅作上下文。

## 测试件覆盖

- 锚点 0 / 1：两位同名"张伟"（initials 分别为 ZW / ZW2）。
- 锚点 2：李四，经 `commentsExtended.xml` 的 `paraIdParent` 回复锚点 0。
- 锚点 99：断开的引用（`comments.xml` 无 id=99）。
- 批注 3：王五，已删除对象（`document.xml` 无锚点），作历史证据。
