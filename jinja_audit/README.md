# Jinja 用户模板发布预审（离线）

面向“调用方维护一份用户可用模板允许名单”的场景。正式渲染之前，预审器只解析模板源码与 AST，
不加载模板加载器、不执行渲染、不访问网络，回答两个问题：

1. 入口模板沿 extends / include / import / from-import 会触及哪些引用，哪些必须人工复核？
2. 给定允许名单与历史批准，这个入口当前能不能发布？

## 三种可判定程度

每个模板名表达式被归为三类（Resolution）：

- static：字符串常量，离线即可确定唯一目标，例如 include "footer.html"。
- candidates：有限候选集合，逐一检查每一个值，来源有两种：
  - Jinja 字面量列表：include ["card_a.html", "card_b.html"]；
  - 宿主显式声明的变量域：candidates={"entry.html": {"theme": ["dark.html", "light.html"]}}，
    对应 include theme。
- unknown：拼接、过滤器、函数调用、属性访问、未声明变量等无法离线界定的表达式，
  例如 include theme ~ ".html"。此时宿主必须明确挂起（hold），不能猜测。

## 发布决策

audit_entry(...) 返回 AuditReport，决策取最严重级别：

- reject：模板无法解析、入口/目标缺失或不在允许名单、没有批准、批准已失效；
- hold：存在无法界定的模板名表达式，等待宿主对该分支做出决定；
- release：闭包内每个可达模板都在允许名单上，且批准的版本哈希与当前内容完全一致。

include ... ignore missing 的缺失目标降级为 warning；普通缺失仍是 error。

## 批准随版本失效

build_approval 对审批时刻的整个传递闭包逐一记录 SHA-256 内容哈希。闭包中任何模板发生改动
（包括两层 include 深处的文件）都会产生 approval.stale，旧批准立即失效，必须重新复核并签发新批准。
批准只对其签发的入口有效（approval.entry_mismatch）。

## 用法示例

```python
from jinja_audit import TemplateRepository, audit_entry, build_approval

repository = TemplateRepository({
    "entry.html": '{% include "shell.html" %}{% include ["card_a.html", "card_b.html"] %}',
    "shell.html": '{% include "footer.html" %}',
    "footer.html": "footer",
    "card_a.html": "a",
    "card_b.html": "b",
})
allowed = set(repository.sources)
report = audit_entry("entry.html", repository, allowed)  # 无批准 -> reject
approval = build_approval("entry.html", repository, report.closure)
report = audit_entry("entry.html", repository, allowed, approval=approval)  # release
```

## 为什么入口已批准，仍可能不能发布

批准针对的是“入口 + 整个传递闭包的具体内容版本”，而不是入口名字本身。至少四类情况会让一个已批准入口在发布前再次被拦下：

1. 闭包里有模板被改动（哪怕是两层 include 深处的 footer/icons），哈希不再匹配，approval.stale → reject。
2. 多值模板名的某个候选不在允许名单或仓库中，target.not_allowed / template.missing → reject；入口本身在名单上并不能替下游候选背书。
3. 模板名取决于无法离线界定的变量（如 theme ~ ".html" 或未声明域的变量），reference.unbounded → hold，宿主必须显式挂起，或通过 candidates 声明有限取值后重新复核。
4. 批准签发给了另一个入口，approval.entry_mismatch → reject。

## 离线测试

测试位于 tests_jinja_audit/，全部为纯内存、无网络、无文件加载：

- test_references.py：static / candidates / unknown 三态与四种引用构造；
- test_audit_decisions.py：两层 include 闭包遍历、多值候选逐一检查、挂起与声明域解除挂起；
- test_approvals.py：批准缺失、深层改动失效、入口失配、缺失模板与 ignore missing、语法错误、环引用；
- test_release_scenario.py：端到端场景，显式断言“入口已批准仍 hold/reject”以及重新声明域后 release。

运行（使用独立 ini，避免收集器扫描上层受限目录）：

```bash
python3 -m pytest tests_jinja_audit -c tests_jinja_audit/pytest.ini --rootdir=tests_jinja_audit
```
