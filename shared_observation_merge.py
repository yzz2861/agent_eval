"""整改台共享观察合并演示。

两团队为同一组件 gateway-svc 各写一份 CVSS 记录，共享"外部可达"事实，
但各自观察到不同后果。本脚本把事实身份与可继承条件作为明确输入，
用 cvss 库既有计分确认处置后每份风险是否达标，并演示撤销一条共享
观察后待办如何拆开、之前的验收还剩多少有效。
"""

from dataclasses import dataclass, field

from cvss import CVSS3

PASS_THRESHOLD = 7.0  # 达标线：base score < 7.0（低于 High）


@dataclass
class Fact:
    """一条可继承的事实观察，身份由 fact_id 唯一确定。"""

    fact_id: str
    metric: str
    value: str
    evidence: str
    scope_component: str
    revoked: bool = False
    successor: str = ""

    def inheritable_by(self, record):
        """可继承条件：同组件且未被撤销。"""
        return self.scope_component == record.component and not self.revoked


@dataclass
class Record:
    """一个团队提交的一份 CVSS 记录。"""

    record_id: str
    team: str
    component: str
    own_metrics: dict
    remediation: dict


@dataclass
class Todo:
    """整改待办。共享事实合并为一项；独立后果各归各的记录。"""

    todo_id: str
    source_key: str
    applies_to: list = field(default_factory=list)
    merged: bool = False


BASE_CONTEXT = {"AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"}

SHARED_FACT = Fact(
    fact_id="F-REACH-001",
    metric="AV",
    value="N",
    evidence="egress-scan-2026-11-19: 443/tcp 对公网开放",
    scope_component="gateway-svc",
)

RECORD_A = Record(
    record_id="R-NET-01",
    team="NET 团队",
    component="gateway-svc",
    own_metrics={"C": "H"},  # 独立后果：机密性泄露
    remediation={"PR": "L", "C": "L"},  # 共享处置(加认证) + 自身处置(脱敏)
)

RECORD_B = Record(
    record_id="R-APP-02",
    team="APP 团队",
    component="gateway-svc",
    own_metrics={"A": "H"},  # 独立后果：可用性崩溃
    remediation={"PR": "L", "A": "L"},  # 共享处置(加认证) + 自身处置(降级保护)
)

SUCCESSOR_FACT = Fact(
    fact_id="F-REACH-002",
    metric="AV",
    value="A",
    evidence="recheck-2026-11-22: 仅相邻网段可达，公网入口已下线",
    scope_component="gateway-svc",
)


def build_vector(record, fact, remediated):
    metrics = dict(BASE_CONTEXT)
    metrics[fact.metric] = fact.value
    metrics.update(record.own_metrics)
    if remediated:
        metrics.update(record.remediation)
    ordered = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    return "CVSS:3.1/" + "/".join("{}:{}".format(k, metrics[k]) for k in ordered)


def score(vector):
    c = CVSS3(vector)
    return c.scores()[0], c.severities()[0]


def merge_todos(records, facts):
    todos = {}
    for fact in facts:
        inheritors = [r.record_id for r in records if fact.inheritable_by(r)]
        if inheritors:
            todos[fact.fact_id] = Todo(
                todo_id="T-SHARED-" + fact.fact_id,
                source_key=fact.fact_id,
                applies_to=inheritors,
                merged=len(inheritors) > 1,
            )
    for record in records:
        for metric in record.own_metrics:
            key = "{}:{}".format(record.record_id, metric)
            todos[key] = Todo(
                todo_id="T-{}-{}".format(record.record_id, metric),
                source_key=key,
                applies_to=[record.record_id],
            )
    return todos


def report_scores(records, fact, label):
    print("== {} ==".format(label))
    results = {}
    for record in records:
        for phase, remediated in (("原始", False), ("处置后", True)):
            vector = build_vector(record, fact, remediated)
            base, severity = score(vector)
            verdict = "达标" if base < PASS_THRESHOLD else "不达标"
            results[(record.record_id, phase)] = (base, verdict)
            print("  {} {} {} -> {} {} ({})".format(
                record.record_id, phase, vector, base, severity, verdict))
    print()
    return results


def main():
    records = [RECORD_A, RECORD_B]

    print("== 明确输入：事实身份与可继承条件 ==")
    print("  共享事实 {}: {}:{} ({})".format(
        SHARED_FACT.fact_id, SHARED_FACT.metric, SHARED_FACT.value, SHARED_FACT.evidence))
    print("  可继承条件: 同组件({}) 且未被撤销".format(SHARED_FACT.scope_component))
    for record in records:
        print("  记录 {} ({}): 继承 {} -> {}, 独立观察 {}".format(
            record.record_id, record.team, SHARED_FACT.fact_id,
            SHARED_FACT.inheritable_by(record), record.own_metrics))
    print()

    before = report_scores(records, SHARED_FACT, "四个虚构向量计分（阈值 base < {}）".format(PASS_THRESHOLD))

    todos = merge_todos(records, [SHARED_FACT])
    print("== 待办合并结果 ==")
    for todo in todos.values():
        kind = "合并待办" if todo.merged else "独立待办"
        print("  {} [{}] 覆盖 {}".format(todo.todo_id, kind, ", ".join(todo.applies_to)))
    print()

    print("== 撤销共享观察 {} ==".format(SHARED_FACT.fact_id))
    SHARED_FACT.revoked = True
    SHARED_FACT.successor = SUCCESSOR_FACT.fact_id
    print("  原事实撤销，继任事实 {}: AV:A ({})".format(
        SUCCESSOR_FACT.fact_id, SUCCESSOR_FACT.evidence))

    todos_after = merge_todos(records, [SHARED_FACT, SUCCESSOR_FACT])
    shared_todos = [t for t in todos_after.values() if t.source_key == SHARED_FACT.fact_id]
    print("  拆分说明: 合并待办 T-SHARED-{} 因事实身份被撤销而解散".format(SHARED_FACT.fact_id))
    print("          （撤销后仍存续的合并待办 {} 项）；两份记录退化为各自独立待办，".format(len(shared_todos)))
    print("          需按继任事实 {} 重新确认后才能再次合并。".format(SUCCESSOR_FACT.fact_id))
    for record in records:
        print("          -> T-{}-AV (独立, 待重新继承 {})".format(
            record.record_id, SUCCESSOR_FACT.fact_id))
    print()

    after = report_scores(records, SUCCESSOR_FACT, "撤销后按继任事实重算")

    accepted_before = [k for k, (_, v) in before.items() if k[1] == "处置后" and v == "达标"]
    still_valid = [k for k in accepted_before if after[k][1] == "达标"]
    print("== 之前验收还剩多少有效 ==")
    print("  处置后已验收记录: {}/{}".format(len(accepted_before), len(records)))
    print("  撤销共享观察后分数仍达标: {}/{}".format(len(still_valid), len(accepted_before)))
    for record in records:
        old = before[(record.record_id, "处置后")][0]
        new = after[(record.record_id, "处置后")][0]
        print("  {}: {} -> {}".format(record.record_id, old, new))
    print("  结论: 分数层面的验收 {}% 保留；但基于 {} 的合并验收证书 0 项继续有效，".format(
        int(100 * len(still_valid) / max(1, len(accepted_before))), SHARED_FACT.fact_id))
    print("        每份记录须按 {} 单独重新验收。".format(SUCCESSOR_FACT.fact_id))


if __name__ == "__main__":
    main()
