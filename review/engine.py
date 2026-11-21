"""审查引擎：对照评分判定排序陈述，并检测陈述组合冲突。"""

from dataclasses import dataclass, field

from cvss import CVSS2, CVSS3, CVSS4

from .model import KIND_PRIOR

_CALCULATORS = {"cvss2": CVSS2, "cvss3": CVSS3, "cvss4": CVSS4}

# 判定结论
CONSISTENT = "consistent"  # 与评分一致
TIE_OK = "tie_ok"  # 可以并列
INVERTED = "inverted"  # 确定倒置
INCOMPARABLE = "incomparable"  # 不同量表不可比较

VERDICT_LABELS = {
    CONSISTENT: "与评分一致",
    TIE_OK: "可以并列",
    INVERTED: "确定倒置",
    INCOMPARABLE: "不同量表不可比较",
}

_EPSILON = 1e-9


@dataclass
class Verdict:
    statement: object
    status: str
    scores: dict = field(default_factory=dict)  # object -> score（仅可比时）
    detail: str = ""


@dataclass
class Conflict:
    statement_ids: tuple
    chain: str  # 可读链条，如 甲 —S1:优先→ 乙 —S2:同档→ 甲


def compute_scores(tickets):
    """按量表计算各工单基础分；无对应向量的工单该量表记为 None。"""
    scores = {}
    for ticket_id, ticket in tickets.items():
        scores[ticket_id] = {}
        for scale, vector in ticket.vectors.items():
            scores[ticket_id][scale] = _CALCULATORS[scale](vector).scores()[0]
    return scores


def resolve_active(statements, as_of):
    """解析基准日生效的陈述。

    同一覆盖对象集合上，时间窗包含基准日且 valid_from 最新的陈述生效；
    其余被遮蔽。更新因此只影响其覆盖的对象与时间窗。
    返回 (active, shadowed)，各自为陈述列表。
    """
    by_coverage = {}
    for stmt in statements:
        if stmt.covers_date(as_of):
            by_coverage.setdefault(stmt.coverage_key, []).append(stmt)

    active, shadowed = [], []
    for candidates in by_coverage.values():
        candidates.sort(key=lambda s: s.valid_from)
        active.append(candidates[-1])
        shadowed.extend(candidates[:-1])
    active.sort(key=lambda s: s.id)
    shadowed.sort(key=lambda s: s.id)
    return active, shadowed


def evaluate_statement(stmt, scores, tolerance):
    """对照评分条件判定单条陈述。"""
    missing = [
        obj for obj in stmt.objects if stmt.scale not in scores.get(obj, {})
    ]
    if missing:
        return Verdict(
            statement=stmt,
            status=INCOMPARABLE,
            detail="工单 {0} 缺少 {1} 评分，量表不同不可比较".format(
                "、".join(missing), stmt.scale
            ),
        )

    obj_scores = {obj: scores[obj][stmt.scale] for obj in stmt.objects}

    if stmt.kind == KIND_PRIOR:
        high, low = stmt.objects
        diff = obj_scores[high] - obj_scores[low]
        detail = "{0} {2:.1f} vs {1} {3:.1f}（{4}）".format(
            high, low, obj_scores[high], obj_scores[low], stmt.scale
        )
        if diff > tolerance + _EPSILON:
            return Verdict(stmt, CONSISTENT, obj_scores, detail)
        if diff < -(tolerance + _EPSILON):
            return Verdict(stmt, INVERTED, obj_scores, detail + "，陈述要求相反")
        return Verdict(stmt, TIE_OK, obj_scores, detail + "，分差在容差内")

    spread = max(obj_scores.values()) - min(obj_scores.values())
    detail = "、".join(
        "{0} {1:.1f}".format(obj, obj_scores[obj]) for obj in stmt.objects
    ) + "（{0}）".format(stmt.scale)
    if spread <= tolerance + _EPSILON:
        return Verdict(stmt, TIE_OK, obj_scores, detail + "，分差在容差内")
    return Verdict(stmt, INVERTED, obj_scores, detail + "，同档陈述被评分拉开")


def _find_conflicts(active):
    """在生效陈述中找出放到一起才冲突的最小陈述组合。

    优先陈述构成有向严格边，同档陈述构成双向边；任何包含至少一条
    严格边的有向环即为一组无法同时成立的陈述。只报告极小组合。
    """
    edges = []  # (src, dst, statement_id, kind)
    nodes = set()
    for stmt in active:
        objs = list(stmt.objects)
        nodes.update(objs)
        if stmt.kind == KIND_PRIOR:
            edges.append((objs[0], objs[1], stmt.id, "优先"))
        else:
            for i, a in enumerate(objs):
                for b in objs[i + 1 :]:
                    edges.append((a, b, stmt.id, "同档"))
                    edges.append((b, a, stmt.id, "同档"))

    adj = {}
    for edge in edges:
        adj.setdefault(edge[0], []).append(edge)

    order = {n: i for i, n in enumerate(sorted(nodes))}
    cycles = []

    def dfs(start, current, visited, path):
        for edge in adj.get(current, []):
            _, dst, _, _ = edge
            if dst == start and path:
                cycles.append(path + [edge])
            elif dst not in visited and order[dst] > order[start]:
                visited.add(dst)
                dfs(start, dst, visited, path + [edge])
                visited.discard(dst)

    for node in sorted(nodes):
        dfs(node, node, {node}, [])

    candidates = {}
    for cycle in cycles:
        if not any(kind == "优先" for _, _, _, kind in cycle):
            continue
        key = frozenset(sid for _, _, sid, _ in cycle)
        if key not in candidates:
            candidates[key] = cycle

    minimal = [
        key
        for key in candidates
        if not any(other < key for other in candidates)
    ]

    conflicts = []
    for key in sorted(minimal, key=lambda k: sorted(k)):
        conflicts.append(
            Conflict(
                statement_ids=tuple(sorted(key)),
                chain=_format_chain(candidates[key]),
            )
        )
    return conflicts


def _format_chain(cycle):
    parts = []
    for src, _, sid, kind in cycle:
        parts.append("{0} —{1}:{2}→".format(src, sid, kind))
    closing = cycle[-1][1]
    return " ".join(parts) + " " + closing


def evaluate_case(tickets, statements, as_of, tolerance=0.0):
    """完整评估：返回评分、生效/被遮蔽陈述、逐条判定与冲突组合。"""
    scores = compute_scores(tickets)
    active, shadowed = resolve_active(statements, as_of)
    verdicts = [evaluate_statement(stmt, scores, tolerance) for stmt in active]
    conflicts = _find_conflicts(active)
    inactive = [
        stmt for stmt in statements if not stmt.covers_date(as_of)
    ]
    inactive.sort(key=lambda s: s.id)
    return {
        "as_of": as_of,
        "tolerance": tolerance,
        "scores": scores,
        "active": active,
        "shadowed": shadowed,
        "inactive": inactive,
        "verdicts": verdicts,
        "conflicts": conflicts,
    }
