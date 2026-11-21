"""离线审查的数据模型：工单评分条件与有来源的排序陈述。"""

import json
from dataclasses import dataclass, field
from datetime import date

SCALES = ("cvss2", "cvss3", "cvss4")

KIND_PRIOR = "prior"  # 前者优先于后者
KIND_SAME_TIER = "same_tier"  # 同档


def _parse_date(value, field_name, statement_id):
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ValueError(
            "陈述 {0} 的 {1} 不是合法日期: {2!r}".format(statement_id, field_name, value)
        )


@dataclass
class Ticket:
    """一条整改工单及其现有评分条件（各量表的 CVSS 向量）。"""

    id: str
    vectors: dict = field(default_factory=dict)  # scale -> CVSS 向量字符串


@dataclass
class Statement:
    """一条有来源的排序陈述。

    kind="prior" 时 objects=[高优先, 低优先]；kind="same_tier" 时 objects
    为两个及以上同档对象。valid_from/valid_to 界定时间窗（含端点），
    valid_to 为 None 表示开放窗口。更新通过新增一条同覆盖对象的陈述完成，
    只影响其覆盖的对象与时间窗，窗口之外的旧陈述仍然有效。
    """

    id: str
    author: str
    kind: str
    objects: tuple
    scale: str
    valid_from: date
    valid_to: date = None
    note: str = ""
    supersedes: str = None

    @property
    def coverage_key(self):
        return frozenset(self.objects)

    def covers_date(self, day):
        if day < self.valid_from:
            return False
        return self.valid_to is None or day <= self.valid_to

    def describe(self):
        if self.kind == KIND_PRIOR:
            return "{0} 优先于 {1}".format(self.objects[0], self.objects[1])
        return "{0} 同档".format("、".join(self.objects))


def load_case(path):
    """从 JSON 文件加载工单与排序陈述，返回 (tickets, statements)。"""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    tickets = {}
    for item in raw.get("tickets", []):
        vectors = item.get("vectors", {})
        unknown = set(vectors) - set(SCALES)
        if unknown:
            raise ValueError("工单 {0} 使用未知量表: {1}".format(item["id"], sorted(unknown)))
        tickets[item["id"]] = Ticket(id=item["id"], vectors=dict(vectors))

    statements = []
    for item in raw.get("statements", []):
        stmt = Statement(
            id=item["id"],
            author=item.get("author", ""),
            kind=item["kind"],
            objects=tuple(item["objects"]),
            scale=item["scale"],
            valid_from=_parse_date(item["valid_from"], "valid_from", item["id"]),
            valid_to=_parse_date(item.get("valid_to"), "valid_to", item["id"]),
            note=item.get("note", ""),
            supersedes=item.get("supersedes"),
        )
        if stmt.kind not in (KIND_PRIOR, KIND_SAME_TIER):
            raise ValueError("陈述 {0} 的 kind 非法: {1!r}".format(stmt.id, stmt.kind))
        if stmt.scale not in SCALES:
            raise ValueError("陈述 {0} 使用未知量表: {1!r}".format(stmt.id, stmt.scale))
        if stmt.kind == KIND_PRIOR and len(stmt.objects) != 2:
            raise ValueError("陈述 {0} 为优先陈述，objects 必须恰好两个".format(stmt.id))
        if stmt.kind == KIND_SAME_TIER and len(stmt.objects) < 2:
            raise ValueError("陈述 {0} 为同档陈述，objects 至少两个".format(stmt.id))
        missing = [obj for obj in stmt.objects if obj not in tickets]
        if missing:
            raise ValueError("陈述 {0} 引用了不存在的工单: {1}".format(stmt.id, missing))
        statements.append(stmt)

    return tickets, statements
