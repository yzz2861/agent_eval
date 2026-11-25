"""离线策略签收审计工具.

多个服务从版本库取相同的 YAML 策略片段, 并分别签收自己消费的安全条款.
维护者调整片段后, 本工具在不加载自定义构造器的前提下, 仅通过 PyYAML 的
节点接口(compose)记录受控标量、锚点与合并引用, 再按调用方提供的消费路径
对比旧、新两份快照, 判定每条签收属于:

- VALID                 语义未变, 签收仍然有效;
- REAPPROVAL_NEEDED     实际依赖发生变化, 需要重新审批;
- INSUFFICIENT_EVIDENCE 证据不足, 无法离线判定(例如旧声明未记录来源).

支持的节点子集(文档化约定, 超出即抛 UnsupportedNodeError):

- 标量节点: 任意 tag, 语义比较基于 (tag, value), 与书写风格、锚点名无关;
- 序列节点: 块式/流式均可, 消费路径下标从 0 开始(如 servers.0.host);
- 映射节点: 键必须是标量且不含 '.', 同一映射内显式键不得重复;
- 锚点与别名: 允许出现在任意上述节点上, 不允许递归引用;
- 合并键 '<<': 值必须是映射锚点的别名, 或由别名组成的序列;
  显式键优先于合并键, 合并序列中先声明者优先;
- 每个快照必须是单文档流.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from yaml.composer import Composer
from yaml.nodes import MappingNode, ScalarNode, SequenceNode
from yaml.parser import Parser
from yaml.reader import Reader
from yaml.resolver import Resolver
from yaml.scanner import Scanner

__all__ = [
    "UnsupportedNodeError",
    "ScalarFact",
    "AnchorFact",
    "MergeFact",
    "ResolvedScalar",
    "Snapshot",
    "Signoff",
    "DependencyReport",
    "ConsumerVerdict",
    "evaluate_signoff",
    "format_report",
    "VALID",
    "REAPPROVAL_NEEDED",
    "INSUFFICIENT_EVIDENCE",
]

MERGE_TAG = "tag:yaml.org,2002:merge"

VALID = "valid"
REAPPROVAL_NEEDED = "reapproval_needed"
INSUFFICIENT_EVIDENCE = "insufficient_evidence"

_UNCHANGED = "unchanged"
_CHANGED = "changed"
_UNKNOWN = "unknown"


class UnsupportedNodeError(Exception):
    """快照中出现文档化节点子集之外的结构."""


class _AnchorComposer(Composer):
    """在标准节点上额外记录锚点名(仅组合, 不构造)."""

    def compose_scalar_node(self, anchor):
        node = super().compose_scalar_node(anchor)
        node.anchor = anchor
        return node

    def compose_sequence_node(self, anchor):
        node = super().compose_sequence_node(anchor)
        node.anchor = anchor
        return node

    def compose_mapping_node(self, anchor):
        node = super().compose_mapping_node(anchor)
        node.anchor = anchor
        return node


class _NodeLoader(Reader, Scanner, Parser, _AnchorComposer, Resolver):
    """只到节点层为止的 Loader: 不含 Constructor, 不会构造任何 Python 对象."""

    def __init__(self, stream):
        Reader.__init__(self, stream)
        Scanner.__init__(self)
        Parser.__init__(self)
        _AnchorComposer.__init__(self)
        Resolver.__init__(self)


@dataclass(frozen=True)
class ScalarFact:
    """受控标量: 出现路径、语义值与书写位置."""

    path: str
    tag: str
    value: str
    anchor: Optional[str]
    line: int
    column: int


@dataclass(frozen=True)
class AnchorFact:
    """锚点定义: 锚点名与其定义处路径."""

    anchor: str
    path: str


@dataclass(frozen=True)
class MergeFact:
    """合并引用: 发起合并的映射路径及被引用的锚点."""

    path: str
    anchors: Tuple[str, ...]
    targets: Tuple[str, ...]


@dataclass(frozen=True)
class ResolvedScalar:
    """消费路径上的生效标量及其来源."""

    path: str
    tag: str
    value: str
    origin: str
    via_anchor: Optional[str]

    def describe(self) -> str:
        parts = ["%r (%s)" % (self.value, self.tag), "定义于 %s" % self.origin]
        if self.via_anchor:
            parts.append("经锚点 %r 合并继承" % self.via_anchor)
        return "; ".join(parts)


def _join(prefix: str, key: str) -> str:
    return key if not prefix else "%s.%s" % (prefix, key)


class Snapshot:
    """一份 YAML 策略片段的节点级快照."""

    def __init__(self, snapshot_id: str):
        self.snapshot_id = snapshot_id
        self.scalars: List[ScalarFact] = []
        self.anchors: Dict[str, AnchorFact] = {}
        self.merges: List[MergeFact] = []
        self.effective: Dict[str, ResolvedScalar] = {}
        self._anchor_nodes: Dict[str, object] = {}

    @classmethod
    def record(cls, source: str, snapshot_id: str) -> "Snapshot":
        """从 YAML 文本记录快照(仅节点接口, 不调用构造器)."""
        loader = _NodeLoader(source)
        try:
            root = loader.get_single_node()
        finally:
            loader.dispose()
        snapshot = cls(snapshot_id)
        if root is None:
            return snapshot
        snapshot._collect(root, "", ())
        snapshot.merges = [
            MergeFact(path=fact.path, anchors=fact.anchors, targets=tuple(
                snapshot.anchors[anchor].path for anchor in fact.anchors))
            for fact in snapshot.merges
        ]
        snapshot._resolve(root, "", "", None, ())
        return snapshot

    def _collect(self, node, path, ancestry):
        """第一遍: 记录受控标量、锚点与合并引用, 并校验节点子集."""
        if id(node) in ancestry:
            raise UnsupportedNodeError("路径 %r 处出现递归别名, 超出支持的节点子集" % path)
        ancestry = ancestry + (id(node),)
        anchor = getattr(node, "anchor", None)
        if anchor is not None and anchor not in self.anchors:
            self.anchors[anchor] = AnchorFact(anchor, path)
            self._anchor_nodes[anchor] = node
        if isinstance(node, ScalarNode):
            mark = node.start_mark
            self.scalars.append(ScalarFact(
                path=path, tag=node.tag, value=node.value, anchor=anchor,
                line=mark.line + 1 if mark else 0,
                column=mark.column + 1 if mark else 0,
            ))
        elif isinstance(node, SequenceNode):
            for index, item in enumerate(node.value):
                self._collect(item, _join(path, str(index)), ancestry)
        elif isinstance(node, MappingNode):
            seen_keys = set()
            for key_node, value_node in node.value:
                if not isinstance(key_node, ScalarNode):
                    raise UnsupportedNodeError(
                        "路径 %r 处映射键不是标量, 超出支持的节点子集" % path)
                if key_node.tag == MERGE_TAG:
                    anchors = self._merge_anchors(value_node, path)
                    self.merges.append(MergeFact(path=path, anchors=anchors, targets=()))
                    continue
                key = key_node.value
                if "." in key:
                    raise UnsupportedNodeError(
                        "映射键 %r 含 '.', 无法用于消费路径定位" % key)
                if key in seen_keys:
                    raise UnsupportedNodeError(
                        "路径 %r 处显式键 %r 重复" % (path, key))
                seen_keys.add(key)
                self._collect(value_node, _join(path, key), ancestry)
        else:
            raise UnsupportedNodeError("路径 %r 处节点类型不受支持" % path)

    def _merge_anchors(self, value_node, path) -> Tuple[str, ...]:
        """校验合并值形态, 返回被引用的锚点名."""
        if isinstance(value_node, MappingNode) and getattr(value_node, "anchor", None):
            return (value_node.anchor,)
        if isinstance(value_node, SequenceNode):
            anchors = []
            for item in value_node.value:
                if not (isinstance(item, MappingNode) and getattr(item, "anchor", None)):
                    raise UnsupportedNodeError(
                        "路径 %r 处合并序列只允许映射锚点别名" % path)
                anchors.append(item.anchor)
            return tuple(anchors)
        raise UnsupportedNodeError(
            "路径 %r 处合并键 << 仅支持映射锚点别名或别名序列" % path)

    def _mapping_entries(self, node, base_path, merge_chain):
        """求映射节点的有效键集: key -> (值节点, 定义处路径, 来源锚点)."""
        explicit: Dict[str, tuple] = {}
        merged: Dict[str, tuple] = {}
        for key_node, value_node in node.value:
            if key_node.tag == MERGE_TAG:
                for anchor in self._merge_anchors(value_node, base_path):
                    target = self._anchor_nodes.get(anchor)
                    if target is None:
                        raise UnsupportedNodeError(
                            "路径 %r 处合并引用了未记录的锚点 %r" % (base_path, anchor))
                    if id(target) in merge_chain:
                        raise UnsupportedNodeError(
                            "路径 %r 处合并引用形成循环" % base_path)
                    target_path = self.anchors[anchor].path
                    sub = self._mapping_entries(
                        target, target_path, merge_chain + (id(target),))
                    for key, entry in sub.items():
                        if key not in merged:
                            value, origin, via = entry
                            merged[key] = (value, origin, via or anchor)
                continue
            key = key_node.value
            explicit[key] = (value_node, _join(base_path, key), None)
        entries = dict(merged)
        entries.update(explicit)
        return entries

    def _resolve(self, node, path, origin, via_anchor, ancestry):
        """第二遍: 计算每条消费路径上的生效标量及其来源."""
        if id(node) in ancestry:
            raise UnsupportedNodeError("路径 %r 处出现递归别名, 超出支持的节点子集" % path)
        ancestry = ancestry + (id(node),)
        if isinstance(node, ScalarNode):
            self.effective[path] = ResolvedScalar(
                path=path, tag=node.tag, value=node.value,
                origin=origin, via_anchor=via_anchor)
        elif isinstance(node, SequenceNode):
            for index, item in enumerate(node.value):
                self._resolve(item, _join(path, str(index)),
                              _join(origin, str(index)), via_anchor, ancestry)
        elif isinstance(node, MappingNode):
            for key, (value_node, entry_origin, entry_via) in \
                    self._mapping_entries(node, origin, (id(node),)).items():
                self._resolve(value_node, _join(path, key), entry_origin,
                              entry_via or via_anchor, ancestry)

    def resolve(self, path: str) -> Optional[ResolvedScalar]:
        """返回消费路径上的生效标量, 不存在时返回 None."""
        return self.effective.get(path)


@dataclass(frozen=True)
class Signoff:
    """消费方的签收声明.

    sources 为 None 表示旧声明未记录消费来源路径.
    """

    consumer: str
    snapshot_id: Optional[str]
    sources: Optional[Tuple[str, ...]]


@dataclass
class DependencyReport:
    """单条消费路径的核对结果."""

    path: str
    status: str
    old: Optional[ResolvedScalar]
    new: Optional[ResolvedScalar]
    note: str = ""


@dataclass
class ConsumerVerdict:
    """单个消费方的签收判定."""

    consumer: str
    status: str
    dependencies: List[DependencyReport] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    @property
    def triggering_dependencies(self) -> List[str]:
        """导致需要重新审批的依赖路径."""
        return [d.path for d in self.dependencies if d.status == _CHANGED]


def evaluate_signoff(signoff: Signoff, old: Snapshot, new: Snapshot) -> ConsumerVerdict:
    """按消费路径对比旧、新快照, 判定签收是否仍然有效."""
    if not signoff.sources:
        return ConsumerVerdict(
            consumer=signoff.consumer,
            status=INSUFFICIENT_EVIDENCE,
            reasons=["签收声明未记录消费来源路径, 无法离线核对"],
        )
    if signoff.snapshot_id is None or signoff.snapshot_id != old.snapshot_id:
        return ConsumerVerdict(
            consumer=signoff.consumer,
            status=INSUFFICIENT_EVIDENCE,
            reasons=["签收声明的快照标识 %r 与旧快照 %r 不一致"
                     % (signoff.snapshot_id, old.snapshot_id)],
        )
    dependencies: List[DependencyReport] = []
    for path in signoff.sources:
        old_entry = old.resolve(path)
        new_entry = new.resolve(path)
        if old_entry is None:
            dependencies.append(DependencyReport(
                path=path, status=_UNKNOWN, old=None, new=new_entry,
                note="旧快照中不存在该消费路径, 缺少比对基准"))
        elif new_entry is None:
            dependencies.append(DependencyReport(
                path=path, status=_CHANGED, old=old_entry, new=None,
                note="新快照中该依赖已被移除"))
        elif (old_entry.tag, old_entry.value) == (new_entry.tag, new_entry.value):
            dependencies.append(DependencyReport(
                path=path, status=_UNCHANGED, old=old_entry, new=new_entry))
        else:
            dependencies.append(DependencyReport(
                path=path, status=_CHANGED, old=old_entry, new=new_entry,
                note="生效值发生变化"))
    if any(d.status == _CHANGED for d in dependencies):
        status = REAPPROVAL_NEEDED
    elif any(d.status == _UNKNOWN for d in dependencies):
        status = INSUFFICIENT_EVIDENCE
    else:
        status = VALID
    return ConsumerVerdict(consumer=signoff.consumer, status=status,
                           dependencies=dependencies)


def _describe_entry(entry: Optional[ResolvedScalar]) -> str:
    return entry.describe() if entry is not None else "<缺失>"


def format_report(verdicts: List[ConsumerVerdict]) -> str:
    """把判定结果格式化为可定位依赖的文本报告."""
    labels = {
        VALID: "签收有效(语义未变)",
        REAPPROVAL_NEEDED: "需要重新审批",
        INSUFFICIENT_EVIDENCE: "证据不足, 需人工核对",
    }
    lines: List[str] = []
    for verdict in verdicts:
        lines.append("[%s] %s" % (verdict.consumer, labels[verdict.status]))
        for reason in verdict.reasons:
            lines.append("  原因: %s" % reason)
        for dep in verdict.dependencies:
            if dep.status == _CHANGED:
                lines.append("  变更依赖 %s:" % dep.path)
                lines.append("    旧值: %s" % _describe_entry(dep.old))
                lines.append("    新值: %s" % _describe_entry(dep.new))
                if dep.note:
                    lines.append("    说明: %s" % dep.note)
            elif dep.status == _UNKNOWN:
                lines.append("  无法核对依赖 %s: %s" % (dep.path, dep.note))
            else:
                lines.append("  未变依赖 %s: %s" % (dep.path, _describe_entry(dep.new)))
    return "\n".join(lines)
