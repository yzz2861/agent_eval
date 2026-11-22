"""Short timeline and meeting-ready statistics rendering."""

from __future__ import annotations

from datetime import datetime

from sigma.quota.ledger import WindowLedger
from sigma.quota.types import (
    KIND_ACTIONABLE,
    KIND_CORRECTION,
    KIND_DEDUCTION,
    KIND_DUPLICATE,
    KIND_LATE_REJECTED,
    KIND_WINDOW_CLOSED,
    ReconciliationResult,
    TimelineEntry,
)

_SYMBOLS = {
    KIND_DEDUCTION: "扣减",
    KIND_DUPLICATE: "重复",
    KIND_ACTIONABLE: "待处理",
    KIND_LATE_REJECTED: "迟到",
    KIND_CORRECTION: "回算",
    KIND_WINDOW_CLOSED: "关窗",
}


def _fmt_time(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.strftime("%H:%M:%S")


def _fmt_window(entry: TimelineEntry) -> str:
    if entry.window_start is None or entry.window_end is None:
        return "-"
    return f"{_fmt_time(entry.window_start)}-{_fmt_time(entry.window_end)}"


def render_timeline(result: ReconciliationResult) -> str:
    """Render a compact, human-readable timeline of every reconciliation step."""
    lines = [
        "时间线 (按接收顺序)",
        "----------------",
    ]
    for entry in result.timeline:
        symbol = _SYMBOLS.get(entry.kind, entry.kind)
        event = entry.event_id or "-"
        lines.append(
            f"{_fmt_time(entry.timestamp)} | {symbol:<4} | "
            f"组={entry.group_key} 窗口={_fmt_window(entry)} 事件={event}"
        )
        if entry.detail:
            lines.append(" " * 10 + entry.detail)
    return "\n".join(lines)


def render_window_stats(ledger: WindowLedger) -> str:
    """Render one window ledger showing each deduction and what remains open."""
    lines = [
        (
            f"窗口 {_fmt_time(ledger.window_start)}-{_fmt_time(ledger.window_end)} "
            f"组={ledger.group_key} 额度={ledger.quota}"
        ),
            f"  例外扣减 ({len(ledger.deductions())}):",
    ]
    if ledger.deductions():
        for index, event in enumerate(ledger.deductions(), start=1):
            copies = ledger.copies_by_event.get(event.event_id, 1)
            suffix = f" [{copies} 份副本, 只扣一次]" if copies > 1 else ""
            lines.append(f"    {index}. {event.event_id}{suffix}")
    else:
        lines.append("    (无)")
    lines.append(f"  仍须处理 ({len(ledger.actionable())}):")
    if ledger.actionable():
        for event in ledger.actionable():
            reason = (
                "超额例外"
                if event.exempt
                else "不属例外范围"
            )
            lines.append(f"    - {event.event_id} ({reason})")
    else:
        lines.append("    (无)")
    lines.append(
        f"  去重副本={ledger.duplicate_count()} 独立事件={len(ledger.distinct_events())}"
    )
    return "\n".join(lines)


def render_summary(result: ReconciliationResult) -> str:
    """Aggregate the numbers a review meeting expects across all windows."""
    ledgers = list(result.ledgers.values())
    total_deductions = sum(len(ledger.deductions()) for ledger in ledgers)
    total_actionable = sum(len(ledger.actionable()) for ledger in ledgers)
    total_duplicates = sum(ledger.duplicate_count() for ledger in ledgers)
    lines = [
        "统计汇总",
        "--------",
        f"窗口数: {len(ledgers)}",
        f"例外扣减总次数: {total_deductions}",
        f"仍须处理操作数: {total_actionable}",
        f"被去重的副本数: {total_duplicates}",
        f"迟到拒收数: {len(result.late_rejected)}",
        f"回算修正数: {len(result.corrections)}",
    ]
    return "\n".join(lines)


def render_report(result: ReconciliationResult) -> str:
    """Full offline report: summary, per-window stats, then the short timeline."""
    parts = [render_summary(result), ""]
    for ledger in sorted(
        result.ledgers.values(),
        key=lambda item: (item.group_key, item.window_start),
    ):
        parts.append(render_window_stats(ledger))
        parts.append("")
    parts.append(render_timeline(result))
    return "\n".join(parts)
