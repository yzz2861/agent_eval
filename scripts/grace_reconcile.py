#!/usr/bin/env python3
"""Reconcile working-day grace periods with branch/date outage evidence."""
from __future__ import annotations

import argparse
import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any


WEEKDAYS_CN = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]


def parse_date(value: str) -> date:
    return date.fromisoformat(value)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def baseline_identities(baseline: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    identities: dict[tuple[str, str, str], dict[str, Any]] = {}
    for filename, entries in baseline.get("results", {}).items():
        for entry in entries:
            key = (str(entry["type"]), str(entry.get("filename", filename)), str(entry["hashed_secret"]))
            identities[key] = entry
    return identities


def is_working_day(day: date, weekdays: set[int], holidays: set[date]) -> bool:
    return day.isoweekday() in weekdays and day not in holidays


def working_days_from(start: date, weekdays: set[int], holidays: set[date]):
    day = start
    while True:
        if is_working_day(day, weekdays, holidays):
            yield day
        day += timedelta(days=1)


def count_working_days(start_exclusive: date, end_inclusive: date, weekdays: set[int], holidays: set[date]) -> int:
    count = 0
    day = start_exclusive + timedelta(days=1)
    while day <= end_inclusive:
        if is_working_day(day, weekdays, holidays):
            count += 1
        day += timedelta(days=1)
    return count


def nominal_due_date(start: date, allowance: int, weekdays: set[int], holidays: set[date]) -> date:
    for index, day in enumerate(working_days_from(start, weekdays, holidays), start=1):
        if index == allowance:
            return day
    raise AssertionError("unreachable")


def short_hash(value: str) -> str:
    return value[:7] + "..." + value[-7:]


def evaluate_record(
    record: dict[str, Any],
    identities: dict[tuple[str, str, str], dict[str, Any]],
    weekdays: set[int],
    holidays: set[date],
    as_of: date,
) -> dict[str, Any]:
    finding = record["finding"]
    identity_key = (finding["type"], finding["filename"], finding["hashed_secret"])
    if identity_key not in identities:
        raise ValueError(record["id"] + ": finding identity is absent from .secrets.baseline")

    baseline_entry = identities[identity_key]
    baseline_line = baseline_entry.get("line_number")
    requested_line = finding.get("baseline_line_number")
    line_matches = requested_line in (None, baseline_line)

    release_line_ref = record["release_line"]
    if isinstance(release_line_ref, dict):
        release_line_id = release_line_ref["id"]
        release_line_name = release_line_ref["name"]
        branches = set(release_line_ref["branches"])
    else:
        release_line_id = record.get("release_line_id", release_line_ref)
        release_line_name = release_line_ref
        branches = set(record["branches"])
    start = parse_date(record["start_date"])
    allowance = int(record["allowance_working_days"])
    if allowance <= 0:
        raise ValueError(record["id"] + ": allowance_working_days must be positive")

    evidence_rows: list[dict[str, Any]] = []
    seen_bindings: set[tuple[str, date]] = set()
    for raw in record.get("outage_evidence", []):
        branch = str(raw["branch"])
        outage_date = parse_date(str(raw["date"]))
        binding = (branch, outage_date)
        if binding in seen_bindings:
            raise ValueError(record["id"] + ": duplicate branch/date binding " + branch + "#" + outage_date.isoformat())
        seen_bindings.add(binding)
        if branch not in branches:
            raise ValueError(record["id"] + ": evidence branch is outside release line: " + branch)

        verified = raw.get("status") == "verified"
        working = is_working_day(outage_date, weekdays, holidays)
        rows_for_date = [item for item in record.get("outage_evidence", []) if parse_date(str(item["date"])) == outage_date]
        evidence_rows.append({
            "branch": branch,
            "date": outage_date.isoformat(),
            "weekday": WEEKDAYS_CN[outage_date.weekday()],
            "evidence_id": raw["evidence_id"],
            "status": raw.get("status", "unknown"),
            "verified_working_outage": verified and working,
            "treatment": (
                "证据有效；该发布线当日只计一次，合流不重复冲抵"
                if verified and working and len(rows_for_date) > 1
                else "计入暂停工作日"
                if verified and working
                else "未证实或非工作日，不冲抵工作日宽限"
            ),
        })

    counted_evidence = [row for row in evidence_rows if row["verified_working_outage"]]
    paused_dates = sorted({parse_date(row["date"]) for row in counted_evidence})
    paused_set = set(paused_dates)

    schedule: list[dict[str, Any]] = []
    due_date: date | None = None
    billable = 0
    for day in working_days_from(start, weekdays, holidays):
        if day in paused_set:
            day_evidence = [row for row in counted_evidence if row["date"] == day.isoformat()]
            schedule.append({
                "date": day.isoformat(),
                "weekday": WEEKDAYS_CN[day.weekday()],
                "kind": "outage",
                "billable_index": None,
                "evidence_ids": [row["evidence_id"] for row in day_evidence],
                "branch_count": len({row["branch"] for row in day_evidence}),
                "binding_count": len(day_evidence),
            })
            continue

        billable += 1
        kind = "due" if billable == allowance else "work"
        schedule.append({
            "date": day.isoformat(),
            "weekday": WEEKDAYS_CN[day.weekday()],
            "kind": kind,
            "billable_index": billable,
            "evidence_ids": [],
            "branch_count": 0,
            "binding_count": 0,
        })
        if kind == "due":
            due_date = day
            break

    assert due_date is not None
    applied_pause_dates = [day for day in paused_dates if day <= due_date]
    used = sum(
        1 for row in schedule
        if row["billable_index"] is not None and parse_date(row["date"]) <= as_of
    )
    paused_as_of = len([day for day in applied_pause_dates if day <= as_of])
    remaining = max(0, allowance - used)
    state = "exhausted" if due_date <= as_of else "active"
    overdue_days = count_working_days(due_date, as_of, weekdays, holidays) if due_date < as_of else 0
    raw_binding_days = len(counted_evidence)
    deduplicated_pause_days = len(paused_dates)

    return {
        "id": record["id"],
        "release_line_id": release_line_id,
        "release_line": release_line_name,
        "branches": sorted(branches),
        "finding": {
            "type": finding["type"],
            "filename": finding["filename"],
            "hashed_secret": finding["hashed_secret"],
            "baseline_line_number": baseline_line,
            "requested_line_number": requested_line,
            "line_matches_baseline": line_matches,
            "identity_key": identity_key[0] + "|" + identity_key[1] + "|" + identity_key[2],
        },
        "start_date": start.isoformat(),
        "allowance_working_days": allowance,
        "nominal_due_date": nominal_due_date(start, allowance, weekdays, holidays).isoformat(),
        "due_date": due_date.isoformat(),
        "due_weekday": WEEKDAYS_CN[due_date.weekday()],
        "used_working_days_as_of": used,
        "paused_working_days_as_of": paused_as_of,
        "remaining_working_days": remaining,
        "state": state,
        "overdue_working_days_as_of": overdue_days,
        "verified_branch_days": raw_binding_days,
        "deduplicated_pause_days": deduplicated_pause_days,
        "applied_pause_working_days": len(applied_pause_dates),
        "duplicate_days_removed": raw_binding_days - deduplicated_pause_days,
        "evidence": evidence_rows,
        "schedule": schedule,
    }
def identity_cell(record):
    finding = record["finding"]
    line = finding["requested_line_number"] or finding["baseline_line_number"] or "n/a"
    short = finding["hashed_secret"][:7] + "..." + finding["hashed_secret"][-7:]
    return (
        finding["type"] + "<br>"
        + finding["filename"] + ":" + str(line) + "<br>"
        + short
    )


def state_label(state):
    return "已用尽" if state == "exhausted" else "在用"


def summary_table(results):
    lines = [
        "| 宽限记录 | 发布线 | detect-secrets 身份 | 额度 | 基准日已用 | 有效停机 | 剩余 | 状态 | 确定截止日 |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for record in results:
        dedupe = str(record["verified_branch_days"]) + " 绑定→" + str(record["deduplicated_pause_days"]) + " 日"
        if record["duplicate_days_removed"]:
            dedupe += "（核减 " + str(record["duplicate_days_removed"]) + "）"
        used = str(record["used_working_days_as_of"]) + "/" + str(record["allowance_working_days"])
        deadline = record["due_date"] + "（" + record["due_weekday"] + "）"
        lines.append("| " + " | ".join([
            record["id"],
            record["release_line"],
            identity_cell(record),
            str(record["allowance_working_days"]) + " 工作日",
            used,
            dedupe,
            str(record["remaining_working_days"]),
            state_label(record["state"]),
            deadline,
        ]) + " |")
    return "\n".join(lines)


def timetable_table(results, weekdays, holidays, as_of):
    start = min(parse_date(record["start_date"]) for record in results)
    end = max(parse_date(record["due_date"]) for record in results)
    days = []
    for day in working_days_from(start, weekdays, holidays):
        days.append(day)
        if day >= end:
            break

    schedules = {}
    starts = {}
    dues = {}
    for record in results:
        schedules[record["id"]] = {row["date"]: row for row in record["schedule"]}
        starts[record["id"]] = parse_date(record["start_date"])
        dues[record["id"]] = parse_date(record["due_date"])

    headers = ["工作日"] + [record["id"] for record in results]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for day in days:
        day_label = day.isoformat() + " " + WEEKDAYS_CN[day.weekday()]
        if day == as_of:
            day_label += "（基准日）"
        cells = [day_label]
        for record in results:
            record_id = record["id"]
            if day < starts[record_id]:
                cells.append("未起算")
                continue
            row = schedules[record_id].get(day.isoformat())
            if row is None:
                cells.append("已截止 " + record["due_date"][5:] if day > dues[record_id] else "—")
            elif row["kind"] == "outage":
                if row["binding_count"] > 1:
                    cells.append("停机：" + str(row["binding_count"]) + " 个分支绑定，计 1 日")
                else:
                    cells.append("停机：" + ",".join(row["evidence_ids"]))
            elif row["kind"] == "due":
                cells.append("W" + str(row["billable_index"]) + " 用尽/确定截止")
            else:
                cells.append("W" + str(row["billable_index"]))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def evidence_table(results):
    lines = [
        "| 绑定键 branch#date | 宽限记录 | 分支 | 停机日 | 证据 | 状态 | 工作日处理 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for record in results:
        for evidence in record["evidence"]:
            binding = evidence["branch"] + "#" + evidence["date"]
            lines.append("| " + " | ".join([
                binding,
                record["id"],
                evidence["branch"],
                evidence["date"] + "（" + evidence["weekday"] + "）",
                evidence["evidence_id"],
                evidence["status"],
                evidence["treatment"],
            ]) + " |")
    return "\n".join(lines)


def ticket_block(record):
    finding = record["finding"]
    lines = [
        "### " + record["id"],
        "",
        "- 处理结论：宽限记录 **" + record["id"] + "** 已用尽 " + str(record["used_working_days_as_of"]) + "/" + str(record["allowance_working_days"]) + " 个工作日。",
        "- 确定截止日：**" + record["due_date"] + "（" + record["due_weekday"] + "）**；无新证据时不再顺延。",
        "- detect-secrets 身份：" + finding["type"] + " / " + finding["filename"] + ":" + str(finding["requested_line_number"]) + " / " + finding["hashed_secret"] + "。",
        "- 发布线与分支：" + record["release_line"] + " / " + ", ".join(record["branches"]) + "。",
    ]
    if record["overdue_working_days_as_of"]:
        lines.append("- 截至台账基准日已超过截止日 " + str(record["overdue_working_days_as_of"]) + " 个工作日，应立即按例外流程处置。")
    lines.append("- 独立停机证据：")
    for evidence in record["evidence"]:
        lines.append(
            "  - " + evidence["branch"] + "#" + evidence["date"]
            + "（" + evidence["weekday"] + "） → " + evidence["evidence_id"]
            + "，" + evidence["status"] + "；" + evidence["treatment"] + "。"
        )
    path = []
    for row in record["schedule"]:
        if row["kind"] == "outage":
            path.append(row["date"][5:] + " " + row["weekday"] + " 停机")
        elif row["kind"] == "due":
            path.append(row["date"][5:] + " " + row["weekday"] + " W" + str(row["billable_index"]) + " 用尽")
        else:
            path.append(row["date"][5:] + " " + row["weekday"] + " W" + str(row["billable_index"]))
    lines.append("- 工作日路径：" + " → ".join(path) + "。")
    return lines


def render_report(ledger, results, weekdays, holidays, as_of):
    lines = [
        "# 宽限期延期核对报告",
        "",
        "核对基准日：" + as_of.isoformat() + "（" + WEEKDAYS_CN[as_of.weekday()] + "）；工作日为周一至周五，节假日集合来自台账。",
    ]
    if ledger.get("notice"):
        lines += ["", "> " + ledger["notice"]]
    lines += ["", "## 总览", "", summary_table(results)]
    lines += [
        "", "## 短时间表", "",
        "Wn 表示第 n 个实际消耗的整改工作日；停机日持有按分支和日期绑定的已证实证据，不推进 Wn。",
        "", timetable_table(results, weekdays, holidays, as_of),
        "", "周末和台账 holidays 中的日期不是工作日；基准日之后的 Wn 和截止日为按当前证据生成的确定排期。",
    ]
    lines += ["", "## 停线证据绑定", "", evidence_table(results)]
    if ledger.get("dedupe_note"):
        lines += ["", "> " + ledger["dedupe_note"]]
    exhausted = [record for record in results if record["state"] == "exhausted"]
    lines += ["", "## 审核单：用尽记录", ""]
    if not exhausted:
        lines.append("基准日没有宽限记录用尽。")
    for record in exhausted:
        lines += ticket_block(record) + [""]
    active = [record for record in results if record["state"] != "exhausted"]
    lines += ["## 未用尽记录", ""]
    for record in active:
        lines.append(
            "- " + record["id"] + "：已用 " + str(record["used_working_days_as_of"]) + "/" + str(record["allowance_working_days"])
            + "，剩余 " + str(record["remaining_working_days"]) + " 工作日；当前确定截止日 " + record["due_date"]
            + "（" + record["due_weekday"] + "）。"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", default="compliance/grace_ledger.json")
    parser.add_argument("--baseline", default=".secrets.baseline")
    parser.add_argument("--json-out", default="compliance/grace-reconciliation.json")
    parser.add_argument("--markdown-out", default="compliance/grace_audit_report.md")
    args = parser.parse_args()

    ledger_path = Path(args.ledger)
    baseline_path = Path(args.baseline)
    ledger = load_json(ledger_path)
    baseline = load_json(baseline_path)
    calendar = ledger["calendar"]
    weekdays = {int(value) for value in calendar["working_weekdays"]}
    holidays = {parse_date(value) for value in calendar.get("holidays", [])}
    as_of = parse_date(ledger["as_of"])
    identities = baseline_identities(baseline)
    results = [
        evaluate_record(record, identities, weekdays, holidays, as_of)
        for record in ledger["grace_records"]
    ]

    json_out = Path(args.json_out)
    markdown_out = Path(args.markdown_out)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    payload = {"as_of": ledger["as_of"], "results": results}
    json_out.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    markdown_out.write_text(render_report(ledger, results, weekdays, holidays, as_of), encoding="utf-8")
    print("wrote " + str(markdown_out) + " and " + str(json_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
