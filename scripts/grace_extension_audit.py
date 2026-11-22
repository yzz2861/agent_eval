#!/usr/bin/env python3
"""延期核对:用 .secrets.baseline 的既有发现身份 + 本地台账 remediation_ledger.json
核算每条发布线实际使用的宽限期,生成审核单 extension_audit.md。

规则:
- 宽限期按工作日计(周一至周五,可配节假日),自 discovery_date 起算。
- 已证实停机日暂停整改计时;停线证据按 (分支, 日期) 独立绑定。
- 分支合流后,共享发现身份(hashed_secret)去重减重;同一暂停日只冲抵一次。
"""
import argparse
import json
from datetime import date, timedelta

DAY_NAMES = ['周一', '周二', '周三', '周四', '周五', '周六', '周日']


def parse_day(text):
    return date.fromisoformat(text)


def is_workday(day, holidays):
    return day.weekday() < 5 and day not in holidays


def workdays_between(start, end, holidays):
    """[start, end] 内的工作日列表。"""
    days = []
    current = start
    while current <= end:
        if is_workday(current, holidays):
            days.append(current)
        current += timedelta(days=1)
    return days


def load_baseline_identities(path):
    """从 baseline 提取发现身份: hashed_secret -> 位置与插件类型。"""
    with open(path) as f:
        baseline = json.load(f)
    identities = {}
    for filename, results in baseline['results'].items():
        for item in results:
            entry = identities.setdefault(
                item['hashed_secret'],
                {'locations': [], 'types': []},
            )
            entry['locations'].append(f"{filename}:{item['line_number']}")
            if item['type'] not in entry['types']:
                entry['types'].append(item['type'])
    return identities


def resolve_merges(ledger):
    """应用合流:源分支的发现与停机日并入目标分支,返回 (存活线, 合流记录)。"""
    lines = {}
    for branch in ledger['branches']:
        seen = set()
        downtime = {}
        for item in branch['downtime']:
            key = item['date']
            if key in seen:
                raise ValueError(
                    f"{branch['name']} 的停机证据重复绑定日期 {key}",
                )
            seen.add(key)
            downtime[key] = item['evidence']
        lines[branch['name']] = {
            'findings': list(branch['findings']),
            'downtime': downtime,
        }

    merge_notes = []
    for merge in ledger.get('merges', []):
        source = lines.pop(merge['source'])
        target = lines[merge['target']]
        before = len(target['findings'])
        shared = sorted(set(target['findings']) & set(source['findings']))
        target['findings'] = sorted(set(target['findings']) | set(source['findings']))
        deduped = before + len(source['findings']) - len(target['findings'])
        overlapped_pause = sorted(
            set(target['downtime']) & set(source['downtime']),
        )
        for day, evidence in source['downtime'].items():
            target['downtime'].setdefault(day, evidence)
        merge_notes.append({
            'source': merge['source'],
            'target': merge['target'],
            'date': merge['date'],
            'shared_findings': shared,
            'deduped_count': deduped,
            'overlapped_pause_days': overlapped_pause,
        })
    return lines, merge_notes


def audit_line(name, line, policy, holidays):
    discovery = parse_day(policy['discovery_date'])
    audit_date = parse_day(policy['audit_date'])
    grace = policy['grace_workdays']

    pause_days = {}
    for day_text, evidence in sorted(line['downtime'].items()):
        day = parse_day(day_text)
        if not is_workday(day, holidays):
            continue
        pause_days[day] = evidence

    elapsed = workdays_between(discovery, audit_date, holidays)
    paused_elapsed = [d for d in elapsed if d in pause_days]
    consumed = len(elapsed) - len(paused_elapsed)

    # 截止日: 自发现日起累计 grace 个"非停机工作日"的日期
    deadline = None
    counted = 0
    current = discovery
    while counted < grace:
        if is_workday(current, holidays) and current not in pause_days:
            counted += 1
            deadline = current
        current += timedelta(days=1)

    return {
        'name': name,
        'finding_count': len(line['findings']),
        'elapsed_workdays': len(elapsed),
        'pause_days': pause_days,
        'consumed': consumed,
        'remaining': grace - consumed,
        'exhausted': consumed >= grace,
        'deadline': deadline,
    }


def fmt(day):
    return f"{day.isoformat()} {DAY_NAMES[day.weekday()]}"


def render_report(policy, identities, lines, merge_notes, audits):
    holidays = {parse_day(d) for d in policy['holidays']}
    discovery = parse_day(policy['discovery_date'])
    audit_date = parse_day(policy['audit_date'])
    grace = policy['grace_workdays']

    out = []
    out.append('# 延期核对审核单')
    out.append('')
    out.append(f"- 发现基线: `.secrets.baseline`(既有发现身份 {len(identities)} 个,按 hashed_secret 去重)")
    out.append(f"- 台账: `remediation_ledger.json`;宽限期 {grace} 个工作日,自 {fmt(discovery)} 起算")
    out.append(f"- 核对基准日: {fmt(audit_date)}")
    out.append('')

    out.append('## 合流减重')
    for note in merge_notes:
        shared = ', '.join(h[:12] + '…' for h in note['shared_findings']) or '无'
        out.append(
            f"- `{note['source']}` → `{note['target']}`({note['date']}):"
            f"共享发现 {shared} 去重 {note['deduped_count']} 项;"
        )
        for day in note['overlapped_pause_days']:
            out.append(
                f"  - 暂停日 {day} 两分支均有证据,只冲抵一次(不重复计)"
            )
    out.append('')

    out.append('## 各发布线宽限核算')
    out.append('')
    out.append('| 发布线 | 待审项 | 已过工作日 | 停机扣减 | 已用宽限 | 剩余 | 状态 | 确定截止日 |')
    out.append('| --- | --- | --- | --- | --- | --- | --- | --- |')
    for audit in audits:
        status = '**宽限用尽**' if audit['exhausted'] else '计时有宽限'
        out.append(
            f"| `{audit['name']}` | {audit['finding_count']} | "
            f"{audit['elapsed_workdays']} | {len(audit['pause_days'])} | "
            f"{audit['consumed']}/{grace} | {max(audit['remaining'], 0)} | "
            f"{status} | {fmt(audit['deadline'])} |"
        )
    out.append('')

    out.append('## 短时间表(工作日 / 停机日)')
    out.append('')
    header = '| 日期 | 星期 | 类型 | ' + ' | '.join(a['name'] for a in audits) + ' |'
    out.append(header)
    out.append('| --- | --- | --- | ' + ' | '.join('---' for _ in audits) + ' |')
    last_day = max(a['deadline'] for a in audits)
    current = discovery
    while current <= max(last_day, audit_date):
        kind = '工作日' if is_workday(current, holidays) else '周末'
        marks = []
        for audit in audits:
            if current in audit['pause_days']:
                marks.append(f"停机({audit['pause_days'][current].split()[0]})")
            elif is_workday(current, holidays):
                marks.append('计时')
            else:
                marks.append('—')
        out.append(
            f"| {current.isoformat()} | {DAY_NAMES[current.weekday()]} | {kind} | "
            + ' | '.join(marks) + ' |'
        )
        current += timedelta(days=1)
    out.append('')

    out.append('## 结论')
    for audit in audits:
        if audit['exhausted']:
            out.append(
                f"- `{audit['name']}` 的宽限记录**已用尽**"
                f"(截止 {fmt(audit['deadline'])},核对日已用 "
                f"{audit['consumed']}/{grace} 个工作日),应立即整改或升级审批。"
            )
        else:
            out.append(
                f"- `{audit['name']}` 处理后确定截止日为 **{fmt(audit['deadline'])}**"
                f"(剩余宽限 {audit['remaining']} 个工作日)。"
            )
    out.append('')
    return '\n'.join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default='.secrets.baseline')
    parser.add_argument('--ledger', default='remediation_ledger.json')
    parser.add_argument('--output', default='extension_audit.md')
    args = parser.parse_args()

    identities = load_baseline_identities(args.baseline)
    with open(args.ledger) as f:
        ledger = json.load(f)

    for branch in ledger['branches']:
        for hashed in branch['findings']:
            if hashed not in identities:
                raise ValueError(f"台账发现 {hashed} 不在 baseline 既有身份中")

    policy = ledger['policy']
    holidays = {parse_day(d) for d in policy['holidays']}
    lines, merge_notes = resolve_merges(ledger)
    audits = [
        audit_line(name, line, policy, holidays)
        for name, line in sorted(lines.items())
    ]

    report = render_report(policy, identities, lines, merge_notes, audits)
    with open(args.output, 'w') as f:
        f.write(report)
    print(f"审核单已生成: {args.output}")
    for audit in audits:
        state = '用尽' if audit['exhausted'] else f"剩余 {audit['remaining']}"
        print(f"  {audit['name']}: 已用 {audit['consumed']}/{policy['grace_workdays']} ({state}), 截止 {audit['deadline']}")


if __name__ == '__main__':
    main()
