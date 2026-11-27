"""Re-audit incident keystore backups against declared collection scopes.

Reads the *public* certificate view of each JKS backup with pyjks (trusted
certificate entries plus private-key certificate chains; no private key is
decrypted) and cross-checks it, in time order, against the scope each
collection event declared. For the target certificate every collection is
classified into one of three evidence classes:

* observed         -- 确有观察: the certificate is positively seen.
* absent_in_scope  -- 能证明在声明范围内缺席: the declared scope is fully
                      accounted for and the certificate is not in it.
* inconclusive     -- 无法排除: a scope gap means "not found" proves nothing.

Alias renames are bridged by the public certificate identity (SHA-256 of
the DER encoding), not by alias strings.
"""

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jks

HERE = Path(__file__).resolve().parent
FIXTURES_DIR = HERE / "fixtures"
REPORTS_DIR = HERE / "reports"

EVIDENCE_OBSERVED = "observed"
EVIDENCE_ABSENT_IN_SCOPE = "absent_in_scope"
EVIDENCE_INCONCLUSIVE = "inconclusive"

EVIDENCE_LABELS = {
    EVIDENCE_OBSERVED: "确有观察",
    EVIDENCE_ABSENT_IN_SCOPE: "能证明在声明范围内缺席",
    EVIDENCE_INCONCLUSIVE: "无法排除",
}

STRENGTH_LABELS = {"strong": "强", "weak": "弱"}


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def public_cert_view(path, store_password):
    """Return {alias: [{"sha256":..., "source":..., "timestamp":...}]}

    Only public material is read: trusted certificate entries and the
    certificate chains of private key entries. Private keys themselves
    are never decrypted.
    """
    store = jks.KeyStore.load(str(path), store_password)
    view = {}

    def add(alias, der, source, timestamp):
        view.setdefault(alias, []).append({
            "sha256": sha256_hex(der),
            "source": source,
            "timestamp": timestamp,
        })

    for alias, cert in store.certs.items():
        add(alias, cert.cert, "trusted_cert", cert.timestamp)
    for alias, key in store.private_keys.items():
        for cert_type, der in key.cert_chain:
            add(alias, der, "private_key_chain:" + cert_type, key.timestamp)
    return view


def view_fingerprints(view):
    return {alias: sorted({item["sha256"] for item in items})
            for alias, items in view.items()}


@dataclass
class CollectionFinding:
    collection_id: str
    at: str
    backup_id: str
    backup_taken_at: str
    temporal_ok: bool
    declared_scope: list
    scope_gap: list
    uncovered_present_aliases: list
    scope_complete: bool
    target_aliases_in_backup: list
    target_in_declared_scope: bool
    record_missing: list
    record_extra: list
    record_consistent: bool
    evidence: list = field(default_factory=list)


@dataclass
class CaseAudit:
    case: str
    summary: str
    target: dict
    mandated_aliases: list
    backups: list
    target_sightings: dict
    alias_renames: list
    findings: list
    conclusion: dict


def _audit_collection(col, backup, view, mandated, target_fp):
    aliases_present = set(view)
    scope = list(col["declared_scope"])
    scope_set = set(scope)
    scope_gap = sorted(set(mandated) - scope_set)
    uncovered_present = sorted(aliases_present - scope_set)
    scope_complete = not scope_gap and not uncovered_present

    target_aliases = sorted(
        alias for alias, fps in view_fingerprints(view).items()
        if target_fp in fps
    )
    target_in_scope = any(a in scope_set for a in target_aliases)

    recorded = {(r["alias"], r["sha256"]) for r in col["recorded_observations"]}
    actual = {(alias, fp)
              for alias, fps in view_fingerprints(view).items()
              if alias in scope_set for fp in fps}
    record_missing = sorted(actual - recorded)
    record_extra = sorted(recorded - actual)
    record_consistent = not record_missing and not record_extra

    finding = CollectionFinding(
        collection_id=col["id"],
        at=col["at"],
        backup_id=backup["id"],
        backup_taken_at=backup["taken_at"],
        temporal_ok=col["at"] >= backup["taken_at"],
        declared_scope=scope,
        scope_gap=scope_gap,
        uncovered_present_aliases=uncovered_present,
        scope_complete=scope_complete,
        target_aliases_in_backup=target_aliases,
        target_in_declared_scope=target_in_scope,
        record_missing=sorted(record_missing),
        record_extra=sorted(record_extra),
        record_consistent=record_consistent,
    )

    evidence = []
    if target_aliases:
        aliases_text = ", ".join(target_aliases)
        if target_in_scope and not any(fp == target_fp for a, fp in recorded):
            evidence.append((EVIDENCE_OBSERVED,
                             "目标证书在声明范围内的别名 %s 下，但采集记录遗漏" % aliases_text))
        else:
            evidence.append((EVIDENCE_OBSERVED,
                             "复审在备份 %s 的公开证书视图中直接观察到目标证书（别名 %s）"
                             % (backup["id"], aliases_text)))
        if not target_in_scope:
            evidence.append((EVIDENCE_INCONCLUSIVE,
                             "目标证书所在别名 %s 不在声明范围内，该次“未找到”不能排除其存在"
                             % aliases_text))
    else:
        if record_consistent:
            evidence.append((EVIDENCE_ABSENT_IN_SCOPE,
                             "声明范围内的公开证书视图与采集记录一致，目标证书确不在声明范围内"))
        if scope_complete and record_consistent:
            evidence.append((EVIDENCE_ABSENT_IN_SCOPE,
                             "声明范围覆盖全部规定别名且与备份实际内容一致（完整盘点单），"
                             "范围内缺席即整体缺席"))
        elif not scope_complete:
            gap = sorted(set(scope_gap) | set(uncovered_present))
            evidence.append((EVIDENCE_INCONCLUSIVE,
                             "声明范围存在缺口（%s），即使记录为“未找到”也无法排除目标证书"
                             "藏于未采集别名" % ", ".join(gap)))
    if not record_consistent:
        evidence.append((EVIDENCE_INCONCLUSIVE,
                         "采集记录与公开证书视图不一致（缺失 %d 条、多出 %d 条），"
                         "记录可信度受损" % (len(record_missing), len(record_extra))))
    finding.evidence = evidence
    return finding


def audit_case(case_dir):
    case_dir = Path(case_dir)
    manifest = json.loads((case_dir / "manifest.json").read_text())
    target_fp = manifest["target_certificate"]["sha256"]
    mandated = manifest["mandated_aliases"]
    password = manifest.get("store_password", "")

    backups = sorted(manifest["backups"], key=lambda b: b["taken_at"])
    views = {b["id"]: public_cert_view(case_dir / b["file"], password)
             for b in backups}

    sightings = {}
    for b in backups:
        aliases = sorted(
            alias for alias, fps in view_fingerprints(views[b["id"]]).items()
            if target_fp in fps
        )
        if aliases:
            sightings[b["id"]] = aliases

    renames = []
    sighted = [(b["taken_at"], b["id"], sightings[b["id"]])
               for b in backups if b["id"] in sightings]
    for (t_prev, _, aliases_prev), (t_next, _, aliases_next) in zip(sighted, sighted[1:]):
        if aliases_prev != aliases_next:
            renames.append(
                "%s → %s（同一公开证书指纹 %s…，跨备份接上）"
                % (", ".join(aliases_prev), ", ".join(aliases_next), target_fp[:12]))

    backups_by_id = {b["id"]: b for b in backups}
    findings = [
        _audit_collection(col, backups_by_id[col["backup"]],
                          views[col["backup"]], mandated, target_fp)
        for col in sorted(manifest["collections"], key=lambda c: c["at"])
    ]

    conclusion = _conclude(manifest, backups, sightings, findings)
    return CaseAudit(
        case=manifest["case"],
        summary=manifest["summary"],
        target=manifest["target_certificate"],
        mandated_aliases=mandated,
        backups=[dict(b, aliases=sorted(views[b["id"]])) for b in backups],
        target_sightings=sightings,
        alias_renames=renames,
        findings=findings,
        conclusion=conclusion,
    )


def _conclude(manifest, backups, sightings, findings):
    timeline = []
    for b in backups:
        if b["id"] in sightings:
            timeline.append({
                "at": b["taken_at"],
                "class": EVIDENCE_OBSERVED,
                "detail": "备份 %s 公开证书视图中观察到目标证书（别名 %s）"
                          % (b["id"], ", ".join(sightings[b["id"]])),
            })
    for f in findings:
        classes = {cls for cls, _ in f.evidence}
        if EVIDENCE_OBSERVED in classes and f.target_in_declared_scope:
            cls = EVIDENCE_OBSERVED
        elif EVIDENCE_INCONCLUSIVE in classes:
            cls = EVIDENCE_INCONCLUSIVE
        elif EVIDENCE_ABSENT_IN_SCOPE in classes:
            cls = EVIDENCE_ABSENT_IN_SCOPE
        else:
            cls = EVIDENCE_OBSERVED
        timeline.append({
            "at": f.at,
            "class": cls,
            "detail": "采集 %s（备份 %s）：%s"
                      % (f.collection_id, f.backup_id, EVIDENCE_LABELS[cls]),
        })
    timeline.sort(key=lambda e: e["at"])

    proven_absent = [f for f in findings
                     if not f.target_aliases_in_backup
                     and f.scope_complete and f.record_consistent]
    inconclusive = [f for f in findings
                    if any(cls == EVIDENCE_INCONCLUSIVE for cls, _ in f.evidence)]

    if sightings and not proven_absent:
        outcome = EVIDENCE_OBSERVED
        headline = ("复审在 %d 份备份的公开证书视图中直接观察到目标证书；"
                    "历史“未找到”记录对应的采集均存在范围缺口，"
                    "旧证书缺席的结论不成立。" % len(sightings))
        absence_strength = "weak"
    elif sightings and proven_absent:
        outcome = "observed_then_absent"
        last_seen = max(b["taken_at"] for b in backups if b["id"] in sightings)
        first_proof = min(f.at for f in proven_absent)
        headline = ("目标证书曾于 %s 确有观察；自 %s 起的完整盘点单可证明其已不在"
                    "声明范围（即全量）之内，缺席结论成立。" % (last_seen, first_proof))
        absence_strength = "strong"
    elif proven_absent and not inconclusive:
        outcome = EVIDENCE_ABSENT_IN_SCOPE
        headline = "各次采集均为完整盘点单且与公开证书视图一致，能证明目标证书在声明范围内缺席。"
        absence_strength = "strong"
    else:
        outcome = EVIDENCE_INCONCLUSIVE
        headline = "采集声明范围存在缺口，现有记录无法排除目标证书的存在。"
        absence_strength = "weak"

    return {
        "headline": headline,
        "outcome": outcome,
        "historical_absence_strength": absence_strength,
        "timeline": timeline,
    }


def render_markdown(audit):
    lines = []
    add = lines.append
    target = audit.target
    add("# 事故复审报告：%s" % audit.case)
    add("")
    add("- 案情：%s" % audit.summary)
    add("- 目标证书：%s" % target["label"])
    add("- 公开身份（证书 DER 的 SHA-256）：%s" % target["sha256"])
    add("- 规定别名清单：%s" % ", ".join(audit.mandated_aliases))
    add("")
    add("## 备份与别名时间线")
    add("")
    add("| 备份 | 时间 | 公开证书视图中的别名 | 目标证书 |")
    add("| --- | --- | --- | --- |")
    for b in audit.backups:
        sighted = audit.target_sightings.get(b["id"])
        mark = "观察到（别名 %s）" % ", ".join(sighted) if sighted else "未出现"
        add("| %s | %s | %s | %s |"
            % (b["id"], b["taken_at"], ", ".join(b["aliases"]), mark))
    add("")
    if audit.alias_renames:
        add("别名变更（靠公开证书身份接上，与别名字符串无关）：")
        for rename in audit.alias_renames:
            add("- %s" % rename)
        add("")
    add("## 采集逐条核对")
    for f in audit.findings:
        add("")
        add("### 采集 %s（%s，依据备份 %s）" % (f.collection_id, f.at, f.backup_id))
        temporal = "采集时间晚于备份时间，时序正常" if f.temporal_ok \
            else "采集时间早于备份时间，时序异常"
        add("- 时序核对：%s（备份时间 %s）" % (temporal, f.backup_taken_at))
        add("- 声明范围：%s" % ", ".join(f.declared_scope))
        if f.scope_complete:
            add("- 范围核对：完整盘点单，覆盖全部规定别名及备份实际内容")
        else:
            add("- 范围缺口：规定别名未覆盖 %s；备份中实际未覆盖别名 %s"
                % (", ".join(f.scope_gap) or "无",
                   ", ".join(f.uncovered_present_aliases) or "无"))
        consistency = "一致" if f.record_consistent \
            else "不一致（缺失 %s；多出 %s）" % (f.record_missing, f.record_extra)
        add("- 记录与公开证书视图核对：%s" % consistency)
        add("- 证据：")
        for cls, detail in f.evidence:
            add("  - 【%s】%s" % (EVIDENCE_LABELS[cls], detail))
    add("")
    add("## 结论")
    add("")
    conclusion = audit.conclusion
    add("- %s" % conclusion["headline"])
    add("- 历史缺席结论的证据强度：%s"
        % STRENGTH_LABELS[conclusion["historical_absence_strength"]])
    add("- 证据时间线：")
    for entry in conclusion["timeline"]:
        add("  - %s 【%s】%s"
            % (entry["at"], EVIDENCE_LABELS[entry["class"]], entry["detail"]))
    add("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", nargs="*",
                        help="fixture case directories (default: all under fixtures/)")
    parser.add_argument("--reports-dir", default=str(REPORTS_DIR))
    args = parser.parse_args(argv)

    case_dirs = [Path(c) for c in args.cases] if args.cases \
        else sorted(p for p in FIXTURES_DIR.iterdir() if p.is_dir())
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(exist_ok=True)

    for case_dir in case_dirs:
        audit = audit_case(case_dir)
        report = render_markdown(audit)
        report_path = reports_dir / (audit.case + ".md")
        report_path.write_text(report, encoding="utf-8")
        print("%s: %s" % (audit.case, audit.conclusion["headline"]))
        print("  历史缺席结论证据强度：%s；报告 -> %s"
              % (STRENGTH_LABELS[audit.conclusion["historical_absence_strength"]],
                 report_path))


if __name__ == "__main__":
    main()
