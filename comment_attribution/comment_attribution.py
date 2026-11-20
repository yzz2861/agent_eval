#!/usr/bin/env python3
"""OOXML 批注离线归属分析。

以 document.xml 中的批注锚点（w:commentRangeStart）为入口，关联：
- word/comments.xml         批注本体（作者、时间、paraId）
- word/commentsExtended.xml 回复关系（paraIdParent）
- word/commentsIds.xml      持久 ID（durableId）

取证规则：
1. 局部 ID 不跨部件认人：w:id 只在单个部件内有意义；同名作者不合并，
   仅在部件内用 (author, initials, paraId, durableId) 区分。
2. 删除过的对象标为历史证据：comments.xml 有记录但 document.xml
   无锚点的批注，不参与现行归属。
3. 缺一段引用不能给出肯定归属：document.xml 有锚点但 comments.xml
   无对应记录的锚点，只报告事实，不下作者结论。

格式识别借 oletools.oleid + oletools.ooxml.get_type，
OOXML 部件读取借 oletools.ooxml.XmlParser。
"""

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                os.pardir))

from oletools.oleid import OleID               # noqa: E402
from oletools.ooxml import XmlParser, get_type  # noqa: E402

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W14 = "http://schemas.microsoft.com/office/word/2010/wordml"
W15 = "http://schemas.microsoft.com/office/word/2012/wordml"
W16CID = "http://schemas.microsoft.com/office/word/2016/wordml/cid"
CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
DC = "http://purl.org/dc/elements/1.1/"

PART_DOCUMENT = "word/document.xml"
PART_COMMENTS = "word/comments.xml"
PART_COMMENTS_EX = "word/commentsExtended.xml"
PART_COMMENTS_IDS = "word/commentsIds.xml"
PART_CORE = "docProps/core.xml"

WANTED_PARTS = [PART_DOCUMENT, PART_COMMENTS, PART_COMMENTS_EX,
                PART_COMMENTS_IDS, PART_CORE]


def qn(ns, local):
    return "{%s}%s" % (ns, local)


def identify_format(path):
    """用 oleid 指标 + ooxml.get_type 做格式识别。"""
    oleid = OleID(path)
    indicators = []
    for ind in oleid.check():
        indicators.append({
            "id": ind.id,
            "name": ind.name,
            "value": ind.value if isinstance(ind.value, (str, bool, int))
                     else repr(ind.value),
        })
    return {
        "ooxml_type": get_type(path),
        "oleid": indicators,
    }


def read_parts(path):
    """用 oletools.ooxml.XmlParser 读取目标部件，返回 {part: root}。"""
    parser = XmlParser(path)
    parts = {}
    available = set()
    for name, handle in parser.iter_files():
        available.add(name)
    for part in WANTED_PARTS:
        if part not in available:
            continue
        for name, handle in parser.iter_files([part]):
            parts[name] = ET.parse(handle).getroot()
    return parts, sorted(available)


def parse_anchors(root):
    """document.xml 中的锚点：commentRangeStart/End、commentReference。"""
    anchors = {}
    for elem in root.iter():
        if elem.tag == qn(W, "commentRangeStart"):
            kind = "rangeStart"
        elif elem.tag == qn(W, "commentRangeEnd"):
            kind = "rangeEnd"
        elif elem.tag == qn(W, "commentReference"):
            kind = "reference"
        else:
            continue
        cid = elem.get(qn(W, "id"))
        anchors.setdefault(cid, set()).add(kind)
    return {cid: sorted(kinds) for cid, kinds in anchors.items()}


def parse_comments(root):
    """comments.xml 中的批注本体。"""
    comments = {}
    for c in root.iter(qn(W, "comment")):
        cid = c.get(qn(W, "id"))
        para_id = None
        texts = []
        for p in c.iter(qn(W, "p")):
            if para_id is None:
                para_id = p.get(qn(W14, "paraId"))
            for t in p.iter(qn(W, "t")):
                texts.append(t.text or "")
        comments[cid] = {
            "author": c.get(qn(W, "author")),
            "initials": c.get(qn(W, "initials")),
            "date": c.get(qn(W, "date")),
            "paraId": para_id,
            "text": "".join(texts),
        }
    return comments


def parse_comments_ex(root):
    """commentsExtended.xml：paraId -> {paraIdParent, done}。"""
    ex = {}
    for c in root.iter(qn(W15, "commentEx")):
        ex[c.get(qn(W15, "paraId"))] = {
            "paraIdParent": c.get(qn(W15, "paraIdParent")),
            "done": c.get(qn(W15, "done")),
        }
    return ex


def parse_comments_ids(root):
    """commentsIds.xml：paraId -> durableId。"""
    ids = {}
    for c in root.iter(qn(W16CID, "commentId")):
        ids[c.get(qn(W16CID, "paraId"))] = c.get(qn(W16CID, "durableId"))
    return ids


def parse_core(root):
    """docProps/core.xml：文档级元数据（仅上下文，不作批注归属）。"""
    def _text(tag):
        elem = root.find(tag)
        return elem.text if elem is not None else None
    return {
        "creator": _text(qn(DC, "creator")),
        "lastModifiedBy": _text(qn(CP, "lastModifiedBy")),
    }


def build_attribution(parts):
    anchors = parse_anchors(parts[PART_DOCUMENT])
    comments = (parse_comments(parts[PART_COMMENTS])
                if PART_COMMENTS in parts else {})
    comments_ex = (parse_comments_ex(parts[PART_COMMENTS_EX])
                   if PART_COMMENTS_EX in parts else {})
    comments_ids = (parse_comments_ids(parts[PART_COMMENTS_IDS])
                    if PART_COMMENTS_IDS in parts else {})

    para_to_cid = {c["paraId"]: cid for cid, c in comments.items()
                   if c["paraId"]}

    # 同名作者检测：同一 author 名对应多个 (initials, paraId) 组合
    name_groups = {}
    for cid, c in comments.items():
        name_groups.setdefault(c["author"], set()).add(
            (c["initials"], c["paraId"]))
    ambiguous_names = {name for name, keys in name_groups.items()
                       if len(keys) > 1}

    entries = []
    for cid in sorted(anchors, key=lambda x: int(x)):
        anchor_kinds = anchors[cid]
        comment = comments.get(cid)
        if comment is None:
            entries.append({
                "anchor_id": cid,
                "anchor_kinds": anchor_kinds,
                "status": "broken_reference",
                "conclusion": "引用断开：锚点存在但 comments.xml 无记录，"
                              "不能给出肯定归属",
                "source_parts": [PART_DOCUMENT],
                "missing_parts": [PART_COMMENTS],
            })
            continue

        source_parts = [PART_DOCUMENT, PART_COMMENTS]
        para_id = comment["paraId"]
        durable_id = comments_ids.get(para_id)
        if durable_id:
            source_parts.append(PART_COMMENTS_IDS)

        reply_to = None
        ex = comments_ex.get(para_id)
        if ex is not None:
            source_parts.append(PART_COMMENTS_EX)
            parent_para = ex["paraIdParent"]
            if parent_para and parent_para in para_to_cid:
                reply_to = para_to_cid[parent_para]

        notes = []
        if comment["author"] in ambiguous_names:
            notes.append("同名作者×%d：仅在部件内以 "
                         "(initials=%s, paraId=%s) 区分，不跨部件认人"
                         % (len(name_groups[comment["author"]]),
                            comment["initials"], para_id))

        entries.append({
            "anchor_id": cid,
            "anchor_kinds": anchor_kinds,
            "status": "attributed",
            "author": comment["author"],
            "initials": comment["initials"],
            "date": comment["date"],
            "paraId": para_id,
            "durableId": durable_id,
            "reply_to_anchor": reply_to,
            "text": comment["text"],
            "conclusion": "锚点→批注→回复链均有源部件支持" + (
                "；" + "；".join(notes) if notes else ""),
            "source_parts": source_parts,
            "missing_parts": [],
        })

    # 历史证据：comments.xml 有记录但 document.xml 无锚点
    historical = []
    for cid in sorted(comments, key=lambda x: int(x)):
        if cid in anchors:
            continue
        c = comments[cid]
        historical.append({
            "comment_id": cid,
            "status": "historical_evidence",
            "author": c["author"],
            "initials": c["initials"],
            "date": c["date"],
            "text": c["text"],
            "conclusion": "已删除对象（正文锚点缺失），仅作历史证据，"
                          "不参与现行归属",
            "source_parts": [PART_COMMENTS],
            "missing_parts": [PART_DOCUMENT],
        })

    return entries, historical


def render_markdown(report):
    lines = []
    lines.append("# 批注离线归属表")
    lines.append("")
    lines.append("- 文件：`%s`" % report["file"])
    lines.append("- 格式识别：`ooxml.get_type` → `%s`；oleid 指标 %d 项"
                 % (report["format"]["ooxml_type"],
                    len(report["format"]["oleid"])))
    core = report.get("core") or {}
    lines.append("- 文档级元数据（仅上下文，不作批注归属）：creator=%s，"
                 "lastModifiedBy=%s"
                 % (core.get("creator"), core.get("lastModifiedBy")))
    lines.append("")
    lines.append("## 现行批注（以锚点为入口）")
    lines.append("")
    lines.append("| 锚点ID | 作者 | 缩写 | 时间 | 回复 | 结论 | 源部件支持 |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for e in report["entries"]:
        if e["status"] == "broken_reference":
            lines.append("| %s | — | — | — | — | %s | %s |" % (
                e["anchor_id"], e["conclusion"],
                ", ".join("`%s`" % p for p in e["source_parts"])))
            continue
        reply = ("锚点 %s" % e["reply_to_anchor"]
                 if e["reply_to_anchor"] is not None else "—")
        lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            e["anchor_id"], e["author"], e["initials"], e["date"], reply,
            e["conclusion"],
            ", ".join("`%s`" % p for p in e["source_parts"])))
    lines.append("")
    lines.append("## 历史证据（已删除对象）")
    lines.append("")
    if report["historical"]:
        lines.append("| 批注ID | 作者 | 缩写 | 时间 | 结论 | 源部件支持 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for h in report["historical"]:
            lines.append("| %s | %s | %s | %s | %s | %s |" % (
                h["comment_id"], h["author"], h["initials"], h["date"],
                h["conclusion"],
                ", ".join("`%s`" % p for p in h["source_parts"])))
    else:
        lines.append("（无）")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="OOXML 批注离线归属分析")
    ap.add_argument("docx", help="待分析的 .docx 文件")
    ap.add_argument("--out-dir", default=None, help="输出目录（默认仅打印）")
    args = ap.parse_args()

    report = {"file": os.path.basename(args.docx)}
    report["format"] = identify_format(args.docx)
    parts, available = read_parts(args.docx)
    report["parts_present"] = [p for p in WANTED_PARTS if p in parts]
    report["parts_missing"] = [p for p in WANTED_PARTS if p not in parts]
    if PART_CORE in parts:
        report["core"] = parse_core(parts[PART_CORE])
    entries, historical = build_attribution(parts)
    report["entries"] = entries
    report["historical"] = historical

    md = render_markdown(report)
    print(md)

    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        md_path = os.path.join(args.out_dir, "attribution.md")
        json_path = os.path.join(args.out_dir, "attribution.json")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print("written: %s" % md_path)
        print("written: %s" % json_path)


if __name__ == "__main__":
    main()
