from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from pypdf import PdfReader
from pypdf.generic import (
    ArrayObject,
    ContentStream,
    DictionaryObject,
    IndirectObject,
    StreamObject,
)

TICK = chr(96)
CHINESE_WATERMARK = chr(0x6C34) + chr(0x5370)
WATERMARK_NAME_RE = re.compile(
    r"(?:^|[/_.\- ])(wm|watermark|" + re.escape(CHINESE_WATERMARK) + r")(?:$|[/_.\- ])",
    re.IGNORECASE,
)
WATERMARK_BYTES_RE = re.compile(
    rb"water[ _-]?mark|" + re.escape(CHINESE_WATERMARK.encode("utf-8")),
    re.IGNORECASE,
)
MAX_TEXT_EVIDENCE = 12000


def ic(value: Any) -> str:
    return f"{TICK}{value}{TICK}"


def object_id(obj: Any) -> list[int] | None:
    if isinstance(obj, IndirectObject):
        return [obj.idnum, obj.generation]
    reference = getattr(obj, "indirect_reference", None)
    if isinstance(reference, IndirectObject):
        return [reference.idnum, reference.generation]
    return None


def resolve(obj: Any) -> Any:
    return obj.get_object() if isinstance(obj, IndirectObject) else obj


def safe_decode(data: bytes | None) -> str:
    if data is None:
        return ""
    text = data[:MAX_TEXT_EVIDENCE].decode("utf-8", errors="replace")
    if len(data) > MAX_TEXT_EVIDENCE:
        text += f"\n... [truncated {len(data) - MAX_TEXT_EVIDENCE} bytes] ..."
    return text.replace("\x00", "\\x00")


def native_pdf_object(obj: Any, depth: int = 0, seen: set[int] | None = None) -> Any:
    if seen is None:
        seen = set()
    if isinstance(obj, IndirectObject):
        return f"{obj.idnum} {obj.generation} R"
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if depth >= 8:
        return "..."
    marker = id(obj)
    if marker in seen:
        return "<cycle>"
    if isinstance(obj, DictionaryObject):
        seen.add(marker)
        result = {
            str(key): native_pdf_object(value, depth + 1, seen)
            for key, value in obj.items()
        }
        seen.remove(marker)
        return result
    if isinstance(obj, ArrayObject):
        return [native_pdf_object(value, depth + 1, seen) for value in obj]
    if isinstance(obj, bytes):
        return safe_decode(obj)
    return str(obj)


def stream_bytes(obj: Any) -> bytes | None:
    resolved = resolve(obj)
    if isinstance(resolved, StreamObject):
        try:
            return resolved.get_data()
        except Exception as error:  # noqa: BLE001
            return f"[pypdf decode error: {type(error).__name__}: {error}]".encode()
    if isinstance(resolved, ArrayObject):
        chunks = [stream_bytes(child) or b"" for child in resolved]
        return b"\n".join(chunks)
    return None


def content_object_refs(raw_page: DictionaryObject) -> list[dict[str, Any]]:
    if "/Contents" not in raw_page:
        return []
    entry = raw_page.raw_get("/Contents")
    values = entry if isinstance(entry, ArrayObject) else [entry]
    result = []
    for value in values:
        data = stream_bytes(value) or b""
        result.append(
            {
                "object": object_id(value),
                "kind": type(resolve(value)).__name__,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest() if data else None,
                "decoded": safe_decode(data),
            }
        )
    return result


def build_scope_chain(raw_page: DictionaryObject):
    chain = []
    node: Any = raw_page
    forced_node_id: list[int] | None = None
    visited: set[tuple[int, int]] = set()
    effective_resources = None
    effective_from = None

    while isinstance(node, DictionaryObject):
        node_ref = forced_node_id or object_id(node)
        node_key = tuple(node_ref) if node_ref else None
        if node_key and node_key in visited:
            break
        if node_key:
            visited.add(node_key)

        has_resources = "/Resources" in node
        raw_resources = node.raw_get("/Resources") if has_resources else None
        resources = resolve(raw_resources) if raw_resources is not None else None
        chain.append(
            {
                "holder_object": node_ref,
                "holder_type": str(node.get("/Type", "<untyped dictionary>")),
                "has_direct_resources": has_resources,
                "resources_object": object_id(raw_resources) or object_id(resources),
            }
        )
        if has_resources and effective_resources is None and isinstance(resources, DictionaryObject):
            effective_resources = resources
            effective_from = node_ref

        if "/Parent" not in node:
            break
        parent_entry = node.raw_get("/Parent")
        forced_node_id = object_id(parent_entry)
        parent = resolve(parent_entry)
        if not isinstance(parent, DictionaryObject):
            break
        node = parent

    return chain, effective_resources, effective_from


def xobject_declarations(resources: DictionaryObject | None) -> dict[str, dict[str, Any]]:
    declarations = {}
    if resources is None or "/XObject" not in resources:
        return declarations
    xobjects = resolve(resources.raw_get("/XObject"))
    if not isinstance(xobjects, DictionaryObject):
        return declarations

    for name, entry in xobjects.items():
        obj = resolve(entry)
        data = stream_bytes(obj) if isinstance(obj, StreamObject) else None
        reasons = []
        if WATERMARK_NAME_RE.search(name):
            reasons.append(f"resource name matches watermark pattern: {name}")
        if data and WATERMARK_BYTES_RE.search(data):
            reasons.append("decoded stream contains /Watermark marker or watermark text")
        declarations[name] = {
            "name": name,
            "object": object_id(entry) or object_id(obj),
            "subtype": str(obj.get("/Subtype")) if isinstance(obj, DictionaryObject) else None,
            "length": len(data) if data is not None else None,
            "sha256": hashlib.sha256(data).hexdigest() if data else None,
            "watermark_reasons": reasons,
            "is_watermark_candidate": bool(reasons),
            "decoded_stream": safe_decode(data) if data is not None else None,
        }
    return declarations


def resolve_named_xobject(resources, name):
    if resources is None or "/XObject" not in resources:
        return None, None
    xobjects = resolve(resources.raw_get("/XObject"))
    if not isinstance(xobjects, DictionaryObject) or name not in xobjects:
        return None, None
    entry = xobjects.raw_get(name)
    return object_id(entry), resolve(entry)


def operation_marker(operands, operator):
    op = operator.decode("latin1", errors="replace")
    if op in {"BDC", "BMC", "DP"}:
        rendered = native_pdf_object(list(operands))
        serialized = json.dumps(rendered, ensure_ascii=False)
        if "Watermark" in serialized:
            return {"operator": op, "watermark_marked_content": rendered}
    if op in {"Tj", "TJ", "'", '"'}:
        rendered = native_pdf_object(list(operands))
        if WATERMARK_BYTES_RE.search(json.dumps(rendered, ensure_ascii=False).encode()):
            return {"operator": op, "watermark_text": rendered}
    return None


def summarize_direct_operators(content_obj, reader) -> dict[str, Any]:
    try:
        operations = ContentStream(resolve(content_obj), reader).operations
    except Exception as error:  # noqa: BLE001
        return {"parse_error": f"{type(error).__name__}: {error}"}

    counts: dict[str, int] = {}
    graphics_operators = {
        "m", "l", "c", "v", "y", "h", "re", "S", "s", "f", "F",
        "f*", "B", "B*", "b", "b*", "n",
    }
    text_operators = {"BT", "ET", "Tj", "TJ", "'", '"', "Td", "TD", "Tm", "T*"}
    graphics_count = 0
    text_count = 0
    do_count = 0
    for _operands, operator in operations:
        name = operator.decode("latin1", errors="replace")
        counts[name] = counts.get(name, 0) + 1
        if name in graphics_operators:
            graphics_count += 1
        if name in text_operators:
            text_count += 1
        if name == "Do":
            do_count += 1
    return {
        "operator_counts": counts,
        "graphics_operator_count": graphics_count,
        "text_operator_count": text_count,
        "do_count": do_count,
    }


def scan_references(*, content_obj, reader, resources, source, edges, markers, visited, chain):
    try:
        operations = ContentStream(resolve(content_obj), reader).operations
    except Exception as error:  # noqa: BLE001
        markers.append({"source": source, "parse_error": f"{type(error).__name__}: {error}"})
        return

    for index, (operands, operator) in enumerate(operations):
        marker = operation_marker(operands, operator)
        if marker:
            markers.append({"source": source, "operation_index": index, **marker})
        if operator != b"Do" or not operands:
            continue

        name = str(operands[0])
        target_id, target_obj = resolve_named_xobject(resources, name)
        edge = {
            "from": source,
            "operation_index": index,
            "name": name,
            "target_object": target_id,
            "target_subtype": str(target_obj.get("/Subtype")) if isinstance(target_obj, DictionaryObject) else None,
            "reference_chain": [*chain, f"{source['label']} op#{index}: {name} Do"],
        }
        edges.append(edge)

        target_key = tuple(target_id) if target_id else None
        if not isinstance(target_obj, StreamObject) or edge["target_subtype"] != "/Form":
            continue
        if target_key and target_key in visited:
            continue
        if target_key:
            visited.add(target_key)

        form_resources = target_obj.get("/Resources") if "/Resources" in target_obj else resources
        scan_references(
            content_obj=target_obj,
            reader=reader,
            resources=form_resources,
            source={"label": f"Form XObject {name}", "object": target_id},
            edges=edges,
            markers=markers,
            visited=visited,
            chain=edge["reference_chain"],
        )


def audit_pdf(path: Path, receipt=None, receipt_path: Path | None = None) -> dict[str, Any]:
    reader = PdfReader(str(path), strict=False)
    if getattr(reader, "is_encrypted", False):
        reader.decrypt("")

    receipt_pages = {}
    if receipt:
        for claim in receipt.get("page_claims", []):
            receipt_pages[int(claim["page"])] = claim
        for page_number in receipt.get("specified_pages", []):
            receipt_pages.setdefault(int(page_number), {"page": int(page_number), "receipt_status": "specified"})

    pages = []
    proven = []
    resource_only = []
    no_evidence = []
    receipt_claimed = set()
    if receipt:
        receipt_claimed.update(int(page) for page in receipt.get("specified_pages", []))
        receipt_claimed.update(int(claim["page"]) for claim in receipt.get("page_claims", []))

    for page_number, page in enumerate(reader.pages, start=1):
        page_ref = page.indirect_reference
        raw_page = page_ref.get_object() if isinstance(page_ref, IndirectObject) else page
        page_id = object_id(page_ref) or object_id(raw_page)
        scope_chain, effective_resources, effective_from = build_scope_chain(raw_page)
        declarations = xobject_declarations(effective_resources)

        edges = []
        markers = []
        contents = content_object_refs(raw_page)
        content_obj = raw_page.raw_get("/Contents") if "/Contents" in raw_page else None
        direct_content = summarize_direct_operators(content_obj, reader) if content_obj is not None else {}
        if content_obj is not None:
            scan_references(
                content_obj=content_obj,
                reader=reader,
                resources=effective_resources,
                source={"label": "page /Contents", "object": contents[0]["object"] if contents else None},
                edges=edges,
                markers=markers,
                visited=set(),
                chain=[f"page {page_number} object {page_id}"],
            )

        reachable = {tuple(edge["target_object"]) for edge in edges if edge.get("target_object")}
        watermarks = []
        for name, declaration in declarations.items():
            if not declaration["is_watermark_candidate"]:
                continue
            target_key = tuple(declaration["object"]) if declaration["object"] else None
            is_used = target_key in reachable
            watermarks.append(
                {
                    "name": name,
                    "object": declaration["object"],
                    "reachable_from_page_content": is_used,
                    "status": "used" if is_used else "declared_only",
                    "reasons": declaration["watermark_reasons"],
                    "reference_edges": [
                        edge for edge in edges if edge.get("target_object") == declaration["object"]
                    ],
                }
            )

        direct_markers = [m for m in markers if "watermark_marked_content" in m or "watermark_text" in m]
        used = [w for w in watermarks if w["reachable_from_page_content"]]
        declared_only = [w for w in watermarks if not w["reachable_from_page_content"]]
        if used or any("watermark_marked_content" in m for m in direct_markers):
            verdict = "proven_watermark_use"
            proven.append(page_number)
        elif declared_only:
            verdict = "watermark_resource_only_declared"
            resource_only.append(page_number)
        else:
            verdict = "no_watermark_evidence"
            no_evidence.append(page_number)

        pages.append(
            {
                "page_number": page_number,
                "page_object": page_id,
                "verdict": verdict,
                "receipt_claim": receipt_pages.get(page_number),
                "raw_page_dictionary": native_pdf_object(raw_page),
                "contents": contents,
                "direct_content": direct_content,
                "resource_scope_chain": scope_chain,
                "effective_resources_from_holder": effective_from,
                "xobject_declarations": list(declarations.values()),
                "content_do_edges": edges,
                "watermark_findings": watermarks,
                "watermark_markers": markers,
                "direct_watermark_markers": direct_markers,
            }
        )

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pdf": str(path),
        "pdf_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "page_count": len(reader.pages),
        "summary": {
            "proven_watermark_pages": proven,
            "resource_only_pages": resource_only,
            "no_watermark_evidence_pages": no_evidence,
        },
        "receipt_review": {
            "claimed_pages": sorted(receipt_claimed),
            "supported_claims": sorted(receipt_claimed & set(proven)),
            "unsupported_claims_resource_only": sorted(receipt_claimed & set(resource_only)),
            "unsupported_claims_no_evidence": sorted(receipt_claimed & set(no_evidence)),
            "proven_but_not_claimed": sorted(set(proven) - receipt_claimed) if receipt else [],
        }
        if receipt
        else None,
        "receipt": receipt,
        "receipt_path": str(receipt_path) if receipt_path else None,
        "pages": pages,
    }


def code_block(text: str) -> str:
    return "~~~~\n" + text + "\n~~~~\n"


def render_page_markdown(report, page) -> str:
    pdf_path = report["pdf"]
    lines = [f"# 页内水印证据：第 {page['page_number']} 页", ""]
    lines += [f"- 档案：{ic(pdf_path)}", f"- PDF SHA-256：{ic(report['pdf_sha256'])}"]
    page_obj = page["page_object"]
    lines.append(f"- 页面对象：{ic(f'{page_obj[0]} {page_obj[1]} R')}")
    lines.append(f"- 判定：**{page['verdict']}**")
    if page.get("receipt_claim"):
        lines.append(f"- 回执声明：{ic(json.dumps(page['receipt_claim'], ensure_ascii=False))}")
    lines += ["", "## 1. 页面身份与资源作用域", ""]
    for index, scope in enumerate(page["resource_scope_chain"], 1):
        holder = scope["holder_object"]
        holder_text = f"{holder[0]} {holder[1]} R" if holder else "<direct/unknown>"
        resources = scope["resources_object"]
        resources_text = f"{resources[0]} {resources[1]} R" if resources else "无 /Resources"
        lines.append(
            f"{index}. 持有者 {ic(holder_text)}（{scope['holder_type']}）；"
            f"自有 /Resources={ic(scope['has_direct_resources'])}；"
            f"资源对象={ic(resources_text)}"
        )
    effective = page.get("effective_resources_from_holder")
    if effective:
        lines.append(f"- 生效资源由持有者 {ic(f'{effective[0]} {effective[1]} R')} 提供。")

    lines += ["", "## 2. 水印对象与真实引用", ""]
    if not page["watermark_findings"]:
        lines.append("- 未发现按名称或流内 /Watermark 标记可识别的水印 XObject。")
    for item in page["watermark_findings"]:
        obj = item["object"]
        obj_text = f"{obj[0]} {obj[1]} R" if obj else "<unknown>"
        lines.append(f"- {ic(item['name'])} -> {ic(obj_text)}：**{item['status']}**")
        for reason in item["reasons"]:
            lines.append(f"  - 识别依据：{reason}")
        for edge in item.get("reference_edges", []):
            lines.append(f"  - 引用链：{ic(' -> '.join(edge['reference_chain']))}")
        if not item["reachable_from_page_content"]:
            lines.append("  - 内容流没有对应的 Do 操作；仅声明资源，不能证明水印被绘制。")

    lines += ["", "## 3. Do 操作与水印标记", ""]
    direct = page.get("direct_content", {})
    if direct:
        lines.append(
            "- 页面直写操作统计："
            f"图形/路径 {ic(direct.get('graphics_operator_count', 0))} 个，"
            f"文本 {ic(direct.get('text_operator_count', 0))} 个，"
            f"Do {ic(direct.get('do_count', 0))} 个。"
        )
        lines.append(f"- 操作计数：{ic(json.dumps(direct.get('operator_counts', {}), ensure_ascii=False))}")
    if not page["content_do_edges"]:
        lines.append("- 本页静态内容流未发现任何 Do XObject 调用。")
    for edge in page["content_do_edges"]:
        target = edge["target_object"]
        target_text = f"{target[0]} {target[1]} R" if target else "未解析"
        lines.append(
            f"- 操作 #{edge['operation_index']}：{ic(edge['name'] + ' Do')} -> "
            f"{ic(target_text)}（{edge.get('target_subtype')}）"
        )
    for marker in page["direct_watermark_markers"]:
        lines.append(f"- 水印标记：{ic(json.dumps(marker, ensure_ascii=False))}")

    lines += ["", "## 4. 解码后的页内流", ""]
    for content in page["contents"]:
        obj = content.get("object")
        obj_text = f"{obj[0]} {obj[1]} R" if obj else "<direct>"
        lines.append(
            f"内容对象 {ic(obj_text)}，{content['bytes']} bytes，"
            f"SHA-256 {ic(content['sha256'] or '')}："
        )
        lines.append(code_block(content["decoded"]))
    for declaration in page["xobject_declarations"]:
        if declaration.get("decoded_stream"):
            obj = declaration["object"]
            obj_text = f"{obj[0]} {obj[1]} R" if obj else "<unknown>"
            lines.append(f"XObject {ic(declaration['name'])} -> {ic(obj_text)} 解码流：")
            lines.append(code_block(declaration["decoded_stream"]))

    lines += ["## 5. 原始页面对象", "", code_block(json.dumps(page["raw_page_dictionary"], ensure_ascii=False, indent=2))]
    lines += ["## 6. 独立复核命令", "", "~~~~bash",
              "PYTHONPATH=. .venv/bin/python watermark_audit/audit_watermarks.py audit "
              f"--pdf {report['pdf']}"
              + (f" --receipt {report['receipt_path']}" if report.get("receipt_path") else ""),
              "~~~~", ""]
    return "\n".join(lines)


def write_outputs(report, out_dir: Path):
    target_dir = out_dir / Path(report["pdf"]).stem
    target_dir.mkdir(parents=True, exist_ok=True)
    written = []
    json_path = target_dir / "audit_report.json"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    written.append(json_path)

    for page in report["pages"]:
        stem = f"page_{page['page_number']:02d}_object_{page['page_object'][0]}"
        md_path = target_dir / f"{stem}_evidence.md"
        md_path.write_text(render_page_markdown(report, page), encoding="utf-8")
        written.append(md_path)
        for index, content in enumerate(page["contents"], 1):
            stream_path = target_dir / f"{stem}_content_{index}.txt"
            stream_path.write_text(content["decoded"], encoding="utf-8")
            written.append(stream_path)

    combined = target_dir / "SHARED_TEMPLATE_EVIDENCE.md"
    combined.write_text(
        "# 两页共用模板：水印引用对照证据\n\n"
        + "\n\n---\n\n".join(render_page_markdown(report, page) for page in report["pages"]),
        encoding="utf-8",
    )
    written.append(combined)

    summary_path = out_dir / "REVIEW_REPORT.md"
    lines = [
        "# 水印回执复核汇总",
        "",
        f"- 档案：{ic(report['pdf'])}",
        f"- 页数：{report['page_count']}",
        f"- 可证明使用水印：{ic(report['summary']['proven_watermark_pages'])}",
        f"- 只声明水印资源：{ic(report['summary']['resource_only_pages'])}",
        f"- 未发现水印特征：{ic(report['summary']['no_watermark_evidence_pages'])}",
        "",
        "| 页码 | 页对象 | 判定 | 实际引用 | 只声明资源 |",
        "|---:|---|---|---|---|",
    ]
    review = report.get("receipt_review")
    if review:
        lines = lines[:8] + [
            "## 回执裁决",
            "",
            f"- 回执声称页面：{ic(review['claimed_pages'])}",
            f"- 证据支持：{ic(review['supported_claims'])}",
            f"- 仅资源声明、不支持已应用：{ic(review['unsupported_claims_resource_only'])}",
            f"- 无证据、不支持已应用：{ic(review['unsupported_claims_no_evidence'])}",
            "",
            "## 逐页判定",
            "",
            "| 页码 | 页对象 | 判定 | 实际引用 | 只声明资源 |",
            "|---:|---|---|---|---|",
        ] + lines[10:]
    for page in report["pages"]:
        used = ", ".join(w["name"] for w in page["watermark_findings"] if w["reachable_from_page_content"]) or "—"
        declared = ", ".join(w["name"] for w in page["watermark_findings"] if not w["reachable_from_page_content"]) or "—"
        obj = page["page_object"]
        lines.append(
            f"| {page['page_number']} | {ic(f'{obj[0]} {obj[1]} R')} | "
            f"{page['verdict']} | {used} | {declared} |"
        )
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    written.append(summary_path)
    return written


def load_receipt(path: Path | None):
    return json.loads(path.read_text(encoding="utf-8")) if path else None


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit")
    audit.add_argument("--pdf", type=Path, required=True)
    audit.add_argument("--receipt", type=Path)
    audit.add_argument("--out", type=Path, default=PROJECT_ROOT / "watermark_audit" / "evidence")
    args = parser.parse_args()
    report = audit_pdf(
        args.pdf,
        load_receipt(args.receipt),
        receipt_path=args.receipt,
    )
    written = write_outputs(report, args.out)
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    for path in written:
        print(path.relative_to(PROJECT_ROOT))


if __name__ == "__main__":
    main()
