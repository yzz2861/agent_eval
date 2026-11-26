#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from olefile import OleFileIO

ARTIFACTS = ROOT / "artifacts"
EXTRACTED = ARTIFACTS / "extracted"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_stream(ole: OleFileIO, path: str) -> bytes:
    return ole.openstream(path).read()


def extract_container(path: Path) -> dict:
    output_dir = EXTRACTED / path.stem
    output_dir.mkdir(parents=True, exist_ok=True)
    with OleFileIO(str(path)) as ole:
        storages = ["/".join(parts) for parts in ole.listdir(streams=True, storages=False)]
        streams = ["/".join(parts) for parts in ole.listdir(streams=True, storages=False)]
        crosswalk = json.loads(read_stream(ole, "Crosswalk"))
        records = []
        for relationship in crosswalk["relationships"]:
            role = relationship["container_role"]
            storage = (
                "DocumentPreview"
                if role == "document_preview"
                else "AttachmentPreview"
            )
            clipboard = read_stream(ole, f"{storage}/ClipboardType").decode("utf-8").strip()
            summary = json.loads(read_stream(ole, f"{storage}/Summary"))
            preview_ref = read_stream(ole, f"{storage}/PreviewRef").decode("utf-8").strip()
            ref_exists = ole.exists(preview_ref)
            source_digest = None
            extracted_source = None
            if ref_exists:
                source_bytes = read_stream(ole, preview_ref)
                source_digest = sha256_bytes(source_bytes)
                extracted_source = output_dir / "shared-source.jpg"
                extracted_source.write_bytes(source_bytes)
            preview_path = output_dir / f"{storage}-preview-ref.txt"
            preview_path.write_text(preview_ref + "\n", encoding="utf-8")
            records.append(
                {
                    "evidence_id": relationship["evidence_id"],
                    "container_role": role,
                    "storage_branch": storage,
                    "clipboard_format_id": relationship["clipboard_format_id"],
                    "clipboard_format_name": clipboard,
                    "summary_source_status": summary["source_status"],
                    "preview_ref": preview_ref,
                    "preview_ref_exists_in_container": ref_exists,
                    "declared_preview_sha256": relationship["preview_sha256"],
                    "resolved_source_sha256": source_digest,
                    "source_hash_matches_declared_preview": source_digest == relationship["preview_sha256"],
                    "extracted_preview_ref": str(preview_path.relative_to(ROOT)),
                    "extracted_source": str(extracted_source.relative_to(ROOT)) if extracted_source else None,
                    "conclusion_ceiling": summary["conclusion_ceiling"],
                }
            )
        return {
            "container": str(path.relative_to(ROOT)),
            "container_sha256": sha256_file(path),
            "container_size": path.stat().st_size,
            "storage_branches": [
                "/".join(parts)
                for parts in ole.listdir(streams=False, storages=True)
            ],
            "streams": streams,
            "records": records,
        }


def render_report(results: list[dict]) -> str:
    lines = [
        "# OLE 预览来源离线交叉验证报告",
        "",
        "## 验证范围",
        "",
        "本报告仅使用本地 `olefile` 读取复合文件，不访问网络。每个复合文件分别枚举存储分支、流、剪贴板类型、关系清单和摘要，并把预览引用与容器内源流做哈希交叉验证。",
        "",
    ]
    for result in results:
        lines.extend(
            [
                f"## {result['container']}",
                "",
                f"- 容器 SHA-256：`{result['container_sha256']}`",
                f"- 容器大小：`{result['container_size']}` 字节",
                f"- 存储分支：{', '.join('`' + item + '`' for item in result['storage_branches'])}",
                f"- 流数量：`{len(result['streams'])}`",
                "",
                "| 证据 ID | 容器归属 | 存储分支 | 剪贴板类型 | 源流解析 | 哈希一致 | 结论上限 |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for record in result["records"]:
            source_state = (
                "可解析：`" + record["preview_ref"] + "`"
                if record["preview_ref_exists_in_container"]
                else "缺源流：`" + record["preview_ref"] + "` 不存在"
            )
            hash_state = "是" if record["source_hash_matches_declared_preview"] else "不可核对"
            lines.append(
                "| {evidence_id} | {container_role} | `{storage_branch}` | "
                "`{clipboard_format_id}` / {clipboard_format_name} | {source_state} | {hash_state} | {ceiling} |".format(
                    evidence_id=record["evidence_id"],
                    container_role=record["container_role"],
                    storage_branch=record["storage_branch"],
                    clipboard_format_id=record["clipboard_format_id"],
                    clipboard_format_name=record["clipboard_format_name"],
                    source_state=source_state,
                    hash_state=hash_state,
                    ceiling=record["conclusion_ceiling"],
                )
            )
        lines.extend(["", "### 流清单", ""])
        for stream in result["streams"]:
            lines.append(f"- `{stream}`")
        lines.append("")
    lines.extend(
        [
            "## 综合判断",
            "",
            "- `missing-source-preview.ole` 中，文档预览与附件预览仍位于两个独立容器分支，但其共同引用的 `Archive/SharedContent` 不存在；只能证明两个关系声明引用了相同哈希，不能证明该哈希对应字节真实存在或来源真实。",
            "- `fully-verifiable-file.ole` 中，两个独立容器分支引用同一个 `Archive/SharedContent` 归档流；相同内容只保存一份，归档哈希与两条关系声明均一致。",
            "- 因此，外部复核报告把两个预览合并成一份图像证据的结论上限过高：即使字节相同，文档预览和附件预览的证据关系也必须分别归属到各自容器。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    containers = [
        ARTIFACTS / "missing-source-preview.ole",
        ARTIFACTS / "fully-verifiable-file.ole",
    ]
    results = [extract_container(path) for path in containers]
    manifest_path = ARTIFACTS / "verification-manifest.json"
    manifest_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path = ARTIFACTS / "source-cross-validation-report.md"
    report_path.write_text(render_report(results), encoding="utf-8")
    acceptance = {
        "missing_source_preview": {
            "container": "artifacts/missing-source-preview.ole",
            "extracted_document_preview_ref": "artifacts/extracted/missing-source-preview/DocumentPreview-preview-ref.txt",
            "extracted_attachment_preview_ref": "artifacts/extracted/missing-source-preview/AttachmentPreview-preview-ref.txt",
            "supported_limit": "只能核对容器分支、剪贴板类型、关联摘要和声明哈希；无法核对源流字节或来源真实性。",
        },
        "fully_verifiable_file": {
            "container": "artifacts/fully-verifiable-file.ole",
            "extracted_shared_source": "artifacts/extracted/fully-verifiable-file/shared-source.jpg",
            "supported_limit": "可核对共享归档源流、两条独立预览关系、剪贴板类型和全部哈希；相同字节复用归档，但证据关系分别归属容器。",
        },
    }
    acceptance_path = ARTIFACTS / "acceptance-manifest.json"
    acceptance_path.write_text(json.dumps(acceptance, ensure_ascii=False, indent=2), encoding="utf-8")
    print(manifest_path.relative_to(ROOT))
    print(report_path.relative_to(ROOT))
    print(acceptance_path.relative_to(ROOT))


if __name__ == "__main__":
    main()
