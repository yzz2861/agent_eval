#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
MINI_CUTOFF = 4096
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
NOSTREAM = 0xFFFFFFFF
STGTY_STORAGE = 1
STGTY_STREAM = 2
STGTY_ROOT = 5


@dataclass
class Node:
    name: str
    entry_type: int
    data: bytes = b""
    sid: int = -1
    left: int = NOSTREAM
    right: int = NOSTREAM
    child: int = NOSTREAM
    start: int = ENDOFCHAIN
    size: int = 0


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(payload: dict | list) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")


def casefold_name(name: str) -> str:
    return name.lower()


def build_tree(nodes: list[Node]) -> int:
    if not nodes:
        return NOSTREAM
    nodes.sort(key=lambda node: casefold_name(node.name))
    nodes_by_sid = {node.sid: node for node in nodes}
    root_sid = nodes[0].sid

    def insert(parent_sid: int, node: Node) -> None:
        parent = nodes_by_sid[parent_sid]
        if casefold_name(node.name) < casefold_name(parent.name):
            if parent.left == NOSTREAM:
                parent.left = node.sid
            else:
                insert(parent.left, node)
        else:
            if parent.right == NOSTREAM:
                parent.right = node.sid
            else:
                insert(parent.right, node)

    for node in nodes[1:]:
        insert(root_sid, node)
    return root_sid


def directory_entry(node: Node) -> bytes:
    encoded_name = node.name.encode("utf-16-le") + b"\x00\x00"
    if len(encoded_name) > 64:
        raise ValueError(f"directory name too long: {node.name}")
    return struct.pack(
        "<64sHBBIII16sIQQIII",
        encoded_name.ljust(64, b"\x00"),
        len(encoded_name),
        node.entry_type,
        1 if node.entry_type != STGTY_ROOT and node.sid % 2 == 0 else 0,
        node.left,
        node.right,
        node.child,
        b"\x00" * 16,
        0,
        0,
        0,
        node.start,
        node.size & 0xFFFFFFFF,
        node.size >> 32,
    )


def allocate_chain(
    fat: list[int],
    sectors: list[bytes | None],
    data: bytes,
    unit_size: int,
    minimum_sector: int = 2,
) -> tuple[int, list[int]]:
    required_sectors = max(1, (len(data) + unit_size - 1) // unit_size)
    chain: list[int] = []
    while len(chain) < required_sectors:
        sector_id = max(len(fat), minimum_sector)
        while len(fat) < sector_id:
            fat.append(FREESECT)
            sectors.append(b"\x00" * SECTOR_SIZE)
        chain.append(sector_id)
        fat.append(FREESECT)
        sectors.append(b"\x00" * unit_size)
    for index, sector_id in enumerate(chain):
        fat[sector_id] = chain[index + 1] if index + 1 < len(chain) else ENDOFCHAIN
        start = index * unit_size
        chunk = data[start : start + unit_size]
        sectors[sector_id] = chunk.ljust(unit_size, b"\x00")
    return chain[0], chain


def allocate_mini_chain(
    minifat: list[int],
    mini_sectors: list[bytes],
    data: bytes,
) -> int:
    required_sectors = max(1, (len(data) + MINI_SECTOR_SIZE - 1) // MINI_SECTOR_SIZE)
    chain: list[int] = []
    while len(chain) < required_sectors:
        chain.append(len(minifat))
        minifat.append(ENDOFCHAIN)
        mini_sectors.append(b"\x00" * MINI_SECTOR_SIZE)
    for index, sector_id in enumerate(chain):
        minifat[sector_id] = chain[index + 1] if index + 1 < len(chain) else ENDOFCHAIN
        start = index * MINI_SECTOR_SIZE
        mini_sectors[sector_id] = data[start : start + MINI_SECTOR_SIZE].ljust(
            MINI_SECTOR_SIZE, b"\x00"
        )
    return chain[0]


def make_evidence(preview: bytes, source_available: bool) -> dict:
    preview_hash = sha256(preview)
    return {
        "preview_sha256": preview_hash,
        "preview_size": len(preview),
        "source_available": source_available,
        "relationships": [
            {
                "evidence_id": "DOC-PREVIEW-001",
                "container_role": "document_preview",
                "clipboard_format_id": 0xC001,
                "clipboard_format_name": "JPEG",
                "rendering_intent": "document_page_render",
                "preview_archive_ref": "Archive/SharedContent" if source_available else None,
                "preview_sha256": preview_hash,
            },
            {
                "evidence_id": "ATT-PREVIEW-001",
                "container_role": "attachment_preview",
                "clipboard_format_id": 0xC001,
                "clipboard_format_name": "JPEG",
                "rendering_intent": "attachment_thumbnail_render",
                "preview_archive_ref": "Archive/SharedContent" if source_available else None,
                "preview_sha256": preview_hash,
            },
        ],
    }


def summary_for(container_role: str, evidence_id: str, source_available: bool, digest: str) -> dict:
    return {
        "evidence_id": evidence_id,
        "container_role": container_role,
        "clipboard_type": {
            "format_id": "0xC001",
            "registered_name": "JPEG",
            "cf_dib_equivalent": False,
        },
        "source_status": "verifiable_archive_source" if source_available else "source_stream_absent",
        "preview_sha256": digest,
        "conclusion_ceiling": (
            "可证明预览内容及证据关系来源"
            if source_available
            else "仅能证明预览声明和哈希；不能证明源流存在、来源链条或真实性"
        ),
    }


def build_container(output_path: Path, include_source: bool) -> None:
    preview = Path("tests/images/flower.jpg").read_bytes()
    digest = sha256(preview)
    evidence = make_evidence(preview, include_source)
    document_summary = json_bytes(
        summary_for("document_preview", "DOC-PREVIEW-001", include_source, digest)
    )
    attachment_summary = json_bytes(
        summary_for("attachment_preview", "ATT-PREVIEW-001", include_source, digest)
    )

    root = Node("Root Entry", STGTY_ROOT)
    evidence_storage = Node("Evidence", STGTY_STORAGE)
    document_storage = Node("DocumentPreview", STGTY_STORAGE)
    attachment_storage = Node("AttachmentPreview", STGTY_STORAGE)
    archive_storage = Node("Archive", STGTY_STORAGE)
    manifest_node = Node("Crosswalk", STGTY_STREAM, json_bytes(evidence))
    doc_summary_node = Node("Summary", STGTY_STREAM, document_summary)
    att_summary_node = Node("Summary", STGTY_STREAM, attachment_summary)
    doc_clip_node = Node("ClipboardType", STGTY_STREAM, b"JPEG\n")
    att_clip_node = Node("ClipboardType", STGTY_STREAM, b"JPEG\n")
    shared_node = Node("SharedContent", STGTY_STREAM, preview)
    doc_preview_node = Node("PreviewRef", STGTY_STREAM, b"Archive/SharedContent\n")
    att_preview_node = Node("PreviewRef", STGTY_STREAM, b"Archive/SharedContent\n")

    all_nodes = [
        root,
        evidence_storage,
        manifest_node,
        document_storage,
        attachment_storage,
        doc_summary_node,
        doc_clip_node,
        doc_preview_node,
        att_summary_node,
        att_clip_node,
        att_preview_node,
    ]
    root_children = [manifest_node, document_storage, attachment_storage]
    if include_source:
        all_nodes.extend([archive_storage, shared_node])
        root_children.append(archive_storage)
    for sid, node in enumerate(all_nodes):
        node.sid = sid

    root.child = build_tree(root_children)
    document_storage.child = build_tree([doc_clip_node, doc_preview_node, doc_summary_node])
    attachment_storage.child = build_tree([att_clip_node, att_preview_node, att_summary_node])
    if include_source:
        archive_storage.child = build_tree([shared_node])

    small_nodes = [
        node
        for node in all_nodes
        if node.entry_type == STGTY_STREAM and len(node.data) < MINI_CUTOFF
    ]
    minifat: list[int] = []
    mini_sectors: list[bytes] = []
    for node in small_nodes:
        node.start = allocate_mini_chain(minifat, mini_sectors, node.data)
        node.size = len(node.data)

    ministream = b"".join(mini_sectors)
    fat: list[int] = []
    sectors: list[bytes | None] = []
    fat.extend([FREESECT, FREESECT])
    sectors.extend([b"\x00" * SECTOR_SIZE, b"\x00" * SECTOR_SIZE])

    minifat_sector_count = max(1, (len(minifat) * 4 + SECTOR_SIZE - 1) // SECTOR_SIZE)
    minifat_start, _ = allocate_chain(
        fat,
        sectors,
        struct.pack("<" + "I" * len(minifat), *minifat) if minifat else b"",
        SECTOR_SIZE,
    )
    ministream_start, _ = allocate_chain(fat, sectors, ministream, SECTOR_SIZE)

    directory_start, _ = allocate_chain(
        fat, sectors, b"".join(directory_entry(node) for node in all_nodes), SECTOR_SIZE
    )
    for node in all_nodes:
        if node.entry_type == STGTY_STREAM and len(node.data) >= MINI_CUTOFF:
            node.start, _ = allocate_chain(fat, sectors, node.data, SECTOR_SIZE)
            node.size = len(node.data)

    root.start = ministream_start
    root.size = len(ministream)
    directory_data = b"".join(directory_entry(node) for node in all_nodes)
    directory_sector_count = (len(directory_data) + SECTOR_SIZE - 1) // SECTOR_SIZE
    sectors[directory_start : directory_start + directory_sector_count] = [
        directory_data[index : index + SECTOR_SIZE].ljust(SECTOR_SIZE, b"\x00")
        for index in range(0, len(directory_data), SECTOR_SIZE)
    ]
    fat_sector_count = 1
    if len(fat) > 128:
        raise RuntimeError("this minimal writer expects one FAT sector")
    minifat_data = struct.pack("<" + "I" * len(minifat), *minifat)
    for index in range(minifat_sector_count):
        start = index * 128
        minifat_chunk = minifat[start : start + 128]
        padded_minifat = minifat_chunk + [FREESECT] * (128 - len(minifat_chunk))
        sectors[minifat_start + index] = struct.pack("<128I", *padded_minifat)

    difat = [0] + [FREESECT] * 108
    for sector_id in range(fat_sector_count):
        start = sector_id * 128
        fat_chunk = fat[start : start + 128]
        padded_fat = fat_chunk + [FREESECT] * (128 - len(fat_chunk))
        sectors[sector_id] = struct.pack("<128I", *padded_fat)
    header = struct.pack(
        "<8s16sHHHHHHLLLLLLLLLL",
        bytes.fromhex("d0cf11e0a1b11ae1"),
        b"\x00" * 16,
        0x003E,
        0x0003,
        0xFFFE,
        9,
        6,
        0,
        0,
        0,
        fat_sector_count,
        directory_start,
        0,
        MINI_CUTOFF,
        minifat_start,
        minifat_sector_count,
        FREESECT,
        0,
    ) + struct.pack("<109I", 0, *([FREESECT] * 108))
    header = header.ljust(SECTOR_SIZE, b"\x00")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(header + b"".join(sector or b"\x00" * SECTOR_SIZE for sector in sectors))


def main() -> None:
    output = Path("artifacts")
    build_container(output / "missing-source-preview.ole", include_source=False)
    build_container(output / "fully-verifiable-file.ole", include_source=True)


if __name__ == "__main__":
    main()
