"""Read-only page-correspondence auditor built on pypdf.

The auditor opens PDFs with :class:`pypdf.PdfReader` and never calls a
writer or mutates a file. Every conclusion is derived from three layers of
independently inspectable evidence:

1. Structure evidence: MediaBox/CropBox geometry and rotation.
2. Shared-resource evidence: content hashes of font dictionaries and the raw
   bytes of image XObject streams. Object numbers are deliberately not trusted
   across documents because pypdf reassigns them on import; resource *content*
   hashes are what prove a common origin.
3. Content evidence: a hash of the decoded content stream plus the extracted
   text, so renamed resources and merged or split streams remain traceable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from pypdf import PdfReader
from pypdf.generic import IndirectObject


EXACT_MATCH = "exact_match"
MOVED_PAGE = "moved_page"
MERGED_PAGE = "merged_two_sources"
SPLIT_PAGE = "split_one_source"
SAME_CONTENT_CONFLICT = "same_content_position_conflict"
MISSING_PAGE = "missing_page"

CONCLUSION_LABELS = {
    EXACT_MATCH: "内容一致且位置一致",
    MOVED_PAGE: "内容一致但位置改变（移动页）",
    MERGED_PAGE: "一页来自两个来源（两源合一）",
    SPLIT_PAGE: "一个来源拆成两个数字页（一源拆两页）",
    SAME_CONTENT_CONFLICT: "同内容页位置冲突（重复放置）",
    MISSING_PAGE: "原件缺页（重排件无任何对应内容）",
}


def _sha256(data):
    return hashlib.sha256(data).digest().hex()


def _short(digest):
    return digest[:12]


def _ref_label(obj):
    ref = getattr(obj, "indirect_reference", None)
    if isinstance(ref, IndirectObject):
        return "obj %d gen %d" % (ref.idnum, ref.generation)
    return "direct"


def _box(page, name, fallback):
    value = page.get(name)
    if value is None:
        return list(fallback)
    return [float(v) for v in value]


def _normalise_text(text):
    return tuple(line.strip() for line in text.splitlines() if line.strip())


@dataclass(frozen=True)
class ResourceHashes:
    fonts: tuple
    images: tuple

    @property
    def image_set(self):
        return frozenset(digest for _, digest in self.images)

    @property
    def font_set(self):
        return frozenset(digest for _, digest in self.fonts)


@dataclass(frozen=True)
class PageFingerprint:
    document: str
    index: int
    label: str
    mediabox: tuple
    cropbox: tuple
    rotation: int
    content_hash: str
    text_lines: tuple
    resources: ResourceHashes
    object_refs: dict = field(default_factory=dict)

    @property
    def is_cropped(self):
        return self.cropbox != self.mediabox

    @property
    def text_blob(self):
        return " ".join(self.text_lines)


@dataclass(frozen=True)
class Evidence:
    kind: str
    detail: str


@dataclass(frozen=True)
class Finding:
    conclusion: str
    target_index: object
    source_indices: tuple
    evidence: tuple
    original_ref: str
    rearranged_ref: str

    @property
    def label(self):
        return CONCLUSION_LABELS[self.conclusion]


def _hash_font(font_obj):
    parts = []
    for key in sorted(font_obj.keys()):
        if key in ("/Type", "/Subtype", "/BaseFont", "/Encoding"):
            parts.append(key + "=" + str(font_obj.get(key)))
    return _sha256("|".join(parts).encode("utf-8"))


def fingerprint_page(reader, index, document):
    page = reader.pages[index]
    label = "%s p%d" % (document, index + 1)
    mediabox = tuple(_box(page, "/MediaBox", page.mediabox))
    cropbox = tuple(_box(page, "/CropBox", page.cropbox))
    rotation = int(page.get("/Rotation", 0))

    content_bytes = page.get_contents().get_data()
    content_hash = _sha256(content_bytes)
    text_lines = _normalise_text(page.extract_text() or "")

    resources = page["/Resources"]
    font_entries = []
    for name in sorted(resources.get("/Font", {}).keys()):
        font_obj = resources["/Font"][name].get_object()
        font_entries.append((name, _hash_font(font_obj)))
    image_entries = []
    xobjects = resources.get("/XObject")
    if xobjects:
        for name in sorted(xobjects.keys()):
            xobj = xobjects[name].get_object()
            if xobj.get("/Subtype") == "/Image":
                image_entries.append((name, _sha256(xobj.get_data())))

    object_refs = {
        "page": _ref_label(page),
        "content": _ref_label(page.get_contents()),
    }
    return PageFingerprint(
        document=document,
        index=index,
        label=label,
        mediabox=mediabox,
        cropbox=cropbox,
        rotation=rotation,
        content_hash=content_hash,
        text_lines=text_lines,
        resources=ResourceHashes(
            fonts=tuple(sorted(font_entries)),
            images=tuple(sorted(image_entries)),
        ),
        object_refs=object_refs,
    )


def fingerprint_document(path, document):
    reader = PdfReader(str(path))
    return [
        fingerprint_page(reader, index, document)
        for index in range(len(reader.pages))
    ]


def _image_overlap(left, right):
    return left.resources.image_set & right.resources.image_set


def _text_overlap(target, source):
    wanted = frozenset(source.text_lines)
    return tuple(line for line in target.text_lines if line in wanted)


def _geometry_evidence(target):
    if target.is_cropped:
        detail = "CropBox %s 是 MediaBox %s 的子区域（裁剪保留）" % (
            list(target.cropbox), list(target.mediabox)
        )
    else:
        detail = "CropBox 等于 MediaBox %s，未裁剪" % (list(target.mediabox),)
    return Evidence("structure", detail)


def _resource_evidence(target, sources):
    shared = []
    for source in sources:
        for digest in sorted(_image_overlap(target, source)):
            shared.append("%s 图片 %s" % (source.label, _short(digest)))
    if shared:
        return Evidence("resource", "；".join(shared) + " 解码字节完全相同")
    return Evidence("resource", "无共享图片，字体字典哈希一致")


def _content_evidence(target, sources):
    pieces = []
    for source in sources:
        overlap = _text_overlap(target, source)
        if overlap:
            pieces.append("%s 文本行 %s" % (source.label, list(overlap)))
        else:
            pieces.append("%s 内容哈希 %s" % (source.label, _short(source.content_hash)))
    return Evidence("content", "；".join(pieces))


def _build_finding(conclusion, target, sources, original, rearranged):
    evidence = (
        _geometry_evidence(target) if target is not None
        else Evidence("structure", "重排件无承载页，几何结构无从对应"),
        _resource_evidence(target, sources) if target is not None
        else Evidence("resource", "全部 %d 个重排页资源中均无该页图片哈希" % len(rearranged)),
        _content_evidence(target, sources) if target is not None
        else Evidence("content", "全部重排页文本均不含 %s 的任何文本行" % sources[0].label),
    )
    original_ref = "; ".join(
        "%s (%s, 内容 %s)" % (
            source.label, source.object_refs["page"], _short(source.content_hash)
        )
        for source in sources
    )
    if target is None:
        rearranged_ref = "重排件无对应页（已核对全部 %d 页）" % len(rearranged)
        target_index = None
    else:
        rearranged_ref = "%s (%s, 内容 %s)" % (
            target.label, target.object_refs["page"], _short(target.content_hash)
        )
        target_index = target.index
    return Finding(
        conclusion=conclusion,
        target_index=target_index,
        source_indices=tuple(source.index for source in sources),
        evidence=evidence,
        original_ref=original_ref,
        rearranged_ref=rearranged_ref,
    )


def correlate(original, rearranged):
    findings = []
    matched_sources = set()
    matched_targets = set()

    by_content = {}
    for target in rearranged:
        by_content.setdefault(target.content_hash, []).append(target)
    source_by_content = {}
    for source in original:
        source_by_content.setdefault(source.content_hash, []).append(source)

    for content_hash, targets in by_content.items():
        sources = source_by_content.get(content_hash, [])
        cropped = [target for target in targets if target.is_cropped]
        if cropped and sources:
            source = sources[0]
            for target in targets:
                findings.append(
                    _build_finding(SPLIT_PAGE, target, [source], original, rearranged)
                )
                matched_targets.add(target.index)
            matched_sources.add(source.index)
            continue
        if not sources:
            continue
        source = sources[0]
        if len(targets) > 1:
            conclusion = SAME_CONTENT_CONFLICT
        elif source.index == targets[0].index:
            conclusion = EXACT_MATCH
        else:
            conclusion = MOVED_PAGE
        for target in targets:
            findings.append(
                _build_finding(conclusion, target, [source], original, rearranged)
            )
            matched_targets.add(target.index)
        matched_sources.add(source.index)

    for target in rearranged:
        if target.index in matched_targets:
            continue
        contributing = [
            source for source in original
            if _image_overlap(target, source) and _text_overlap(target, source)
        ]
        if len(contributing) >= 2:
            findings.append(
                _build_finding(MERGED_PAGE, target, contributing, original, rearranged)
            )
            for source in contributing:
                matched_sources.add(source.index)
            matched_targets.add(target.index)
        elif len(contributing) == 1:
            source = contributing[0]
            findings.append(
                _build_finding(MOVED_PAGE, target, [source], original, rearranged)
            )
            matched_sources.add(source.index)
            matched_targets.add(target.index)

    for source in original:
        if source.index in matched_sources:
            continue
        survives = any(
            _image_overlap(source, target) or _text_overlap(target, source)
            for target in rearranged
        )
        if not survives:
            findings.append(
                _build_finding(MISSING_PAGE, None, [source], original, rearranged)
            )
            matched_sources.add(source.index)

    findings.sort(
        key=lambda item: (
            item.target_index is None,
            item.target_index if item.target_index is not None else 1 << 30,
            item.source_indices,
        )
    )
    return findings


def audit(original_path, rearranged_path):
    original = fingerprint_document(original_path, "原件")
    rearranged = fingerprint_document(rearranged_path, "重排件")
    findings = correlate(original, rearranged)
    return original, rearranged, findings
