# /// script
# requires-python = ">=3.10"
# dependencies = ["dissect.cstruct"]
# ///
"""设备事件记录取证：在 dissect.cstruct 解析结果上叠加调查员声明的证据映射。

背景：两代固件的事件记录都把事件状态放在同名字段 ``status`` 里，但枚举编号、
温度单位/精度、字段集合都变了。旧取证脚本直接按原始字节做 diff，把一批刚升级
的机器误报为"状态变化"。本脚本演示：

1. 版本判别：先用最小头部 struct 读 ``version``，再选择完整 schema；
2. 枚举含义拆并：v1/v2 的 status 枚举按调查员声明映射到规范标签；
3. 单位和精度变化：temp 按版本换算到摄氏度后再比较；
4. 部分记录才有的字段：error_code 仅存在于 v2；
5. 版本不明或来源不足：保留原值和 schema 位置，说明无法与旧版比较的前提。

三份短记录做前后对照，输出一条可证的变化和两条需要额外材料才能下结论的比较。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from dissect.cstruct import cstruct

# ---------------------------------------------------------------------------
# 结构定义（沿用 dissect.cstruct 现有结构读取）
# ---------------------------------------------------------------------------

EVENT_DEF = """
#define EVENT_MAGIC 0x45564E54  // 'EVNT'

enum StatusV1 : uint8 {
    OK       = 0,
    DEGRADED = 1,
    FAILED   = 2,
};

enum StatusV2 : uint8 {
    OK       = 0,
    WARN     = 1,   // v2 新增，与 v1 的对应关系无证据
    DEGRADED = 2,
    FAILED   = 3,
};

// 仅用于版本判别的最小头部
typedef struct {
    uint32  magic;
    uint16  version;
} event_hdr;

typedef struct {
    uint32   magic;
    uint16   version;   // = 1
    uint16   seq;
    uint32   timestamp;
    StatusV1 status;
    uint8    flags;
    uint16   temp;      // 单位 0.1 °C
} event_v1;

typedef struct {
    uint32   magic;
    uint16   version;   // = 2
    uint16   seq;
    uint32   timestamp;
    StatusV2 status;
    uint8    flags;
    uint16   temp;        // 单位 0.001 °C（精度提高）
    uint32   error_code;  // v2 新增，v1 记录中不存在
} event_v2;
"""

cs = cstruct()
cs.load(EVENT_DEF)

# ---------------------------------------------------------------------------
# 调查员声明的证据映射（每条都注明来源；无来源的对应关系不允许进入映射）
# ---------------------------------------------------------------------------

EVIDENCE_MAP = {
    "version_field": "version",
    "versions": {
        1: {"struct": "event_v1", "source": "固件 v1.4 数据手册 §2.1"},
        2: {"struct": "event_v2", "source": "固件 v2.0 发布说明 §3"},
    },
    "fields": {
        "status": {
            "kind": "enum",
            # (版本, 原始值) -> 规范标签；刻意不映射 (2, 1) WARN：来源不足
            "map": {
                (1, 0): "OK",
                (1, 1): "DEGRADED",
                (1, 2): "FAILED",
                (2, 0): "OK",
                (2, 2): "DEGRADED",
                (2, 3): "FAILED",
            },
            "source": "v2.0 发布说明 §3.2：枚举重编号，OK/DEGRADED/FAILED 语义不变",
        },
        "temp": {
            "kind": "unit",
            "scale": {1: 0.1, 2: 0.001},  # 原始值 -> 摄氏度
            "unit": "°C",
            "source": "v1.4 手册 §2.1 与 v2.0 手册 §4.1：温度字段单位",
        },
        "error_code": {
            "kind": "partial",
            "present_in": [2],
            "source": "v2.0 schema 新增字段；v1 侧是否存在等价信息无证据",
        },
    },
}


# ---------------------------------------------------------------------------
# 解析与比较
# ---------------------------------------------------------------------------


@dataclass
class ParsedRecord:
    name: str
    raw: bytes
    version: int | None
    struct_name: str | None
    values: dict = field(default_factory=dict)  # 字段 -> (原始值, 展示值)
    offsets: dict = field(default_factory=dict)  # 字段 -> schema 位置字符串


def parse_record(name: str, raw: bytes) -> ParsedRecord:
    """版本判别：先读最小头部，再按证据映射选择完整 schema。"""
    hdr = cs.event_hdr(raw)
    if hdr.magic != cs.EVENT_MAGIC:
        return ParsedRecord(name, raw, None, None)
    version = hdr.version
    ver_entry = EVIDENCE_MAP["versions"].get(version)
    if ver_entry is None:
        # 版本不明：不猜测布局，保留原值与已确认的 schema 位置
        rec = ParsedRecord(name, raw, version, None)
        rec.offsets["version"] = schema_pos("event_hdr", "version")
        return rec
    struct_name = ver_entry["struct"]
    parsed = getattr(cs, struct_name)(raw)
    rec = ParsedRecord(name, raw, version, struct_name)
    for fname in parsed.__members__:
        value = getattr(parsed, fname)
        raw_value = value.value if hasattr(value, "value") else value
        rec.values[fname] = (raw_value, str(value))
        rec.offsets[fname] = schema_pos(struct_name, fname)
    return rec


def schema_pos(struct_name: str, fname: str) -> str:
    f = getattr(cs, struct_name).__members__[fname]
    return f"{struct_name}.{fname} @ +0x{f.offset:02x}"


def normalize(rec: ParsedRecord, fname: str):
    """按证据映射把字段换算到规范形式；无法换算时返回 None。"""
    if fname not in rec.values:
        return None
    raw_value, _ = rec.values[fname]
    spec = EVIDENCE_MAP["fields"].get(fname)
    if spec is None:
        return raw_value
    if spec["kind"] == "enum":
        return spec["map"].get((rec.version, raw_value))  # 未映射 -> None
    if spec["kind"] == "unit":
        return raw_value * spec["scale"][rec.version]
    return raw_value


def compare_field(before: ParsedRecord, after: ParsedRecord, fname: str) -> str:
    spec = EVIDENCE_MAP["fields"].get(fname, {})
    pos_b = before.offsets.get(fname, f"{fname}（v{before.version} schema 中不存在）")
    pos_a = after.offsets.get(fname, f"{fname}（v{after.version} schema 中不存在）")
    lines = [f"字段 {fname}:"]

    # 仅在部分记录中出现的字段
    if spec.get("kind") == "partial" and before.version not in spec["present_in"]:
        raw_a, disp_a = after.values[fname]
        lines.append(f"  v{after.version} 原值 {disp_a} (0x{raw_a:x})，位置 {pos_a}")
        lines.append(f"  v{before.version} 无此字段（{pos_b}）")
        lines.append("  结论：证据不足 —— 需要 v1 固件手册证明 v1 侧是否存在等价信息，否则无法与旧版比较")
        return "\n".join(lines)

    raw_b, disp_b = before.values[fname]
    raw_a, disp_a = after.values[fname]
    norm_b, norm_a = normalize(before, fname), normalize(after, fname)
    lines.append(f"  原值: v{before.version}={disp_b} ({pos_b})  v{after.version}={disp_a} ({pos_a})")

    if norm_b is None or norm_a is None:
        missing = f"v{before.version} 值 {disp_b}" if norm_b is None else f"v{after.version} 值 {disp_a}"
        lines.append(f"  结论：证据不足 —— {missing} 在证据映射中无对应项；"
                     f"需要厂商确认该枚举值与旧版的对应关系后才能比较。原值与 schema 位置已保留")
    elif norm_b == norm_a:
        naive = "原始值相同" if raw_b == raw_a else f"原始值不同（{raw_b} vs {raw_a}，单位/精度变化所致）"
        lines.append(f"  结论：无变化（规范化后均为 {norm_b}；{naive}）")
    else:
        lines.append(f"  结论：可证变化 {norm_b} -> {norm_a}（依据：{spec.get('source', 'n/a')}）")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 三份短记录
# ---------------------------------------------------------------------------

def build_records() -> tuple[bytes, bytes, bytes]:
    r1 = struct.pack("<IHHI BBH", 0x45564E54, 1, 1, 1700000000, 2, 0, 235)          # v1: FAILED, 23.5°C
    r2 = struct.pack("<IHHI BBHI", 0x45564E54, 2, 2, 1700000300, 2, 0, 23500, 0x10)  # v2: DEGRADED, 23.5°C
    r3 = struct.pack("<IHHI BBHI", 0x45564E54, 9, 3, 1700000600, 1, 0, 180, 0x0)     # version=9 未知
    return r1, r2, r3


def main() -> None:
    raw1, raw2, raw3 = build_records()
    before = parse_record("R1（升级前）", raw1)
    after = parse_record("R2（升级后）", raw2)
    unknown = parse_record("R3（版本不明）", raw3)

    print("== 记录解析 ==")
    for rec in (before, after, unknown):
        if rec.struct_name:
            print(f"{rec.name}: version={rec.version} -> {rec.struct_name}")
        else:
            print(f"{rec.name}: version={rec.version} 不在证据映射中，"
                  f"保留原始字节 {rec.raw.hex()}，已确认位置 {rec.offsets.get('version')}")

    print("\n== 前后对照：R1 (v1) vs R2 (v2) ==")
    print(compare_field(before, after, "status"))
    print(compare_field(before, after, "temp"))
    print(compare_field(before, after, "error_code"))

    print("\n== 前后对照：R1 (v1) vs R3 (version=9) ==")
    if unknown.struct_name is None:
        print(f"  结论：证据不足 —— version=9 无已声明的 schema 映射，整份记录无法与旧版比较；"
              f"需要该版本固件镜像或数据手册建立 version->schema 证据。"
              f"原始字节 {unknown.raw.hex()} 与版本字段位置 {unknown.offsets['version']} 已保留")


if __name__ == "__main__":
    main()
