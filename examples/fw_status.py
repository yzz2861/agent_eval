"""Read-only firmware status table interpreter.

The device no longer boots; only the status bytes and the two mode-specific
structure conventions (repair / daily) remain. A bit region of the status
table has different meanings per mode. This tool takes an external state
(the mode) plus the structure definitions and produces, from the same bytes,
the interpretation that holds under that condition:

- Mode confirmed: common fields + conditional fields of that mode.
- Mode unknown: common fields and the two mutually exclusive branches shown
  separately, each annotated with its raw bit range.

See __main__ for a demo: the same bytes are reinterpreted after switching
the external state.
"""

from dissect.cstruct import cstruct

DEFS = """
struct fw_common {
    uint8   magic;          // fixed marker 0xA5
    uint8   hw_rev;         // hardware revision
    uint16  uptime_hours;   // cumulative uptime
    uint16  err_count;      // cumulative error count
    uint8   bat_level : 7;  // battery percent
    uint8   charging  : 1;  // charging flag
};

struct fw_variant_repair {
    uint8   fault_code   : 4;  // repair mode: active fault code
    uint8   part_request : 1;  // repair mode: replacement part requested
    uint8   bench_test   : 1;  // repair mode: bench test running
    uint8   cal_unlock   : 1;  // repair mode: calibration unlocked
    uint8   repair_flag  : 1;  // repair mode: sticky repair flag
    uint8   service_slot;      // repair mode: service bay slot id
};

struct fw_variant_daily {
    uint8   power_state  : 2;  // daily mode: 0 off 1 idle 2 active 3 boost
    uint8   fan_speed    : 3;  // daily mode: fan level 0-7
    uint8   eco_mode     : 1;  // daily mode: eco mode
    uint8   night_mode   : 1;  // daily mode: night mode
    uint8   user_present : 1;  // daily mode: user present
    uint8   profile_id;        // daily mode: active profile
};
"""

MODE_STRUCTS = {
    "repair": "fw_variant_repair",
    "daily": "fw_variant_daily",
}

MODE_LABELS = {
    "repair": "维修模式",
    "daily": "日常模式",
}

_cs = cstruct()
_cs.load(DEFS)


def _bit_ranges(struct_type, base_bit=0):
    """Compute the absolute bit range [lo, hi) of each field, in order."""
    ranges = {}
    cursor = base_bit
    for name, field in struct_type.__members__.items():
        if field.bits is None:
            start = base_bit + field.offset * 8
            end = start + field.type.__size__ * 8
        else:
            unit = field.type.__size__ * 8
            if field.offset is not None:
                cursor = base_bit + field.offset * 8
            elif (cursor - base_bit) % unit + field.bits > unit:
                cursor = base_bit + (cursor - base_bit + unit - 1) // unit * unit
            start, end = cursor, cursor + field.bits
        cursor = end
        ranges[name] = (start, end)
    return ranges


def _fields(struct_type, data, base_bit):
    inst = struct_type(data)
    ranges = _bit_ranges(struct_type, base_bit)
    return [
        {"name": name, "value": getattr(inst, name), "bits": ranges[name]}
        for name in struct_type.__members__
    ]


def interpret(data, mode=None):
    """Read-only interpretation of one status record.

    mode: "repair" / "daily" / None (caller cannot confirm the mode).
    Returns common fields plus the conditionally valid branch fields,
    each annotated with its raw bit range.
    """
    data = bytes(data)
    common_type = _cs.fw_common
    common_size = common_type.__size__
    variant = data[common_size:]

    if mode is None:
        branch_names = list(MODE_STRUCTS)
        exclusive = True
    elif mode in MODE_STRUCTS:
        branch_names = [mode]
        exclusive = False
    else:
        raise ValueError(f"unknown mode: {mode!r}")

    variant_base = common_size * 8
    return {
        "mode": mode,
        "exclusive": exclusive,
        "common": _fields(common_type, data, 0),
        "variant_raw": variant,
        "branches": {
            name: _fields(getattr(_cs, MODE_STRUCTS[name]), variant, variant_base)
            for name in branch_names
        },
    }


def _fmt_field(field):
    lo, hi = field["bits"]
    return f"    {field['name']:<14} = {field['value']!r:<6}  bits {lo}..{hi - 1}"


def format_report(report):
    lines = []
    mode = report["mode"]
    lines.append(f"外部状态: {MODE_LABELS.get(mode, '未知（无法独立确认）')}")
    lines.append("共同字段（两种模式含义一致）:")
    lines.extend(_fmt_field(f) for f in report["common"])
    raw = report["variant_raw"]
    base = _cs.fw_common.__size__
    lines.append(
        f"条件区域原始字节: 字节 {base}..{base + len(raw) - 1} = {raw.hex(' ')}"
    )
    if report["exclusive"]:
        lines.append("相斥字段（按各自分支成立，二者取其一）:")
    else:
        lines.append("条件字段:")
    for name, fields in report["branches"].items():
        lines.append(f"  分支 [{MODE_LABELS[name]}]:")
        lines.extend(_fmt_field(f) for f in fields)
    return "\n".join(lines)


if __name__ == "__main__":
    data = bytes([0xA5, 0x02, 0x2C, 0x01, 0x03, 0x00, 0xDB, 0xD5, 0x07])
    print(f"状态字节: {data.hex(' ')}\n")

    reports = {m: interpret(data, m) for m in ("daily", "repair", None)}
    for report in reports.values():
        print(format_report(report))
        print()

    common_by_mode = {
        m: [(f["name"], f["value"]) for f in r["common"]]
        for m, r in reports.items()
    }
    assert common_by_mode["daily"] == common_by_mode["repair"] == common_by_mode[None]
    print("校验通过：三种外部状态下共同字段保持一致。")
