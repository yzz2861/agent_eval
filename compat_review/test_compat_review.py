"""兼容审查验证用例(离线,只读输入):排列不变性、类别变更重审、线格式与镜像一致性。"""

import base64
import json
from datetime import datetime
from pathlib import Path

import cbor2

from review import categorize, collect_unknown_tags, review_pair

HERE = Path(__file__).parent

SHORT_READER = {
    "reader_id": "short-object-reader",
    "signoff": "SO-TEST-001",
    "fields": {
        "a": {"category": "count", "required": True},
        "b": {"category": "text", "required": True},
    },
}


def to_mirror(node):
    """cbor2 解码结果 -> 审查用的镜像记号(与 objects/*.json 同构)。"""
    if isinstance(node, cbor2.CBORTag):
        return {"$tag": node.tag, "value": to_mirror(node.value)}
    if isinstance(node, datetime):  # cbor2 默认把 tag 1 解码为 datetime
        return {"$tag": 1, "value": int(node.timestamp())}
    if isinstance(node, bytes):
        return {"$bytes": base64.b64encode(node).decode("ascii")}
    if isinstance(node, dict):
        return {key: to_mirror(value) for key, value in node.items()}
    if isinstance(node, list):
        return [to_mirror(item) for item in node]
    return node


def decode_bytes(data):
    return to_mirror(cbor2.loads(data))


def decode_file(path):
    return to_mirror(cbor2.loads(Path(path).read_bytes()))


def test_permutation_does_not_change_approval():
    obj_order1 = decode_bytes(cbor2.dumps({"a": 1, "b": "x"}))
    obj_order2 = decode_bytes(cbor2.dumps({"b": "x", "a": 1}))
    assert obj_order1 == obj_order2  # 排列只是线格式现象,解码后逻辑形状相同

    result1 = review_pair(SHORT_READER, "order1", obj_order1)
    result2 = review_pair(SHORT_READER, "order2", obj_order2)
    assert result1["verdict"] == result2["verdict"] == "COMPATIBLE"
    assert result1["findings"] == result2["findings"] == []
    assert sorted(result1["boundary"]) == sorted(result2["boundary"])


def test_same_name_category_change_triggers_rereview():
    obj_text = decode_bytes(cbor2.dumps({"a": 1, "b": "x"}))
    obj_bytes = decode_bytes(cbor2.dumps({"a": 1, "b": b"x"}))
    assert obj_text["b"] != obj_bytes["b"]  # 同名字段,对象事实类别不同

    baseline = review_pair(SHORT_READER, "text", obj_text)
    changed = review_pair(SHORT_READER, "bytes", obj_bytes)
    assert baseline["verdict"] == "COMPATIBLE"
    assert changed["verdict"] == "RE-REVIEW"
    mismatch = [f for f in changed["findings"] if f["kind"] == "category-mismatch"]
    assert len(mismatch) == 1
    assert mismatch[0]["field"] == "b"
    assert mismatch[0]["approved"] == "text"
    assert mismatch[0]["actual"] == "opaque-bytes"


def test_wire_matches_mirror():
    for name in ("gen1", "gen2"):
        mirror = json.loads((HERE / "objects" / f"{name}.json").read_text(encoding="utf-8"))["value"]
        assert decode_file(HERE / "objects" / f"{name}.cbor") == mirror


def test_unknown_tag_stays_pending():
    obj = decode_bytes(cbor2.dumps({"meta": cbor2.CBORTag(60001, "x")}))
    assert categorize(obj["meta"]) == "unknown-tag(60001)"
    assert collect_unknown_tags(obj) == [("$.meta", 60001)]
