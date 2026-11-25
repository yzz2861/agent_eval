"""一次性生成两代档案的 CBOR 线格式文件(objects/gen1.cbor, objects/gen2.cbor)。

数据源为 objects/gen1.json 与 objects/gen2.json 中的已解码镜像;
生成后 review.py 与测试只读取这些文件,不再修改。
"""

import base64
import json
from pathlib import Path

import cbor2

HERE = Path(__file__).parent


def to_cbor_value(node):
    if isinstance(node, dict):
        if "$bytes" in node:
            return base64.b64decode(node["$bytes"])
        if "$tag" in node:
            return cbor2.CBORTag(node["$tag"], to_cbor_value(node["value"]))
        return {key: to_cbor_value(value) for key, value in node.items()}
    if isinstance(node, list):
        return [to_cbor_value(item) for item in node]
    return node


def main():
    for name in ("gen1", "gen2"):
        mirror = json.loads((HERE / "objects" / f"{name}.json").read_text(encoding="utf-8"))
        payload = to_cbor_value(mirror["value"])
        out = HERE / "objects" / f"{name}.cbor"
        out.write_bytes(cbor2.dumps(payload))
        print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
