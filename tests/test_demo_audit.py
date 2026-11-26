from __future__ import annotations

import importlib
import json

from dns_audit.demo import build_demo_audit


def test_demo_invariants_and_json() -> None:
    audit = build_demo_audit()
    payload = json.dumps(audit.to_dict(), ensure_ascii=False)
    assert '0x4242' not in payload
    assert 'edge-a' in payload and 'edge-b' in payload


def test_compatibility_entrypoints_importable() -> None:
    for module_name in (
        'dns_offline_audit',
        'dns_alias_audit',
        'offline_alias_observer',
    ):
        module = importlib.import_module(module_name)
        assert hasattr(module, 'main')
