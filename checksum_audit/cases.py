"""Adapter: turn build_samples dicts into engine FrameCase objects."""
from __future__ import annotations

from dataclasses import dataclass

from .build_samples import build_frames, COLLECTORS


@dataclass
class FrameCase:
    name: str
    note: str
    collector: object
    sample: bytes
    wire_len: int


def collector_declarations():
    return dict(COLLECTORS)


def build_cases():
    cases = []
    for item in build_frames():
        wire = item["wire"]
        cap_len = item["cap_len"]
        cases.append(FrameCase(
            name=item["name"],
            note=item["note"],
            collector=COLLECTORS[item["collector"]],
            sample=wire[:cap_len],
            wire_len=item.get("wire_len", len(wire)),
        ))
    return cases
