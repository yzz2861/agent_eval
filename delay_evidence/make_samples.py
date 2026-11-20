"""Generate deterministic synthetic samples for the evidence view."""

from __future__ import annotations

import os

import pefile

from .sample_builder import SampleSpec, build_sample


SAMPLE_A_SPECS = [
    SampleSpec("appcrt140.dll", ["crt_initialize", 1234], bound=True),
    SampleSpec("kernel32.dll", ["Sleep", "GetLastError"], bound=False),
]

SAMPLE_B_SPECS = [
    SampleSpec("appcrt140.dll", ["crt_initialize", 1234], bound=False),
    SampleSpec("kernel32.dll", ["Sleep"], bound=True),
]


def write_samples(directory):
    os.makedirs(directory, exist_ok=True)
    image_a, _ = build_sample(SAMPLE_A_SPECS)
    image_b, _ = build_sample(SAMPLE_B_SPECS)
    path_a = os.path.join(directory, "sample_a_generation_v1.dll")
    path_b = os.path.join(directory, "sample_b_generation_v2.dll")
    with open(path_a, "wb") as handle:
        handle.write(image_a)
    with open(path_b, "wb") as handle:
        handle.write(image_b)
    helper = pefile.PE(data=image_a)
    rdata = next(
        section for section in helper.sections
        if section.Name.startswith(b".rdata")
    )
    fragment_path = os.path.join(directory, "delay_directory_fragment.bin")
    raw_start = rdata.PointerToRawData
    raw_end = raw_start + rdata.SizeOfRawData
    with open(fragment_path, "wb") as handle:
        handle.write(image_a[raw_start:raw_end])
    return {
        "sample_a": path_a,
        "sample_b": path_b,
        "fragment": fragment_path,
        "fragment_base_rva": rdata.VirtualAddress,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(write_samples("samples"), indent=2))
