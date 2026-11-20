#!/usr/bin/env python
# -------------------------------------------------------------------------------
# elftools script: attribute_address.py
#
# Offline attribution of crash-report addresses against explicitly supplied
# module ELF, external debug ELF files, and instance load mappings.
#
# This code is in the public domain.
# -------------------------------------------------------------------------------
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Sequence

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from elftools.elf.address_attribution import (  # noqa: E402
    AttributionInputError,
    AttributionRequest,
    DebugFile,
    LoadMapping,
    attribute_addresses,
    parse_int,
    request_from_config,
)


def _split_named_value(value: str, default_name: str) -> tuple[str, str]:
    """Split ``name=value`` while leaving a plain value alone."""
    if "=" in value:
        name, raw = value.split("=", 1)
        if name and raw:
            return name, raw
    return default_name, value


def _mapping_from_bias_argument(value: str, index: int) -> LoadMapping:
    name, raw = _split_named_value(value, f"bias-{index}")
    return LoadMapping.from_bias(name, parse_int(raw, what="bias"))


def _mapping_from_region_argument(value: str, index: int) -> LoadMapping:
    name, raw = _split_named_value(value, f"region-{index}")
    parts = raw.split(":")
    if len(parts) not in (3, 4):
        raise AttributionInputError(
            "region must be [name=]runtime_start:runtime_end:elf_start[:elf_size]"
        )
    region = {
        "runtime_start": parts[0],
        "runtime_end": parts[1],
        "elf_start": parts[2],
    }
    if len(parts) == 4:
        region["elf_size"] = parts[3]
    return LoadMapping.from_regions(name, [region])


def _mapping_from_json_argument(value: str, index: int) -> LoadMapping:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise AttributionInputError(f"mapping JSON is not valid: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AttributionInputError("mapping JSON must be an object")
    return LoadMapping.from_dict(parsed, default_name=f"mapping-{index}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Attribute runtime addresses to DWARF file/line rows using only "
            "the module ELF, external debug files, and load mappings supplied "
            "by the caller."
        ),
        epilog=(
            "The JSON request form is recommended when more than one mapping "
            "or a multi-region mapping is needed. The report includes a "
            "top-level conflicts array for the crash platform."
        ),
    )
    parser.add_argument(
        "--config",
        help="JSON request file (main_elf, debug_files, mappings, addresses)",
    )
    parser.add_argument("--main", help="module ELF (not a core dump)")
    parser.add_argument(
        "--debug",
        action="append",
        default=[],
        help="external debug ELF (repeat for each candidate package)",
    )
    parser.add_argument(
        "--bias",
        action="append",
        default=[],
        metavar="[NAME=]BIAS",
        help="add a load-bias mapping; repeat for alternative hypotheses",
    )
    parser.add_argument(
        "--region",
        action="append",
        default=[],
        metavar="[NAME=]START:END:ELF_START[:ELF_SIZE]",
        help="add an explicit runtime-to-ELF-address mapping region",
    )
    parser.add_argument(
        "--mapping-json",
        action="append",
        default=[],
        help="add a mapping from an inline JSON object",
    )
    parser.add_argument(
        "--address",
        action="append",
        default=[],
        help="runtime address in decimal or 0x form (repeatable)",
    )
    parser.add_argument(
        "--output", help="write the full JSON report here instead of stdout"
    )
    parser.add_argument("--conflicts-out", help="write only the conflict records here")
    parser.add_argument(
        "--compact",
        action="store_true",
        help="emit compact JSON instead of indented JSON",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 3 when any address is not resolved or a conflict exists",
    )
    parser.add_argument(
        "--no-main-dwarf",
        action="store_true",
        help="use the main ELF for identity and mappings only, not line rows",
    )
    return parser


def _request_from_args(args: argparse.Namespace) -> AttributionRequest:
    if args.config:
        if (
            args.main
            or args.debug
            or args.bias
            or args.region
            or args.mapping_json
            or args.address
        ):
            raise AttributionInputError(
                "--config cannot be combined with --main/--debug/--bias/--region/"
                "--mapping-json/--address"
            )
        with open(args.config, encoding="utf-8") as config_file:
            config = json.load(config_file)
        return request_from_config(
            config, base_dir=os.path.dirname(os.path.abspath(args.config))
        )

    if not args.main:
        raise AttributionInputError("--main is required")
    if not args.address:
        raise AttributionInputError("at least one --address is required")

    mappings: list[LoadMapping] = []
    for index, value in enumerate(args.bias, start=1):
        mappings.append(_mapping_from_bias_argument(value, index))
    for index, value in enumerate(args.region, start=1):
        mappings.append(_mapping_from_region_argument(value, index))
    for index, value in enumerate(args.mapping_json, start=1):
        mappings.append(_mapping_from_json_argument(value, index))
    if not mappings:
        raise AttributionInputError(
            "at least one --bias, --region, or --mapping-json is required"
        )

    return AttributionRequest(
        main_elf=os.path.abspath(args.main),
        debug_files=tuple(
            DebugFile(os.path.abspath(path), id=f"debug-{index}")
            for index, path in enumerate(args.debug)
        ),
        mappings=tuple(mappings),
        addresses=tuple(parse_int(value, what="address") for value in args.address),
        include_main=not args.no_main_dwarf,
    )


def _write_json(path: str, value: Any, *, compact: bool) -> None:
    with open(path, "w", encoding="utf-8") as output:
        json.dump(value, output, indent=None if compact else 2, ensure_ascii=False)
        output.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        request = _request_from_args(args)
        report = attribute_addresses(request)
    except (AttributionInputError, OSError, json.JSONDecodeError) as exc:
        print(f"attribute_address: {exc}", file=sys.stderr)
        return 2

    payload = report.to_dict()
    try:
        if args.output:
            _write_json(args.output, payload, compact=args.compact)
        else:
            indent = None if args.compact else 2
            json.dump(payload, sys.stdout, indent=indent, ensure_ascii=False)
            sys.stdout.write("\n")

        if args.conflicts_out:
            _write_json(args.conflicts_out, payload["conflicts"], compact=args.compact)
    except OSError as exc:
        print(f"attribute_address: could not write report: {exc}", file=sys.stderr)
        return 2

    if args.strict:
        unresolved = (
            payload["summary"]["unresolved"] + payload["summary"]["provisional"]
        )
        ambiguous = payload["summary"]["ambiguous"]
        if unresolved or ambiguous or payload["conflicts"]:
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
