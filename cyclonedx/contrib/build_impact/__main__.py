# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

"""Command line entry point for the offline build-tool impact assessment."""

from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import List, Optional, Sequence

from .assess import FrozenBuildArchive, ToolAdvisory, assess, load_observations
from .report import render_csv, render_json, render_markdown


def _parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog='python -m cyclonedx.contrib.build_impact',
        description=(
            'Reconcile CycloneDX release SBOMs against an explicitly frozen build-behaviour archive '
            'and a build-tool repository advisory. All inputs are read locally; no network access is used.'
        ),
    )
    parser.add_argument('--archive', required=True, help='frozen build-behaviour archive JSON')
    parser.add_argument('--advisory', required=True, help='tool repository advisory JSON')
    parser.add_argument('--sbom', action='append', default=[], help='release SBOM JSON (repeatable)')
    parser.add_argument('--sbom-dir', help='directory searched recursively for release SBOM JSON files')
    parser.add_argument('--json-out', help='write the machine-readable audit sheet here')
    parser.add_argument('--markdown-out', help='write the Markdown audit sheet here')
    parser.add_argument('--csv-out', help='write the CSV audit sheet here')
    parser.add_argument(
        '--fail-on',
        choices=('none', 'affected', 'unconfirmed', 'any'),
        default='none',
        help='return exit code 2 when the selected condition is present',
    )
    return parser


def _sbom_paths(args: Namespace) -> List[str]:
    paths = {str(Path(item)) for item in args.sbom}
    if args.sbom_dir:
        paths.update(str(path) for path in sorted(Path(args.sbom_dir).rglob('*.json')))
    if not paths:
        raise SystemExit('at least one --sbom or --sbom-dir is required')
    return sorted(paths)


def _write(path: str, content: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open('w', encoding='utf-8', newline='\n') as stream:
        stream.write(content)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    archive = FrozenBuildArchive.load(args.archive)
    advisory = ToolAdvisory.load(args.advisory)
    report = assess(archive, advisory, load_observations(_sbom_paths(args)))

    wrote_output = False
    if args.json_out:
        _write(args.json_out, render_json(report))
        wrote_output = True
    if args.markdown_out:
        _write(args.markdown_out, render_markdown(report))
        wrote_output = True
    if args.csv_out:
        _write(args.csv_out, render_csv(report))
        wrote_output = True

    if not wrote_output:
        print(render_markdown(report), end='')
    else:
        print(
            f'packages={len(report.findings)} affected={len(report.affected)} '
            f'not_affected={len(report.not_affected)} tool_unconfirmed={len(report.tool_unconfirmed)} '
            f'reverify_tool_source={len(report.requires_tool_provenance_reverification)}'
        )

    if args.fail_on == 'affected' and report.affected:
        return 2
    if args.fail_on == 'unconfirmed' and report.tool_unconfirmed:
        return 2
    if args.fail_on == 'any' and (report.affected or report.tool_unconfirmed):
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
