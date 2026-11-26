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

"""Command line entry point for offline CycloneDX residency checks."""

import argparse
import json
from typing import Any, Optional

from .residency import check_residency


def _parse_allow(value: str) -> tuple[str, tuple[str, ...]]:
    if '=' not in value:
        raise argparse.ArgumentTypeError('--allow must use CATEGORY=REGION[,REGION]')
    category, regions = value.split('=', 1)
    return category, tuple(part.strip() for part in regions.split(',') if part.strip())


def _policy(path: Optional[str]) -> dict[str, Any]:
    if not path:
        return {}
    with open(path, encoding='utf-8') as source:
        value = json.load(source)
    if not isinstance(value, dict):
        raise ValueError('Residency policy JSON must be an object')
    return value


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='python -m cyclonedx.compliance',
        description='Offline residency and failover-path compliance for a CycloneDX service manifest.',
    )
    parser.add_argument('manifest', help='CycloneDX JSON/XML file or an inline JSON document')
    parser.add_argument('--policy', help='Residency policy JSON file')
    parser.add_argument('--allow', action='append', default=[], type=_parse_allow,
                        help='Category rule, for example PII=EU or Customer=US,CA')
    parser.add_argument('--entrypoint', action='append', dest='entrypoints')
    parser.add_argument('--endpoint', action='append', dest='endpoints')
    parser.add_argument('--enable-condition', action='append', dest='enabled_conditions')
    parser.add_argument('--disable-condition', action='append', dest='disabled_conditions')
    parser.add_argument('--require-proof', action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument('--indent', type=int, default=2)
    parser.add_argument('--output', help='Write the report JSON to this file instead of stdout')
    parser.add_argument('--fail-on-noncompliance', action='store_true')
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    policy = _policy(arguments.policy)
    if arguments.allow:
        policy['allowed_regions'] = dict(arguments.allow)
    report = check_residency(
        arguments.manifest,
        policy,
        enabled_conditions=arguments.enabled_conditions,
        disabled_conditions=arguments.disabled_conditions,
        require_proof=arguments.require_proof,
        entrypoints=arguments.entrypoints,
        endpoints=arguments.endpoints,
    )
    rendered = json.dumps(report.to_dict(), indent=arguments.indent, sort_keys=True)
    if arguments.output:
        with open(arguments.output, 'w', encoding='utf-8', newline='\n') as destination:
            destination.write(rendered + '\n')
    else:
        print(rendered)
    return 1 if arguments.fail_on_noncompliance and not report.is_compliant else 0


if __name__ == '__main__':
    raise SystemExit(main())
