#!/usr/bin/env python3

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

"""Generate the identical-digest sample SBOM cohort."""

from json import dump
from pathlib import Path
from typing import Any, Dict, List

DIGEST = '84ff0b62b508841b3010e8707eb0b0c9463bb8a052580903b08f93c30829cda0'
OUTPUT_DIRECTORY = Path(__file__).parent / 'data' / 'sbom'

PACKAGES: List[Dict[str, str]] = [
    {
        'release_id': 'REL-US-EARLY',
        'serial': 'urn:uuid:11111111-1111-4111-8111-111111111111',
        'timestamp': '2026-02-11T10:00:00Z',
        'channel': 'us-east',
        'file': 'orders-api-4.2.0-us-early.cdx.json',
    },
    {
        'release_id': 'REL-EU-BAD',
        'serial': 'urn:uuid:22222222-2222-4222-8222-222222222222',
        'timestamp': '2026-03-21T09:00:00Z',
        'channel': 'eu-central',
        'file': 'orders-api-4.2.0-eu-bad.cdx.json',
    },
    {
        'release_id': 'REL-APAC-REBUILD',
        'serial': 'urn:uuid:33333333-3333-4333-8333-333333333333',
        'timestamp': '2026-04-13T05:00:00Z',
        'channel': 'ap-southeast',
        'file': 'orders-api-4.2.0-apac-rebuild.cdx.json',
    },
    {
        'release_id': 'REL-CN-PINNED',
        'serial': 'urn:uuid:44444444-4444-4444-8444-444444444444',
        'timestamp': '2026-01-16T08:00:00Z',
        'channel': 'cn-north',
        'file': 'orders-api-4.2.0-cn-pinned.cdx.json',
    },
    {
        'release_id': 'REL-LATAM-COPY',
        'serial': 'urn:uuid:55555555-5555-4555-8555-555555555555',
        'timestamp': '2026-05-03T12:00:00Z',
        'channel': 'latam',
        'file': 'orders-api-4.2.0-latam-copy.cdx.json',
    },
    {
        'release_id': 'REL-US-LATE',
        'serial': 'urn:uuid:66666666-6666-4666-8666-666666666666',
        'timestamp': '2026-04-21T15:00:00Z',
        'channel': 'us-west',
        'file': 'orders-api-4.2.0-us-late.cdx.json',
    },
]


def _build_sbom(package: Dict[str, str]) -> Dict[str, Any]:
    release_id = package['release_id']
    channel = package['channel']
    timestamp = package['timestamp']
    artifact_url = f'artifact://{channel}/orders-api-4.2.0.tar.gz'
    occurrence_context = f'release_id={release_id}; observed_at={timestamp}'
    return {
        '$schema': 'http://cyclonedx.org/schema/bom-1.6.schema.json',
        'bomFormat': 'CycloneDX',
        'specVersion': '1.6',
        'serialNumber': package['serial'],
        'version': 1,
        'metadata': {
            'timestamp': package['timestamp'],
            'component': {
                'type': 'application',
                'bom-ref': f'orders-api-{release_id}',
                'name': 'orders-api',
                'version': '4.2.0',
                'purl': 'pkg:generic/orders-api@4.2.0',
                'hashes': [
                    {'alg': 'SHA-256', 'content': DIGEST},
                ],
                'properties': [
                    {'name': 'acme:release_id', 'value': release_id},
                    {'name': 'acme:channel', 'value': channel},
                ],
                'evidence': {
                    'identity': [
                        {
                            'field': 'hash',
                            'confidence': 1.0,
                            'concludedValue': DIGEST,
                            'methods': [
                                {
                                    'technique': 'hash-comparison',
                                    'confidence': 1.0,
                                    'value': 'artifact digest from the release manifest',
                                },
                            ],
                            'tools': ['tool:forgepack'],
                        },
                        {
                            'field': 'name',
                            'confidence': 1.0,
                            'concludedValue': 'orders-api',
                        },
                    ],
                    'occurrences': [
                        {
                            'location': artifact_url,
                            'symbol': channel,
                            'additionalContext': occurrence_context,
                        },
                    ],
                },
            },
            'tools': {
                'components': [
                    {
                        'type': 'application',
                        'bom-ref': 'tool:forgepack',
                        'name': 'forgepack',
                    },
                ],
            },
        },
    }


def main() -> None:
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    for package in PACKAGES:
        target = OUTPUT_DIRECTORY / package['file']
        with target.open('w', encoding='utf-8', newline='\n') as stream:
            dump(_build_sbom(package), stream, indent=2)
            stream.write('\n')


if __name__ == '__main__':
    main()
