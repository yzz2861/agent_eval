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

"""Reconcile three small batch-review documents and show a deletion delta."""

import sys
from json import loads
from pathlib import Path
from typing import Any

if __package__ in {None, ''}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cyclonedx.contrib.batch import verify_batches  # noqa: E402

_DATA = Path(__file__).with_name('batch_reconciliation')


def _read(name: str) -> Any:
    return loads((_DATA / name).read_text(encoding='utf-8'))


def main() -> None:
    batch_list = _read('batch_list.json')
    review_scope = _read('review_scope.json')
    physical_witness = _read('physical_witness.json')

    before = verify_batches(batch_list, review_scope, physical_witness)
    print('Full reconciliation')
    print(before.render())

    after = verify_batches(batch_list, [], physical_witness)
    delta = after.compare(before)
    print()
    print('After removing the middle review-scope document')
    print(delta.describe())

    assert delta.decreased == ('DELIVERY-A', 'DELIVERY-B'), delta.decreased


if __name__ == '__main__':
    main()
