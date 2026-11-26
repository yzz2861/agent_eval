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

"""
Independent coverage validation for BOMs merged from multiple deliveries.

When a BOM is merged from several CycloneDX documents delivered by different
parties, each party typically guarantees something different — one may
guarantee the completeness of its component inventory, another may only
acknowledge the dependency relations of a few key interfaces. The tools in
this package validate each guarantee separately and attribute shared objects'
external references, duplicate names and cross-delivery relations to their
respective sources, so the merged result is never misread as
"everything guaranteed".
"""

__all__ = [
    'DeliveryScope',
    'CoverageValidator',
    'CoverageReport',
    'ComponentInventoryReport',
    'DependencyClosureReport',
]

from .report import ComponentInventoryReport, CoverageReport, DependencyClosureReport
from .scopes import DeliveryScope
from .validator import CoverageValidator
