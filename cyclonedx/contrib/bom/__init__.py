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

"""Bom related functionality"""

from .merge import (
    BomEvidenceMerger,
    BomMerger,
    BomMergeResult,
    ComponentEvidenceMerger,
    ComponentIdentity,
    EvidenceClaim,
    EvidenceClaimMerger,
    EvidenceClaimMergeResult,
    EvidenceMerger,
    TrustSource,
    UnattributedClaim,
    UnattributedReason,
    merge,
    merge_boms,
    merge_components,
    merge_evidence_claims,
    merge_trust_sources,
)

__all__ = [
    'BomEvidenceMerger',
    'BomMergeResult',
    'BomMerger',
    'ComponentEvidenceMerger',
    'ComponentIdentity',
    'EvidenceClaim',
    'EvidenceClaimMergeResult',
    'EvidenceClaimMerger',
    'EvidenceMerger',
    'TrustSource',
    'UnattributedClaim',
    'UnattributedReason',
    'merge',
    'merge_boms',
    'merge_components',
    'merge_evidence_claims',
    'merge_trust_sources',
]
