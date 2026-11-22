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
Offline build-tool impact assessment.

This contrib module reconciles CycloneDX SBOM components and evidence objects
against an explicitly frozen build-behaviour archive and a build-tool
repository advisory. It is deliberately offline: all inputs are local files.
"""

__all__ = [
    'AdvisoryError',
    'ArchiveNotFrozenError',
    'AssessmentError',
    'BuildRecord',
    'FrozenBuildArchive',
    'ImpactFinding',
    'ImpactReport',
    'ImpactStatus',
    'SameDigestCohort',
    'SbomObservation',
    'SbomTool',
    'ToolAdvisory',
    'ToolInvocation',
    'ToolObservation',
    'ToolSource',
    'ToolVerdict',
    'assess',
    'evaluate_tool_invocation',
    'load_observations',
    'render_csv',
    'render_json',
    'render_markdown',
    'report_to_dict',
]

from .assess import (
    AdvisoryError,
    ArchiveNotFrozenError,
    AssessmentError,
    BuildRecord,
    FrozenBuildArchive,
    ImpactFinding,
    ImpactReport,
    ImpactStatus,
    SameDigestCohort,
    SbomObservation,
    SbomTool,
    ToolAdvisory,
    ToolInvocation,
    ToolObservation,
    ToolSource,
    ToolVerdict,
    assess,
    evaluate_tool_invocation,
    load_observations,
)
from .report import render_csv, render_json, render_markdown, report_to_dict
