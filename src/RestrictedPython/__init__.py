##############################################################################
#
# Copyright (c) 2002 Zope Foundation and Contributors.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE
#
##############################################################################
"""RestrictedPython package."""

# flake8: NOQA: E401

# This is a file to define public API in the base namespace of the package.
# use: isort:skip to supress all isort related warnings / errors,
# as this file should be logically grouped imports

# compile_restricted methods:
from RestrictedPython.compile import compile_restricted  # isort:skip
from RestrictedPython.compile import compile_restricted_artifact  # isort:skip
from RestrictedPython.compile import compile_restricted_descriptor  # isort:skip
from RestrictedPython.compile import compile_restricted_eval  # isort:skip
from RestrictedPython.compile import compile_restricted_eval_artifact  # isort:skip
from RestrictedPython.compile import compile_restricted_exec  # isort:skip
from RestrictedPython.compile import compile_restricted_exec_artifact  # isort:skip
from RestrictedPython.compile import compile_restricted_function  # isort:skip
from RestrictedPython.compile import compile_restricted_function_artifact  # isort:skip
from RestrictedPython.compile import compile_restricted_single  # isort:skip
from RestrictedPython.compile import compile_restricted_single_artifact  # isort:skip
from RestrictedPython.compile import compile_restricted_with_artifact  # isort:skip
from RestrictedPython.compile import compile_restricted_with_descriptor  # isort:skip

# reviewable compile artifacts and approvals
from RestrictedPython.artifacts import ApprovalCheck  # isort:skip
from RestrictedPython.artifacts import ApprovalDecision  # isort:skip
from RestrictedPython.artifacts import ApprovalRecord  # isort:skip
from RestrictedPython.artifacts import ArtifactDescriptor  # isort:skip
from RestrictedPython.artifacts import approval_applies  # isort:skip
from RestrictedPython.artifacts import approval_matches  # isort:skip
from RestrictedPython.artifacts import approval_record  # isort:skip
from RestrictedPython.artifacts import approval_still_applies  # isort:skip
from RestrictedPython.artifacts import artifact_summary  # isort:skip
from RestrictedPython.artifacts import build_compile_artifact  # isort:skip
from RestrictedPython.artifacts import build_compile_environment  # isort:skip
from RestrictedPython.artifacts import check_approval  # isort:skip
from RestrictedPython.artifacts import CompilationArtifact  # isort:skip
from RestrictedPython.artifacts import CompileArtifact  # isort:skip
from RestrictedPython.artifacts import CompileEnvironment  # isort:skip
from RestrictedPython.artifacts import compare_artifacts  # isort:skip
from RestrictedPython.artifacts import create_approval_record  # isort:skip
from RestrictedPython.artifacts import current_guard_version  # isort:skip
from RestrictedPython.artifacts import describe_artifact  # isort:skip
from RestrictedPython.artifacts import describe_compile  # isort:skip
from RestrictedPython.artifacts import is_approval_applicable  # isort:skip
from RestrictedPython.artifacts import is_approval_valid  # isort:skip
from RestrictedPython.artifacts import verify_approval  # isort:skip

# predefined builtins
from RestrictedPython.Guards import GUARD_VERSION  # isort:skip
from RestrictedPython.Guards import GUARDS_VERSION  # isort:skip
from RestrictedPython.Guards import safe_builtins  # isort:skip
from RestrictedPython.Guards import safe_globals  # isort:skip
from RestrictedPython.Limits import limited_builtins  # isort:skip
from RestrictedPython.Utilities import utility_builtins  # isort:skip

# Helper Methods
from RestrictedPython.PrintCollector import PrintCollector  # isort:skip
from RestrictedPython.compile import CompileResult  # isort:skip

# Policy
from RestrictedPython.transformer import RestrictingNodeTransformer  # isort:skip

#
from RestrictedPython.Eval import RestrictionCapableEval
