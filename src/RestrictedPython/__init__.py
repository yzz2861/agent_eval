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
from RestrictedPython.compile import compile_restricted_eval  # isort:skip
from RestrictedPython.compile import compile_restricted_exec  # isort:skip
from RestrictedPython.compile import compile_restricted_function  # isort:skip
from RestrictedPython.compile import compile_restricted_single  # isort:skip

# predefined builtins
from RestrictedPython.Guards import safe_builtins  # isort:skip
from RestrictedPython.Guards import safe_globals  # isort:skip
from RestrictedPython.Limits import limited_builtins  # isort:skip
from RestrictedPython.Utilities import utility_builtins  # isort:skip

# Helper Methods
from RestrictedPython.PrintCollector import PrintCollector  # isort:skip
from RestrictedPython.compile import CompileResult  # isort:skip

# Optional call evidence
from RestrictedPython.evidence import CallReceipt  # isort:skip
from RestrictedPython.evidence import EvidenceCompileResult  # isort:skip
from RestrictedPython.evidence import EvidenceRecorder  # isort:skip
from RestrictedPython.evidence import EvidenceReport  # isort:skip
from RestrictedPython.evidence import EvidenceRunResult  # isort:skip
from RestrictedPython.evidence import EvidenceSession  # isort:skip
from RestrictedPython.evidence import EvidenceSink  # isort:skip
from RestrictedPython.evidence import EvidenceTrace  # isort:skip
from RestrictedPython.evidence import FunctionAdapter  # isort:skip
from RestrictedPython.evidence import compile_restricted_evidence  # isort:skip
from RestrictedPython.evidence import (  # isort:skip
    compile_restricted_with_evidence)
from RestrictedPython.evidence import execute_restricted  # isort:skip
from RestrictedPython.evidence import run_restricted  # isort:skip
from RestrictedPython.evidence import run_restricted_evidence  # isort:skip

# Policy
from RestrictedPython.transformer import RestrictingNodeTransformer  # isort:skip

#
from RestrictedPython.Eval import RestrictionCapableEval
