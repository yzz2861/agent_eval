#!/usr/bin/env python

# Example rule built on the reusable control flow analysis. It detects a
# user-controlled file path reaching a file-reading sink without going through
# the configured path validator. The validator uses the RAISES contract:
# validate_path() is expected to raise on an unsafe path, so a straight-line
# call validates the rest of the path but a swallowed exception does not.

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from .. import flow
from .helpers import FlowAnalysisLinter


class UnverifiedFilepathReadLinter(FlowAnalysisLinter):
    off_by_default = False

    _code = 'DUO139'
    _error_tmpl = (
        'DUO139 unvalidated user file path reaches "{sink}" '
        'via {evidence}'
    )
    _unknown_tmpl = (
        'DUO139 unable to prove validation of file path reaching "{sink}" '
        '(too many paths)'
    )

    rule_spec = flow.RuleSpec(
        name="unverified-filepath-read",
        # Untrusted origins: request parameters and user path helpers.
        sources=(
            "request.args.get",
            "request.form.get",
            "user_supplied_path",
        ),
        # Configured validator. It raises on an invalid/unsafe path.
        validators=("validate_path",),
        # Dangerous sinks that read from the file system.
        sinks=("open", "read_file"),
        validator_contract=flow.ValidatorContract.RAISES,
    )
