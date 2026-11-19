# SPDX-License-Identifier: Apache-2.0
r"""
==============================================
B616: Sensitive data emitted to logging sinks
==============================================

Code generators often add exception logging around every interface. A review
that only checks whether a masking helper was called can miss fallback
branches that still write the original request field into structured logs.

This plugin runs a flow-sensitive taint analysis over locally generated
Python code. It tracks values from explicitly configured sensitive sources
through local aliases, dictionary updates and dictionary unpacking, across
exception handlers, up to the arguments of configured structured logging
sinks. A finding is only raised when a sensitive field can actually reach a
log call without passing through a configured trusted sanitizer.

Sensitive sources, trusted sanitizers and logging sinks are all given
explicitly by project configuration; nothing is inferred from names.

**Config Options:**

.. code-block:: yaml

    sensitive_log:
      local_only: true
      local_paths:
        - src/generated
      sensitive_sources:
        - name: flask.request.get_json
          fields: [card_no, ssn]
      trusted_sanitizers:
        - security.mask_card
      log_sinks:
        - logging.Logger.info
        - logging.Logger.exception

B616 reports a confirmed sensitive field reaching a log sink. B617 reports a
value whose sanitization cannot be confirmed statically because it flows
through an unmodeled external call; those diagnostics are presented
separately at lower confidence for manual triage.

.. versionadded:: 0.0.0
"""

import bandit
from bandit.core import issue
from bandit.core import test_properties as test
from bandit.plugins.sensitive_log import engine


def gen_config(name):
    if name == "sensitive_log":
        return {
            "local_only": True,
            "local_paths": [],
            "sensitive_sources": [],
            "trusted_sanitizers": [],
            "log_sinks": engine.SensitiveLogConfig.DEFAULT_SINKS,
        }
    return None


def _findings(context, config):
    filename = context._context.get("filename", "")
    parsed = engine.SensitiveLogConfig(config)
    if not parsed.is_local_file(filename):
        return []
    source = context.file_data
    source.seek(0)
    data = source.read()
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    try:
        return engine.analyze_source(data, config)
    except SyntaxError:
        return []


def _issue(finding):
    if finding.kind == engine.Finding.LEAK:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.INSERTION_OF_SENSITIVE_INFORMATION_INTO_LOG_FILE,
            text=finding.text,
            lineno=finding.lineno,
            col_offset=finding.col_offset,
        )
    return bandit.Issue(
        severity=bandit.LOW,
        confidence=bandit.LOW,
        cwe=issue.Cwe.INSERTION_OF_SENSITIVE_INFORMATION_INTO_LOG_FILE,
        text=finding.text,
        lineno=finding.lineno,
        col_offset=finding.col_offset,
    )


@test.takes_config("sensitive_log")
@test.checks("File")
@test.test_id("B616")
def sensitive_log_leak(context, config):
    """Confirmed sensitive field reaching a structured logging sink."""
    issues = [
        _issue(finding)
        for finding in _findings(context, config)
        if finding.kind == engine.Finding.LEAK
    ]
    return issues or None


@test.takes_config("sensitive_log")
@test.checks("File")
@test.test_id("B617")
def sensitive_log_unverified(context, config):
    """Log argument depending on an unmodeled external call."""
    issues = [
        _issue(finding)
        for finding in _findings(context, config)
        if finding.kind == engine.Finding.UNKNOWN
    ]
    return issues or None
