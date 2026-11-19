"""
Differential oracles for the structure-aware RTF fuzzer.

Two oracles are maintained on purpose:

* the *valid* oracle compares the extracted object bytes of semantically
  equivalent encodings - any difference is a discrepancy worth reducing;
* the *invalid* oracle classifies the diagnostics produced by deliberately
  contradictory samples and, most importantly, fails when a malformed sample
  silently recovers a complete object instead of reporting a problem.

Every rtfobj invocation is wrapped so that parser log messages (the anti-
analysis diagnostics emitted by the backslash-bin handler, for example) are
captured alongside the extracted objects.
"""

import hashlib
import logging

from . import model
from .. import rtfobj


class DiagnosticLogHandler(logging.Handler):
    """Collect rtfobj log records emitted during a single parse."""

    def __init__(self):
        logging.Handler.__init__(self)
        self.records = []

    def emit(self, record):
        self.records.append({
            "level": record.levelname,
            "message": record.getMessage(),
        })


class ExtractionResult(object):
    """Structured outcome of running rtfobj on one RTF document."""

    def __init__(self, document, objects, diagnostics, error=None):
        self.document = bytes(document)
        self.object_fingerprints = tuple(objects)
        self.diagnostics = tuple(diagnostics)
        self.error = error

    @property
    def object_count(self):
        return len(self.object_fingerprints)

    @property
    def diagnostic_codes(self):
        return tuple(item["message"] for item in self.diagnostics)

    def to_record(self):
        return {
            "document_size": len(self.document),
            "object_count": self.object_count,
            "object_fingerprints": list(self.object_fingerprints),
            "diagnostics": list(self.diagnostics),
            "error": self.error,
        }


def _fingerprint_object(rtf_object):
    raw = rtf_object.rawdata or b""
    return {
        "start": rtf_object.start,
        "end": rtf_object.end,
        "length": len(raw),
        "md5": hashlib.md5(raw).hexdigest(),
        "is_ole": bool(rtf_object.is_ole),
    }


def extract(document):
    """Run rtfobj on *document* and return an :class:`ExtractionResult`.

    The function never raises for malformed input: a parser exception is
    captured as the result's error so that crash-like behaviour can be
    compared like any other diagnostic instead of aborting the campaign.
    """
    handler = DiagnosticLogHandler()
    handler.setLevel(logging.DEBUG)
    logger = rtfobj.log
    logger.addHandler(handler)
    previous_level = logger.level
    logger.setLevel(logging.DEBUG)
    objects = []
    error = None
    try:
        parser = rtfobj.RtfObjParser(bytes(document))
        parser.parse()
        for rtf_object in parser.objects:
            objects.append(_fingerprint_object(rtf_object))
    except Exception as exc:  # noqa: BLE001 - intentional broad capture
        error = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
    return ExtractionResult(document, objects, handler.records, error)


def equivalent_fingerprints(left, right):
    """Compare object bytes regardless of their position in the document."""
    left_hashes = sorted(item["md5"] for item in left.object_fingerprints)
    right_hashes = sorted(item["md5"] for item in right.object_fingerprints)
    return left_hashes == right_hashes


class Difference(object):
    """A discrepancy between a baseline extraction and a variant extraction."""

    def __init__(self, kind, baseline, variant, detail):
        self.kind = kind
        self.baseline = baseline
        self.variant = variant
        self.detail = dict(detail)

    def signature(self):
        """Stable signature used by the syntax-unit reducer.

        The signature captures *what kind* of difference was observed, not the
        concrete document size, so reducing the sample cannot silently turn the
        finding into an unrelated parse exception.
        """
        baseline = self.baseline
        variant = self.variant
        return {
            "kind": self.kind,
            "baseline_count": baseline.object_count,
            "variant_count": variant.object_count,
            "baseline_md5": sorted(item["md5"]
                                    for item in baseline.object_fingerprints),
            "variant_md5": sorted(item["md5"]
                                   for item in variant.object_fingerprints),
            "variant_error": variant.error["type"] if variant.error else None,
            "detail": self.detail,
        }


def compare_valid(baseline, variant, mutation_record):
    """Oracle for legal re-encodings: object bytes must stay identical."""
    if equivalent_fingerprints(baseline, variant):
        return None
    detail = {"mutation": mutation_record}
    if variant.error is not None:
        kind = "valid_variant_raised"
    elif variant.object_count != baseline.object_count:
        kind = "valid_variant_object_count"
    else:
        kind = "valid_variant_byte_difference"
    return Difference(kind, baseline, variant, detail)


def compare_invalid(baseline, variant, mutation_record, expected_payload_md5):
    """Oracle for deliberately invalid samples.

    A finding is reported when the malformed document still yields a complete,
    untouched copy of the expected object (silent recovery), or when the parser
    raises instead of producing a documented diagnostic.
    """
    detail = {"mutation": mutation_record}
    if variant.error is not None:
        detail["reason"] = "parser_raised_on_invalid_input"
        return Difference("invalid_variant_raised", baseline, variant, detail)
    recovered_full = any(
        item["md5"] == expected_payload_md5
        and item["length"] == baseline.object_fingerprints[0]["length"]
        for item in variant.object_fingerprints)
    if recovered_full:
        detail["reason"] = "length_or_syntax_contradiction_silently_ignored"
        return Difference("invalid_silent_full_object", baseline, variant,
                          detail)
    return None


class Budget(object):
    """Dual budget limiting both parse steps and bytes read.

    A campaign stops as soon as either the maximum number of parser executions
    (max_steps) or the cumulative number of bytes fed to the parser
    (max_bytes) is reached.  The budget is shared by the fuzzing loop and the
    reducer so a single hard ceiling always applies.
    """

    def __init__(self, max_steps, max_bytes):
        self.max_steps = int(max_steps)
        self.max_bytes = int(max_bytes)
        self.steps_used = 0
        self.bytes_used = 0
        self.stop_reason = None

    def allow(self, document_size):
        if self.steps_used >= self.max_steps:
            self.stop_reason = "max_steps_reached"
            return False
        if self.bytes_used + document_size > self.max_bytes:
            self.stop_reason = "max_bytes_reached"
            return False
        return True

    def consume(self, document_size):
        self.steps_used += 1
        self.bytes_used += int(document_size)

    @property
    def exhausted(self):
        return self.stop_reason is not None

    def snapshot(self):
        return {
            "max_steps": self.max_steps,
            "max_bytes": self.max_bytes,
            "steps_used": self.steps_used,
            "bytes_used": self.bytes_used,
            "stop_reason": self.stop_reason,
        }


def run_with_budget(document, budget):
    """Run one extraction while honouring and updating the shared budget."""
    size = len(document)
    if not budget.allow(size):
        return None
    result = extract(document)
    budget.consume(size)
    return result
