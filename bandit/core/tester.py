#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import copy
import logging
import warnings

from bandit.core import constants
from bandit.core import context as b_context
from bandit.core import utils

warnings.formatwarning = utils.warnings_formatter
LOG = logging.getLogger(__name__)


class BanditTester:
    def __init__(self, testset, debug, nosec_lines, metrics, suppressed=None):
        self.results = []
        self.testset = testset
        self.last_result = None
        self.debug = debug
        self.nosec_lines = nosec_lines
        self.metrics = metrics
        self.suppressed = suppressed if suppressed is not None else []

    def run_tests(self, raw_context, checktype):
        """Runs all tests for a certain type of check, for example

        Runs all tests for a certain type of check, for example 'functions'
        store results in results.

        :param raw_context: Raw context dictionary
        :param checktype: The type of checks to run
        :return: a score based on the number and type of test results with
                extra metrics about nosec comments
        """

        scores = {
            "SEVERITY": [0] * len(constants.RANKING),
            "CONFIDENCE": [0] * len(constants.RANKING),
        }

        tests = self.testset.get_tests(checktype)
        for test in tests:
            name = test.__name__
            # execute test with an instance of the context class
            temp_context = copy.copy(raw_context)
            context = b_context.Context(temp_context)
            try:
                if hasattr(test, "_config"):
                    result = test(context, test._config)
                else:
                    result = test(context)

                if result is not None:
                    nosec_tests_to_skip = self._get_nosecs_from_contexts(
                        temp_context, test_result=result
                    )

                    if isinstance(temp_context["filename"], bytes):
                        result.fname = temp_context["filename"].decode("utf-8")
                    else:
                        result.fname = temp_context["filename"]
                    result.fdata = temp_context["file_data"]

                    if result.lineno is None:
                        result.lineno = temp_context["lineno"]
                    if result.linerange == []:
                        result.linerange = temp_context["linerange"]
                    if result.col_offset == -1:
                        result.col_offset = temp_context["col_offset"]
                    result.end_col_offset = temp_context.get(
                        "end_col_offset", 0
                    )
                    result.test = name
                    if result.test_id == "":
                        result.test_id = test._test_id

                    suppressing_record = self._find_suppressing_record(
                        nosec_tests_to_skip, result.test_id
                    )
                    if suppressing_record is not None:
                        if suppressing_record.blanket:
                            LOG.debug("skipped, nosec without test number")
                            self.metrics.note_nosec()
                        else:
                            LOG.debug(
                                f"skipped, nosec for test {result.test_id}"
                            )
                            self.metrics.note_skipped_test()
                        result.nosec_comment = suppressing_record.comment
                        result.nosec_test_id = result.test_id
                        self.suppressed.append(result)
                        continue

                    self.results.append(result)

                    LOG.debug("Issue identified by %s: %s", name, result)
                    sev = constants.RANKING.index(result.severity)
                    val = constants.RANKING_VALUES[result.severity]
                    scores["SEVERITY"][sev] += val
                    con = constants.RANKING.index(result.confidence)
                    val = constants.RANKING_VALUES[result.confidence]
                    scores["CONFIDENCE"][con] += val
                else:
                    nosec_tests_to_skip = self._get_nosecs_from_contexts(
                        temp_context
                    )
                    if self._find_suppressing_record(
                        nosec_tests_to_skip, test._test_id
                    ):
                        LOG.warning(
                            f"nosec encountered ({test._test_id}), but no "
                            f"failed test on file "
                            f"{temp_context['filename']}:"
                            f"{temp_context['lineno']}"
                        )

            except Exception as e:
                self.report_error(name, context, e)
                if self.debug:
                    raise
        LOG.debug("Returning scores: %s", scores)
        return scores

    def _get_nosecs_from_contexts(self, context, test_result=None):
        """Collect structured nosec records covering the current context.

        :param context: temp context
        :param test_result: optional test result
        :return: list of NosecRecord objects, empty when no comment applies
        """
        records = []
        if test_result is not None:
            base_records = self.nosec_lines.get(test_result.lineno) or []
            for base_record in base_records:
                if base_record not in records:
                    records.append(base_record)
        context_record = utils.get_nosec(self.nosec_lines, context)
        if context_record is not None:
            for record in context_record:
                if record not in records:
                    records.append(record)
        return records

    @staticmethod
    def _find_suppressing_record(records, test_id):
        """Return the record that explicitly covers ``test_id``, if any."""
        blanket_match = None
        has_specific_record = False
        for record in records:
            if record.blanket:
                if record.suppresses(test_id):
                    blanket_match = record
                continue
            has_specific_record = True
            if record.suppresses(test_id):
                # Specific selectors always win over a blanket directive,
                # including when the two comments sit on adjacent lines.
                return record
        # A blanket directive only applies when no specific directive is in
        # scope; otherwise an unrelated id must stay visible to the scanner.
        return None if has_specific_record else blanket_match

    @staticmethod
    def report_error(test, context, error):
        what = "Bandit internal error running: "
        what += f"{test} "
        what += "on file %s at line %i: " % (
            context._context["filename"],
            context._context["lineno"],
        )
        what += str(error)
        import traceback

        what += traceback.format_exc()
        LOG.error(what)
