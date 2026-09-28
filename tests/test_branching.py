# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

import json
import logging

import pytest

import structlog

from structlog.branching import Branch, BranchFanout
from structlog.contextvars import bind_contextvars, merge_contextvars
from structlog.exceptions import DropEvent
from structlog.processors import JSONRenderer
from structlog.stdlib import ExtraAdder
from structlog.testing import CapturingLogger


def _counting_processor(counter):
    """
    Return a processor that counts how often it ran.
    """

    def processor(logger, method_name, event_dict):
        counter["runs"] += 1

        return event_dict

    return processor


class TestBranchFanout:
    def test_shared_processors_run_once(self):
        """
        Processors before the fan-out run exactly once per event, no
        matter how many branches there are.
        """
        counter = {"runs": 0}
        received = []
        structlog.configure(
            processors=[
                _counting_processor(counter),
                BranchFanout(
                    [
                        Branch(sink=received.append),
                        Branch(sink=received.append),
                    ]
                ),
            ],
        )

        structlog.get_logger().info("hello")

        assert 1 == counter["runs"]
        assert 2 == len(received)
        assert received[0] is not received[1]

    def test_branches_are_isolated(self):
        """
        Deleting keys and mutating nested values in one branch does not
        affect the other branches.
        """
        received = []

        def destructive(logger, method_name, event_dict):
            del event_dict["secret"]
            event_dict["nested"]["value"] = "tampered"

            return event_dict

        structlog.configure(
            processors=[
                BranchFanout(
                    [
                        Branch(
                            processors=[destructive],
                            sink=received.append,
                        ),
                        Branch(sink=received.append),
                    ]
                ),
            ],
        )

        structlog.get_logger().info(
            "hello", secret="s3cr3t", nested={"value": "original"}
        )

        assert "secret" not in received[0]
        assert "tampered" == received[0]["nested"]["value"]
        assert "s3cr3t" == received[1]["secret"]
        assert "original" == received[1]["nested"]["value"]

    def test_drop_event_is_branch_local(self):
        """
        A branch raising DropEvent (e.g. the console branch) is skipped,
        but the other branches (e.g. the audit branch) still receive the
        complete event dict from the shared processing stage.
        """
        received = []

        def dropper(logger, method_name, event_dict):
            raise DropEvent

        structlog.configure(
            processors=[
                BranchFanout(
                    [
                        Branch(processors=[dropper], sink=received.append),
                        Branch(sink=received.append),
                    ]
                ),
            ],
        )

        structlog.get_logger().info("hello", audit="yes")

        assert 1 == len(received)
        assert {"event": "hello", "audit": "yes"} == received[0]

    def test_branch_error_continue(self):
        """
        With on_branch_error="continue", an exception in one branch does
        not prevent the remaining branches from running.
        """
        received = []

        def boom(logger, method_name, event_dict):
            raise ValueError("boom")

        structlog.configure(
            processors=[
                BranchFanout(
                    [
                        Branch(processors=[boom], sink=received.append),
                        Branch(sink=received.append),
                    ],
                    on_branch_error="continue",
                ),
            ],
        )

        structlog.get_logger().info("hello")

        assert 1 == len(received)

    def test_branch_error_raise(self):
        """
        With on_branch_error="raise", an exception in one branch
        propagates and skips the remaining branches.
        """
        received = []

        def boom(logger, method_name, event_dict):
            raise ValueError("boom")

        structlog.configure(
            processors=[
                BranchFanout(
                    [
                        Branch(processors=[boom], sink=received.append),
                        Branch(sink=received.append),
                    ],
                    on_branch_error="raise",
                ),
            ],
        )

        with pytest.raises(ValueError, match="boom"):
            structlog.get_logger().info("hello")

        assert [] == received

    def test_invalid_error_policy(self):
        """
        An unknown on_branch_error policy is rejected.
        """
        with pytest.raises(ValueError, match="on_branch_error"):
            BranchFanout([], on_branch_error="ignore")

    def test_wrapped_logger_is_not_called(self):
        """
        The fan-out handles all output itself, so the wrapped logger
        never sees the event.
        """
        cl = CapturingLogger()
        received = []
        structlog.configure(
            processors=[BranchFanout([Branch(sink=received.append)])],
            logger_factory=lambda *args: cl,
        )

        structlog.get_logger().info("hello")

        assert 1 == len(received)
        assert [] == cl.calls

    def test_renderer_and_sink(self):
        """
        Each branch can render the event dict differently before it
        reaches its sink.
        """
        rendered = []
        raw = []
        structlog.configure(
            processors=[
                BranchFanout(
                    [
                        Branch(
                            renderer=JSONRenderer(),
                            sink=rendered.append,
                        ),
                        Branch(sink=raw.append),
                    ]
                ),
            ],
        )

        structlog.get_logger().info("hello")

        assert {"event": "hello"} == json.loads(rendered[0])
        assert {"event": "hello"} == raw[0]

    def test_contextvars_merged_once(self):
        """
        Bound contextvars are merged into the event dict once, in the
        shared stage, and are visible to all branches.
        """
        counter = {"runs": 0}
        received = []
        structlog.configure(
            processors=[
                merge_contextvars,
                _counting_processor(counter),
                BranchFanout(
                    [
                        Branch(sink=received.append),
                        Branch(sink=received.append),
                    ]
                ),
            ],
        )
        bind_contextvars(request_id="abc")

        structlog.get_logger().info("hello")

        assert 1 == counter["runs"]
        assert 2 == len(received)
        assert all("abc" == ed["request_id"] for ed in received)

    def test_stdlib_extra_merged_once(self):
        """
        stdlib logging extra fields are merged into the event dict once,
        in the shared stage, and are visible to all branches.
        """
        counter = {"runs": 0}
        received = []
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="hello",
            args=(),
            exc_info=None,
        )
        record.user = "jane"
        structlog.configure(
            processors=[
                ExtraAdder(),
                _counting_processor(counter),
                BranchFanout(
                    [
                        Branch(sink=received.append),
                        Branch(sink=received.append),
                    ]
                ),
            ],
        )

        structlog.get_logger().info("hello", _record=record)

        assert 1 == counter["runs"]
        assert 2 == len(received)
        assert all("jane" == ed["user"] for ed in received)
