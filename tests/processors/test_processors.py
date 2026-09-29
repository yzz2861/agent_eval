# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

from __future__ import annotations

import functools
import inspect
import json
import logging
import os
import pickle
import sys
import threading

from io import StringIO

import pytest

import structlog

from structlog import BoundLogger
from structlog._utils import get_processname
from structlog.processors import (
    CallsiteParameter,
    CallsiteParameterAdder,
    EventRenamer,
    ExceptionPrettyPrinter,
    JSONRenderer,
    PathRedactor,
    RedactionRule,
    StackInfoRenderer,
    UnicodeDecoder,
    UnicodeEncoder,
    _figure_out_exc_info,
    format_exc_info,
)
from structlog.stdlib import ProcessorFormatter
from structlog.testing import CapturingLoggerFactory
from structlog.typing import EventDict, ExcInfo

from ..additional_frame import additional_frame


try:
    import simplejson
except ImportError:
    simplejson = None


class TestUnicodeEncoder:
    def test_encodes(self):
        """
        Unicode strings get encoded (as UTF-8 by default).
        """
        e = UnicodeEncoder()

        assert {"foo": b"b\xc3\xa4r"} == e(None, None, {"foo": "b\xe4r"})

    def test_passes_arguments(self):
        """
        Encoding options are passed into the encoding call.
        """
        e = UnicodeEncoder("latin1", "xmlcharrefreplace")

        assert {"foo": b"&#8211;"} == e(None, None, {"foo": "\u2013"})

    def test_bytes_nop(self):
        """
        If the string is already bytes, don't do anything.
        """
        e = UnicodeEncoder()

        assert {"foo": b"b\xc3\xa4r"} == e(None, None, {"foo": b"b\xc3\xa4r"})


class TestUnicodeDecoder:
    def test_decodes(self):
        """
        Byte strings get decoded (as UTF-8 by default).
        """
        ud = UnicodeDecoder()

        assert {"foo": "b\xe4r"} == ud(None, None, {"foo": b"b\xc3\xa4r"})

    def test_passes_arguments(self):
        """
        Encoding options are passed into the encoding call.
        """
        ud = UnicodeDecoder("utf-8", "ignore")

        assert {"foo": ""} == ud(None, None, {"foo": b"\xa1\xa4"})

    def test_bytes_nop(self):
        """
        If the value is already unicode, don't do anything.
        """
        ud = UnicodeDecoder()

        assert {"foo": "b\u2013r"} == ud(None, None, {"foo": "b\u2013r"})


class TestExceptionPrettyPrinter:
    def test_stdout_by_default(self):
        """
        If no file is supplied, use stdout.
        """
        epp = ExceptionPrettyPrinter()

        assert sys.stdout is epp._file

    def test_prints_exception(self, sio):
        """
        If there's an `exception` key in the event_dict, just print it out.
        This happens if `format_exc_info` was run before us in the chain.
        """
        epp = ExceptionPrettyPrinter(file=sio)
        try:
            raise ValueError
        except ValueError:
            ed = format_exc_info(None, None, {"exc_info": True})
        epp(None, None, ed)

        out = sio.getvalue()

        assert "test_prints_exception" in out
        assert "raise ValueError" in out

    def test_uses_exception_formatter(self, sio):
        """
        If an `exception_formatter` is passed, use that to render the
        exception rather than the default.
        """

        def formatter(exc_info: ExcInfo) -> str:
            return f"error: {exc_info}"

        epp = ExceptionPrettyPrinter(file=sio, exception_formatter=formatter)
        try:
            raise ValueError
        except ValueError as e:
            epp(None, None, {"exc_info": True})
            formatted = formatter(e)

        out = sio.getvalue()

        assert formatted in out

    def test_removes_exception_after_printing(self, sio):
        """
        After pretty printing `exception` is removed from the event_dict.
        """
        epp = ExceptionPrettyPrinter(sio)
        try:
            raise ValueError
        except ValueError:
            ed = format_exc_info(None, None, {"exc_info": True})

        assert "exception" in ed

        new_ed = epp(None, None, ed)

        assert "exception" not in new_ed

    def test_handles_exc_info(self, sio):
        """
        If `exc_info` is passed in, it behaves like `format_exc_info`.
        """
        epp = ExceptionPrettyPrinter(sio)
        try:
            raise ValueError
        except ValueError:
            epp(None, None, {"exc_info": True})

        out = sio.getvalue()

        assert "test_handles_exc_info" in out
        assert "raise ValueError" in out

    def test_removes_exc_info_after_printing(self, sio):
        """
        After pretty printing `exception` is removed from the event_dict.
        """
        epp = ExceptionPrettyPrinter(sio)
        try:
            raise ValueError
        except ValueError:
            ed = epp(None, None, {"exc_info": True})

        assert "exc_info" not in ed

    def test_nop_if_no_exception(self, sio):
        """
        If there is no exception, don't print anything.
        """
        epp = ExceptionPrettyPrinter(sio)
        epp(None, None, {})

        assert "" == sio.getvalue()

    def test_own_exc_info(self, sio):
        """
        If exc_info is a tuple, use it.
        """
        epp = ExceptionPrettyPrinter(sio)
        try:
            raise ValueError("XXX")
        except ValueError:
            ei = sys.exc_info()

        epp(None, None, {"exc_info": ei})

        assert "XXX" in sio.getvalue()

    def test_exception_on_py3(self, sio):
        """
        On Python 3, it's also legal to pass an Exception.
        """
        epp = ExceptionPrettyPrinter(sio)
        try:
            raise ValueError("XXX")
        except ValueError as e:
            epp(None, None, {"exc_info": e})

        assert "XXX" in sio.getvalue()


@pytest.fixture
def sir():
    return StackInfoRenderer()


class TestStackInfoRenderer:
    def test_removes_stack_info(self, sir):
        """
        The `stack_info` key is removed from `event_dict`.
        """
        ed = sir(None, None, {"stack_info": True})

        assert "stack_info" not in ed

    def test_adds_stack_if_asked(self, sir):
        """
        If `stack_info` is true, `stack` is added.
        """
        ed = sir(None, None, {"stack_info": True})

        assert "stack" in ed

    def test_renders_correct_stack(self, sir):
        """
        The rendered stack is correct.
        """
        ed = sir(None, None, {"stack_info": True})

        assert 'ed = sir(None, None, {"stack_info": True})' in ed["stack"]

    def test_additional_ignores(self):
        """
        Filtering of names works.
        """
        sir = StackInfoRenderer(["tests.additional_frame"])

        ed = additional_frame(
            functools.partial(sir, None, None, {"stack_info": True})
        )

        assert "additional_frame.py" not in ed["stack"]


class TestFigureOutExcInfo:
    @pytest.mark.parametrize("true_value", [True, 1, 1.1])
    def test_obtains_exc_info_on_True(self, true_value):
        """
        If the passed argument evaluates to True obtain exc_info ourselves.
        """
        try:
            0 / 0
        except Exception:
            assert sys.exc_info() == _figure_out_exc_info(true_value)
        else:
            pytest.fail("Exception not raised.")

    def test_py3_exception_no_traceback(self):
        """
        Exceptions without tracebacks are simply returned with None for
        traceback.
        """
        e = ValueError()

        assert (e.__class__, e, None) == _figure_out_exc_info(e)


class TestCallsiteParameterAdder:
    parameter_strings = {
        "pathname",
        "filename",
        "module",
        "func_name",
        "lineno",
        "thread",
        "thread_name",
        "process",
        "process_name",
    }

    # Exclude QUAL_NAME and QUAL_MODULE from the general set to keep parity with
    # stdlib LogRecord-derived parameters. QUAL_NAME and QUAL_MODULE are tested
    # separately.
    _all_parameters = {
        p
        for p in set(CallsiteParameter)
        if p
        not in (CallsiteParameter.QUAL_NAME, CallsiteParameter.QUAL_MODULE)
    }

    def test_all_parameters(self) -> None:
        """
        All callsite parameters are included in ``self.parameter_strings`` and
        the dictionary returned by ``self.get_callsite_parameters`` contains
        keys for all callsite parameters.
        """

        assert self.parameter_strings == {
            member.value for member in self._all_parameters
        }
        assert self.parameter_strings == self.get_callsite_parameters().keys()

    @pytest.mark.skipif(
        sys.version_info < (3, 11), reason="QUAL_NAME requires Python 3.11+"
    )
    def test_qual_name_structlog(self) -> None:
        """
        QUAL_NAME is added for structlog-originated events on Python 3.11+.
        """
        processor = CallsiteParameterAdder(
            parameters={CallsiteParameter.QUAL_NAME}
        )
        event_dict: EventDict = {"event": "msg"}
        actual = processor(None, None, event_dict)

        assert actual["qual_name"].endswith(
            f"{self.__class__.__name__}.test_qual_name_structlog"
        )

    def test_qual_module_structlog(self) -> None:
        """
        QUAL_MODULE is added for structlog-originated events.
        """
        processor = CallsiteParameterAdder(
            parameters={CallsiteParameter.QUAL_MODULE}
        )
        event_dict: EventDict = {"event": "msg"}
        actual = processor(None, None, event_dict)

        assert "tests.processors.test_processors" == actual["qual_module"]

    def test_qual_name_logging_origin_absent(self) -> None:
        """
        QUAL_NAME is not sourced from stdlib LogRecord and remains absent
        (because it doesn't exist).
        """
        processor = CallsiteParameterAdder(
            parameters={CallsiteParameter.QUAL_NAME}
        )
        record = logging.LogRecord(
            "name",
            logging.INFO,
            __file__,
            0,
            "message",
            None,
            None,
            "func",
        )
        event_dict: EventDict = {
            "event": "message",
            "_record": record,
            "_from_structlog": False,
        }
        actual = processor(None, None, event_dict)

        assert "qual_name" not in actual

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("wrapper_class", "method_name"),
        [
            (structlog.stdlib.BoundLogger, "ainfo"),
            (structlog.stdlib.AsyncBoundLogger, "info"),
        ],
    )
    async def test_async(self, wrapper_class, method_name) -> None:
        """
        Callsite information for async invocations are correct.
        Thread information is now correctly captured before async bridge.
        """
        string_io = StringIO()

        class StringIOLogger(structlog.PrintLogger):
            def __init__(self):
                super().__init__(file=string_io)

        processor = self.make_processor(None, ["concurrent", "threading"])
        structlog.configure(
            processors=[processor, JSONRenderer()],
            logger_factory=StringIOLogger,
            wrapper_class=wrapper_class,
            cache_logger_on_first_use=True,
        )

        logger = structlog.stdlib.get_logger()

        # Capture thread info before async call
        expected_thread = threading.get_ident()
        expected_thread_name = threading.current_thread().name

        callsite_params = self.get_callsite_parameters()
        await getattr(logger, method_name)("baz")
        logger_params = json.loads(string_io.getvalue())

        assert expected_thread == logger_params["thread"]
        assert expected_thread_name == logger_params["thread_name"]

        # Remove thread info from comparison for remaining params
        for key in ["thread", "thread_name"]:
            callsite_params.pop(key)
            logger_params.pop(key)

        assert {"event": "baz", **callsite_params} == logger_params

    @pytest.mark.asyncio
    async def test_async_native_logger(self) -> None:
        """
        Callsite thread information for native async invocations is correct.
        """
        cf = CapturingLoggerFactory()
        structlog.configure(
            processors=[
                CallsiteParameterAdder(
                    parameters=[
                        CallsiteParameter.THREAD,
                        CallsiteParameter.THREAD_NAME,
                    ]
                ),
            ],
            logger_factory=cf,
            wrapper_class=structlog._native.BoundLoggerFilteringAtInfo,
            cache_logger_on_first_use=True,
        )

        logger = structlog.get_logger()

        expected_thread = threading.get_ident()
        expected_thread_name = threading.current_thread().name

        await logger.ainfo("test native async")

        captured = cf.logger.calls[0].kwargs

        assert expected_thread == captured["thread"]
        assert expected_thread_name == captured["thread_name"]

    def test_additional_ignores(self) -> None:
        """
        Stack frames from modules with names that start with values in
        `additional_ignores` are ignored when determining the callsite.
        """
        test_message = "test message"
        additional_ignores = ["tests.additional_frame"]
        processor = self.make_processor(None, additional_ignores)
        event_dict: EventDict = {"event": test_message}

        # Warning: the next two lines must appear exactly like this to make
        # line numbers match.
        callsite_params = self.get_callsite_parameters(1)
        actual = processor(None, None, event_dict)

        expected = {"event": test_message, **callsite_params}

        assert expected == actual

    @pytest.mark.parametrize("origin", ["logging", "structlog"])
    @pytest.mark.parametrize(
        "parameter_strings",
        [
            None,
            *[{parameter} for parameter in parameter_strings],
            set(),
            parameter_strings,
            {"pathname", "filename"},
            {"module", "func_name"},
        ],
    )
    def test_processor(
        self,
        origin: str,
        parameter_strings: set[str] | None,
    ):
        """
        The correct callsite parameters are added to event dictionaries.
        """
        test_message = "test message"
        processor = self.make_processor(parameter_strings)
        if origin == "structlog":
            event_dict: EventDict = {"event": test_message}
            callsite_params = self.get_callsite_parameters()
            actual = processor(None, None, event_dict)
        elif origin == "logging":
            callsite_params = self.get_callsite_parameters()
            record = logging.LogRecord(
                "name",
                logging.INFO,
                callsite_params["pathname"],
                callsite_params["lineno"],
                test_message,
                None,
                None,
                callsite_params["func_name"],
            )
            event_dict: EventDict = {
                "event": test_message,
                "_record": record,
                "_from_structlog": False,
            }
            actual = processor(None, None, event_dict)
        else:
            pytest.fail(f"invalid origin {origin}")
        actual = {
            key: value
            for key, value in actual.items()
            if not key.startswith("_")
        }
        callsite_params = self.filter_parameter_dict(
            callsite_params, parameter_strings
        )
        expected = {"event": test_message, **callsite_params}

        assert expected == actual

    @pytest.mark.parametrize(
        "setup",
        ["common-without-pre", "common-with-pre", "shared", "everywhere"],
    )
    @pytest.mark.parametrize("origin", ["logging", "structlog"])
    @pytest.mark.parametrize(
        "parameter_strings",
        [
            None,
            *[{parameter} for parameter in parameter_strings],
            set(),
            parameter_strings,
            {"pathname", "filename"},
            {"module", "func_name"},
        ],
    )
    def test_e2e(
        self,
        setup: str,
        origin: str,
        parameter_strings: set[str] | None,
    ) -> None:
        """
        Logging output contains the correct callsite parameters.
        """
        logger = logging.Logger(sys._getframe().f_code.co_name)
        string_io = StringIO()
        handler = logging.StreamHandler(string_io)
        processors = [self.make_processor(parameter_strings)]
        if setup == "common-without-pre":
            common_processors = processors
            formatter = ProcessorFormatter(
                processors=[*processors, JSONRenderer()]
            )
        elif setup == "common-with-pre":
            common_processors = processors
            formatter = ProcessorFormatter(
                foreign_pre_chain=processors,
                processors=[JSONRenderer()],
            )
        elif setup == "shared":
            common_processors = []
            formatter = ProcessorFormatter(
                processors=[*processors, JSONRenderer()],
            )
        elif setup == "everywhere":
            common_processors = processors
            formatter = ProcessorFormatter(
                foreign_pre_chain=processors,
                processors=[*processors, JSONRenderer()],
            )
        else:
            pytest.fail(f"invalid setup {setup}")
        handler.setFormatter(formatter)
        handler.setLevel(0)
        logger.addHandler(handler)
        logger.setLevel(0)

        test_message = "test message"
        if origin == "logging":
            callsite_params = self.get_callsite_parameters()
            logger.info(test_message)
        elif origin == "structlog":
            ctx = {}
            bound_logger = BoundLogger(
                logger,
                [*common_processors, ProcessorFormatter.wrap_for_formatter],
                ctx,
            )
            callsite_params = self.get_callsite_parameters()
            bound_logger.info(test_message)
        else:
            pytest.fail(f"invalid origin {origin}")

        callsite_params = self.filter_parameter_dict(
            callsite_params, parameter_strings
        )
        actual = {
            key: value
            for key, value in json.loads(string_io.getvalue()).items()
            if not key.startswith("_")
        }
        expected = {"event": test_message, **callsite_params}

        assert expected == actual

    def test_pickeable_callsite_parameter_adder(self) -> None:
        """
        An instance of ``CallsiteParameterAdder`` can be pickled.  This
        functionality may be used to propagate structlog configurations to
        subprocesses.
        """
        pickle.dumps(CallsiteParameterAdder())

    @classmethod
    def make_processor(
        cls,
        parameter_strings: set[str] | None,
        additional_ignores: list[str] | None = None,
    ) -> CallsiteParameterAdder:
        """
        Creates a ``CallsiteParameterAdder`` with parameters matching the
        supplied *parameter_strings* values and with the supplied
        *additional_ignores* values.

        Args:
            parameter_strings:
                Strings for which corresponding ``CallsiteParameters`` should
                be included in the resulting ``CallsiteParameterAdded``.

            additional_ignores:
                Used as *additional_ignores* for the resulting
                ``CallsiteParameterAdded``.
        """
        if parameter_strings is None:
            return CallsiteParameterAdder(
                parameters=cls._all_parameters,
                additional_ignores=additional_ignores,
            )

        parameters = cls.filter_parameters(parameter_strings)
        return CallsiteParameterAdder(
            parameters=parameters,
            additional_ignores=additional_ignores,
        )

    @classmethod
    def filter_parameters(
        cls, parameter_strings: set[str] | None
    ) -> set[CallsiteParameter]:
        """
        Returns a set containing all ``CallsiteParameter`` members with values
        that are in ``parameter_strings``.

        Args:
            parameter_strings:
                The parameters strings for which corresponding
                ``CallsiteParameter`` members should be returned. If this value
                is `None` then all ``CallsiteParameter`` will be returned.
        """
        if parameter_strings is None:
            return cls._all_parameters
        return {
            parameter
            for parameter in cls._all_parameters
            if parameter.value in parameter_strings
        }

    @classmethod
    def filter_parameter_dict(
        cls, input: dict[str, object], parameter_strings: set[str] | None
    ) -> dict[str, object]:
        """
        Returns a dictionary that is equivalent to *input* but with all keys
        not in *parameter_strings* removed.

        Args:
            parameter_strings:
                The keys to keep in the dictionary, if this value is ``None``
                then all keys matching ``cls.parameter_strings`` are kept.
        """
        if parameter_strings is None:
            parameter_strings = cls.parameter_strings
        return {
            key: value
            for key, value in input.items()
            if key in parameter_strings
        }

    @classmethod
    def get_callsite_parameters(cls, offset: int = 1) -> dict[str, object]:
        """
        This function creates dictionary of callsite parameters for the line
        that is ``offset`` lines after the invocation of this function.

        Args:
            offset:
                The amount of lines after the invocation of this function that
                callsite parameters should be generated for.
        """
        frame_info = inspect.stack()[1]
        frame_traceback = inspect.getframeinfo(frame_info[0])
        return {
            "pathname": frame_traceback.filename,
            "filename": os.path.basename(frame_traceback.filename),
            "module": os.path.splitext(
                os.path.basename(frame_traceback.filename)
            )[0],
            "func_name": frame_info.function,
            "lineno": frame_info.lineno + offset,
            "thread": threading.get_ident(),
            "thread_name": threading.current_thread().name,
            "process": os.getpid(),
            "process_name": get_processname(),
        }


class TestRenameKey:
    def test_rename_once(self):
        """
        Renaming event to something else works.
        """
        assert {"msg": "hi", "foo": "bar"} == EventRenamer("msg")(
            None, None, {"event": "hi", "foo": "bar"}
        )

    def test_rename_twice(self):
        """
        Renaming both from and to `event` works.
        """
        assert {
            "msg": "hi",
            "event": "fabulous",
            "foo": "bar",
        } == EventRenamer("msg", "_event")(
            None, None, {"event": "hi", "foo": "bar", "_event": "fabulous"}
        )

    def test_replace_by_key_is_optional(self):
        """
        The key that is renamed to `event` doesn't have to exist.
        """
        assert {"msg": "hi", "foo": "bar"} == EventRenamer("msg", "missing")(
            None, None, {"event": "hi", "foo": "bar"}
        )


class TestPathRedactor:
    def test_exact_path_replace(self):
        """
        An exact path rule replaces only the value at that path.
        """
        redactor = PathRedactor([RedactionRule.at("user", "password")])

        assert {
            "event": "login",
            "user": {"name": "jane", "password": "***"},
        } == redactor(
            None,
            None,
            {
                "event": "login",
                "user": {"name": "jane", "password": "hunter2"},
            },
        )

    def test_wildcard_matches_list_positions(self):
        """
        ANY matches any sequence index, so secrets hiding in dicts within
        lists are redacted too.
        """
        redactor = PathRedactor(
            [RedactionRule.at("items", PathRedactor.ANY, "secret")]
        )

        assert {
            "items": [{"secret": "***", "n": 1}, {"secret": "***", "n": 2}],
        } == redactor(
            None,
            None,
            {"items": [{"secret": "a", "n": 1}, {"secret": "b", "n": 2}]},
        )

    def test_wildcard_matches_dict_keys(self):
        """
        ANY also matches any dict key at its position.
        """
        redactor = PathRedactor(
            [RedactionRule.at("users", PathRedactor.ANY, "token")]
        )

        assert {
            "users": {"a": {"token": "***"}, "b": {"token": "***"}},
        } == redactor(
            None,
            None,
            {"users": {"a": {"token": "t1"}, "b": {"token": "t2"}}},
        )

    def test_named_rule_matches_anywhere(self):
        """
        Field-name rules match a key no matter how deeply it is nested.
        """
        redactor = PathRedactor([RedactionRule.named("password")])

        assert {
            "password": "***",
            "deep": {"deeper": [{"password": "***"}]},
        } == redactor(
            None,
            None,
            {"password": "x", "deep": {"deeper": [{"password": "y"}]}},
        )

    def test_delete_dict_key(self):
        """
        The DELETE action removes a matched dict key entirely.
        """
        redactor = PathRedactor(
            [RedactionRule.named("secret", action=PathRedactor.DELETE)]
        )

        assert {"a": 1, "nested": {}} == redactor(
            None, None, {"a": 1, "secret": "x", "nested": {"secret": "y"}}
        )

    def test_delete_list_element(self):
        """
        The DELETE action removes matched sequence elements.
        """
        redactor = PathRedactor(
            [RedactionRule.at("items", 1, action=PathRedactor.DELETE)]
        )

        assert {"items": ["a", "c"]} == redactor(
            None, None, {"items": ["a", "b", "c"]}
        )

    def test_transform_callable(self):
        """
        A callable action transforms the matched value.
        """
        redactor = PathRedactor(
            [RedactionRule.named("token", action=lambda v: v[:2] + "...")]
        )

        assert {"token": "ab..."} == redactor(None, None, {"token": "abcdef"})

    def test_transform_exception_falls_back_to_replacement(self):
        """
        If a transform callable raises, the safe replacement is used instead
        of leaking the value.
        """

        def boom(_):
            raise ValueError("nope")

        redactor = PathRedactor([RedactionRule.named("token", action=boom)])

        assert {"token": "***"} == redactor(None, None, {"token": "abcdef"})

    def test_custom_replacement(self):
        """
        The default replacement is configurable.
        """
        redactor = PathRedactor(
            [RedactionRule.named("pw")], replacement="<redacted>"
        )

        assert {"pw": "<redacted>"} == redactor(None, None, {"pw": "x"})

    def test_fixed_replacement_value(self):
        """
        A non-callable action replaces the value as-is.
        """
        redactor = PathRedactor([RedactionRule.named("pw", action=0)])

        assert {"pw": 0} == redactor(None, None, {"pw": "x"})

    def test_rule_priority_exact_wildcard_named(self):
        """
        Exact path rules beat wildcard rules, which beat field-name rules.
        """
        redactor = PathRedactor(
            [
                RedactionRule.named("secret", action="named"),
                RedactionRule.at("a", PathRedactor.ANY, action="wild"),
                RedactionRule.at("a", 0, action="exact"),
            ]
        )

        assert {
            "a": ["exact", "wild"],
            "b": {"secret": "named"},
        } == redactor(None, None, {"a": ["x", "y"], "b": {"secret": "z"}})

    def test_first_rule_wins_within_tier(self):
        """
        Within one priority tier, the rule defined first wins.
        """
        redactor = PathRedactor(
            [
                RedactionRule.named("secret", action="first"),
                RedactionRule.named("secret", action="second"),
            ]
        )

        assert {"secret": "first"} == redactor(None, None, {"secret": "x"})

    def test_does_not_mutate_input(self):
        """
        The original event dict and all of its values are left untouched.
        """
        inner = {"password": "hunter2", "name": "jane"}
        items = [{"secret": "s3cr3t"}]
        event_dict = {"event": "login", "user": inner, "items": items}

        redactor = PathRedactor(
            [
                RedactionRule.named("password"),
                RedactionRule.at("items", PathRedactor.ANY, "secret"),
            ]
        )
        result = redactor(None, None, event_dict)

        assert {"password": "hunter2", "name": "jane"} == inner
        assert [{"secret": "s3cr3t"}] == items
        assert event_dict["user"] is inner
        assert event_dict["items"] is items
        assert result is not event_dict

    def test_untouched_values_keep_identity(self):
        """
        Values that are not affected by any rule are returned as the same
        object, preserving their type and identity.
        """
        payload = {"a": [1, 2], "b": {"c": "d"}}
        redactor = PathRedactor([RedactionRule.named("password")])

        result = redactor(None, None, {"payload": payload, "n": 42})

        assert result["payload"] is payload
        assert 42 == result["n"]
        assert isinstance(result["n"], int)

    def test_shared_subobject_processed_once(self):
        """
        A shared sub-object is redacted once and stays shared (identical) in
        the result.
        """
        shared = {"password": "hunter2"}
        redactor = PathRedactor([RedactionRule.named("password")])

        result = redactor(None, None, {"a": shared, "b": shared})

        assert {"password": "***"} == result["a"]
        assert result["a"] is result["b"]

    def test_cycle_does_not_recurse_forever(self):
        """
        Cyclic references are replaced by a placeholder instead of causing
        infinite recursion.
        """
        event_dict = {"event": "x"}
        event_dict["self"] = event_dict
        inner = {"password": "hunter2"}
        inner["loop"] = inner
        event_dict["inner"] = inner

        redactor = PathRedactor([RedactionRule.named("password")])
        result = redactor(None, None, event_dict)

        assert "<cycle>" == result["self"]
        assert {"password": "***", "loop": "<cycle>"} == result["inner"]

    def test_max_depth_omits_without_repr(self):
        """
        Once the depth budget is exhausted, the remaining content is replaced
        by a placeholder -- never by a full repr.
        """
        redactor = PathRedactor([], max_depth=2)

        result = redactor(None, None, {"a": {"b": {"c": {"d": "secret"}}}})

        assert {"a": {"b": {"c": "<omitted>"}}} == result
        assert "secret" not in repr(result)

    def test_max_nodes_omits_without_repr(self):
        """
        Once the node budget is exhausted, remaining containers are replaced
        by a placeholder -- never by a full repr.
        """
        redactor = PathRedactor([], max_nodes=3)

        result = redactor(
            None, None, {"a": {"x": 1}, "b": {"y": 2}, "c": {"z": "secret"}}
        )

        assert "<omitted>" == result["c"]
        assert "secret" not in repr(result)

    def test_types_preserved(self):
        """
        Values that don't match a rule keep their original types.
        """
        redactor = PathRedactor([RedactionRule.named("password")])

        result = redactor(
            None,
            None,
            {
                "int": 1,
                "float": 1.5,
                "bool": True,
                "none": None,
                "tuple": (1, 2),
                "password": "x",
            },
        )

        assert isinstance(result["int"], int)
        assert isinstance(result["float"], float)
        assert isinstance(result["bool"], bool)
        assert result["none"] is None
        assert (1, 2) == result["tuple"]
        assert isinstance(result["tuple"], tuple)

    def test_tuple_type_preserved_on_change(self):
        """
        Tuples that require redaction are rebuilt as tuples.
        """
        redactor = PathRedactor([RedactionRule.named("password")])

        result = redactor(None, None, {"t": (1, {"password": "x"})})

        assert (1, {"password": "***"}) == result["t"]
        assert isinstance(result["t"], tuple)

    def test_exception_locals_redacted(self):
        """
        Secrets in structured exception locals (as produced by
        ExceptionRenderer with ExceptionDictTransformer) are redacted.
        """
        from structlog.tracebacks import ExceptionDictTransformer

        chain = [
            structlog.processors.ExceptionRenderer(
                ExceptionDictTransformer(show_locals=True, use_rich=False)
            ),
            PathRedactor([RedactionRule.named("password")]),
            JSONRenderer(),
        ]

        def run():
            password = "hunter2"  # noqa: F841
            raise ValueError("boom")

        event_dict = {"event": "failed"}
        try:
            run()
        except ValueError:
            event_dict["exc_info"] = sys.exc_info()

        for processor in chain:
            event_dict = processor(None, None, event_dict)

        rendered = json.loads(event_dict)
        assert "hunter2" not in event_dict

        locals_ = rendered["exception"][0]["frames"][-1]["locals"]
        assert "***" == locals_["password"]

    def test_json_renderer_and_stdlib_bridge_agree(self, sio):
        """
        The same redactor in a native structlog chain and in a
        ProcessorFormatter foreign pre-chain produces the same redacted
        output.
        """
        redactor = PathRedactor(
            [
                RedactionRule.at("user", "password"),
                RedactionRule.at("items", PathRedactor.ANY, "secret"),
            ]
        )
        payload = {
            "user": {"name": "jane", "password": "hunter2"},
            "items": [{"secret": "s3cr3t", "n": 1}],
        }

        structlog.configure(
            processors=[
                redactor,
                structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
            ],
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        formatter = structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=[structlog.stdlib.ExtraAdder(), redactor],
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                JSONRenderer(),
            ],
        )
        handler = logging.StreamHandler(sio)
        handler.setFormatter(formatter)
        stdlib_logger = logging.getLogger("test_redactor_bridge")
        stdlib_logger.addHandler(handler)
        stdlib_logger.setLevel(logging.INFO)
        stdlib_logger.propagate = False

        structlog.get_logger("test_redactor_bridge").info("hello", **payload)
        stdlib_logger.info("hello", extra=payload)

        native_line, foreign_line = sio.getvalue().splitlines()
        native = json.loads(native_line)
        foreign = json.loads(foreign_line)

        for rendered in (native, foreign):
            assert "hunter2" not in native_line
            assert "s3cr3t" not in foreign_line
            assert {"name": "jane", "password": "***"} == rendered["user"]
            assert [{"secret": "***", "n": 1}] == rendered["items"]

    def test_invalid_rule_raises(self):
        """
        Rules without a path or name -- or with both -- are rejected.
        """
        with pytest.raises(ValueError, match="path or a name"):
            PathRedactor([RedactionRule()])

        with pytest.raises(ValueError, match="not both"):
            PathRedactor([RedactionRule(path=("a",), name="a")])
