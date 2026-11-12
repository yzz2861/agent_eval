### IMPORTS
### ============================================================================
## Future
from __future__ import annotations

## Standard Library
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from dataclasses import dataclass
import datetime
import enum
import io
import json
import logging
import sys
import traceback
from types import TracebackType
from typing import Any
from collections.abc import Generator, Sequence
import uuid
import zoneinfo

## Installed
import freezegun
import pytest

## Application
import pythonjsonlogger
import pythonjsonlogger.defaults
from pythonjsonlogger.core import RESERVED_ATTRS, BaseJsonFormatter, merge_record_extra
from pythonjsonlogger.core import (
    bind_log_context,
    clear_log_context,
    log_context,
    sanitize_context,
    set_log_context,
)
from pythonjsonlogger.json import JsonFormatter

if pythonjsonlogger.ORJSON_AVAILABLE:
    from pythonjsonlogger.orjson import OrjsonFormatter

if pythonjsonlogger.MSGSPEC_AVAILABLE:
    from pythonjsonlogger.msgspec import MsgspecFormatter

### SETUP
### ============================================================================
ALL_FORMATTERS: list[type[BaseJsonFormatter]] = [JsonFormatter]
if pythonjsonlogger.ORJSON_AVAILABLE:
    ALL_FORMATTERS.append(OrjsonFormatter)  # type: ignore[unbound-name]
if pythonjsonlogger.MSGSPEC_AVAILABLE:
    ALL_FORMATTERS.append(MsgspecFormatter)  # type: ignore[unbound-name]

_LOGGER_COUNT = 0


@dataclass
class LoggingEnvironment:
    logger: logging.Logger
    buffer: io.StringIO
    handler: logging.Handler

    def set_formatter(self, formatter: BaseJsonFormatter) -> None:
        self.handler.setFormatter(formatter)
        return

    def load_json(self) -> Any:
        return json.loads(self.buffer.getvalue())


@pytest.fixture
def env() -> Generator[LoggingEnvironment]:
    global _LOGGER_COUNT  # pylint: disable=global-statement
    _LOGGER_COUNT += 1
    logger = logging.getLogger(f"pythonjsonlogger.tests.{_LOGGER_COUNT}")
    logger.setLevel(logging.DEBUG)
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    logger.addHandler(handler)
    yield LoggingEnvironment(logger=logger, buffer=buffer, handler=handler)
    logger.removeHandler(handler)
    logger.setLevel(logging.NOTSET)
    buffer.close()
    return


def get_traceback_from_exception_followed_by_log_call(env_: LoggingEnvironment) -> str:
    try:
        raise Exception("test")
    except Exception as e:
        env_.logger.exception("hello")
        str_traceback = traceback.format_exc()
        # Formatter removes trailing new line
        if str_traceback.endswith("\n"):
            str_traceback = str_traceback[:-1]
    return str_traceback


def load_json_lines(env_: LoggingEnvironment) -> list[Any]:
    return [json.loads(line) for line in env_.buffer.getvalue().splitlines() if line]


class SomeClass:
    def __init__(self, thing: int):
        self.thing = thing
        return


class BrokenClass:
    def __str__(self) -> str:
        raise ValueError("hahah sucker")

    def __repr__(self) -> str:
        return self.__str__()


@dataclass
class SomeDataclass:
    things: str
    stuff: int
    junk: bool


try:
    raise ValueError
except ValueError as e:
    STATIC_TRACEBACK = e.__traceback__
    del e


class MultiEnum(enum.Enum):
    NONE = None
    BOOL = False
    STR = "somestring"
    INT = 99
    BYTES = b"some-bytes"


NO_TEST = object()  # Sentinal


### TESTS
### ============================================================================
def test_reserved_attrs_cover_logrecord_defaults():
    record = logging.makeLogRecord({})
    # Use a subset check because RESERVED_ATTRS also includes message and asctime,
    # which formatters add later and are absent from a newly created LogRecord.
    assert set(vars(record)) <= set(RESERVED_ATTRS)


def test_merge_record_extra():
    record = logging.LogRecord(
        "name", level=1, pathname="", lineno=1, msg="Some message", args=None, exc_info=None
    )
    output = merge_record_extra(record, target={"foo": "bar"}, reserved=[])
    assert output["foo"] == "bar"
    assert output["msg"] == "Some message"
    return


## Common Formatter Tests
## -----------------------------------------------------------------------------
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_default_format(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_())

    msg = "testing logging format"
    env.logger.info(msg)

    log_json = env.load_json()

    assert log_json["message"] == msg
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_percentage_format(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    # Note: We use different %s styles in the format to check the regex correctly collects them,
    # and %% is an escaped literal percent so %%(notafield)s is not a field
    env.set_formatter(
        class_(
            "[%(levelname)8s] %(message)s %(filename)s:%(lineno)d"
            " 100%% %%(notafield)s %(asctime)"
        )
    )

    msg = "testing logging format"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["message"] == msg
    assert log_json.keys() == {"levelname", "message", "filename", "lineno", "asctime"}
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_string_template_format(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    # Note: string templates support both $name and ${name}, and $$ is an escaped literal $
    env.set_formatter(
        class_("$$literal $levelname ${message} $filename ${lineno} $asctime", style="$")
    )

    msg = "testing logging format"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["message"] == msg
    assert log_json.keys() == {"levelname", "message", "filename", "lineno", "asctime"}
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_str_format_format(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    # Note: {{ }} is an escaped literal brace, and !r / :>{width} are not part of a field name
    env.set_formatter(
        class_(
            "{{literal}} {levelname:>{width}} {message!r} {filename} {lineno} {asctime}",
            style="{",
        )
    )

    msg = "testing logging format"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["message"] == msg
    assert log_json.keys() == {"levelname", "message", "filename", "lineno", "asctime"}
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_comma_format(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    # Note: we have double comma `,,` to test handling "empty" names
    env.set_formatter(class_("levelname,,message,filename,lineno,asctime,", style=","))

    msg = "testing logging format"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["message"] == msg
    assert log_json.keys() == {"levelname", "message", "filename", "lineno", "asctime"}
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_sequence_list_format(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(["levelname", "message", "filename", "lineno", "asctime"]))

    msg = "testing logging format"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["message"] == msg
    assert log_json.keys() == {"levelname", "message", "filename", "lineno", "asctime"}
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_sequence_tuple_format(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(("levelname", "message", "filename", "lineno", "asctime")))

    msg = "testing logging format"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["message"] == msg
    assert log_json.keys() == {"levelname", "message", "filename", "lineno", "asctime"}
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
@pytest.mark.parametrize(
    "fmt,style,expected",
    [
        pytest.param(None, "%", False, id="default"),
        pytest.param("%(message)s", "%", False, id="percent-message"),
        pytest.param("%(asctime)s %(message)s", "%", True, id="percent-time"),
        pytest.param("%%(asctime)s %(message)s", "%", False, id="percent-literal"),
        pytest.param("{message}", "{", False, id="braces-message"),
        pytest.param("{asctime!s} {message}", "{", True, id="braces-time"),
        pytest.param("{{asctime}} {message}", "{", False, id="braces-literal"),
        pytest.param("$message", "$", False, id="template-message"),
        pytest.param("$asctime $message", "$", True, id="template-time"),
        pytest.param("${asctime} $message", "$", True, id="braced-template-time"),
        pytest.param("$${asctime} $message", "$", False, id="template-literal"),
        pytest.param("message", ",", False, id="comma-message"),
        pytest.param("message, asctime,", ",", True, id="comma-time"),
        pytest.param("message,not_asctime", ",", False, id="comma-other-field"),
        pytest.param(["message"], "%", False, id="list-message"),
        pytest.param(["message", "asctime"], "%", True, id="list-time"),
        pytest.param(["message", "asctime_suffix"], "%", False, id="list-other-field"),
        pytest.param([], "%", False, id="empty-list"),
        pytest.param(("message",), "%", False, id="tuple-message"),
        pytest.param(("asctime", "message"), "%", True, id="tuple-time"),
        pytest.param((), "%", False, id="empty-tuple"),
    ],
)
def test_uses_time(
    env: LoggingEnvironment,
    class_: type[BaseJsonFormatter],
    fmt: Sequence[str] | None,
    style: str,
    expected: bool,
) -> None:
    formatter = class_(fmt, style=style, rename_fields={"asctime": "time"})
    assert formatter.usesTime() is expected
    env.set_formatter(formatter)
    env.logger.info("test message")
    assert ("time" in env.load_json()) is expected
    return


def test_uses_time_custom_parse(env: LoggingEnvironment) -> None:
    class CustomJsonFormatter(JsonFormatter):
        def parse(self) -> list[str]:
            return ["message", "asctime"]

    formatter = CustomJsonFormatter("custom format", style="custom", validate=False)
    assert formatter.usesTime() is True
    env.set_formatter(formatter)
    env.logger.info("test message")
    assert "asctime" in env.load_json()
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_uses_time_timestamp_option(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    formatter = class_(timestamp=True)
    assert formatter.usesTime() is False
    env.set_formatter(formatter)
    env.logger.info("test message")
    log_json = env.load_json()
    assert "timestamp" in log_json
    assert "asctime" not in log_json
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_defaults_field(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(defaults={"first": 1, "second": 2}))

    env.logger.info("testing defaults field", extra={"first": 1234})
    log_json = env.load_json()

    assert log_json["first"] == 1234
    assert log_json["second"] == 2
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_defaults_not_shared_with_caller(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    defaults = {"environment": "dev"}
    formatter = class_(defaults=defaults)
    assert formatter.defaults is not defaults
    defaults["environment"] = "prod"
    env.set_formatter(formatter)

    env.logger.info("testing defaults isolation")
    log_json = env.load_json()

    assert log_json["environment"] == "dev"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
@pytest.mark.parametrize("reserved_attrs", ["filename", ""])
def test_reserved_attrs_string(class_: type[BaseJsonFormatter], reserved_attrs: str) -> None:
    with pytest.raises(
        TypeError, match="reserved_attrs must be a sequence of field names, not a string"
    ):
        class_(reserved_attrs=reserved_attrs)
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
@pytest.mark.parametrize("reserved_attrs", [["filename"], ("filename",)])
def test_reserved_attrs_sequence(
    env: LoggingEnvironment,
    class_: type[BaseJsonFormatter],
    reserved_attrs: list[str] | tuple[str, ...],
) -> None:
    env.set_formatter(class_(reserved_attrs=reserved_attrs))

    env.logger.info("hello", extra={"user": "x"})
    log_json = env.load_json()

    assert log_json["message"] == "hello"
    assert log_json["user"] == "x"
    assert "filename" not in log_json
    assert "levelname" in log_json
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_rename_base_field(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(rename_fields={"message": "@message"}))

    msg = "testing logging format"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["@message"] == msg
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_rename_with_defaults(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    """Make sure that the default fields are also renamed."""
    env.set_formatter(class_(rename_fields={"custom": "@custom"}, defaults={"custom": 1234}))

    msg = "testing rename with defaults"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["@custom"] == 1234
    assert "custom" not in log_json
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_rename_missing(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(rename_fields={"missing_field": "new_field"}))

    msg = "test rename missing field"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["message"] == msg
    assert "missing_field" not in log_json
    assert "new_field" not in log_json
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_rename_keep_missing(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(
        class_(rename_fields={"missing_field": "new_field"}, rename_fields_keep_missing=True)
    )

    msg = "test keep rename missing field"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["message"] == msg
    assert "missing_field" not in log_json
    assert log_json["new_field"] is None
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_rename_preserve_order(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(
        class_("{levelname}{message}{asctime}", style="{", rename_fields={"levelname": "LEVEL"})
    )

    env.logger.info("testing logging rename order")
    log_json = env.load_json()

    assert list(log_json.keys())[0] == "LEVEL"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_rename_once(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(
        class_(
            "{levelname}{message}{asctime}",
            style="{",
            rename_fields={"levelname": "LEVEL", "message": "levelname"},
        )
    )

    msg = "something"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["LEVEL"] == "INFO"
    assert log_json["levelname"] == msg
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_add_static_fields(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(static_fields={"log_stream": "kafka"}))

    msg = "testing static fields"
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["log_stream"] == "kafka"
    assert log_json["message"] == msg
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_format_keys(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    supported_keys = [
        "asctime",
        "created",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "thread",
        "threadName",
    ]

    log_format = lambda x: [f"%({i:s})s" for i in x]
    custom_format = " ".join(log_format(supported_keys))

    env.set_formatter(class_(custom_format))

    msg = "testing logging format"
    env.logger.info(msg)
    log_json = env.load_json()

    for key in supported_keys:
        assert key in log_json
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_unknown_format_key(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_("%(unknown_key)s %(message)s"))
    env.logger.info("testing unknown logging format")
    # make sure no error occurs
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_log_dict(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_())

    msg = {"text": "testing logging", "num": 1, 5: "9", "nested": {"more": "data"}}
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["text"] == msg["text"]
    assert log_json["num"] == msg["num"]
    assert log_json["5"] == msg[5]
    assert log_json["nested"] == msg["nested"]
    assert log_json["message"] == ""
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_log_dict_defaults(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(defaults={"d1": 1234, "d2": "hello"}))

    msg = {"d2": "world"}
    env.logger.info(msg)
    log_json = env.load_json()

    assert log_json["d1"] == 1234
    assert log_json["d2"] == "world"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_log_dict_not_modified(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_())

    msg = {"text": "testing logging", "nested": {"more": "data"}}
    try:
        raise ValueError("test")
    except ValueError:
        env.logger.exception(msg, stack_info=True)
    log_json = env.load_json()

    assert log_json["exc_info"]
    assert log_json["stack_info"]
    assert msg == {"text": "testing logging", "nested": {"more": "data"}}
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_log_extra(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_())

    extra = {"text": "testing logging", "num": 1, 5: "9", "nested": {"more": "data"}}
    env.logger.info("hello", extra=extra)  # type: ignore[arg-type]
    log_json = env.load_json()

    assert log_json["text"] == extra["text"]
    assert log_json["num"] == extra["num"]
    assert log_json["5"] == extra[5]
    assert log_json["nested"] == extra["nested"]
    assert log_json["message"] == "hello"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_custom_logic_adds_field(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    class CustomJsonFormatter(class_):  # type: ignore[valid-type,misc]

        def process_log_record(self, log_data):
            log_data["custom"] = "value"
            return super().process_log_record(log_data)

    env.set_formatter(CustomJsonFormatter())
    env.logger.info("message")
    log_json = env.load_json()

    assert log_json["custom"] == "value"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exc_info(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_())

    expected_value = get_traceback_from_exception_followed_by_log_call(env)
    log_json = env.load_json()

    assert log_json["exc_info"] == expected_value
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exc_info_renamed(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_("%(exc_info)s", rename_fields={"exc_info": "stack_trace"}))

    expected_value = get_traceback_from_exception_followed_by_log_call(env)
    log_json = env.load_json()

    assert log_json["stack_trace"] == expected_value
    assert "exc_info" not in log_json
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exc_info_renamed_not_required(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(rename_fields={"exc_info": "stack_trace"}))

    expected_value = get_traceback_from_exception_followed_by_log_call(env)
    log_json = env.load_json()

    assert log_json["stack_trace"] == expected_value
    assert "exc_info" not in log_json
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exc_info_renamed_no_error(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(rename_fields={"exc_info": "stack_trace"}))

    env.logger.info("message")
    log_json = env.load_json()

    assert "stack_trace" not in log_json
    assert "exc_info" not in log_json
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_custom_object_serialization(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    def encode_complex(z):
        if isinstance(z, complex):
            return (z.real, z.imag)
        raise TypeError(f"Object of type {type(z)} is no JSON serializable")

    env.set_formatter(class_(json_default=encode_complex))  # type: ignore[call-arg]

    env.logger.info("foo", extra={"special": complex(3, 8)})
    log_json = env.load_json()

    assert log_json["special"] == [3.0, 8.0]
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_rename_reserved_attrs(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    log_format = lambda x: [f"%({i:s})s" for i in x]
    reserved_attrs_map = {
        "exc_info": "error.type",
        "exc_text": "error.message",
        "funcName": "log.origin.function",
        "levelname": "log.level",
        "module": "log.origin.file.name",
        "processName": "process.name",
        "threadName": "process.thread.name",
        "msg": "log.message",
    }

    custom_format = " ".join(log_format(reserved_attrs_map.keys()))
    reserved_attrs = [
        attr for attr in RESERVED_ATTRS if attr not in list(reserved_attrs_map.keys())
    ]
    env.set_formatter(
        class_(custom_format, reserved_attrs=reserved_attrs, rename_fields=reserved_attrs_map)
    )

    env.logger.info("message")
    log_json = env.load_json()

    for old_name, new_name in reserved_attrs_map.items():
        assert new_name in log_json
        assert old_name not in log_json
    return


@freezegun.freeze_time(datetime.datetime(2017, 7, 14, 2, 40))
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_default_encoder_with_timestamp(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    if (pythonjsonlogger.ORJSON_AVAILABLE and class_ is OrjsonFormatter) or (
        pythonjsonlogger.MSGSPEC_AVAILABLE and class_ is MsgspecFormatter
    ):
        # FakeDatetime not supported
        # https://github.com/ijl/orjson/issues/481
        # https://github.com/jcrist/msgspec/issues/678
        def json_default(obj: Any) -> Any:
            if isinstance(obj, freezegun.api.FakeDate):
                return obj.isoformat()
            raise ValueError(f"Unexpected object: {obj!r}")

        env.set_formatter(class_(timestamp=True, json_default=json_default))  # type: ignore[call-arg]
    else:
        env.set_formatter(class_(timestamp=True))

    env.logger.info("Hello")
    log_json = env.load_json()

    assert log_json["timestamp"] == "2017-07-14T02:40:00+00:00"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
@pytest.mark.parametrize(
    ["obj", "type_", "expected"],
    [
        ("somestring", str, "somestring"),
        ("some unicode Привет", str, "some unicode Привет"),
        (1234, int, 1234),
        (1234.5, float, 1234.5),
        (False, bool, False),
        (None, type(None), None),
        (b"some-bytes", str, "c29tZS1ieXRlcw=="),
        (b"fancy-bytes-\xf0\xf1", str, "ZmFuY3ktYnl0ZXMt8PE="),
        (datetime.time(16, 45, 30, 100), str, "16:45:30.000100"),
        (datetime.date(2024, 5, 5), str, "2024-05-05"),
        (datetime.datetime(2024, 5, 5, 16, 45, 30, 100), str, "2024-05-05T16:45:30.000100"),
        (
            datetime.datetime(2024, 5, 5, 16, 45, 30, 100, zoneinfo.ZoneInfo("Australia/Sydney")),
            str,
            "2024-05-05T16:45:30.000100+10:00",
        ),
        (
            uuid.UUID("urn:uuid:12345678-1234-5678-1234-567812345678"),
            str,
            "12345678-1234-5678-1234-567812345678",
        ),
        (Exception, str, "Exception"),
        (Exception("Foo occurred"), str, "Exception: Foo occurred"),
        (BaseException, str, "BaseException"),
        (BaseException("BaseFoo occurred"), str, "BaseException: BaseFoo occurred"),
        (STATIC_TRACEBACK, str, pythonjsonlogger.defaults.traceback_default(STATIC_TRACEBACK)),  # type: ignore[arg-type]
        (
            SomeDataclass(things="le_things", stuff=99, junk=False),
            dict,
            {"things": "le_things", "stuff": 99, "junk": False},
        ),
        (SomeDataclass, str, "SomeDataclass"),
        (SomeClass, str, "SomeClass"),
        (SomeClass(1234), str, NO_TEST),
        (BrokenClass(), str, "__could_not_encode__"),
        (MultiEnum.NONE, type(None), None),
        (MultiEnum.BOOL, bool, MultiEnum.BOOL.value),
        (MultiEnum.STR, str, MultiEnum.STR.value),
        (MultiEnum.INT, int, MultiEnum.INT.value),
        (MultiEnum.BYTES, str, "c29tZS1ieXRlcw=="),
        (MultiEnum, list, [None, False, "somestring", 99, "c29tZS1ieXRlcw=="]),
    ],
)
def test_common_types_encoded(
    env: LoggingEnvironment,
    class_: type[BaseJsonFormatter],
    obj: object,
    type_: type,
    expected: Any,
):
    ## Known bad cases
    if pythonjsonlogger.MSGSPEC_AVAILABLE and class_ is MsgspecFormatter:
        # Dataclass: https://github.com/jcrist/msgspec/issues/681
        # Enum: https://github.com/jcrist/msgspec/issues/680
        # These have been fixed in msgspec 0.19.0, however they also dropped python 3.8 support.
        # https://github.com/jcrist/msgspec/releases/tag/0.19.0
        if sys.version_info < (3, 9) and (
            obj is SomeDataclass
            or (
                isinstance(obj, enum.Enum)
                and obj in {MultiEnum.BYTES, MultiEnum.NONE, MultiEnum.BOOL}
            )
        ):
            pytest.xfail()

    ## Test
    env.set_formatter(class_())
    extra = {
        "extra": obj,
        "extra_dict": {"item": obj},
        "extra_list": [obj],
    }
    env.logger.info("hello", extra=extra)
    log_json = env.load_json()

    assert isinstance(log_json["extra"], type_)
    assert isinstance(log_json["extra_dict"]["item"], type_)
    assert isinstance(log_json["extra_list"][0], type_)

    if expected is NO_TEST:
        return

    if expected is None or isinstance(expected, bool):
        assert log_json["extra"] is expected
        assert log_json["extra_dict"]["item"] is expected
        assert log_json["extra_list"][0] is expected
    else:
        assert log_json["extra"] == expected
        assert log_json["extra_dict"]["item"] == expected
        assert log_json["extra_list"][0] == expected
    return


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Exception notes require Python 3.11 or higher"
)
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
@pytest.mark.parametrize(
    ["notes", "expected"],
    [
        ([], "ValueError: my error"),
        (["context"], "ValueError: my error\ncontext"),
        ([""], "ValueError: my error\n"),
        (["first", "second"], "ValueError: my error\nfirst\nsecond"),
        (["line 1\nline 2", "Привет"], "ValueError: my error\nline 1\nline 2\nПривет"),
    ],
)
def test_dict_exception_notes(
    env: LoggingEnvironment,
    class_: type[BaseJsonFormatter],
    notes: list[str],
    expected: str,
) -> None:
    env.set_formatter(class_())
    err = ValueError("my error")
    for note in notes:
        err.add_note(note)

    env.logger.info({"error": err, "nested": {"error": err}, "errors": [err]})
    log_json = env.load_json()

    assert log_json["error"] == expected
    assert log_json["nested"]["error"] == expected
    assert log_json["errors"] == [expected]
    return


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Exception notes require Python 3.11 or higher"
)
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_dict_exception_note_subclass(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    class Note(str):
        """A string subclass accepted by add_note."""

    err = ValueError("my error")
    err.add_note(Note("context"))
    env.set_formatter(class_())
    env.logger.info({"error": err})

    assert env.load_json()["error"] == "ValueError: my error\ncontext"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_dict_exception_message_compatibility(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    class CustomError(Exception):
        """An exception with a custom formatted message."""

        def __format__(self, format_spec: str) -> str:
            return "custom message"

    env.set_formatter(class_())
    env.logger.info({"empty": ValueError(), "custom": CustomError("original message")})
    log_json = env.load_json()

    assert log_json["empty"] == "ValueError: "
    assert log_json["custom"] == "CustomError: custom message"
    return


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Exception groups and notes require Python 3.11 or higher"
)
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
@pytest.mark.parametrize("with_group_note", [False, True])
def test_dict_exception_group_notes(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter], with_group_note: bool
) -> None:
    child = ValueError("child error")
    child.add_note("child note")
    group = ExceptionGroup("my group", [child])
    expected = "ExceptionGroup: my group (1 sub-exception)"
    if with_group_note:
        group.add_note("group note")
        expected += "\ngroup note"
    env.set_formatter(class_())
    env.logger.info({"error": group})

    assert env.load_json()["error"] == expected
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_custom_default(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    def custom_default(obj):
        if isinstance(obj, SomeClass):
            return {"TYPE": obj.thing}
        return None

    env.set_formatter(class_(json_default=custom_default))  # type: ignore[call-arg]
    env.logger.info("hello", extra={"extra": SomeClass(999)})
    log_json = env.load_json()

    assert log_json["extra"] == {"TYPE": 999}
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exc_info_as_array(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(exc_info_as_array=True))

    try:
        raise Exception("Error")
    except BaseException:
        env.logger.exception("Error occurs")
    log_json = env.load_json()

    assert isinstance(log_json["exc_info"], list)
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
@pytest.mark.parametrize("exc_info_as_array", [False, True])
@pytest.mark.parametrize(
    "message",
    [
        pytest.param("hello", id="cached-text"),
        pytest.param({"exc_info": "caller text"}, id="string-override"),
        pytest.param({"exc_info": ["caller", "text"]}, id="list-override"),
    ],
)
def test_cached_exc_text(
    env: LoggingEnvironment,
    class_: type[BaseJsonFormatter],
    exc_info_as_array: bool,
    message: str | dict[str, Any],
) -> None:
    """Honor the array option for cached exceptions without replacing caller overrides."""
    env.set_formatter(class_(exc_info_as_array=exc_info_as_array))
    original_message = message.copy() if isinstance(message, dict) else message
    # Start with a real exception so the cached text includes its multiline traceback.
    try:
        raise ValueError("first line\nsecond line")
    except ValueError:
        record = env.logger.makeRecord(
            env.logger.name, logging.ERROR, __file__, 0, message, (), sys.exc_info()
        )

    # Mirror SocketHandler's receiver state: formatted exception text survives,
    # but the original exc_info tuple is cleared before the record is transported.
    logging.Formatter().format(record)
    cached_text = record.exc_text
    assert cached_text is not None
    received = logging.makeLogRecord({**record.__dict__, "exc_info": None})
    env.logger.handle(received)

    # The option controls the cached fallback, not a caller-supplied exc_info value.
    expected: str | list[str] = cached_text.splitlines() if exc_info_as_array else cached_text
    if isinstance(message, dict):
        expected = message["exc_info"]
    assert env.load_json()["exc_info"] == expected
    assert received.exc_text == cached_text
    assert message == original_message
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exc_info_as_array_no_exc_info(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(exc_info_as_array=True))

    env.logger.info("hello")
    log_json = env.load_json()

    assert "exc_info" not in log_json
    return


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Exception notes require Python 3.11 or higher"
)
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exception_notes(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_())

    try:
        err = ValueError("my error")
        err.add_note("this is a note")
        raise err
    except ValueError:
        env.logger.exception("oops")

    log_json = env.load_json()
    assert "ValueError: my error" in log_json["exc_info"]
    assert "this is a note" in log_json["exc_info"]
    return


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Exception notes require Python 3.11 or higher"
)
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exception_notes_as_array(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(exc_info_as_array=True))

    try:
        err = ValueError("my error")
        err.add_note("this is a note")
        raise err
    except ValueError:
        env.logger.exception("oops")

    log_json = env.load_json()
    assert isinstance(log_json["exc_info"], list)
    full_traceback = "\n".join(log_json["exc_info"])
    assert "ValueError: my error" in full_traceback
    assert "this is a note" in full_traceback
    return


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Exception groups require Python 3.11 or higher"
)
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exception_groups(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_())

    try:
        raise ExceptionGroup("my group", [ValueError("err 1"), TypeError("err 2")])
    except ExceptionGroup:
        env.logger.exception("oops")

    log_json = env.load_json()
    assert "ExceptionGroup: my group" in log_json["exc_info"]
    assert "ValueError: err 1" in log_json["exc_info"]
    assert "TypeError: err 2" in log_json["exc_info"]
    return


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Exception groups require Python 3.11 or higher"
)
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exception_groups_as_array(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(exc_info_as_array=True))

    try:
        raise ExceptionGroup("my group", [ValueError("err 1"), TypeError("err 2")])
    except ExceptionGroup:
        env.logger.exception("oops")

    log_json = env.load_json()
    assert isinstance(log_json["exc_info"], list)
    full_traceback = "\n".join(log_json["exc_info"])
    assert "ExceptionGroup: my group" in full_traceback
    assert "ValueError: err 1" in full_traceback
    assert "TypeError: err 2" in full_traceback
    return


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Exception groups and notes require Python 3.11 or higher"
)
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exception_groups_with_notes(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_())

    try:
        err1 = ValueError("err 1")
        err1.add_note("note 1")
        err2 = TypeError("err 2")
        err2.add_note("note 2")
        eg = ExceptionGroup("my group", [err1, err2])
        eg.add_note("group note")
        raise eg
    except ExceptionGroup:
        env.logger.exception("oops")

    log_json = env.load_json()
    assert "ExceptionGroup: my group" in log_json["exc_info"]
    assert "group note" in log_json["exc_info"]
    assert "ValueError: err 1" in log_json["exc_info"]
    assert "note 1" in log_json["exc_info"]
    assert "TypeError: err 2" in log_json["exc_info"]
    assert "note 2" in log_json["exc_info"]
    return


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="Exception groups and notes require Python 3.11 or higher"
)
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_exception_groups_with_notes_as_array(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
):
    env.set_formatter(class_(exc_info_as_array=True))

    try:
        err1 = ValueError("err 1")
        err1.add_note("note 1")
        err2 = TypeError("err 2")
        err2.add_note("note 2")
        eg = ExceptionGroup("my group", [err1, err2])
        eg.add_note("group note")
        raise eg
    except ExceptionGroup:
        env.logger.exception("oops")

    log_json = env.load_json()
    assert isinstance(log_json["exc_info"], list)
    full_traceback = "\n".join(log_json["exc_info"])
    assert "ExceptionGroup: my group" in full_traceback
    assert "group note" in full_traceback
    assert "ValueError: err 1" in full_traceback
    assert "note 1" in full_traceback
    assert "TypeError: err 2" in full_traceback
    assert "note 2" in full_traceback
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_stack_info_as_array(env: LoggingEnvironment, class_: type[BaseJsonFormatter]):
    env.set_formatter(class_(stack_info_as_array=True))

    env.logger.info("hello", stack_info=True)
    log_json = env.load_json()

    assert isinstance(log_json["stack_info"], list)
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_stack_info_as_array_no_stack_info(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
):
    env.set_formatter(class_(stack_info_as_array=True))

    env.logger.info("hello", stack_info=False)
    log_json = env.load_json()

    assert "stack_info" not in log_json
    return


## Context / Correlation Tests
## -----------------------------------------------------------------------------
@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_fields_are_isolated_between_asyncio_tasks(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    """Interleaved coroutines must never observe another task's context."""
    clear_log_context()
    env.set_formatter(class_(context_fields=["trace_id", "request_id"]))

    async def worker(index: int) -> None:
        token = set_log_context({"trace_id": f"trace-{index}", "request_id": f"request-{index}"})
        try:
            for step in range(3):
                env.logger.info(f"{index}:{step}")
                await asyncio.sleep(0)
        finally:
            log_context.reset(token)

    async def main() -> None:
        await asyncio.gather(*(worker(index) for index in range(8)))

    asyncio.run(main())

    lines = load_json_lines(env)
    assert len(lines) == 24
    for line in lines:
        index = line["message"].split(":", 1)[0]
        assert line["trace_id"] == f"trace-{index}"
        assert line["request_id"] == f"request-{index}"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_fields_are_isolated_between_threads(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    clear_log_context()
    env.set_formatter(class_(context_fields=["trace_id"]))

    def worker(index: int) -> None:
        token = set_log_context({"trace_id": f"thread-{index}"})
        try:
            for step in range(10):
                env.logger.info(f"{index}:{step}")
        finally:
            log_context.reset(token)

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(worker, range(8)))

    lines = load_json_lines(env)
    assert len(lines) == 80
    for line in lines:
        index = line["message"].split(":", 1)[0]
        assert line["trace_id"] == f"thread-{index}"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_field_precedence(env: LoggingEnvironment, class_: type[BaseJsonFormatter]) -> None:
    clear_log_context()
    env.set_formatter(
        class_(
            context_fields=["trace_id", "span_id"],
            defaults={"trace_id": "default"},
            static_fields={"trace_id": "static", "service": "billing"},
        )
    )
    token = set_log_context({"trace_id": "context", "span_id": "context-span"})
    try:
        env.logger.info("context beats defaults")
        env.logger.info("extra wins", extra={"trace_id": "extra"})
        env.logger.info({"message": "dict message wins", "trace_id": "message"})
    finally:
        log_context.reset(token)

    first, second, third = load_json_lines(env)
    assert first["trace_id"] == "static"
    assert first["span_id"] == "context-span"
    assert second["trace_id"] == "extra"
    assert third["trace_id"] == "message"
    for line in (first, second, third):
        assert line["service"] == "billing"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_overrides_defaults(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    clear_log_context()
    env.set_formatter(class_(context_fields=["trace_id"], defaults={"trace_id": "default"}))
    token = set_log_context({"trace_id": "context"})
    try:
        env.logger.info("hello")
    finally:
        log_context.reset(token)

    assert env.load_json()["trace_id"] == "context"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_not_configured_output_is_unchanged(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    clear_log_context()
    env.set_formatter(class_())
    env.logger.info("hello")
    baseline_output = env.buffer.getvalue()

    # A configured formatter with no bound context must add no fields.
    clear_log_context()
    env.set_formatter(class_(context_fields=["trace_id"]))
    env.logger.info("hello")
    unbound_output = env.buffer.getvalue().splitlines()[-1] + "\n"

    # A context value must not leak into a formatter that was not configured to use it.
    token = set_log_context({"trace_id": "not-configured"})
    try:
        env.set_formatter(class_())
        env.logger.info("hello")
        unconfigured_output = env.buffer.getvalue().splitlines()[-1] + "\n"
    finally:
        log_context.reset(token)

    assert baseline_output == unbound_output == unconfigured_output
    assert "trace_id" not in json.loads(unbound_output)
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_snapshot_is_taken_before_message_formatting(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    clear_log_context()
    env.set_formatter(class_(context_fields=["trace_id"]))

    class ChangesContext:
        def __format__(self, format_spec: str) -> str:
            set_log_context({"trace_id": "late"})
            return "message"

    set_log_context({"trace_id": "snapshot"})
    try:
        env.logger.info("%s", ChangesContext())
    finally:
        clear_log_context()

    assert env.load_json()["trace_id"] == "snapshot"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_nested_and_unsafe_values(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    clear_log_context()
    circular: dict[str, Any] = {}
    circular["self"] = circular
    unsafe = {
        "trace_id": "trace",
        "request": {"method": "GET", "nested": {"ok": True}},
        "too_deep": {"one": {"two": {"three": 3}}},
        "circular": circular,
        "object": object(),
        "items": list(range(50)),
    }
    token = set_log_context(unsafe)
    try:
        env.set_formatter(
            class_(
                context_fields=True,
                context_max_depth=2,
                context_max_items=6,
                context_on_error="replace",
            )
        )
        env.logger.info("hello")
    finally:
        log_context.reset(token)

    log_json = env.load_json()
    assert log_json["trace_id"] == "trace"
    assert log_json["request"] == {"method": "GET", "nested": {"ok": True}}
    assert log_json["too_deep"] == {"one": {"two": "<max-depth:dict>"}}
    assert log_json["circular"]["self"].startswith("<circular-reference:")
    assert log_json["object"] == "<unserializable:object>"
    assert log_json["items"] == [0, 1, 2, 3, 4, 5]
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_drop_policy_and_bad_mapping(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    clear_log_context()
    circular: dict[str, Any] = {}
    circular["self"] = circular
    token = set_log_context(
        {
            "trace_id": "trace",
            "circular": circular,
            "object": object(),
            "bad_key": {},
        }
    )
    try:
        env.set_formatter(class_(context_fields=True))
        env.logger.info("hello")
    finally:
        log_context.reset(token)

    log_json = env.load_json()
    assert log_json["bad_key"] == {}
    assert log_json["trace_id"] == "trace"
    assert "circular" not in log_json
    assert "object" not in log_json

    assert sanitize_context({"self": circular}) == {}
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_explicit_context_var_and_per_field_var(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    clear_log_context()
    request_var: ContextVar[dict[str, Any] | None] = ContextVar(
        "test_request_context", default=None
    )
    span_var: ContextVar[str | None] = ContextVar("test_span_context", default=None)
    env.set_formatter(
        class_(
            context_var=request_var,
            context_fields={"trace_id": "trace_id", "span_id": span_var},
        )
    )
    request_token = request_var.set({"trace_id": "custom-trace"})
    span_token = span_var.set("custom-span")
    try:
        env.logger.info("hello")
    finally:
        request_var.reset(request_token)
        span_var.reset(span_token)

    log_json = env.load_json()
    assert log_json["trace_id"] == "custom-trace"
    assert log_json["span_id"] == "custom-span"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_alias_parameters_and_instance_api(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    clear_log_context()
    request_var: ContextVar[dict[str, Any] | None] = ContextVar(
        "test_alias_request_context", default=None
    )
    env.set_formatter(class_(context_key="trace_id", context_var=request_var))
    token = env.handler.formatter.set_context(trace_id="alias-trace")
    try:
        env.logger.info("hello")
    finally:
        env.handler.formatter.reset_context(token)

    assert env.load_json()["trace_id"] == "alias-trace"

    span_var: ContextVar[str | None] = ContextVar("test_alias_span_context", default=None)
    env.set_formatter(class_(context_vars={"span_id": span_var}))
    span_token = span_var.set("alias-span")
    try:
        env.logger.info("hello")
    finally:
        span_var.reset(span_token)

    assert load_json_lines(env)[-1]["span_id"] == "alias-span"
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_on_exception(env: LoggingEnvironment, class_: type[BaseJsonFormatter]) -> None:
    clear_log_context()
    env.set_formatter(class_(context_fields=["trace_id"]))
    token = set_log_context({"trace_id": "exception-trace"})
    try:
        try:
            raise ValueError("boom")
        except ValueError:
            env.logger.exception("failed")
    finally:
        log_context.reset(token)

    log_json = env.load_json()
    assert log_json["trace_id"] == "exception-trace"
    assert "ValueError: boom" in log_json["exc_info"]
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_context_on_cancellation(env: LoggingEnvironment, class_: type[BaseJsonFormatter]) -> None:
    clear_log_context()
    env.set_formatter(class_(context_fields=["trace_id"]))

    async def worker(name: str, wait: bool) -> None:
        with bind_log_context(trace_id=name):
            try:
                if wait:
                    await asyncio.sleep(60)
                else:
                    await asyncio.sleep(0)
                    env.logger.info(f"{name}:after-await")
            except asyncio.CancelledError:
                env.logger.info(f"{name}:cancelled")
                raise
            finally:
                env.logger.info(f"{name}:finally")

    async def main() -> None:
        cancelled = asyncio.create_task(worker("cancelled-task", wait=True))
        await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        await worker("next-task", wait=False)

    asyncio.run(main())

    lines = load_json_lines(env)
    assert {line["message"] for line in lines} == {
        "cancelled-task:cancelled",
        "cancelled-task:finally",
        "next-task:after-await",
        "next-task:finally",
    }
    for line in lines:
        assert line["trace_id"] == line["message"].split(":", 1)[0]
    return


@pytest.mark.parametrize("class_", ALL_FORMATTERS)
def test_formatter_does_not_store_request_context(
    env: LoggingEnvironment, class_: type[BaseJsonFormatter]
) -> None:
    clear_log_context()
    formatter = class_(context_fields=["trace_id"])
    env.set_formatter(formatter)
    for index in range(3):
        token = set_log_context({"trace_id": f"trace-{index}"})
        try:
            env.logger.info(f"message-{index}")
        finally:
            log_context.reset(token)

    for line in load_json_lines(env):
        index = line["message"].split("-", 1)[1]
        assert line["trace_id"] == f"trace-{index}"

    assert "trace_id" not in vars(formatter)
    assert not any(
        isinstance(value, str) and value.startswith("trace-") for value in vars(formatter).values()
    )
    return


## JsonFormatter Specific
## -----------------------------------------------------------------------------
def test_json_ensure_ascii_true(env: LoggingEnvironment):
    env.set_formatter(JsonFormatter())
    env.logger.info("Привет")

    # Note: we don't use env.load_json as we want to know the raw output
    msg = env.buffer.getvalue().split('"message": "', 1)[1].split('"', 1)[0]
    assert msg == r"\u041f\u0440\u0438\u0432\u0435\u0442"
    return


def test_json_ensure_ascii_false(env: LoggingEnvironment):
    env.set_formatter(JsonFormatter(json_ensure_ascii=False))
    env.logger.info("Привет")

    # Note: we don't use env.load_json as we want to know the raw output
    msg = env.buffer.getvalue().split('"message": "', 1)[1].split('"', 1)[0]
    assert msg == "Привет"
    return
