import datetime
import decimal
import io
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from werkzeug.http import http_date

import flask
from flask import Blueprint
from flask import json
from flask.json.provider import DefaultJSONProvider


class LegacyJSONProvider(DefaultJSONProvider):
    def loads(self, s, **kwargs):
        rv = super().loads(s, **kwargs)

        if isinstance(rv, dict) and rv.get("format") == "new":
            return {"format": "legacy", "value": rv["value"]}

        return rv


class NewJSONProvider(DefaultJSONProvider):
    @staticmethod
    def default(o):
        if isinstance(o, datetime.date):
            return o.isoformat()

        if isinstance(o, decimal.Decimal):
            return float(o)

        return DefaultJSONProvider.default(o)

    def loads(self, s, **kwargs):
        rv = super().loads(s, **kwargs)

        if isinstance(rv, dict) and rv.get("format") == "new":
            return {"format": "new", "value": rv["value"].upper()}

        return rv


@pytest.fixture
def blueprint_json_client(app):
    value_date = datetime.date(2020, 1, 2)
    value_decimal = decimal.Decimal("1.25")

    parent = Blueprint(
        "parent", __name__, url_prefix="/legacy", json_provider_class=LegacyJSONProvider
    )
    child = Blueprint("child", __name__)
    configured_child = Blueprint(
        "configured_child",
        __name__,
        json_provider_class=NewJSONProvider,
    )
    unconfigured_grandchild = Blueprint("unconfigured_grandchild", __name__)

    @parent.route("/")
    def parent_view():
        return flask.jsonify(date=value_date, decimal=value_decimal)

    @parent.route("/dict")
    def parent_dict_view():
        return {"date": value_date, "decimal": value_decimal}

    @parent.route("/read", methods=["POST"])
    def parent_read_view():
        return flask.request.get_json()

    @parent.route("/template")
    def parent_template_view():
        return flask.render_template_string("{{ value|tojson }}", value=value_date)

    @parent.errorhandler(418)
    def parent_error(error):
        return {"date": value_date, "decimal": value_decimal}, 418

    @parent.route("/error")
    def parent_error_view():
        flask.abort(418)

    @child.route("/inherited")
    def child_view():
        return flask.jsonify(date=value_date, decimal=value_decimal)

    @configured_child.route("/new")
    def configured_child_view():
        return flask.jsonify(date=value_date, decimal=value_decimal)

    @configured_child.route("/read", methods=["POST"])
    def configured_child_read_view():
        return flask.request.get_json()

    @configured_child.route("/template")
    def configured_child_template_view():
        return flask.render_template_string("{{ value|tojson }}", value=value_date)

    @configured_child.errorhandler(418)
    def configured_child_error(error):
        return {"date": value_date, "decimal": value_decimal}, 418

    @configured_child.errorhandler(ValueError)
    def configured_child_value_error(error):
        return {"date": value_date, "decimal": value_decimal}, 400

    @configured_child.route("/error")
    def configured_child_error_view():
        flask.abort(418)

    @configured_child.route("/value-error")
    def configured_child_value_error_view():
        raise ValueError("boom")

    @unconfigured_grandchild.route("/inherited-new")
    def unconfigured_grandchild_view():
        return flask.jsonify(date=value_date, decimal=value_decimal)

    configured_child.register_blueprint(
        unconfigured_grandchild, url_prefix="/grandchild"
    )
    parent.register_blueprint(child, url_prefix="/child")
    parent.register_blueprint(configured_child, url_prefix="/new-api")
    app.register_blueprint(parent)

    @app.route("/app")
    def app_view():
        return flask.jsonify(date=value_date, decimal=value_decimal)

    @app.errorhandler(404)
    def not_found(error):
        return {"date": value_date, "decimal": value_decimal}, 404

    return app.test_client()


def test_blueprint_json_provider_jsonify_and_dict(blueprint_json_client):
    rv = blueprint_json_client.get("/legacy/")
    assert rv.json == {"date": "Thu, 02 Jan 2020 00:00:00 GMT", "decimal": "1.25"}

    rv = blueprint_json_client.get("/legacy/dict")
    assert rv.json == {"date": "Thu, 02 Jan 2020 00:00:00 GMT", "decimal": "1.25"}


def test_blueprint_json_provider_get_json(blueprint_json_client):
    rv = blueprint_json_client.post(
        "/legacy/read",
        json={"format": "new", "value": "legacy"},
    )
    assert rv.json == {"format": "legacy", "value": "legacy"}


def test_blueprint_json_provider_error_response(blueprint_json_client):
    rv = blueprint_json_client.get("/legacy/error")
    assert rv.status_code == 418
    assert rv.json == {"date": "Thu, 02 Jan 2020 00:00:00 GMT", "decimal": "1.25"}


def test_nested_blueprint_inherits_parent_json_provider(blueprint_json_client):
    rv = blueprint_json_client.get("/legacy/child/inherited")
    assert rv.json == {"date": "Thu, 02 Jan 2020 00:00:00 GMT", "decimal": "1.25"}


def test_nested_blueprint_uses_nearest_json_provider(blueprint_json_client):
    rv = blueprint_json_client.get("/legacy/new-api/new")
    assert rv.json == {"date": "2020-01-02", "decimal": 1.25}

    rv = blueprint_json_client.post(
        "/legacy/new-api/read",
        json={"format": "new", "value": "new"},
    )
    assert rv.json == {"format": "new", "value": "NEW"}

    rv = blueprint_json_client.get("/legacy/new-api/grandchild/inherited-new")
    assert rv.json == {"date": "2020-01-02", "decimal": 1.25}


def test_nested_blueprint_error_response_uses_nearest_provider(blueprint_json_client):
    rv = blueprint_json_client.get("/legacy/new-api/error")
    assert rv.status_code == 418
    assert rv.json == {"date": "2020-01-02", "decimal": 1.25}

    rv = blueprint_json_client.get("/legacy/new-api/value-error")
    assert rv.status_code == 400
    assert rv.json == {"date": "2020-01-02", "decimal": 1.25}


def test_app_json_provider_remains_default(blueprint_json_client):
    rv = blueprint_json_client.get("/app")
    assert rv.json == {"date": "Thu, 02 Jan 2020 00:00:00 GMT", "decimal": "1.25"}

    rv = blueprint_json_client.get("/missing")
    assert rv.status_code == 404
    assert rv.json == {"date": "Thu, 02 Jan 2020 00:00:00 GMT", "decimal": "1.25"}


def test_tojson_uses_request_and_app_provider(app, blueprint_json_client):
    value = datetime.date(2020, 1, 2)

    with app.app_context():
        assert flask.render_template_string("{{ value|tojson }}", value=value) == (
            '"Thu, 02 Jan 2020 00:00:00 GMT"'
        )

    rv = blueprint_json_client.get("/legacy/template")
    assert rv.data == b'"Thu, 02 Jan 2020 00:00:00 GMT"'

    rv = blueprint_json_client.get("/legacy/new-api/template")
    assert rv.data == b'"2020-01-02"'


def test_blueprint_json_provider_concurrency(app):
    value_date = datetime.date(2020, 1, 2)
    value_decimal = decimal.Decimal("1.25")
    legacy = Blueprint("legacy", __name__, json_provider_class=LegacyJSONProvider)
    new = Blueprint("new", __name__, json_provider_class=NewJSONProvider)

    @legacy.route("/")
    def legacy_view():
        return {"date": value_date, "decimal": value_decimal}

    @new.route("/")
    def new_view():
        return {"date": value_date, "decimal": value_decimal}

    app.register_blueprint(legacy, url_prefix="/legacy")
    app.register_blueprint(new, url_prefix="/new")

    results = {}
    barrier = threading.Barrier(2)

    def request_json(path, name):
        client = app.test_client()
        barrier.wait()
        results[name] = client.get(path).json

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(request_json, "/legacy/", "legacy"),
            executor.submit(request_json, "/new/", "new"),
        ]

        for future in futures:
            future.result()

    assert results == {
        "legacy": {
            "date": "Thu, 02 Jan 2020 00:00:00 GMT",
            "decimal": "1.25",
        },
        "new": {"date": "2020-01-02", "decimal": 1.25},
    }


def test_blueprint_json_provider_class_attribute(app, client):
    class AttributeBlueprint(Blueprint):
        json_provider_class = NewJSONProvider

    bp = AttributeBlueprint("bp", __name__)

    @bp.route("/")
    def view():
        return flask.jsonify(
            date=datetime.date(2020, 1, 2),
            decimal=decimal.Decimal("1.25"),
        )

    app.register_blueprint(bp)
    assert client.get("/").json == {"date": "2020-01-02", "decimal": 1.25}


@pytest.mark.parametrize("debug", (True, False))
def test_bad_request_debug_message(app, client, debug):
    app.config["DEBUG"] = debug
    app.config["TRAP_BAD_REQUEST_ERRORS"] = False

    @app.route("/json", methods=["POST"])
    def post_json():
        flask.request.get_json()
        return None

    rv = client.post("/json", data=None, content_type="application/json")
    assert rv.status_code == 400
    contains = b"Failed to decode JSON object" in rv.data
    assert contains == debug


def test_json_bad_requests(app, client):
    @app.route("/json", methods=["POST"])
    def return_json():
        return flask.jsonify(foo=str(flask.request.get_json()))

    rv = client.post("/json", data="malformed", content_type="application/json")
    assert rv.status_code == 400


def test_json_custom_mimetypes(app, client):
    @app.route("/json", methods=["POST"])
    def return_json():
        return flask.request.get_json()

    rv = client.post("/json", data='"foo"', content_type="application/x+json")
    assert rv.data == b"foo"


@pytest.mark.parametrize(
    "test_value,expected", [(True, '"\\u2603"'), (False, '"\u2603"')]
)
def test_json_as_unicode(test_value, expected, app, app_ctx):
    app.json.ensure_ascii = test_value
    rv = app.json.dumps("\N{SNOWMAN}")
    assert rv == expected


def test_json_dump_to_file(app, app_ctx):
    test_data = {"name": "Flask"}
    out = io.StringIO()

    flask.json.dump(test_data, out)
    out.seek(0)
    rv = flask.json.load(out)
    assert rv == test_data


@pytest.mark.parametrize(
    "test_value", [0, -1, 1, 23, 3.14, "s", "longer string", True, False, None]
)
def test_jsonify_basic_types(test_value, app, client):
    url = "/jsonify_basic_types"
    app.add_url_rule(url, url, lambda x=test_value: flask.jsonify(x))
    rv = client.get(url)
    assert rv.mimetype == "application/json"
    assert flask.json.loads(rv.data) == test_value


def test_jsonify_dicts(app, client):
    d = {
        "a": 0,
        "b": 23,
        "c": 3.14,
        "d": "t",
        "e": "Hi",
        "f": True,
        "g": False,
        "h": ["test list", 10, False],
        "i": {"test": "dict"},
    }

    @app.route("/kw")
    def return_kwargs():
        return flask.jsonify(**d)

    @app.route("/dict")
    def return_dict():
        return flask.jsonify(d)

    for url in "/kw", "/dict":
        rv = client.get(url)
        assert rv.mimetype == "application/json"
        assert flask.json.loads(rv.data) == d


def test_jsonify_arrays(app, client):
    """Test jsonify of lists and args unpacking."""
    a_list = [
        0,
        42,
        3.14,
        "t",
        "hello",
        True,
        False,
        ["test list", 2, False],
        {"test": "dict"},
    ]

    @app.route("/args_unpack")
    def return_args_unpack():
        return flask.jsonify(*a_list)

    @app.route("/array")
    def return_array():
        return flask.jsonify(a_list)

    for url in "/args_unpack", "/array":
        rv = client.get(url)
        assert rv.mimetype == "application/json"
        assert flask.json.loads(rv.data) == a_list


@pytest.mark.parametrize(
    "value", [datetime.datetime(1973, 3, 11, 6, 30, 45), datetime.date(1975, 1, 5)]
)
def test_jsonify_datetime(app, client, value):
    @app.route("/")
    def index():
        return flask.jsonify(value=value)

    r = client.get()
    assert r.json["value"] == http_date(value)


class FixedOffset(datetime.tzinfo):
    """Fixed offset in hours east from UTC.

    This is a slight adaptation of the ``FixedOffset`` example found in
    https://docs.python.org/2.7/library/datetime.html.
    """

    def __init__(self, hours, name):
        self.__offset = datetime.timedelta(hours=hours)
        self.__name = name

    def utcoffset(self, dt):
        return self.__offset

    def tzname(self, dt):
        return self.__name

    def dst(self, dt):
        return datetime.timedelta()


@pytest.mark.parametrize("tz", (("UTC", 0), ("PST", -8), ("KST", 9)))
def test_jsonify_aware_datetimes(tz):
    """Test if aware datetime.datetime objects are converted into GMT."""
    tzinfo = FixedOffset(hours=tz[1], name=tz[0])
    dt = datetime.datetime(2017, 1, 1, 12, 34, 56, tzinfo=tzinfo)
    gmt = FixedOffset(hours=0, name="GMT")
    expected = dt.astimezone(gmt).strftime('"%a, %d %b %Y %H:%M:%S %Z"')
    assert flask.json.dumps(dt) == expected


def test_jsonify_uuid_types(app, client):
    """Test jsonify with uuid.UUID types"""

    test_uuid = uuid.UUID(bytes=b"\xde\xad\xbe\xef" * 4)
    url = "/uuid_test"
    app.add_url_rule(url, url, lambda: flask.jsonify(x=test_uuid))

    rv = client.get(url)

    rv_x = flask.json.loads(rv.data)["x"]
    assert rv_x == str(test_uuid)
    rv_uuid = uuid.UUID(rv_x)
    assert rv_uuid == test_uuid


def test_json_decimal():
    rv = flask.json.dumps(decimal.Decimal("0.003"))
    assert rv == '"0.003"'


def test_json_attr(app, client):
    @app.route("/add", methods=["POST"])
    def add():
        json = flask.request.get_json()
        return str(json["a"] + json["b"])

    rv = client.post(
        "/add",
        data=flask.json.dumps({"a": 1, "b": 2}),
        content_type="application/json",
    )
    assert rv.data == b"3"


def test_tojson_filter(app, req_ctx):
    # The tojson filter is tested in Jinja, this confirms that it's
    # using Flask's dumps.
    rv = flask.render_template_string(
        "const data = {{ data|tojson }};",
        data={"name": "</script>", "time": datetime.datetime(2021, 2, 1, 7, 15)},
    )
    assert rv == (
        'const data = {"name": "\\u003c/script\\u003e",'
        ' "time": "Mon, 01 Feb 2021 07:15:00 GMT"};'
    )


def test_json_customization(app, client):
    class X:  # noqa: B903, for Python2 compatibility
        def __init__(self, val):
            self.val = val

    def default(o):
        if isinstance(o, X):
            return f"<{o.val}>"

        return DefaultJSONProvider.default(o)

    class CustomProvider(DefaultJSONProvider):
        def object_hook(self, obj):
            if len(obj) == 1 and "_foo" in obj:
                return X(obj["_foo"])

            return obj

        def loads(self, s, **kwargs):
            kwargs.setdefault("object_hook", self.object_hook)
            return super().loads(s, **kwargs)

    app.json = CustomProvider(app)
    app.json.default = default

    @app.route("/", methods=["POST"])
    def index():
        return flask.json.dumps(flask.request.get_json()["x"])

    rv = client.post(
        "/",
        data=flask.json.dumps({"x": {"_foo": 42}}),
        content_type="application/json",
    )
    assert rv.data == b'"<42>"'


def _has_encoding(name):
    try:
        import codecs

        codecs.lookup(name)
        return True
    except LookupError:
        return False


def test_json_key_sorting(app, client):
    app.debug = True
    assert app.json.sort_keys
    d = dict.fromkeys(range(20), "foo")

    @app.route("/")
    def index():
        return flask.jsonify(values=d)

    rv = client.get("/")
    lines = [x.strip() for x in rv.data.strip().decode("utf-8").splitlines()]
    sorted_by_str = [
        "{",
        '"values": {',
        '"0": "foo",',
        '"1": "foo",',
        '"10": "foo",',
        '"11": "foo",',
        '"12": "foo",',
        '"13": "foo",',
        '"14": "foo",',
        '"15": "foo",',
        '"16": "foo",',
        '"17": "foo",',
        '"18": "foo",',
        '"19": "foo",',
        '"2": "foo",',
        '"3": "foo",',
        '"4": "foo",',
        '"5": "foo",',
        '"6": "foo",',
        '"7": "foo",',
        '"8": "foo",',
        '"9": "foo"',
        "}",
        "}",
    ]
    sorted_by_int = [
        "{",
        '"values": {',
        '"0": "foo",',
        '"1": "foo",',
        '"2": "foo",',
        '"3": "foo",',
        '"4": "foo",',
        '"5": "foo",',
        '"6": "foo",',
        '"7": "foo",',
        '"8": "foo",',
        '"9": "foo",',
        '"10": "foo",',
        '"11": "foo",',
        '"12": "foo",',
        '"13": "foo",',
        '"14": "foo",',
        '"15": "foo",',
        '"16": "foo",',
        '"17": "foo",',
        '"18": "foo",',
        '"19": "foo"',
        "}",
        "}",
    ]

    try:
        assert lines == sorted_by_int
    except AssertionError:
        assert lines == sorted_by_str


def test_html_method():
    class ObjectWithHTML:
        def __html__(self):
            return "<p>test</p>"

    result = json.dumps(ObjectWithHTML())
    assert result == '"<p>test</p>"'
