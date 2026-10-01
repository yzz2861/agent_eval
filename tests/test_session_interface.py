import json

import pytest

import flask
from flask.globals import app_ctx
from flask.sessions import SecureCookieSession
from flask.sessions import SecureCookieSessionInterface
from flask.sessions import SessionInterface
from flask.sessions import TrackedSecureCookieSession
from flask.sessions import TrackedSecureCookieSessionInterface


def test_open_session_with_endpoint():
    """If request.endpoint (or other URL matching behavior) is needed
    while loading the session, RequestContext.match_request() can be
    called manually.
    """

    class MySessionInterface(SessionInterface):
        def save_session(self, app, session, response):
            pass

        def open_session(self, app, request):
            app_ctx.match_request()
            assert request.endpoint is not None

    app = flask.Flask(__name__)
    app.session_interface = MySessionInterface()

    @app.get("/")
    def index():
        return "Hello, World!"

    response = app.test_client().get("/")
    assert response.status_code == 200


def test_default_session_does_not_track_nested_modifications():
    session = SecureCookieSession({"filters": {"tags": ["a"]}})

    assert not session.modified
    session["filters"]["tags"].append("b")
    assert not session.modified


def test_session_constructor_can_enable_nested_tracking():
    session = SecureCookieSession({"filters": {"tags": []}}, True)
    session["filters"]["tags"].append("a")
    assert session.modified


def test_tracked_session_detects_nested_modifications():
    session = TrackedSecureCookieSession(
        {"filters": {"tags": ["c"]}, "items": [3, 1, 2]}
    )

    session["filters"].update(kind="test")
    assert session.modified

    session.modified = False
    session["filters"]["tags"].pop()
    assert session.modified

    session.modified = False
    session["filters"].pop("tags")
    assert session.modified

    session.modified = False
    session["items"][1:2] = [2]
    assert session.modified

    session.modified = False
    session["items"].sort()
    assert session.modified


@pytest.mark.parametrize(
    ("mutate"),
    [
        lambda value: value.append(2),
        lambda value: value.extend([2]),
        lambda value: value.insert(0, 2),
        lambda value: value.remove(1),
        lambda value: value.pop(),
        lambda value: value.clear(),
        lambda value: value.__setitem__(slice(0, 1), []),
        lambda value: value.__delitem__(0),
        lambda value: value.sort(),
        lambda value: value.reverse(),
        lambda value: value.__iadd__([2]),
        lambda value: value.__imul__(2),
    ],
)
def test_tracked_session_detects_list_mutations(mutate):
    session = TrackedSecureCookieSession({"values": [1]})
    mutate(session["values"])
    assert session.modified


def test_tracked_session_reads_do_not_modify():
    session = TrackedSecureCookieSession({"filters": {"tags": ["a"]}})

    session["filters"]
    session["filters"]["tags"]
    session["filters"]["tags"][:]
    len(session)
    assert "filters" in session
    list(session)
    session["filters"].items()
    session["filters"]["tags"].copy()

    assert not session.modified


def test_tracked_session_tracks_container_inside_tuple():
    session = TrackedSecureCookieSession({"nested": ({"tags": ["a"]},)})
    session["nested"][0]["tags"].append("b")
    assert session.modified


def test_shared_container_in_tuple_remains_shared():
    shared = {"tags": ["a"]}
    session = TrackedSecureCookieSession({"nested": (shared, shared)})
    session["nested"][0]["tags"].append("b")
    assert session["nested"][1]["tags"] == ["a", "b"]


def test_removed_child_no_longer_marks_session():
    session = TrackedSecureCookieSession({"filters": {"tags": ["a"]}})
    old_tags = session["filters"].pop("tags")
    session.modified = False

    old_tags.append("b")

    assert not session.modified
    assert old_tags == ["a", "b"]


def test_shared_child_continues_tracking_from_either_location():
    session = TrackedSecureCookieSession({})
    filters = {"tags": ["a"]}
    session["filters"] = filters
    session["backup"] = session["filters"]
    session.modified = False

    session.pop("filters")
    session.modified = False
    session["backup"]["tags"].append("b")

    assert session.modified
    assert session["backup"] == {"tags": ["a", "b"]}


def test_reachable_shared_nested_child_still_marks_session():
    session = TrackedSecureCookieSession(
        {"root": {}, "detached": {"shared": {"tags": ["a"]}}}
    )
    session["root"]["shared"] = session["detached"]["shared"]
    detached = session.pop("detached")
    session.modified = False

    detached["shared"]["tags"].append("b")

    assert session.modified
    assert session["root"]["shared"]["tags"] == ["a", "b"]


def test_list_self_reference_operations_remain_usable():
    session = TrackedSecureCookieSession({"values": [1]})
    values = session["values"]

    values[:] = values
    values.extend(values)

    assert values == [1, 1]
    assert session.modified


def test_loaded_session_remains_tracked(app):
    interface = TrackedSecureCookieSessionInterface()
    session = interface._make_session({"filters": {"tags": ["a"]}})
    cookie = interface.get_signing_serializer(app).dumps(dict(session))
    request = app.test_request_context(headers={"Cookie": f"session={cookie}"}).request

    loaded = interface.open_session(app, request)
    loaded["filters"]["tags"].append("b")
    assert loaded.modified


def test_cross_session_tracked_objects_are_copied():
    first = TrackedSecureCookieSession({"filters": {"tags": ["a"]}})
    second = TrackedSecureCookieSession()
    second["filters"] = first["filters"]
    second["filters"]["tags"].append("b")

    assert first["filters"]["tags"] == ["a"]
    assert second["filters"]["tags"] == ["a", "b"]
    assert second.modified
    assert not first.modified


def test_tracked_session_serializes_to_plain_json_types(app):
    interface = TrackedSecureCookieSessionInterface()
    session = interface._make_session({"filters": {"tags": ["a"]}})
    session["filters"]["tags"].append("b")

    decoded = interface.serializer.tag(dict(session))
    json.dumps(decoded)

    assert type(decoded["filters"]) is dict
    assert type(decoded["filters"]["tags"]) is list
    assert decoded["filters"]["tags"] == ["a", "b"]


def test_tracked_session_round_trip(app, client):
    app.session_interface = TrackedSecureCookieSessionInterface()

    @app.post("/seed")
    def seed():
        flask.session["filters"] = {"tags": ["a"]}
        return ""

    @app.post("/tags")
    def add_tag():
        flask.session["filters"]["tags"].append("b")
        return ""

    @app.get("/")
    def index():
        return flask.jsonify(flask.session["filters"])

    seed_response = client.post("/seed")
    update_response = client.post("/tags")

    assert "Set-Cookie" in seed_response.headers
    assert "Set-Cookie" in update_response.headers
    assert client.get("/").get_json() == {"tags": ["a", "b"]}


@pytest.mark.parametrize("value", [lambda: {"self": None}, lambda: []])
def test_tracked_session_rejects_circular_references(app, value):
    interface = TrackedSecureCookieSessionInterface()
    session = interface._make_session()
    circular = value()

    if isinstance(circular, dict):
        circular["self"] = circular
    else:
        circular.append(circular)

    session["circular"] = circular
    response = app.response_class()

    with pytest.raises(ValueError, match="Circular reference"):
        interface.save_session(app, session, response)


def test_tracked_session_rejects_circular_mutation(app):
    interface = TrackedSecureCookieSessionInterface()
    session = interface._make_session({"values": [[]]})
    response = app.response_class()

    session["values"][0].append(session["values"][0])

    with pytest.raises(ValueError, match="Circular reference"):
        interface.save_session(app, session, response)
    assert "Set-Cookie" not in response.headers


def test_custom_session_interface_signature_remains_compatible():
    class CustomInterface(SecureCookieSessionInterface):
        def __init__(self, value):
            self.value = value

    interface = CustomInterface("configured")
    session = interface._make_session({"value": 1})

    assert interface.value == "configured"
    assert session["value"] == 1


def test_custom_session_interface_can_enable_tracking_as_class_attribute():
    class CustomInterface(SecureCookieSessionInterface):
        track_nested_modifications = True

    session = CustomInterface()._make_session({"filters": {"tags": []}})
    session["filters"]["tags"].append("a")
    assert session.modified
