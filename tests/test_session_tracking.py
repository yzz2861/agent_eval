import pytest

import flask
from flask.sessions import SecureCookieSession
from flask.sessions import SecureCookieSessionInterface
from flask.sessions import session_json_serializer


def test_deep_modifications_tracked():
    session = SecureCookieSession(
        {"filters": {"tags": [2, 1]}, "grouped": ({"values": [1]},)},
        track_modifications=True,
    )

    assert session.modified is False

    session["filters"]["tags"][1:2] = [3, 4]
    assert session.modified is True

    session.modified = False
    session["filters"].pop("tags")
    assert session.modified is True

    session.modified = False
    session["filters"].update(tags=[1])
    assert session.modified is True

    session.modified = False
    session["filters"]["tags"].sort()
    assert session.modified is True

    session.modified = False
    session["grouped"][0]["values"].reverse()
    assert session.modified is True

    session["filters"]["tags"].extend([2])
    session.modified = False
    session["filters"]["tags"] *= 1
    assert session.modified is True


def test_reads_do_not_track_modification():
    session = SecureCookieSession(
        {"filters": {"tags": [1, 2]}}, track_modifications=True
    )

    assert session["filters"]["tags"][0] == 1
    assert session["filters"]["tags"][:1] == [1]
    assert session["filters"].get("tags") == [1, 2]
    assert session["filters"].copy()["tags"] == [1, 2]
    assert session.modified is False


def test_removed_child_does_not_modify_session():
    session = SecureCookieSession({"filters": {"tags": [1]}}, track_modifications=True)
    filters = session.pop("filters")
    session.modified = False

    filters["tags"].append(2)

    assert session.modified is False


def test_shared_remains_tracked_while_reachable():
    session = SecureCookieSession({"filters": {"tags": [1]}}, track_modifications=True)
    filters = session["filters"]
    session["copy"] = filters
    session.pop("filters")
    session.modified = False

    filters["tags"].append(2)

    assert session.modified is True


def test_tracked_value_serializes_to_plain_json():
    session = SecureCookieSession({"filters": {"tags": [1]}}, track_modifications=True)

    serialized = session_json_serializer.dumps(dict(session))

    assert serialized == '{"filters":{"tags":[1]}}'
    assert session_json_serializer.loads(serialized) == {"filters": {"tags": [1]}}


def test_shared_values_serialize_once_per_location():
    shared = {"value": 1}

    serialized = session_json_serializer.dumps({"first": shared, "second": shared})

    assert serialized == '{"first":{"value":1},"second":{"value":1}}'


@pytest.mark.parametrize("value", [{}, []])
def test_circular_reference_serialization_error(value):
    if isinstance(value, dict):
        value["self"] = value
    else:
        value.append(value)

    with pytest.raises(ValueError, match="Circular reference"):
        session_json_serializer.dumps(value)


def test_default_mode_remains_shallow():
    session = SecureCookieSession({"filters": {"tags": [1]}})

    session["filters"]["tags"].append(2)

    assert session.modified is False


def test_empty_mutation_does_not_mark_session():
    session = SecureCookieSession({"tags": []}, track_modifications=True)

    session["tags"][0:0] = []
    del session["tags"][0:0]

    assert session.modified is False


class LegacySession(SecureCookieSession):
    def __init__(self, initial=None):
        super().__init__(initial)


def test_custom_session_class_remains_compatible():
    interface = SecureCookieSessionInterface()
    interface.session_class = LegacySession

    session = interface.session_class({"filters": {"tags": [1]}})

    assert session["filters"]["tags"] == [1]

    session = interface._make_session({"filters": {"tags": [1]}})

    assert session["filters"]["tags"] == [1]


def test_interface_enables_deep_tracking():
    interface = SecureCookieSessionInterface()
    interface.track_modifications = True
    session = interface._make_session({"filters": {"tags": [1]}})

    session.modified = False
    session["filters"]["tags"].append(2)

    assert session.modified is True


def test_interface_saves_deep_modifications(app):
    app.session_interface.track_modifications = True
    client = app.test_client()

    @app.post("/init")
    def init_session():
        flask.session["filters"] = {"tags": []}
        return ""

    @app.post("/update")
    def update_session():
        flask.session["filters"]["tags"].append(1)
        return ""

    @app.get("/")
    def read_session():
        return dict(flask.session)

    client.post("/init")
    client.post("/update")

    assert client.get("/").json == {"filters": {"tags": [1]}}
