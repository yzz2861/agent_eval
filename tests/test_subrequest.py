from __future__ import annotations

import flask


def test_subrequest_dispatches_route(app, client):
    events = []

    @app.before_request
    def before_request():
        events.append("before")

    @app.after_request
    def after_request(response):
        events.append("after")
        response.headers["X-Child"] = "true"
        return response

    @app.route("/child")
    def child():
        events.append("child")
        return "child response"

    @app.route("/")
    def index():
        response = flask.current_app.subrequest("/child")
        return response.get_data()

    response = client.get("/")

    assert response.data == b"child response"
    assert events == ["before", "before", "child", "after", "after"]


def test_subrequest_has_independent_context(app, client):
    contexts = []

    @app.route("/child")
    def child():
        flask.g.value = "child"
        flask.session["child"] = True
        contexts.append((flask.request.path, flask.g.get("value"), dict(flask.session)))
        return "child"

    @app.route("/")
    def index():
        flask.g.value = "parent"
        flask.session["parent"] = True
        child_response = flask.current_app.subrequest("/child")
        contexts.append((flask.request.path, flask.g.value, dict(flask.session)))
        return child_response.get_data()

    response = client.get("/")

    assert response.data == b"child"
    assert contexts == [
        ("/child", "child", {"parent": True, "child": True}),
        ("/", "parent", {"parent": True}),
    ]


def test_subrequest_inherits_parent_session_without_access(app, client):
    @app.route("/child")
    def child():
        return flask.session.get("parent", "missing")

    @app.route("/")
    def parent():
        flask.session["parent"] = "value"
        return flask.current_app.subrequest("/child").get_data()

    response = client.get("/")

    assert response.data == b"value"


def test_subrequest_cookies_are_not_added_to_parent_response(app, client):
    @app.route("/child")
    def child():
        flask.session["child"] = True
        response = flask.Response("child")
        response.set_cookie("child_cookie", "value")
        return response

    @app.route("/")
    def index():
        return flask.current_app.subrequest("/child").get_data()

    response = client.get("/")

    assert response.data == b"child"
    assert "Set-Cookie" not in response.headers


def test_subrequest_can_start_without_parent_session(app):
    @app.route("/child")
    def child():
        flask.session["child"] = True
        return "child"

    with app.test_request_context("/"):
        flask.session["parent"] = True
        response = flask.current_app.subrequest("/child", inherit_session=False)

        assert dict(flask.session) == {"parent": True}

    assert any(
        "session=" in cookie for cookie in response.headers.getlist("Set-Cookie")
    )


def test_subrequest_without_parent_request(app):
    @app.route("/child")
    def child():
        flask.g.value = "child"
        return "child"

    with app.app_context():
        response = flask.subrequest("/child")

    assert response.data == b"child"
    assert not flask.has_app_context()


def test_subrequest_error_handler_and_parent_context(app, client):
    child_request = None
    parent_request = None

    @app.errorhandler(500)
    def handle_500(error):
        return "handled", 500

    @app.route("/child")
    def child():
        nonlocal child_request
        child_request = flask.request._get_current_object()
        raise RuntimeError("child error")

    @app.route("/")
    def index():
        nonlocal parent_request
        parent_request = flask.request._get_current_object()
        child_response = flask.current_app.subrequest("/child")
        assert flask.request._get_current_object() is parent_request
        return child_response.get_data(), child_response.status_code

    app.testing = False
    app.config["PROPAGATE_EXCEPTIONS"] = False
    response = client.get("/")

    assert response.data == b"handled"
    assert response.status_code == 500
    assert not flask.has_request_context()
    assert child_request is not parent_request


def test_subrequest_nesting_depth(app):
    app.config["SUBREQUEST_MAX_DEPTH"] = 3

    @app.route("/depth/<int:depth>")
    def depth(depth):
        if depth:
            return flask.current_app.subrequest(f"/depth/{depth - 1}").get_data()

        return "done"

    with app.test_request_context("/"):
        assert flask.current_app.subrequest("/depth/2").data == b"done"
        assert flask.request.path == "/"

        try:
            flask.current_app.subrequest("/depth/3")
        except RuntimeError as error:
            assert str(error) == "Maximum subrequest nesting depth exceeded."
        else:
            raise AssertionError("Expected nesting depth error")


def test_subrequest_stream_keeps_context_until_closed(app, client):
    teardowns = []
    active_paths = []

    @app.teardown_request
    def teardown_request(error):
        teardowns.append(flask.request.path)

    @app.route("/child")
    def child():
        def generate():
            active_paths.append(flask.request.path)
            yield "one"
            active_paths.append(flask.request.path)
            yield "two"

        return flask.Response(generate())

    @app.route("/")
    def index():
        child_response = flask.current_app.subrequest("/child")
        assert flask.request.path == "/"
        return child_response

    response = client.get("/")

    chunks = list(response.iter_encoded())
    assert chunks == [b"one", b"two"]
    assert set(teardowns) == {"/child", "/"}
    assert active_paths == ["/child", "/child"]


def test_subrequest_stream_returned_by_parent(app, client):
    @app.route("/child")
    def child():
        def generate():
            yield flask.request.path
            yield flask.session.get("parent", "missing")

        return flask.Response(generate())

    @app.route("/")
    def index():
        flask.session["parent"] = "value"
        return flask.current_app.subrequest("/child")

    response = client.get("/")

    assert response.data == b"/childvalue"
    assert not flask.has_request_context()


def test_subrequest_stream_direct_close_after_parent(app, client):
    teardowns = []
    captured = []

    @app.teardown_request
    def teardown_request(error):
        teardowns.append(flask.request.path)

    @app.route("/child")
    def child():
        def generate():
            yield "one"
            yield "two"

        return flask.Response(generate())

    @app.route("/")
    def index():
        captured.append(flask.current_app.subrequest("/child"))
        return "parent"

    response = client.get("/")
    child_response = captured[0]

    assert response.data == b"parent"
    assert teardowns == ["/"]

    child_response.close()

    assert teardowns == ["/", "/child"]
    assert not flask.has_request_context()


def test_subrequest_stream_early_close_restores_parent_context(app, client):
    teardowns = []

    @app.teardown_request
    def teardown_request(error):
        teardowns.append((flask.request.path, error))

    @app.route("/child")
    def child():
        def generate():
            yield "before"
            raise RuntimeError("stream error")

        return flask.Response(generate())

    @app.route("/")
    def index():
        flask.g.value = "parent"
        child_response = flask.current_app.subrequest("/child")
        assert next(child_response.iter_encoded()) == b"before"
        child_response.close()
        assert flask.request.path == "/"
        assert flask.g.value == "parent"
        return "parent"

    response = client.get("/")

    assert response.data == b"parent"
    assert teardowns[0][0] == "/child"
    assert isinstance(teardowns[0][1], GeneratorExit)
    assert teardowns[1] == ("/", None)
