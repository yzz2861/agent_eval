from __future__ import annotations

import flask


def test_subrequest_dispatches_route(app):
    events = []

    @app.before_request
    def before_request():
        events.append(("before", flask.request.path))

    @app.after_request
    def after_request(response):
        events.append(("after", flask.request.path))
        return response

    @app.route("/child")
    def child():
        return "child", 201, {"X-Child": "yes"}

    @app.route("/parent")
    def parent():
        response = flask.current_app.subrequest("/child")
        assert flask.request.path == "/parent"
        assert response.status_code == 201
        assert response.headers["X-Child"] == "yes"
        return response.get_data()

    response = app.test_client().get("/parent")

    assert response.data == b"child"
    assert events == [
        ("before", "/parent"),
        ("before", "/child"),
        ("after", "/child"),
        ("after", "/parent"),
    ]


def test_subrequest_has_independent_context_and_session(app):
    @app.route("/child")
    def child():
        assert flask.request.path == "/child"
        flask.g.value = "child"
        flask.session["child"] = "value"
        return "child"

    @app.route("/parent")
    def parent():
        flask.g.value = "parent"
        response = flask.current_app.subrequest("/child")

        assert flask.request.path == "/parent"
        assert flask.g.value == "parent"
        assert "child" not in flask.session
        assert response.headers["Set-Cookie"].startswith("session=")

        return "parent"

    response = app.test_client().get("/parent")

    assert response.data == b"parent"
    assert "Set-Cookie" not in response.headers


def test_subrequest_accepts_request_arguments(app):
    @app.post("/child")
    def child():
        assert flask.request.json == {"name": "value"}
        return flask.request.headers["Cookie"], 200

    with app.test_request_context("/parent", headers={"Cookie": "token=parent"}):
        response = app.subrequest(
            "/child",
            method="POST",
            json={"name": "value"},
        )

        assert response.status_code == 200
        assert response.data == b"token=parent"
        assert flask.request.path == "/parent"


def test_subrequest_nesting_depth(app):
    @app.route("/level/<int:value>")
    def level(value):
        if value == 0:
            return "bottom"

        return flask.current_app.subrequest(f"/level/{value - 1}").get_data()

    @app.route("/too-deep")
    def too_deep():
        try:
            flask.current_app.subrequest("/level/2")
        except RuntimeError as error:
            assert "Subrequest nesting depth 2" in str(error)
            assert flask.request.path == "/too-deep"
            return "recovered"

        return "not recovered"

    response = app.test_client().get("/level/2")
    assert response.data == b"bottom"

    app.config["MAX_SUBREQUEST_DEPTH"] = 1

    response = app.test_client().get("/too-deep")
    assert response.data == b"recovered"


def test_subrequest_error_restores_parent_context(app):
    app.testing = False

    @app.errorhandler(Exception)
    def handle_error(error):
        return "handled", 500

    @app.route("/child")
    def child():
        raise RuntimeError("child failure")

    @app.route("/parent")
    def parent():
        flask.g.value = "parent"
        response = flask.current_app.subrequest("/child")

        assert response.status_code == 500
        assert response.data == b"handled"
        assert flask.request.path == "/parent"
        assert flask.g.value == "parent"
        return "parent"

    response = app.test_client().get("/parent")
    assert response.data == b"parent"


def test_subrequest_propagated_error_restores_parent_context(app):
    @app.route("/child")
    def child():
        raise RuntimeError("child failure")

    @app.route("/parent")
    def parent():
        try:
            flask.current_app.subrequest("/child")
        except RuntimeError as error:
            assert str(error) == "child failure"
        else:
            raise AssertionError("subrequest error was not propagated")

        assert flask.request.path == "/parent"
        return "recovered"

    response = app.test_client().get("/parent")
    assert response.data == b"recovered"


def test_subrequest_stream_context_cleanup(app):
    events = []

    @app.teardown_request
    def teardown_request(error):
        events.append(flask.request.path)

    def generate():
        assert flask.request.path == "/child"
        assert flask.g.value == "child"
        yield b"one"
        yield b"two"

    @app.route("/child")
    def child():
        flask.g.value = "child"
        return flask.Response(generate())

    @app.route("/parent")
    def parent():
        flask.g.value = "parent"
        response = flask.current_app.subrequest("/child")
        chunks = response.response

        assert next(chunks) == b"one"
        chunks.close()

        assert flask.request.path == "/parent"
        assert flask.g.value == "parent"
        assert events == ["/child"]
        return "parent"

    response = app.test_client().get("/parent")
    assert response.data == b"parent"
    assert events == ["/child", "/parent"]


def test_subrequest_stream_full_consumption(app):
    def generate():
        assert flask.request.path == "/child"
        yield b"one"
        yield b"two"

    @app.route("/child")
    def child():
        return flask.Response(generate())

    @app.route("/parent")
    def parent():
        response = flask.current_app.subrequest("/child")
        assert b"".join(response.response) == b"onetwo"
        assert flask.request.path == "/parent"
        return "parent"

    response = app.test_client().get("/parent")
    assert response.data == b"parent"


def test_subrequest_stream_with_context_full_consumption(app):
    @app.route("/child")
    def child():
        def generate():
            yield flask.request.path
            yield " done"

        return flask.Response(flask.stream_with_context(generate()))

    @app.route("/parent")
    def parent():
        response = flask.current_app.subrequest("/child")
        return b"".join(response.response)

    response = app.test_client().get("/parent")
    assert response.data == b"/child done"


def test_subrequest_stream_error_restores_parent_context(app):
    app.testing = False
    teardown_exceptions = []

    @app.teardown_request
    def teardown_request(error):
        if flask.request.path == "/child":
            teardown_exceptions.append(error)

    def generate():
        yield b"before"
        raise RuntimeError("stream failure")

    @app.route("/child")
    def child():
        return flask.Response(generate())

    @app.route("/parent")
    def parent():
        response = flask.current_app.subrequest("/child")
        iterator = iter(response.response)
        assert next(iterator) == b"before"

        try:
            next(iterator)
        except RuntimeError as error:
            assert str(error) == "stream failure"

        assert flask.request.path == "/parent"
        return "parent"

    response = app.test_client().get("/parent")
    assert response.data == b"parent"
    assert type(teardown_exceptions[0]) is RuntimeError
