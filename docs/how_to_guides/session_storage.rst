.. _session_storage:

Session Storage
===============

It is often useful to store information relevant to a user of the app
for the duration of that usage session. For example the user may
choose to want to save a option or be remembered as logged in. This
information can either be stored client side or server side and Quart
provides a system to store the information client side via Secure
Cookie Sessions.

Server Side Sessions
--------------------

Secure cookie sessions store the whole session in the cookie, so if two
browser tabs send concurrent requests that change different fields the
last response wins and the other change is lost. Server side sessions
avoid this: the cookie only carries an opaque session identifier and the
data lives in a store on the server. Quart ships an optional
:class:`~quart.server_sessions.ServerSideSessionInterface` together with
a runnable SQLite reference store,
:class:`~quart.server_sessions.SqliteSessionStore`.

At the end of a request the interface commits only the top level fields
that changed relative to the data read when the request opened, using
the version read at that time:

- concurrent requests changing different top level fields are merged;
- concurrent changes to the same top level field raise
  :class:`~quart.server_sessions.SessionConflictError` instead of
  silently overwriting each other (deleting a field is a change too);
- nested values are compared as a whole top level field;
- a request that does not modify the session never writes to the store;
- an empty session is deleted, and a late request that commits against a
  deleted or expired session raises
  :class:`~quart.server_sessions.SessionNotFoundError` rather than
  recreating the row (so a logout that happens before an old request
  returns cannot bring the session back to life);
- clearing the whole session (``session.clear()`` / logout) records the
  deletion of every field, so it conflicts explicitly with any concurrent
  field change;
- expiration, identifier rotation and empty session deletion all use the
  same version rules.

To use it, attach the interface with a store when constructing the app,

.. code-block:: python

    from quart import Quart
    from quart.server_sessions import (
        ServerSideSessionInterface,
        SqliteSessionStore,
    )

    app = Quart(__name__)
    app.secret_key = "secret"
    app.session_interface = ServerSideSessionInterface(
        SqliteSessionStore("sessions.db"),
    )

Call :meth:`~quart.server_sessions.ServerSideSession.rotate` on login
(any privilege level change) to move the session to a new opaque
identifier, and clear the session on logout,

.. code-block:: python

    from quart import session


    @app.route("/login/", methods=["POST"])
    async def login():
        session.clear()
        session["user_id"] = user_id
        session.rotate()
        return ""


    @app.route("/logout/", methods=["POST"])
    async def logout():
        session.clear()
        return ""

Commit errors are raised while the response is being finalized, after
view functions and ``after_request`` callbacks have run. The interface
exposes
:meth:`~quart.server_sessions.ServerSideSessionInterface.handle_commit_error`
which can be overridden to turn a conflict into a ``409`` response (or a
missing session into ``410``) instead of letting it become a ``500``,

.. code-block:: python

    from quart.server_sessions import (
        ServerSideSessionInterface,
        SessionConflictError,
        SessionNotFoundError,
    )


    class MySessionInterface(ServerSideSessionInterface):
        async def handle_commit_error(self, app, response, error):
            if isinstance(error, SessionConflictError):
                response.status_code = 409
            elif isinstance(error, SessionNotFoundError):
                response.status_code = 410

To implement another backend, subclass
:class:`~quart.server_sessions.ServerSideSessionStore` and serialise the
read/merge/write step so that the committed version is checked
atomically.

Secure Cookie Sessions
----------------------

Secure Cookie Sessions store the session information on the Cookie in
plain text with a signature to ensure that the information is not
altered by the client. They can be used in Quart so long as the
:attr:`~quart.app.Quart.secret_key` is set to a **secret**
value.

An example usage to store a users colour preference would be,

.. code-block:: python

    from quart import session
    ...


    @app.route('/')
    async def index():
        return await render_template(
            'index.html',
            colour=session.get('colour', 'black'),
        )

    @app.route('/colour/', methods=['POST'])
    async def set_colour():
        ...
        session['colour'] = colour
        return redirect(url_for('index'))

Permanent Sessions
------------------

The cookies used by default are not set to be permanent (deleted when
the browser's session ends) to have permanent cookies
``session.permanent`` must be ``True`` when the session is
modified. To set this as the default use this snippet,

.. code-block:: python

    @app.before_request
    def make_session_permanent():
        session.permanent = True

WebSockets
----------

Sessions can be used with WebSockets with an important caveat about
cookies. A cookie can only be set on a HTTP response, and an accepted
WebSocket connection cannot return a HTTP response. Therefore the
default implementation, being based on cookies, will lose any
modifications made during an accepted WebSocket connection.
