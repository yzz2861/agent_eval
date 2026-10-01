.. _session_storage:

Session Storage
===============

It is often useful to store information relevant to a user of the app
for the duration of that usage session. For example the user may
choose to want to save a option or be remembered as logged in. This
information can either be stored client side or server side. Quart
provides client-side Secure Cookie Sessions by default, plus an
optional server-side interface with SQLite as a reference storage.

Server-side Sessions
--------------------

Server-side sessions put only an opaque random identifier in the cookie
and retain the mapping in a :class:`~quart.sessions.SessionStore`. Use
:class:`~quart.sessions.ServerSideSessionInterface` to enable the
SQLite reference store,

.. code-block:: python

    from quart import Quart
    from quart import ServerSideSessionInterface
    from quart import SQLiteSessionStore

    app = Quart(__name__)
    app.session_interface = ServerSideSessionInterface(
        SQLiteSessionStore("sessions.db")
    )

Each request saves the version and field versions read at its start.
At the end of the request, changed top-level keys are committed
optimistically. Changes to distinct top-level keys are merged in one
transaction. If another request changed or deleted one of the same
top-level keys, the losing request returns ``409 Conflict`` and its
response does not update the cookie. Deleting a key counts as changing
that key, while nested values are compared as part of their whole
top-level key.

``session.clear()`` deletes an empty session. A late request that read
the session before logout receives a conflict and cannot recreate it.
Calling ``session.rotate()`` changes the opaque identifier under the
same optimistic concurrency rule. Reads without modifications do not
write or extend the stored session. Expired records are treated as
missing and cannot be revived by a stale request.

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
