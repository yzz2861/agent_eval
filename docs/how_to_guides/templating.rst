.. _templating:

Templates
=========

Quart uses the `Jinja <https://jinja.palletsprojects.com>`_ templating engine,
which is well `documented
<https://jinja.palletsprojects.com/templates/>`_. Quart adds a standard
context, and some standard filters to the Jinja defaults. Quart also
adds the ability to define custom filters, tests and contexts at an
app and blueprint level.

There are two functions to use when templating,
:func:`~quart.templating.render_template` and
:func:`~quart.templating.render_template_string`, both must be
awaited. The return value from either function is a string and can
form a route response directly or be otherwise combined. Both
functions take an variable number of additional keyword arguments to
pass to the template as context, for example,

.. code-block:: python

    @app.route('/')
    async def index():
        return await render_template('index.html', hello='world')

Quart standard extras
---------------------

The standard context includes the ``config``, ``request``,
``session``, and ``g`` with these objects referencing the
``current_app.config`` and those defined in :mod:`~quart.globals`
respectively. The can be accessed as expected,

.. code-block:: python

    @app.route('/')
    async def index():
        return await render_template_string("{{ request.endpoint }}")

The standard global functions are :func:`~quart.helpers.url_for` and
:func:`~quart.helpers.get_flashed_messages`. These can be used as expected,

.. code-block:: python

    @app.route('/')
    async def index():
        return await render_template_string("<a href="{{ url_for('index') }}>index</a>")

Adding filters, tests, globals and context
------------------------------------------

To add a filter for usage in templates, make use of
:meth:`~quart.app.Quart.template_filter` or
:meth:`~quart.blueprints.Blueprint.app_template_filter` as decorators,
or :meth:`~quart.app.Quart.add_template_filter` or
:meth:`~quart.blueprints.Blueprint.add_app_template_filter` as
functions. These expect the filter to take in Any value and return a
str, e.g.

.. code-block:: python

    @app.template_filter(name='upper')
    def upper_case(value):
        return value.upper()

    @app.route('/')
    async def index():
        return await render_template_string("{{ lower | upper }}")

tests and globals work in a very similar way only with the test and
global methods rather than filter.

The context processors however have an additional feature, in that
they can be specified on a per blueprint basis. This allows contextual
information to be present only for requests that are routed to the
blueprint. By default
:meth:`~quart.blueprints.Blueprint.context_processor` adds contextual
information to blueprint routed requests whereas
:meth:`~quart.blueprints.Blueprint.app_context_processor` adds the
information to all requests to the app. An example,

.. code-block:: python

    @blueprint.context_processor
    async def blueprint_only():
        return {'context': 'value'}

    @blueprint.app_context_processor
    async def app_wide():
        return {'context': 'value'}

Rendering one block
-------------------

:func:`~quart.templating.render_template_block` renders a single Jinja
block without rendering the rest of the page. Its streaming equivalent is
:func:`~quart.templating.stream_template_block`. Both build the normal Jinja
inheritance chain, so an overriding child block can call ``super()`` and
nested blocks retain their usual scopes. Quart context processors, the
``request`` and ``g`` proxies, asynchronous filters and template signals
still apply.

Given these templates,

.. code-block:: html

    {# templates/base.html #}
    {{ page_counter('outside') }}
    <!doctype html>
    <html>
      <body>
        <main>{% block content %}Parent {{ value }}{% endblock %}</main>
      </body>
    </html>

.. code-block:: html

    {# templates/partial.html #}
    {% extends "base.html" %}
    {% block content %}Child {{ super() }}{% endblock %}

this app returns the complete document on first load and only the block on
later requests. ``page_counter`` is called by the full page but not by block
rendering. A request to ``/outside-renders`` therefore reports ``1`` after
loading ``/`` and then ``/partial``.

.. code-block:: python

    from quart import (
        Quart,
        g,
        render_template,
        render_template_block,
        stream_template_block,
    )


    app = Quart(__name__)
    outside_renders = 0


    def page_counter(location: str) -> int:
        global outside_renders
        outside_renders += 1
        g.last_location = location
        return outside_renders


    app.add_template_global(page_counter)


    @app.get("/")
    async def index():
        return await render_template("partial.html", value="initial")


    @app.get("/partial")
    async def partial():
        return await render_template_block(
            "partial.html", "content", value="updated"
        )


    @app.get("/partial-stream")
    async def partial_stream():
        return await stream_template_block(
            "partial.html", "content", value="streamed"
        )


    @app.get("/outside-renders")
    async def outside_render_count():
        return {"count": outside_renders}
