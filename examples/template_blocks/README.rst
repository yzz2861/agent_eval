Example: Rendering a single template block
==========================================

A page is rendered in full on first load, after which partial
refreshes render only the block that changed - without executing
the rest of the page.

``page.html`` extends ``layout.html``, overrides the ``content``
block and calls ``{{ super() }}`` to include the parent's default
content. ``layout.html`` calls a ``counter()`` function in its header
and footer: the count proves that output outside the selected block
is never executed during a block render.

Routes:

* ``/`` renders the full page (the counter increments).
* ``/content`` renders only the ``content`` block via
  ``render_template_block`` (the counter does not increment).
* ``/content/stream`` streams only the ``content`` block via
  ``stream_template_block`` (the counter does not increment).
* ``/counter`` returns how often ``counter()`` has been called.

It is managed using `Poetry <https://python-poetry.org>`_ with the
following commands,

.. code-block:: console

    poetry install
    poetry run start
    poetry run pytest -c pyproject.toml tests/
