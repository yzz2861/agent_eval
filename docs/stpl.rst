==============
SimpleTemplate
==============

.. currentmodule:: bottle

Bottle comes with a fast, powerful and easy to learn built-in template engine called *SimpleTemplate* or *stpl* for short. It is the default engine used by the :func:`view` and :func:`template` helpers but can be used as a stand-alone general purpose template engine too. This document explains the template syntax and shows examples for common use cases.

.. rubric:: Basic API Usage:

:class:`SimpleTemplate` implements the :class:`BaseTemplate` API::

   >>> from bottle import SimpleTemplate
   >>> tpl = SimpleTemplate('Hello {{name}}!')
   >>> tpl.render(name='World')
   u'Hello World!'

In this document we use the :func:`template` helper in examples for the sake of simplicity::

   >>> from bottle import template
   >>> template('Hello {{name}}!', name='World')
   u'Hello World!'

You can also pass a dictionary into the template using keyword arguments::

   >>> from bottle import template
   >>> my_dict={'number': '123', 'street': 'Fake St.', 'city': 'Fakeville'}
   >>> template('I live at {{number}} {{street}}, {{city}}', **my_dict)
   u'I live at 123 Fake St., Fakeville'

Just keep in mind that compiling and rendering templates are two different actions, even if the :func:`template` helper hides this fact. Templates are usually compiled only once and cached internally, but rendered many times with different keyword arguments.

:class:`SimpleTemplate` Syntax
==============================

Python is a very powerful language but its whitespace-aware syntax makes it difficult to use as a template language. SimpleTemplate removes some of these restrictions and allows you to write clean, readable and maintainable templates while preserving full access to the features, libraries and speed of the Python language.

.. warning::

   The :class:`SimpleTemplate` syntax compiles directly to python bytecode and is executed on each :meth:`SimpleTemplate.render` call. Do not render untrusted templates! They may contain and execute harmful python code.

Inline Expressions
------------------

You already learned the use of the ``{{...}}`` syntax from the "Hello World!" example above, but there is more: any python expression is allowed within the curly brackets as long as it evaluates to a string or something that has a string representation::

  >>> template('Hello {{name}}!', name='World')
  u'Hello World!'
  >>> template('Hello {{name.title() if name else "stranger"}}!', name=None)
  u'Hello stranger!'
  >>> template('Hello {{name.title() if name else "stranger"}}!', name='mArC')
  u'Hello Marc!'

The contained python expression is executed at render-time and has access to all keyword arguments passed to the :meth:`SimpleTemplate.render` method. HTML special characters are escaped automatically to prevent `XSS <https://en.wikipedia.org/wiki/Cross-Site_Scripting>`_ attacks. You can start the expression with an exclamation mark to disable escaping for that expression::

  >>> template('Hello {{name}}!', name='<b>World</b>')
  u'Hello &lt;b&gt;World&lt;/b&gt;!'
  >>> template('Hello {{!name}}!', name='<b>World</b>')
  u'Hello <b>World</b>!'

Embedded python code
--------------------

.. highlight:: html+django

The template engine allows you to embed lines or blocks of python code within your template. Code lines start with ``%`` and code blocks are surrounded by ``<%`` and ``%>`` tokens:

 .. code-block:: text

  % name = "Bob"  # a line of python code
  <p>Some plain text in between</p>
  <%
    # A block of python code
    name = name.title().strip()
  %>
  <p>More plain text</p>

Embedded python code follows regular python syntax, but with two additional syntax rules:

* **Indentation is ignored.** You can put as much whitespace in front of statements as you want. This allows you to align your code with the surrounding markup and can greatly improve readability.
* Blocks that are normally indented now have to be closed explicitly with an ``end`` keyword.

 .. code-block:: text

  <ul>
    % for item in basket:
      <li>{{item}}</li>
    % end
  </ul>

Both the ``%`` and the ``<%`` tokens are only recognized if they are the first non-whitespace characters in a line. You don't have to escape them if they appear mid-text in your template markup. Only if a line of text starts with one of these tokens, you have to escape it with a backslash. In the rare case where the backslash + token combination appears in your markup at the beginning of a line, you can always help yourself with a string literal in an inline expression:

 .. code-block:: text

  This line contains % and <% but no python code.
  \% This text-line starts with the '%' token.
  \<% Another line that starts with a token but is rendered as text.
  {{'\\%'}} this line starts with an escaped token.


Whitespace Control
-----------------------

Code blocks and code lines always span the whole line. Whitespace in front of after a code segment is stripped away. You won't see empty lines or dangling whitespace in your template because of embedded code::

  <div>
   % if True:
    <span>content</span>
   % end
  </div>

This snippet renders to clean and compact html::

  <div>
    <span>content</span>
  </div>

But embedding code still requires you to start a new line, which may not what you want to see in your rendered template. To skip the newline in front of a code segment, end the text line with a double-backslash::

  <div>\\
   %if True:
  <span>content</span>\\
   %end
  </div>

This time the rendered template looks like this::

  <div><span>content</span></div>

This only works directly in front of code segments. In all other places you can control the whitespace yourself and don't need any special syntax.

Template Functions
==================

Each template is preloaded with a bunch of functions that help with the most common use cases. These functions are always available. You don't have to import or provide them yourself. For everything not covered here there are probably good python libraries available. Remember that you can ``import`` anything you want within your templates. They are python programs after all.

.. currentmodule:: stpl

.. versionchanged:: 0.12
   Prior to this release, :func:`include` and :func:`rebase` were syntax keywords, not functions.

.. function:: include(sub_template, **variables)

  Render a sub-template with the specified variables and insert the resulting text into the current template. The function returns a dictionary containing the local variables passed to or defined within the sub-template::

    % include('header.tpl', title='Page Title')
    Page Content
    % include('footer.tpl')

.. function:: rebase(name, **variables)

  Mark the current template to be later included into a different template. After the current template is rendered, its resulting text is stored in a variable named ``base`` and passed to the base-template, which is then rendered. This can be used to `wrap` a template with surrounding text, or simulate the inheritance feature found in other template engines::

    % rebase('base.tpl', title='Page Title')
    <p>Page Content ...</p>

  This can be combined with the following ``base.tpl``:

  .. code-block:: html

    <html>
    <head>
      <title>{{title or 'No title'}}</title>
    </head>
    <body>
      {{!base}}
    </body>
    </html>


Named Slots
-----------

The ``rebase`` mechanism above passes exactly one block of rendered text (the
``base`` variable) to the layout. If a layout needs more than that, for
example a ``<head>`` section, a sidebar and a block of scripts, templates can
capture output into *named slots* and the layout can read them back later.
Slot state is shared by the whole chain of templates involved in a single
render: the template itself, everything it includes, and any layouts reached
via ``rebase``. Each call to ``render()`` starts with a fresh set of slots,
so repeated renders never accumulate leftover content.

.. function:: slot(name)

  Used as a ``with`` block, captures everything rendered inside the block
  into the named slot, *replacing* any previous content of that slot::

    % with slot('sidebar'):
      <p>Latest news ...</p>
    % end

.. function:: slot_append(name)

  Same as ``slot()``, but *appends* to the current content of the slot
  instead of replacing it. Operations on the same slot apply in execution
  order, so a layout can add default content before or after the content
  captured by the wrapped template::

    % with slot_append('scripts'):
      <script src="extra.js"></script>
    % end

.. function:: slot_get(name, default='')

  Return the rendered content of a slot. The content was already rendered
  (and escaped) when it was captured, so it is inserted into the template
  *without being escaped again*. Reading a slot that was never filled
  returns the default (an empty string) instead of raising an error::

    <head>{{slot_get('head')}}</head>

.. function:: slot_defined(name)

  Return True if the slot has any content, False otherwise.

Expressions inside a slot block follow the normal escaping rules (``{{...}}``
escapes, ``{{!...}}`` does not). Only the insertion via ``slot_get()`` skips
escaping, because the content is already fully rendered at that point.

Sub-templates rendered via ``include()`` contribute to the same slots as
their caller, which allows partials to register scripts or styles for the
final layout. This only applies to slots: ordinary variables defined inside
an included template still do not leak back into the caller. Recursive
includes work as expected, too. Every recursion level appends to or replaces
the shared slots in execution order, and (as with any recursion) unbounded
recursion ends in a ``RecursionError``.

Here is a complete example with a two-level layout (``base.tpl`` and
``mid.tpl``) and two page templates. The root layout defines the slots it
knows about:

.. code-block:: html

  <html>
  <head>{{slot_get('head')}}</head>
  <aside>{{slot_get('sidebar')}}</aside>
  <main>{{!base}}</main>
  {{slot_get('scripts')}}</html>

The middle layout ``mid.tpl`` rebases into it and appends its own sidebar
entry after whatever the page contributed::

  % rebase('base.tpl')
  % with slot_append('sidebar'):
  <span>mid</span>
  % end
  {{!base}}

The first page fills all three slots. ``{{title}}`` is escaped when captured
into the slots, and the layout inserts the rendered slot content verbatim::

  % rebase('mid.tpl')
  % with slot('head'):
  <title>{{title}}</title>
  % end
  % with slot('sidebar'):
  <span>p1</span>
  % end
  % with slot('scripts'):
  <script>{{title}}</script>
  % end
  <h1>{{title}}</h1>

Rendered with ``title='<P1>'`` this produces:

.. code-block:: html

  <html>
  <head><title>&lt;P1&gt;</title>
  </head>
  <aside><span>p1</span>
  <span>mid</span>
  </aside>
  <main><h1>&lt;P1&gt;</h1>
  </main>
  <script>&lt;P1&gt;</script>
  </html>

The second page leaves ``head`` undefined (the layout renders an empty
``<head>``) and relies on an included partial to contribute its script. The
``inc_var`` variable defined by the partial does not leak back::

  % rebase('mid.tpl')
  % with slot('sidebar'):
  <span>p2</span>
  % end
  % include('inc.tpl')
  <h1>P2</h1> inc_var leaked: {{defined('inc_var')}}

with ``inc.tpl`` being::

  % with slot_append('scripts'):
  <script src="inc.js"></script>
  % end
  % inc_var = 'secret'

.. code-block:: html

  <html>
  <head></head>
  <aside><span>p2</span>
  <span>mid</span>
  </aside>
  <main><h1>P2</h1> inc_var leaked: False
  </main>
  <script src="inc.js"></script>
  </html>


Accessing undefined variables in a template raises :exc:`NameError` and
stops rendering immediately. This is standard python behavior and nothing new,
but vanilla python lacks an easy way to check the availability of a variable.
This quickly gets annoying if you want to support flexible inputs or use the
same template in different situations. These functions may help:

.. function:: defined(name)

    Return True if the variable is defined in the current template namespace,
    False otherwise.

.. function:: get(name, default=None)

    Return the variable, or a default value.

.. function:: setdefault(name, default)

    If the variable is not defined, create it with the given default value.
    Return the variable.

Here is an example that uses all three functions to implement optional template
variables in different ways::

    % setdefault('text', 'No Text')
    <h1>{{get('title', 'No Title')}}</h1>
    <p> {{ text }} </p>
    % if defined('author'):
      <p>By {{ author }}</p>
    % end

.. currentmodule:: bottle


:class:`SimpleTemplate` API
==============================

.. autoclass:: SimpleTemplate
   :members:
