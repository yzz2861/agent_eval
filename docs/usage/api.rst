API overview
------------

``compile_restricted`` methods
++++++++++++++++++++++++++++++

.. py:method:: compile_restricted(source, filename, mode, flags, dont_inherit, policy)
    :module: RestrictedPython

    Compiles source code into interpretable byte code.

    :param source: (required). the source code that should be compiled
    :param filename: (optional). defaults to ``'<unknown>'``
    :param mode: (optional). Use ``'exec'``, ``'eval'`` or ``'single'``. defaults to ``'exec'``
    :param flags: (optional). defaults to ``0``
    :param dont_inherit: (optional). defaults to ``False``
    :param policy: (optional). defaults to ``RestrictingNodeTransformer``
    :type source: str or bytes or bytearray or ``ast.Module`` or ``ast.Expression`` or ``ast.Interactive``
    :type filename: str or bytes or os.PathLike[typing.Any]
    :type mode: str
    :type flags: int
    :type dont_inherit: int
    :type policy: RestrictingNodeTransformer class
    :return: Python ``code`` object

.. py:method:: compile_restricted_exec(source, filename, flags, dont_inherit, policy)
    :module: RestrictedPython

    Compiles source code into interpretable byte code with ``mode='exec'``.
    Use mode ``'exec'`` if the source contains a sequence of statements.
    The meaning and defaults of the parameters are the same as in
    ``compile_restricted``.

    :return: CompileResult (code, errors, warnings, used_names, artifact)

.. py:method:: compile_restricted_eval(source, filename, flags, dont_inherit, policy)
    :module: RestrictedPython

    Compiles source code into interpretable byte code with ``mode='eval'``.
    Use mode ``'eval'`` if the source contains a single expression.
    The meaning and defaults of the parameters are the same as in
    ``compile_restricted``.

    :return: CompileResult (code, errors, warnings, used_names, artifact)

.. py:method:: compile_restricted_single(source, filename, flags, dont_inherit, policy)
    :module: RestrictedPython

    Compiles source code into interpretable byte code with ``mode='eval'``.
    Use mode ``'single'`` if the source contains a single interactive statement.
    The meaning and defaults of the parameters are the same as in
    ``compile_restricted``.

    :return: CompileResult (code, errors, warnings, used_names, artifact)

.. py:method:: compile_restricted_function(p, body, name, filename, globalize=None)
    :module: RestrictedPython

    Compiles source code into interpretable byte code with ``mode='function'``.
    Use mode ``'function'`` for full functions.

    :param p: (required). a string representing the function parameters
    :param body: (required). the function body
    :param name: (required). the function name
    :param filename: (optional). defaults to ``'<string>'``
    :param globalize: (optional). list of globals. defaults to ``None``
    :param flags: (optional). defaults to ``0``
    :param dont_inherit: (optional). defaults to ``False``
    :param policy: (optional). defaults to ``RestrictingNodeTransformer``
    :type p: str
    :type body: str or bytes or bytearray or ``ast.Module`` or ``ast.Expression`` or ``ast.Interactive``
    :type name: str
    :type filename: str or bytes or os.PathLike[typing.Any]
    :type globalize: None or list
    :type flags: int
    :type dont_inherit: int
    :type policy: RestrictingNodeTransformer class
    :return: byte code

    The globalize argument, if specified, is a list of variable names to be
    treated as globals (code is generated as if each name in the list
    appeared in a global statement at the top of the function).
    This allows to inject global variables into the generated function that
    feel like they are local variables, so the programmer who uses this doesn't
    have to understand that his code is executed inside a function scope
    instead of the global scope of a module.

    To actually get an executable function, you need to execute this code and
    pull out the defined function out of the locals like this:

    >>> from RestrictedPython import compile_restricted_function
    >>> compiled = compile_restricted_function('', 'pass', 'function_name')
    >>> safe_locals = {}
    >>> safe_globals = {}
    >>> exec(compiled.code, safe_globals, safe_locals)
    >>> compiled_function = safe_locals['function_name']
    >>> result = compiled_function(*[], **{})

    Then if you want to control the globals for a specific call to this
    function, you can regenerate the function like this:

    >>> my_call_specific_global_bindings = dict(foo='bar')
    >>> safe_globals = safe_globals.copy()
    >>> safe_globals.update(my_call_specific_global_bindings)
    >>> import types
    >>> new_function = types.FunctionType(
    ...     compiled_function.__code__,
    ...     safe_globals,
    ...     '<function_name>',
    ...     compiled_function.__defaults__ or ())
    >>> result = new_function(*[], **{})

reviewable compile artifacts
++++++++++++++++++++++++++++

The ``compile_restricted_*`` helpers return a ``CompileResult`` whose
``artifact`` attribute describes the source and the environment which was
used to compile it.  ``compile_restricted`` can return that result too by
passing ``with_artifact=True`` (or ``return_artifact=True``).

.. code-block:: pycon

    >>> from RestrictedPython import compile_restricted_exec
    >>> from RestrictedPython import RestrictingNodeTransformer
    >>> result = compile_restricted_exec('answer = 42')
    >>> result.artifact.policy
    'RestrictedPython.transformer.RestrictingNodeTransformer'
    >>> summary = result.artifact.to_json()  # deterministic text summary
    >>> 'source_sha256' in summary
    True

The artifact contains a SHA-256 digest of the source plus labels for the
policy, policy version, guard version, language feature settings, compiler
flags and Python/RestrictedPython versions.  It never contains source text,
guard objects, globals, builtins or other host object values.

An approval record is only the textual artifact summary:

.. code-block:: pycon

    >>> from RestrictedPython import create_approval_record, check_approval
    >>> record = create_approval_record(result)
    >>> isinstance(record, str)
    True
    >>> check_approval(record, result).applicable
    True

To decide whether an old approval still applies, pass the same source through
the current compiler and compare the new artifact.  Comparison is purely a
metadata operation and never executes the source:

.. code-block:: pycon

    >>> class OtherPolicy(RestrictingNodeTransformer):
    ...     pass
    >>> current = compile_restricted_exec('answer = 42', policy=OtherPolicy)
    >>> decision = check_approval(record, current)
    >>> decision.applicable
    False
    >>> decision.changed_fields
    ('policy',)

The same mechanism reports ``guard_version``, ``policy_version``,
``language_features``, ``flags``, ``python_version`` and other environment
changes.  Pass ``guard_version=``, ``policy_version=`` and
``language_features=`` to the compile helpers (or supply a
``CompileEnvironment`` through ``environment=``) to record the host's actual
settings.

restricted builtins
+++++++++++++++++++

  * ``safe_globals``
  * ``safe_builtins``
  * ``limited_builtins``
  * ``utility_builtins``

helper modules
++++++++++++++

  * ``PrintCollector``


RestrictingNodeTransformer
++++++++++++++++++++++++++

``RestrictingNodeTransformer`` provides the base policy used by RestrictedPython itself.

It is a subclass of a ``NodeTransformer`` which has a set of ``visit_<AST_Elem>`` methods and a ``generic_visit`` method.

``generic_visit`` is a predefined method of any ``NodeVisitor`` which sequentially visits all sub nodes. In RestrictedPython this behaviour is overwritten to always call a new internal method ``not_allowed(node)``.
This results in an implicit blacklisting of all not allowed AST elements.

Any possibly new introduced AST element in Python (new language element) will implicitly be blocked and not allowed in RestrictedPython.

So, if new elements should be introduced, an explicit ``visit_<new AST elem>`` is necessary.
