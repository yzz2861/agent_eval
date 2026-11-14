API overview
------------

``compile_restricted`` methods
++++++++++++++++++++++++++++++

.. py:method:: compile_restricted(source, filename, mode, flags, dont_inherit, policy, budget)
    :module: RestrictedPython

    Compiles source code into interpretable byte code.

    :param source: (required). the source code that should be compiled
    :param filename: (optional). defaults to ``'<unknown>'``
    :param mode: (optional). Use ``'exec'``, ``'eval'`` or ``'single'``. defaults to ``'exec'``
    :param flags: (optional). defaults to ``0``
    :param dont_inherit: (optional). defaults to ``False``
    :param policy: (optional). defaults to ``RestrictingNodeTransformer``
    :param budget: (optional). defaults to ``DEFAULT_COMPILE_BUDGET``
    :type source: str or bytes or bytearray or ``ast.Module`` or ``ast.Expression`` or ``ast.Interactive``
    :type filename: str or bytes or os.PathLike[typing.Any]
    :type mode: str
    :type flags: int
    :type dont_inherit: int
    :type policy: RestrictingNodeTransformer class
    :type budget: CompileBudget
    :return: Python ``code`` object

Compile budgets
+++++++++++++++

All ``compile_restricted*`` methods accept an optional ``budget`` argument
of type ``CompileBudget``.  It defines limits for the compilation itself:

- ``max_source_length``: length of the source in characters/bytes
- ``max_ast_depth``: nesting depth of the parsed AST
- ``max_ast_nodes``: total number of AST nodes
- ``max_constant_size``: size of ``str``/``bytes`` constants
- ``max_code_size``: summed bytecode size of all produced code objects

Each limit may be set to ``None`` to disable it.  If no budget is given,
``DEFAULT_COMPILE_BUDGET`` is used.

Exceeding a budget raises ``BudgetExceededError``, a subclass of
``SyntaxError`` carrying structured diagnostics: ``resource`` (which
budget), ``limit``, ``actual``, ``phase`` (``'parse'``, ``'transform'``,
``'compile'`` or ``'code_object'``), ``filename``, ``lineno`` and
``col_offset``.  A ``RecursionError`` raised by the interpreter itself
while parsing, transforming or compiling pathological input is converted
into ``BudgetExceededError`` as well, so such input can never crash the
compilation process.

.. py:method:: compile_restricted_exec(source, filename, flags, dont_inherit, policy)
    :module: RestrictedPython

    Compiles source code into interpretable byte code with ``mode='exec'``.
    Use mode ``'exec'`` if the source contains a sequence of statements.
    The meaning and defaults of the parameters are the same as in
    ``compile_restricted``.

    :return: CompileResult (a namedtuple with code, errors, warnings, used_names)

.. py:method:: compile_restricted_eval(source, filename, flags, dont_inherit, policy)
    :module: RestrictedPython

    Compiles source code into interpretable byte code with ``mode='eval'``.
    Use mode ``'eval'`` if the source contains a single expression.
    The meaning and defaults of the parameters are the same as in
    ``compile_restricted``.

    :return: CompileResult (a namedtuple with code, errors, warnings, used_names)

.. py:method:: compile_restricted_single(source, filename, flags, dont_inherit, policy)
    :module: RestrictedPython

    Compiles source code into interpretable byte code with ``mode='eval'``.
    Use mode ``'single'`` if the source contains a single interactive statement.
    The meaning and defaults of the parameters are the same as in
    ``compile_restricted``.

    :return: CompileResult (a namedtuple with code, errors, warnings, used_names)

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
