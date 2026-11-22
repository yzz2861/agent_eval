Run these examples from the root directory of pycparser.

Please note that most realistic C code samples would require running the C
preprocessor before passing the code to **pycparser**; see the `README file
<https://github.com/eliben/pycparser/blob/main/README.rst>`_ and
`this blog post
<https://eli.thegreenplace.net/2015/on-parsing-c-type-declarations-and-fake-headers>`_
more details.

expr_range_audit.py
-------------------

``expr_range_audit.py`` is a static range audit for a small C integer
expression.  It uses pycparser only to parse the expression; it does not
compile or run firmware.  The caller supplies the target ``int`` width, the
log-field type, and the business interval that the stored field must satisfy.
The report keeps a per-target evidence trace and distinguishes:

* ``PROVEN`` -- the modeled C range is inside the business interval and no
  promotion, wrap, truncation, undefined behaviour, or unknown type weakens
  the result;
* ``PROVEN_BOUNDS_ONLY`` -- the bounds are proven, but a wrap or truncation
  means the logged count is not the mathematical value;
* ``VIOLATED`` -- a concrete witness exists (or the whole range is outside);
* ``INSUFFICIENT`` -- the evidence is not strong enough (for example a
  possible divide by zero or signed overflow);
* ``NEEDS_CONFIRMATION`` -- an unknown type or identifier must be confirmed by
  the caller.

The built-in example compares two maintained boards::

    python examples/expr_range_audit.py

It audits ``(health - baseline) * 10`` with ``health`` in 0..1000 and
``baseline`` fixed at 800, against the business interval [-8000, 2000].
Both fields are ``uint16_t``; the log field is ``int32_t`` on both boards.
The hand check is:

* ``uint16_t`` promotes to ``int`` only if ``int`` can represent 0..65535.
  A 16-bit ``int`` cannot, so ``uint16_t`` promotes to 16-bit
  ``unsigned int``.  A 32-bit ``int`` can, so it promotes to signed ``int``.
* On the 16-bit board, ``0 - 800`` becomes ``64736`` (modulo 65536), then
  ``64736 * 10`` becomes ``57536`` (modulo 65536), outside the interval.
  The tool reports a witness and ``VIOLATED``.
* On the 32-bit board the same expression is ``-8000``, inside the interval.
  The tool reports ``PROVEN``.

A non-default invocation can compare arbitrary targets::

    python examples/expr_range_audit.py \
        --expr "(health - baseline) * 10" \
        --var "health=uint16_t@0..1000" \
        --var "baseline=uint16_t@800..800" \
        --target "board-16=int32_t@16" \
        --target "board-32=int32_t@32" \
        --bounds=-8000..2000

Use ``--type-width`` (or ``--typedef``) to model ABI-dependent names such as
``size_t``.  Unconfirmed names are reported as ``NEEDS_CONFIRMATION`` rather
than guessed.
