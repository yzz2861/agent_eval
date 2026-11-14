
JWE API
^^^^^^^

.. automodule:: jose.jwe
   :members:

Decompression Budgets
---------------------

Tokens using the ``zip`` header are decompressed through a per-call
:class:`jose.JWEBudget`. The budget limits the compact token size, the
decompressed byte count, the accepted compression ratio, and -- when using
:func:`jose.jwe.decrypt_json` -- the nesting depth and number of containers in
the decompressed JSON. Decompression is streamed in bounded chunks, so a small
compression bomb is rejected without the expanded payload ever being held in
memory.

Defaults are conservative and always enabled; callers may tighten them but
cannot set a limit to zero, negative or infinite.

.. code:: python

        >>> from jose import JWEBudget, jwe
        >>> budget = JWEBudget(max_decompressed_size=8192, max_compression_ratio=25)
        >>> jwe.decrypt(token, key, budget=budget)

Failures are split into three categories, none of which include plaintext
fragments: ``JWEPolicyError`` for exceeded budgets, ``JWEDecompressError`` for
unknown algorithms, truncated streams or trailing data, and
``JWEPayloadError`` for JSON that cannot be parsed.
