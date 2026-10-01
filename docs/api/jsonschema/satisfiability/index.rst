:py:mod:`jsonschema.satisfiability`
================================

.. automodule:: jsonschema.satisfiability
   :members:
   :undoc-members:

Example:

.. testcode::

    from jsonschema import Draft202012Validator, check_satisfiability

    schema = {"type": "integer", "minimum": 2, "maximum": 1}
    result = check_satisfiability(schema)
    assert result.status.value == "contradiction"

    constructible = check_satisfiability({"type": "integer"})
    Draft202012Validator({"type": "integer"}).validate(
        constructible.example,
    )
