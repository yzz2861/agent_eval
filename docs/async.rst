Async Loading and Validation
=============================

Some validators need to call asynchronous code, for example checking a value
against a database or another service over the network. `Schema.load` and
`Schema.validate` remain synchronous, but every step of the load pipeline also
has an explicit asynchronous counterpart:

- `Schema.aload` (corresponding to `Schema.load`),
- `Schema.aloads` (corresponding to `Schema.loads`),
- `Schema.avalidate` (corresponding to `Schema.validate`).

These are coroutine methods: ``await`` them from your own ``async`` code.

.. code-block:: python

    import asyncio

    from marshmallow import (
        Schema,
        ValidationError,
        fields,
        post_load,
        pre_load,
        validates,
        validates_schema,
    )


    class UserSchema(Schema):
        async def check_unique_name(value):
            await asyncio.sleep(0)  # e.g. a database/HTTP request
            if value == "taken":
                raise ValidationError("Name is already taken.")

        # an async field validator
        name = fields.Str(validate=check_unique_name)

        @validates("name")
        async def check_name_too(self, value, **kwargs):
            ...

        @validates_schema
        async def cross_field_check(self, data, **kwargs):
            ...

        @pre_load
        async def unwrap(self, data, **kwargs):
            return data

        @post_load
        async def make_object(self, data, **kwargs):
            return data

    schema = UserSchema()

    result = asyncio.run(schema.aload({"name": "alice"}))
    errors = asyncio.run(schema.avalidate({"name": "taken"}))

Supported steps
---------------

The asynchronous pipeline runs the same stages, in the same order, as the
synchronous one:

1. ``pre_load`` schema hooks,
2. field deserialization (including field-level ``pre_load`` functions),
3. field validators and ``@validates`` hooks,
4. ``@validates_schema`` hooks,
5. ``post_load`` schema hooks (and field-level ``post_load`` functions run as
   part of step 2).

Any of these may be a regular synchronous callable or an ``async def``
function; the two can be freely mixed. ``marshmallow.validate.And`` accepts
async validators too and still combines every error message.

Nested schemas and collections
------------------------------

Async processing propagates through `Nested <marshmallow.fields.Nested>`,
`List <marshmallow.fields.List>`, `Tuple <marshmallow.fields.Tuple>`, and
`Dict <marshmallow.fields.Dict>` fields, including ``many=True``. Error
messages land at exactly the same field/index locations as with synchronous
loading. A nested schema may itself define async validators or hooks; its
parent schema then requires ``aload`` as well.

Concurrency
-----------

Independent work is awaited concurrently: the fields of a single object, and
the items of a collection, do not depend on each other. Dependent stages (the
steps listed above, and hooks that transform data for the next step) still run
in their usual order.

The number of validations that may run at the same time is bounded so that a
large payload cannot start an unbounded number of requests at once. Override
``Schema.ASYNC_CONCURRENCY`` to change the limit (default: 32). The bound is
shared across the whole load run, including nested schemas.

.. code-block:: python

    class MySchema(Schema):
        ASYNC_CONCURRENCY = 8

        # ...

Cancellation
------------

Cancelling the task that awaits ``aload``/``avalidate`` cancels every
validation started by that load run and waits for the cancellations to settle.
No background task keeps running after the load finishes or is cancelled.

Synchronous loading
-------------------

The synchronous API is unchanged. Calling `Schema.load`, `Schema.loads`, or
`Schema.validate` on a schema that defines asynchronous validators or load
hooks (including inside nested schemas) raises ``RuntimeError`` with a clear
message instead of silently returning a coroutine as a field value. Use
``aload``/``avalidate`` for those schemas.
