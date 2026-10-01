.. _async_validation:

Asynchronous validation
=======================

.. versionadded:: 4.4.0

Some validators need to talk to asynchronous services (databases, caches, HTTP
APIs). Schemas may define hooks and validators with ``async def`` and run them
with the asynchronous counterparts of the load API:

- `Schema.aload <marshmallow.Schema.aload>`: asynchronous ``load``
- `Schema.aloads <marshmallow.Schema.aloads>`: asynchronous ``loads``
- `Schema.avalidate <marshmallow.Schema.avalidate>`: asynchronous ``validate``

Methods decorated with `pre_load <marshmallow.decorators.pre_load>`,
`post_load <marshmallow.decorators.post_load>`,
`validates <marshmallow.decorators.validates>`, and
`validates_schema <marshmallow.decorators.validates_schema>` may be coroutine
functions. Synchronous and asynchronous hooks may be mixed freely; the
execution order of the pipeline (pre_load, deserialization, field validators,
schema validators, post_load) is unchanged.

.. code-block:: python

    import asyncio

    from marshmallow import Schema, fields, validates, ValidationError


    async def is_taken(username: str) -> bool:
        # Some asynchronous service call, e.g. a database query
        await asyncio.sleep(0)
        return username == "taken"


    class UserSchema(Schema):
        name = fields.Str(required=True)

        @validates("name")
        async def check_name_available(self, value, **kwargs):
            if await is_taken(value):
                raise ValidationError("Name is already taken.")


    schema = UserSchema()
    data = asyncio.run(schema.aload({"name": "monty"}))

Asynchronous callables may also be passed to the ``validate``, ``pre_load``,
and ``post_load`` parameters of a `Field <marshmallow.fields.Field>`, and
nested schemas with asynchronous hooks are awaited transparently, preserving
error positions for nested data and collections (``many=True``).

Independent work items (items of a collection, fields, field validators) are
run concurrently. Concurrency is bounded by the ``max_concurrency`` parameter,
which defaults to ``marshmallow.schema.DEFAULT_MAX_CONCURRENCY``.

.. code-block:: python

    data = asyncio.run(schema.aload(items, many=True, max_concurrency=8))

If the surrounding task is cancelled, validations that are still running are
cancelled and awaited, so no background tasks are left behind.

The synchronous `Schema.load <marshmallow.Schema.load>`,
`Schema.loads <marshmallow.Schema.loads>`, and
`Schema.validate <marshmallow.Schema.validate>` methods cannot run
asynchronous hooks and raise a `ValueError` if a schema defines any.

