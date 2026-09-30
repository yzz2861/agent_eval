.. _fields:

======
Fields
======


Usage
=====

Fields are defined as properties of a ``Model`` class object:

.. code-block:: python3

    from tortoise.models import Model
    from tortoise import fields

    class Tournament(Model):
        id = fields.IntField(primary_key=True)
        name = fields.CharField(max_length=255)


.. rst-class:: emphasize-children

Reference
=========

Here is the list of fields available with custom options of these fields:

Base Field
----------

.. automodule:: tortoise.fields.base
    :members:
    :undoc-members:
    :exclude-members: field_type, indexable, has_db_field, skip_to_python_if_native, allows_generated, function_cast, SQL_TYPE, GENERATED_SQL

Data Fields
-----------

.. automodule:: tortoise.fields.data
    :members:
    :exclude-members: to_db_value, to_python_value

Relational Fields
-----------------

.. automodule:: tortoise.fields.relational
    :members: ForeignKeyField, OneToOneField, ManyToManyField
    :exclude-members: to_db_value, to_python_value

Encrypted Fields
----------------

.. automodule:: tortoise.fields.encrypted
    :members:
    :exclude-members: to_db_value, to_python_value

``EncryptedField`` stores text transparently encrypted at rest. The application
reads and writes plain ``str`` values, while encryption and decryption are
delegated to an application-provided object implementing the
``EncryptionProvider`` protocol. Tortoise itself never implements any
cryptographic algorithm; it only defines the stored envelope
``enc:v<version>:<key_id>:<base64-ciphertext>`` so every value carries the
format version and the key id it was encrypted with.

.. code-block:: python3

    from tortoise import fields
    from tortoise.models import Model

    class Secret(Model):
        id = fields.IntField(primary_key=True)
        # reference the provider by importable identifier:
        payload = fields.EncryptedField(provider="myapp.crypto:provider")

The provider is resolved lazily from the identifier, and migrations record only
that identifier - never any key material. Key rotation is handled by the
provider: new writes always use ``current_key_id``, while old rows are decrypted
with the key id stored in their own envelope, so old keys must remain available
for decryption.

Because randomized ciphertext is not orderable or searchable, ordering,
range comparisons (``gte``/``lt``/...) and fuzzy matching
(``contains``/``startswith``/...) on encrypted fields are rejected with
``FieldError`` when the query is constructed. Only exact matches and null
checks are available as filters.

DB Default Expressions
----------------------

.. automodule:: tortoise.fields.db_defaults
    :members:

DB Specific Fields
------------------

MySQL
^^^^^

.. automodule:: tortoise.contrib.mysql.fields
    :members: GeometryField, UUIDField

Postgres
^^^^^^^^

.. automodule:: tortoise.contrib.postgres.fields
    :members: TSVectorField

Extending A Field
=================

It is possible to subclass fields allowing use of arbitrary types as long as they can be represented in a
database compatible format. An example of this would be a simple wrapper around the :class:`~tortoise.fields.CharField`
to store and query Enum types.

.. code-block:: python3

    from enum import Enum
    from typing import Type

    from tortoise import ConfigurationError
    from tortoise.fields import CharField


    class EnumField(CharField):
        """
        An example extension to CharField that serializes Enums
        to and from a str representation in the DB.
        """

        def __init__(self, enum_type: Type[Enum], **kwargs):
            super().__init__(128, **kwargs)
            if not issubclass(enum_type, Enum):
                raise ConfigurationError("{} is not a subclass of Enum!".format(enum_type))
            self._enum_type = enum_type

        def to_db_value(self, value: Enum, instance) -> str:
            return value.value

        def to_python_value(self, value: str) -> Enum:
            try:
                return self._enum_type(value)
            except Exception:
                raise ValueError(
                    "Database value {} does not exist on Enum {}.".format(value, self._enum_type)
                )

When subclassing, make sure that the ``to_db_value`` returns the same type as the superclass (in the case of CharField,
that is a ``str``) and that, naturally, ``to_python_value`` accepts the same type in the value parameter (also ``str``).
