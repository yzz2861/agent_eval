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

Encrypted Fields
----------------

The :class:`~tortoise.fields.EncryptedTextField` stores ciphertext in a ``TEXT``
column while the application keeps reading and writing ordinary ``str`` values.
Tortoise does not implement any cryptography itself: the application provides a
provider that performs the actual encryption and decryption, and registers it
at startup:

.. code-block:: python3

    from tortoise import fields, Model
    from tortoise.fields import register_encryption_provider

    class KMSProvider:
        provider_id = "myapp.kms"
        current_key_id = "2026-01"

        def encrypt(self, plaintext: str, *, key_id: str | None = None) -> str:
            # Call your KMS / crypto library here. Return ciphertext as a string.
            ...

        def decrypt(self, ciphertext: str, *, key_id: str) -> str:
            # The key_id comes from the stored value, so rotated keys still work.
            ...

    register_encryption_provider(KMSProvider())

    class Account(Model):
        id = fields.IntField(primary_key=True)
        ssn = fields.EncryptedTextField("myapp.kms")

Stored values carry an envelope version and the id of the key that produced
them (``enc::v1::<key_id>::<ciphertext>``). On read the field asks the provider
to decrypt with the **key id embedded in that row**; rows written with an old
key keep working after rotation as long as the provider can still decrypt with
that key. Every new write (``save``, queryset ``update``, ``bulk_create``)
uses the provider's ``current_key_id``. Values that already carry the envelope
are passed through unchanged, so raw database values are never encrypted a
second time.

Because the ciphertext is randomized, content-based queries cannot be answered
against the plaintext. Ordering, ``contains``/``startswith``/``endswith``,
case-insensitive match, range comparisons (``gt``/``gte``/``lt``/``lte``/
``range``), exact match (``=``) and ``in`` raise ``FieldError`` while the query
is being built instead of returning misleading results; only ``__isnull`` is
available. Look encrypted rows up through a separate non-encrypted identifier.

Migrations only record the provider identifier (``provider="myapp.kms"``),
never keys or key material.

.. automodule:: tortoise.fields.encrypted
    :members:

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
