aiosqlite\: Sqlite for AsyncIO
==============================

.. image:: https://readthedocs.org/projects/aiosqlite/badge/?version=latest
   :target: https://aiosqlite.omnilib.dev/en/latest/?badge=latest
   :alt: Documentation Status
.. image:: https://img.shields.io/pypi/v/aiosqlite.svg
   :target: https://pypi.org/project/aiosqlite
   :alt: PyPI Release
.. image:: https://img.shields.io/badge/change-log-blue
   :target: https://github.com/omnilib/aiosqlite/blob/master/CHANGELOG.md
   :alt: Changelog
.. image:: https://img.shields.io/pypi/l/aiosqlite.svg
   :target: https://github.com/omnilib/aiosqlite/blob/master/LICENSE
   :alt: MIT Licensed

aiosqlite provides a friendly, async interface to sqlite databases.

It replicates the standard ``sqlite3`` module, but with async versions
of all the standard connection and cursor methods, plus context managers for
automatically closing connections and cursors:

.. code-block:: python

    async with aiosqlite.connect(...) as db:
        await db.execute("INSERT INTO some_table ...")
        await db.commit()

        async with db.execute("SELECT * FROM some_table") as cursor:
            async for row in cursor:
                ...

It can also be used in the traditional, procedural manner:

.. code-block:: python

    db = await aiosqlite.connect(...)
    cursor = await db.execute('SELECT * FROM some_table')
    row = await cursor.fetchone()
    rows = await cursor.fetchall()
    await cursor.close()
    await db.close()

aiosqlite also replicates most of the advanced features of ``sqlite3``:

.. code-block:: python

    async with aiosqlite.connect(...) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('SELECT * FROM some_table') as cursor:
            async for row in cursor:
                value = row['column']

        await db.execute('INSERT INTO foo some_table')
        assert db.total_changes > 0


Install
-------

aiosqlite is compatible with Python 3.8 and newer.
You can install it from PyPI:

.. code-block:: console

    $ pip install aiosqlite


Details
-------

aiosqlite allows interaction with SQLite databases on the main AsyncIO event
loop without blocking execution of other coroutines while waiting for queries
or data fetches.  It does this by using a single, shared thread per connection.
This thread executes all actions within a shared request queue to prevent
overlapping actions.

Connection objects are proxies to the real connections, contain the shared
execution thread, and provide context managers to handle automatically closing
connections.  Cursors are similarly proxies to the real cursors, and provide
async iterators to query results.

Query helpers accept an optional per-operation ``timeout``. The deadline starts
when the operation is queued. If it expires before the worker starts the
operation, that operation is skipped entirely. If SQLite is already executing
the operation, aiosqlite interrupts that operation and waits for SQLite to
return before raising ``asyncio.TimeoutError``. Cancelling the awaiting task
follows the same rules, so a late cancellation cannot interrupt a later
operation on the same connection.

.. code-block:: python

    try:
        await db.execute(long_query, timeout=1.0)
    except asyncio.TimeoutError:
        # The interrupted statement has stopped, but the connection and its
        # transaction remain available.
        await db.rollback()


License
-------

aiosqlite is copyright `Amethyst Reese <https://noswap.com>`_, and licensed under the
MIT license.  I am providing code in this repository to you under an open source
license.  This is my personal repository; the license you receive to my code
is from me and not from my employer. See the `LICENSE`_ file for details.

.. _LICENSE: https://github.com/omnilib/aiosqlite/blob/master/LICENSE
