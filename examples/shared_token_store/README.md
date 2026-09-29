# Shared token store example

Two OAuth 2.0 client instances share one account whose authorization server
**rotates refresh tokens** on every refresh. Without coordination, both
instances would refresh the same refresh token concurrently; the second
request would be rejected (`invalid_grant`) and some providers even
invalidate the whole token family on refresh-token reuse.

This example shows how the optional shared token store protocol
(`authlib.oauth2.token_store`) coordinates the refresh:

* `sqlite_token_store.py` — `SQLiteTokenStore` / `AsyncSQLiteTokenStore`,
  a local SQLite implementation of the protocol (versioned token row +
  expiring lease row). Sync and async clients share the same file and the
  same rules.
* `demo_two_clients.py` — spins up a local token endpoint with rotating
  refresh tokens and a refresh counter, then verifies:

  1. two sync clients perform exactly **one** refresh and converge;
  2. two async clients do the same over the same store;
  3. a crashed coordinator's lease expires and another instance recovers;
  4. a persistence failure after a successful refresh raises
     `TokenPersistenceUncertainError` and is **not** retried automatically;
  5. a client without `token_store` keeps the legacy behavior.

Run from the repository root:

```bash
python examples/shared_token_store/demo_two_clients.py
```
