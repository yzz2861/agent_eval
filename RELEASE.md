---
release type: minor
social_messages:
  x: >-
    {project_name} {version} adds configurable persisted queries, including
    Automatic Persisted Queries and manifest-only production mode. 🍓
    https://strawberry.rocks/release/{version}
  linkedin: >-
    {project_name} {version} adds configurable persisted queries. Clients can
    register operation hashes automatically, while production deployments can
    restrict HTTP requests to a pre-approved query manifest.
---

This release adds configurable persisted queries.

Strawberry now supports Automatic Persisted Queries through
`extensions.persistedQuery.sha256Hash`, including the hash-miss retry flow.
It also supports a manifest-only mode that rejects unlisted operation text.

Persisted query entries are scoped to a schema version, limited by entry count
and operation size, and hash mismatches or syntactically invalid operations
are not cached. Each request still validates its operation name, variables,
and HTTP operation type, so cached mutations cannot execute through GET
requests.
