---
release type: minor
social_messages:
  x: >-
    {project_name} {version} is out! This release adds configurable persisted
    queries with automatic registration and manifest-only production support. 🍓
    https://strawberry.rocks/release/{version}
  linkedin: >-
    {project_name} {version} is out. This release adds configurable persisted
    queries, including automatic SHA-256 registration and manifest-only
    production allow lists.
---

This release adds configurable persisted queries for Strawberry HTTP views.

Servers can cache valid query texts after the standard persisted-query miss and
retry flow, or accept only a preloaded manifest in production. Cache entries are
bound to schema versions, bounded by entry count and document size, and every
request still validates its current operation selection, variables, and HTTP
method.
