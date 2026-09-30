---
release type: minor
social_messages:
  x: >-
    {project_name} {version} is out! This release adds configurable TTL and
    capacity limits for DataLoader caches. 🍓
    https://strawberry.rocks/release/{version}
  linkedin: >-
    {project_name} {version} is out. This release adds optional TTL and
    completed-entry capacity limits for DataLoader caches, along with separate
    exception caching and isolated waiter cancellation.
---

This release adds configurable expiration and capacity limits for DataLoader's
default cache.

DataLoaders now accept `cache_ttl` and `cache_max_entries` to bound long-lived
caches, while in-flight loads remain protected and continue to coalesce
duplicate keys within a batch. Exception caching can be disabled with
`cache_exceptions=False`, and TTL checks accept an injectable `time_func` for
deterministic tests.

Clear and forced prime operations are protected against late in-flight batch
results, and cancelling one caller no longer cancels other callers waiting for
the same key.
