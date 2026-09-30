---
release type: minor
social_messages:
  x: >-
    {project_name} {version} is out! This release adds configurable TTL and
    capacity limits for DataLoader caches in long-lived connections. 🍓
    https://strawberry.rocks/release/{version}
  linkedin: >-
    {project_name} {version} adds configurable TTL and capacity limits for
    DataLoader caches, with separate error caching and injected clocks for
    deterministic tests.
---

This release adds optional TTL and capacity limits for DataLoader results.

DataLoader now accepts `result_ttl`, `max_cache_size`, `cache_exceptions`, and
`time_fn`. Completed results can expire and be evicted in LRU order while
in-flight requests remain protected from capacity eviction. Separate callers
that await the same key can also be cancelled independently without cancelling
the shared batch or other waiting callers.
