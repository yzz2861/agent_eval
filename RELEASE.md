---
release type: minor
social_messages:
  x: >-
    {project_name} {version} is out! This release adds per-event context
    managers for subscriptions, keeping transactions and DataLoaders scoped to
    one delivered event. 🍓 https://strawberry.rocks/release/{version}
  linkedin: >-
    {project_name} {version} is out. This release adds per-event context
    managers for subscriptions so resources are cleaned up after each delivered
    event without being shared with adjacent events.
---

This release adds per-event context managers for subscriptions.

Subscription fields can now provide a sync or async context manager factory
that Strawberry enters for each source event before running that event's
resolvers and exits after delivering its result. Connection context remains
available, event resources are isolated between events, and cancellation,
field errors, early stream closure, and context entry failures follow explicit
cleanup paths.
