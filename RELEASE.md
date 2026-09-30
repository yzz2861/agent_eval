---
release type: minor
social_messages:
  x: >-
    {project_name} {version} is out! This release adds per-event context
    managers for subscriptions, so transactions and DataLoaders no longer have
    to span the whole connection. 🍓 https://strawberry.rocks/release/{version}
  linkedin: >-
    {project_name} {version} is out. This release adds per-event context
    managers for subscriptions, keeping transactions and DataLoaders scoped to
    a single delivered event.
---

This release adds per-event context managers for GraphQL subscriptions.

Schemas can now provide `subscription_event_context_getter`, a callable that
receives the long-lived connection context and a source event and returns a
synchronous or asynchronous context manager. Strawberry enters it before
resolving the event's fields and exits it after the result has been delivered,
before requesting the next source event. This keeps database transactions and
DataLoaders isolated while preserving access to the connection context.
