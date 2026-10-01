# CHANGELOG

All notable unreleased changes to this project will be documented in this file.

For released versions, see the [Releases](https://github.com/mirumee/ariadne/releases) page.

## Unreleased

- Added opt-in JSON batch requests support to the ASGI `GraphQLHTTPHandler` via the `batching_enabled`, `max_batch_size` and `batch_query_concurrency` options. Batch responses contain one result per operation, queries are executed with limited concurrency, mutations serially in order, and subscriptions are rejected.

