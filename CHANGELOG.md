# CHANGELOG

All notable unreleased changes to this project will be documented in this file.

For released versions, see the [Releases](https://github.com/mirumee/ariadne/releases) page.

## Unreleased

- Added `executor` option to `GraphQLHTTPHandler` allowing custom executors that return either `ExecutionResult` (regular JSON response) or `IncrementalExecutionResults` (streamed as `multipart/mixed` response when the client accepts it). Added `Executor`, `IncrementalExecutionResults` and `IncrementalPatch` types.

