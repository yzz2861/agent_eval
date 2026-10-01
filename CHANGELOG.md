# CHANGELOG

All notable unreleased changes to this project will be documented in this file.

For released versions, see the [Releases](https://github.com/mirumee/ariadne/releases) page.

## Unreleased

- Added `subscription_authorizer` option to `GraphQLTransportWSHandler` that rechecks authorization of individual subscriptions before each event is sent, and `request_authorization_recheck` method letting the application trigger rechecks on demand. Revoked subscriptions are terminated with an `error` message without closing the websocket connection or affecting other operations.

