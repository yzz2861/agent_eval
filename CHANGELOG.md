# CHANGELOG

All notable unreleased changes to this project will be documented in this file.

For released versions, see the [Releases](https://github.com/mirumee/ariadne/releases) page.

## Unreleased

- Added `TransactionExtension` that wraps mutation operations in application-provided transactions, committing them only when execution completes without errors and rolling them back on errors, interruptions or cancellations. Added `operation_started` and `operation_finished` hooks to `Extension` base class and `Transaction` and `TransactionFactory` types.

