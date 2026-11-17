# Decoder fuzz corpus

Each `*.cbor` file is a minimized payload for
`tests/fuzzers/random_bytes_fuzzer.py`.  The matching `*.json` file records
the expected result:

* `"outcome": "ok"` means `loads()` must return without raising.
* `"outcome": "error"` means `loads()` must raise `CBORDecodeError` (or its
  `CBORDecodeEOF` subclass).  `"exception"` pins the exact exception class and
  `"match"` pins a fragment of the message.
* `"outcome": "unexpected"` is used for a minimized failure found by a fuzz
  campaign.  The replay test keeps it as a strict `xfail` until it is fixed.

`"kwargs"` is passed to `loads()` when replaying the case.  `"category"`
documents which part of the decoder the case exercises.
