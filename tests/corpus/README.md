# COSE decoder regression corpus

Each `*.hex` file contains one hex-encoded byte string (a single line, no
`0x` prefix). The samples are replayed by `tests/test_fuzz_decode.py` against
`CoseMessage.decode`, `Sign1Message.decode`, `Enc0Message.decode`,
`Mac0Message.decode`, and `CoseKey.decode`.

Every sample must make the decoders return an object or raise
`pycose.exceptions.CoseException`. A sample named `reject_*` additionally has
to exercise at least one rejection path.

New samples can be captured from the deterministic mutation run with:

```sh
PYCOSE_FUZZ_SAVE_CORPUS=1 pytest tests/test_fuzz_decode.py
```

The fuzz seed, iteration count, and per-input timeout are configurable through
`PYCOSE_FUZZ_SEED`, `PYCOSE_FUZZ_ITERATIONS`, and `PYCOSE_FUZZ_TIMEOUT`.
