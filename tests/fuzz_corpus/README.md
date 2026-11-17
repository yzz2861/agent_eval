# Fuzz corpus

Regression samples produced by the standard-library-only fuzzing harness in
`tests/fuzz/fuzzing.py`. Each `*.json` file is a self-describing record:

- `target`: one of `jws_compact`, `jws_json`, `jwe_compact`, `jwe_json`,
  `jwk_dict`, or `jwk_raw`.
- `kind` / `exception`: the unexpected outcome observed on the unpatched code.
- `iteration` / `seed`: the deterministic fuzzing coordinates that produced it.
- `payload`: the mutated input. Byte payloads are encoded as
  `bytes::b64::<base64>`; JSON payloads are stored inline.

The samples cover malformed JWS/JWE JSON serializations (wrong-typed top-level
input, payload, signature and recipient containers, invalid base64url headers
and segments). Before the parser hardening they escaped as unhandled
`AttributeError`/`TypeError`/`Error`; they must now always return or raise a
controlled `joserfc` error. `tests/fuzz/test_fuzzing.py` replays every file.

Regenerate / extend the corpus with:

```bash
python tests/fuzz/fuzzing.py --iterations 5000 --seed 20261117
```
