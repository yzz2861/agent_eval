# Tamper-Evident Audit Logs

Audit logging is explicitly opt-in. Existing `JsonFormatter` output is unchanged;
choose an audit formatter or audit handler only for streams that need an integrity
proof.

## Formatter with an existing logger

`AuditFormatter` is a `JsonFormatter` subclass. It can be attached to any existing
`logging.Handler`:

```python
import logging
from pythonjsonlogger.audit import AuditFormatter, AuditVerifier, AuditAnchor

formatter = AuditFormatter(
    keys={"2026-11": b"rotate-me-after-this-month"},
    key_id="2026-11",
    chain_id="exported-security-log",
)

handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger("security.audit")
logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.info("login failed", extra={"actor": "alice", "event": "login_failed"})
```

Each JSON line contains the original fields plus an `_audit` object with `seq`,
`timestamp`, `prev_digest`, `key_id`, and `hmac`. The JSON is canonical (sorted keys,
no insignificant whitespace), and the digest chain starts from
`AuditAnchor.genesis(chain_id)`.

## File handler and crash recovery

For file output, use `AuditFileHandler`. It serializes sequence assignment, signing,
and writes under one handler lock, and commits the chain head only after the write and
flush succeed. If a flush fails, the buffered records stay pending and are retried with
their existing sequence numbers.

```python
from pythonjsonlogger.audit import AuditFileHandler

handler = AuditFileHandler(
    "/var/log/security.jsonl",
    keys={"2026-11": old_key, "2026-12": new_key},
    key_id="2026-11",
    chain_id="exported-security-log",
    fsync=True,
)
```

On startup the handler verifies the existing file, discards only an incomplete trailing
write, and resumes at the sequence number after the last verified record. Supply every
historical key needed to verify records created before a rotation.

Rotate keys without losing verifiability:

```python
formatter.rotate_key("2026-12", new_key)
```

The old key remains in the ring for verification, and each record records the key ID that
signed it. Key material is redacted from `repr`, `str`, log output, and configuration
errors.

## Independent replay

An auditor needs the JSON lines, the key ring, and a known anchor:

```python
from pythonjsonlogger.audit import AuditVerifier, AuditAnchor

verifier = AuditVerifier(keys={"2026-11": old_key, "2026-12": new_key})
result = verifier.verify_file(
    "exported-security.jsonl",
    anchor=AuditAnchor.genesis("exported-security-log"),
)
print(result.sequence, result.digest)
```

Verification fails on modified content, a removed line, reordered records, a sequence
gap, or records from a different chain spliced into the same stream. Replaying an empty
prefix against an explicit anchor is valid and returns that anchor as the head.
