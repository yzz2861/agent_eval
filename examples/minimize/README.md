# Session Minimizer Example

A local tool for shrinking captured WebSocket sessions to a minimal sample
that still triggers the same failure. Useful when a protocol bug only
surfaces after dozens of frames.

The library lives in `lib/protocol/websocket/minimize/`:

- `Session` — an immutable description of a captured session: the
  negotiated handshake configuration plus an ordered list of frames, each
  annotated with the role (`client`/`server`) of the endpoint that sent
  it. Sessions load from and save to a single JSON file.
- `Oracle` — wraps your failure predicate with an execution limit, result
  caching, and stability verification. It can call any external command
  (exit status 0 = failure reproduced) or an in-process callable.
- `Shrinker` — reduces the session in three phases: frame removal
  (delta debugging), payload shrinking, and optional-field (RSV flag)
  clearing.
- `Replay` — plays a session file back against real endpoint objects
  through the actual wire format, with no shrinking machinery involved.

## Guarantees

- The handshake configuration and the mask direction of each frame are
  never modified; they are part of the session identity.
- Pinned frames (`"pinned": true`) are never removed or modified.
- Candidates that violate the frame structure rules (e.g. a continuation
  fragment without its prefix fragments) are rejected without spending
  oracle budget, so necessary prefix fragments cannot be dropped.
- The oracle is never executed more than `limit` times.
- If the oracle gives inconsistent answers for the same session, the
  result is reported as `unstable` — never announced as a success.

## The artificial defect

`defective_server.rb` implements a server endpoint with a deterministic,
fully artificial defect: any ping arms a "diagnostic" code path, and the
next completed message containing `BOOM` crashes it. Triggering the
defect therefore requires a prefix frame (the ping) and a specific
payload, possibly spread over several fragments.

`generate.rb` builds a captured 25-frame session in which this trigger
is buried under keepalives, unrelated messages, a fragmented notice, and
trailing traffic.

## Usage

```bash
# Generate the captured session, shrink it, and write minimized.json:
bundle exec ruby run.rb

# Prove the minimized session reproduces the defect on its own:
bundle exec ruby replay.rb minimized.json
```

`run.rb` invokes `oracle.rb` as an external command — the same way you
would plug in your own failing test or fuzzer harness. The oracle limit
can be adjusted with the `LIMIT` environment variable (default: 500).

## Session file format

```json
{
  "handshake": {
    "client_mask": true,
    "server_mask": false,
    "reserved": 4,
    "maximum_frame_size": 4096,
    "extensions": ["x-diagnostic-extension"]
  },
  "frames": [
    {"endpoint": "client", "opcode": 9, "finished": true, "flags": 0, "payload": ""}
  ]
}
```

Payloads are hex-encoded; `mask` (hex) and `pinned` are optional
per-frame fields. Frames sent by an endpoint are masked at replay time
according to the handshake configuration, so the mask direction is always
preserved.

