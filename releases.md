# Releases

## v0.22.0

  - Add an explicit `role:` (`:client`/`:server`) option to `Connection` and `Framer` which strictly enforces RFC 6455 masking: client frames must be masked and server frames must not be masked. The role is no longer guessed from the outgoing mask configuration.
  - Unify header validation for incoming frames: FIN on control frames, control frame payload length, reserved opcodes, non-minimal/overflowing length encodings, and RSV bits that were not negotiated by an extension. All of these are detected before the (potentially huge) payload is read.
  - Report a `1009` (`MESSAGE_TOO_LARGE`) close code for oversized payloads; structural protocol errors remain `1002` (`PROTOCOL_ERROR`). The code is available on `ProtocolError#code`.
  - Keep the previous behaviour available as legacy mode: omit `role:` to disable masking enforcement (structural validation still applies).

## v0.21.2

  - Fix JSON 3 compatibility by applying `symbolize_names` only when parsing incoming messages. `Coder::JSON` is now a module with fixed parsing and generation behavior; pass a different coder to customize serialization.

## v0.21.1

  - If `Connection#close_write` fails, the connection will now be fully closed to prevent hanging connections.

## v0.21.0

  - All frame reading and writing logic has been consolidated into `Framer` to improve performance.

## v0.20.2

  - Fix error messages for `Frame` to be more descriptive.

## v0.20.1

  - Revert masking enforcement option introduced in v0.20.0 due to compatibility issues.

## v0.20.0

  - Introduce option `requires_masking` to `Framer` for enforcing masking on received frames.

## v0.19.1

  - Ensure ping reply payload is packed correctly.

## v0.19.0

  - Default to empty string for message buffer when no data is provided.

## v0.18.0

  - Add `PingMessage` alongside `TextMessage` and `BinaryMessage` for a consistent message interface.
  - Remove `JSONMessage` (use application-level encoding instead).

## v0.17.0

  - Introduce `#close_write` and `#shutdown` methods on `Connection` for more precise connection lifecycle control.

## v0.16.0

  - Move `#send` logic into `Message` for better encapsulation.
  - Improve error handling when a `nil` message is passed.

## v0.15.0

  - Require `Message` class by default.
