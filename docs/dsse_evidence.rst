Offline DSSE verification evidence
===================================

``Envelope.verify()`` can optionally export a self-describing evidence
document for later offline verification::

    envelope.verify(
        [public_key],
        threshold=1,
        artifact=artifact_bytes,
        artifact_name="artifact.txt",
        evidence="evidence.json",
    )

The same document can be produced without raising on a failed conclusion::

    evidence = envelope.verify_with_evidence(
        [public_key],
        threshold=1,
        artifact=artifact_bytes,
    )
    evidence.write("evidence.json")

Sealing records:

* the exact ``DSSEv1`` pre-authentication encoding (PAE) bytes, payload type,
  payload length, and PAE digest;
* the artifact digest and size that the verification input refers to;
* the key id, key type, scheme, public key material, and backend for every
  signer whose signature was checked.

Only public material is serialized. Private key material is rejected.

Re-verification
---------------

Callers provide the key or certificate material. Embedded public key material
is not trusted unless ``allow_embedded_keys=True`` is explicitly requested.
The recorded algorithm is used as-is; a missing recorded scheme is reported as
``unverifiable`` and is never replaced with a library default::

    from securesystemslib.dsse import verify_evidence

    report = verify_evidence(
        "evidence.json",
        keys=[public_key],
        artifact=artifact_bytes,
    )
    report.raise_for_status()

``report.status`` is one of:

``verified``
    The artifact and signature input were recomputed and the threshold was
    reached.

``rejected``
    Recomputing was possible, but the artifact digest, exact PAE bytes, or a
    signature did not verify.

``unverifiable``
    The sealed conclusion cannot be recomputed, for example because key
    material is missing or a verifier backend is retired. The sealed
    per-signer conclusion is preserved under ``preservedConclusions``.

Use ``disabled_backends``, ``disabled_algorithms``, or ``backend_status`` to
model a backend that is no longer available. Use ``certificates`` to supply
X.509 certificates instead of key objects.

Exchange samples
----------------

Two complete bundles live in ``examples/offline_dsse``. The first still
verifies after its outer JSON is reformatted. The second changes exactly one
artifact byte and is explicitly rejected with ``artifact-digest-mismatch``.
