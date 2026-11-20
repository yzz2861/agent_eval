Sharded artifact verification
=============================

Large release artifacts are often distributed as separate shard files.  The
publisher describes the artifact and all of its shard ranges in a
``ShardManifest``, signs the canonical manifest payload with a DSSE envelope,
and distributes the envelope together with the shards.

``securesystemslib.shard`` provides the receiving side.  It verifies the
manifest signature before touching shard data, verifies each shard by artifact
identity, declared location, offset layout, length and digest, and reports a
complete result or explicit missing byte ranges.

Manifest format
---------------
The manifest payload is canonical JSON and has this form:

.. code-block:: json

   {
     "version": 1,
     "artifact_id": "release.tar",
     "artifact_length": 15,
     "algorithm": "sha256",
     "shards": [
       {
         "index": 0,
         "location": "part-000",
         "offset": 0,
         "length": 4,
         "digest": "sha256 hex digest of these four bytes"
       }
     ]
   }

Shard indexes must be unique and contiguous from zero.  Shard ranges must be
contiguous, non-empty and end exactly at ``artifact_length``.  The manifest is
intentionally complete: a missing shard is missing from the source, not from
the signed manifest.

The DSSE payload type is
``application/vnd.securesystemslib.shard-manifest.v1+json``.  The verifier calls
``Envelope.verify`` before parsing the JSON body.  Signatures and thresholds use
the existing DSSE and signer interfaces.

Receiving with BytesIO
----------------------
The verifier reads only fixed-size chunks, so the complete artifact never has to
be present in memory.  A small BytesIO demonstration looks like this:

.. code-block:: python

   import io

   from securesystemslib import hash as sslib_hash
   from securesystemslib.shard import (
       MemoryShardSource,
       SealedShardManifest,
       Shard,
       ShardManifest,
       ShardVerifier,
   )

   artifact = b"abcdefghijklmno"
   shard_size = 4
   chunks = [
       artifact[i:i + shard_size]
       for i in range(0, len(artifact), shard_size)
   ]

   def descriptor(index, offset, chunk):
       digest = sslib_hash.digest("sha256")
       digest.update(chunk)
       return Shard(
           index=index,
           location=f"part-{index:03d}",
           offset=offset,
           length=len(chunk),
           digest=digest.hexdigest(),
       )

   shards = [
       descriptor(index, index * shard_size, chunk)
       for index, chunk in enumerate(chunks)
   ]
   manifest = ShardManifest(
       artifact_id="release.tar",
       artifact_length=len(artifact),
       shards=tuple(shards),
   )
   sealed = SealedShardManifest.seal(manifest, signer)

   source = MemoryShardSource(
       "release.tar",
       {
           shard.location: io.BytesIO(chunk)
           for shard, chunk in zip(shards, chunks)
       },
   )
   verifier = ShardVerifier([signer.public_key])
   result = verifier.verify(sealed, source)
   result.require_complete()

``MemoryShardSource`` rewinds ``BytesIO`` values before each pass.  A caller
owned stream is not closed by the source.

Resuming from another cache
---------------------------
Keep the same ``ShardVerifier`` and call ``verify`` with another source.  Shards
already verified are reused; only unverified shards are opened and hashed.

.. code-block:: python

   result = verifier.verify(
       sealed,
       MemoryShardSource("release.tar", second_cache_shards),
   )

Every ``ShardReceipt`` contains the manifest ID and the complete shard
descriptor.  A verifier is bound to the first successfully verified manifest.
Presenting a different manifest, including a correctly signed older manifest,
raises ``ManifestMismatchError`` instead of reusing receipts from another
manifest.  ``DirectoryShardSource`` provides the same continuation behavior for
local cache directories.

Failure classification
----------------------
The result keeps these cases separate:

===========================================  =====================================
Condition                                    Result
===========================================  =====================================
Shard location absent                        ``ShardIssueKind.MISSING``
Present but too short                        ``ShardIssueKind.LENGTH_SHORT``
Present but too long                         ``ShardIssueKind.LENGTH_LONG``
Same length, different bytes                 ``ShardIssueKind.DIGEST_MISMATCH``
Content matches another manifest shard       ``ShardIssueKind.MISPLACED``
Different signed manifest                    ``ManifestMismatchError``
Wrong source artifact identity               ``ArtifactIdentityMismatchError``
===========================================  =====================================

``missing_ranges`` contains only absent shards, merged into contiguous
half-open byte ranges.  ``unverified_ranges`` also includes present shards that
failed validation.  A swapped pair is reported as two ``MISPLACED`` issues with
their matching shard indexes, while a truncated final shard is reported as
``LENGTH_SHORT`` and does not appear in ``missing_ranges``.  This prevents
different faults from collapsing into one result.

API reference
-------------
.. autoclass:: securesystemslib.shard.ShardManifest
   :members:

.. autoclass:: securesystemslib.shard.SealedShardManifest
   :members:

.. autoclass:: securesystemslib.shard.ShardVerifier
   :members:

.. autoclass:: securesystemslib.shard.VerificationResult
   :members:

.. autoclass:: securesystemslib.shard.MemoryShardSource
   :members:

.. autoclass:: securesystemslib.shard.DirectoryShardSource
   :members:
