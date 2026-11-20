"""Tests for sharded artifact manifest verification."""

import hashlib
import io
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import VerificationError
from securesystemslib.shard import (
    MANIFEST_PAYLOAD_TYPE,
    ArtifactIdentityMismatchError,
    DirectoryShardSource,
    ManifestMismatchError,
    MemoryShardSource,
    SealedShardManifest,
    Shard,
    ShardIssueKind,
    ShardManifest,
    ShardManifestError,
    ShardNotFoundError,
    ShardSourceError,
    ShardVerifier,
)
from securesystemslib.signer import CryptoSigner

PEMS_DIR = Path(__file__).parent / "data" / "pems"
ARTIFACT_ID = "release.tar"


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_manifest(
    data: bytes, shard_size: int, artifact_id: str = ARTIFACT_ID
) -> tuple[ShardManifest, dict[str, bytes]]:
    shards = []
    chunks = {}
    for index, start in enumerate(range(0, len(data), shard_size)):
        chunk = data[start : start + shard_size]
        location = f"part-{index:03d}"
        shards.append(
            Shard(
                index=index,
                location=location,
                offset=start,
                length=len(chunk),
                digest=_digest(chunk),
            )
        )
        chunks[location] = chunk

    manifest = ShardManifest(
        artifact_id=artifact_id,
        artifact_length=len(data),
        shards=tuple(shards),
    )
    return manifest, chunks


class _TrackingSource:
    """A shard source that records which locations the verifier opens."""

    def __init__(self, artifact_id: str, shards: dict[str, bytes]):
        self.artifact_id = artifact_id
        self.shards = shards
        self.opened: list[str] = []

    @contextmanager
    def open(self, location: str):
        self.opened.append(location)
        try:
            data = self.shards[location]
        except KeyError as e:
            raise ShardNotFoundError(f"Missing shard: {location}") from e
        with io.BytesIO(data) as stream:
            yield stream


class _GuardedBytesIO(io.BytesIO):
    """A BytesIO that rejects unbounded reads."""

    def __init__(self, data: bytes, max_read_size: int):
        super().__init__(data)
        self.max_read_size = max_read_size
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        if size < 0 or size > self.max_read_size:
            raise AssertionError(f"Unexpected read size: {size}")
        self.read_sizes.append(size)
        return super().read(size)


class TestShardManifest(unittest.TestCase):
    def test_roundtrip_and_canonical_encoding(self):
        manifest, _ = _make_manifest(b"abcdefghijklmno", 4)

        encoded = manifest.to_bytes()
        parsed = ShardManifest.from_bytes(encoded)

        self.assertEqual(manifest, parsed)
        self.assertEqual(encoded, parsed.to_bytes())
        self.assertEqual(manifest.fingerprint, _digest(encoded))

    def test_rejects_duplicate_json_fields(self):
        payload = (
            b'{"version":1,"version":1,"artifact_id":"a",'
            b'"artifact_length":0,"algorithm":"sha256","shards":[]}'
        )

        with self.assertRaises(ShardManifestError):
            ShardManifest.from_bytes(payload)

    def test_rejects_gap_in_shard_offsets(self):
        with self.assertRaises(ShardManifestError):
            ShardManifest(
                artifact_id=ARTIFACT_ID,
                artifact_length=8,
                shards=(
                    Shard(0, "part-0", 0, 4, _digest(b"abcd")),
                    Shard(1, "part-1", 5, 3, _digest(b"efg")),
                ),
            )

    def test_rejects_unknown_fields(self):
        manifest, _ = _make_manifest(b"abcd", 4)
        data = manifest.to_dict()
        data["unexpected"] = True

        with self.assertRaises(ShardManifestError):
            ShardManifest.from_dict(data)


class TestShardVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = PEMS_DIR / "ed25519_private.pem"
        private_key = load_pem_private_key(path.read_bytes(), None)
        cls.signer = CryptoSigner(private_key)
        cls.keys = [cls.signer.public_key]

    def _sealed(self, manifest: ShardManifest) -> SealedShardManifest:
        return SealedShardManifest.seal(manifest, self.signer)

    def test_complete_verification_with_bytesio(self):
        data = b"abcdefghijklmno"
        manifest, chunks = _make_manifest(data, 4)
        sealed = self._sealed(manifest)
        max_read_size = 2
        streams = {
            location: _GuardedBytesIO(chunk, max_read_size=max_read_size)
            for location, chunk in chunks.items()
        }
        source = MemoryShardSource(ARTIFACT_ID, streams)

        verifier = ShardVerifier(self.keys, chunk_size=max_read_size)
        result = verifier.verify(sealed, source)

        self.assertTrue(result.complete)
        self.assertEqual(result.verified_indices, (0, 1, 2, 3))
        self.assertEqual(result.issues, ())
        self.assertEqual(result.missing_ranges, ())
        self.assertEqual(result.unverified_ranges, ())
        self.assertEqual(result.checked_bytes, len(data))
        self.assertEqual(result.manifest_id, sealed.manifest_id)
        for receipt in result.receipts:
            self.assertEqual(receipt.manifest_id, sealed.manifest_id)
            self.assertEqual(receipt.artifact_id, ARTIFACT_ID)

        for stream in streams.values():
            self.assertTrue(stream.read_sizes)
            self.assertTrue(all(size <= max_read_size for size in stream.read_sizes))

    def test_manifest_signature_is_checked_before_source_access(self):
        manifest, chunks = _make_manifest(b"abcdefgh", 4)
        sealed = self._sealed(manifest)
        sealed.envelope.payload += b"tampered"
        source = _TrackingSource(ARTIFACT_ID, chunks)

        with self.assertRaises(VerificationError):
            ShardVerifier(self.keys).verify(sealed, source)

        self.assertEqual(source.opened, [])

    def test_for_manifest_binds_only_after_signature_check(self):
        manifest, chunks = _make_manifest(b"abcdefgh", 4)
        sealed = self._sealed(manifest)
        sealed.envelope.payload += b"tampered"
        source = _TrackingSource(ARTIFACT_ID, chunks)
        verifier = ShardVerifier.for_manifest(sealed, self.keys)

        with self.assertRaises(VerificationError):
            verifier.verify(source)

        self.assertIsNone(verifier.manifest_id)
        self.assertEqual(source.opened, [])

    def test_missing_shards_report_explicit_ranges(self):
        manifest, chunks = _make_manifest(b"abcdefghijklmno", 4)
        sealed = self._sealed(manifest)
        del chunks["part-002"]
        del chunks["part-003"]
        source = MemoryShardSource(ARTIFACT_ID, chunks)

        result = ShardVerifier(self.keys).verify(sealed, source)

        self.assertFalse(result.complete)
        self.assertEqual(result.missing_indices, (2, 3))
        self.assertEqual(len(result.missing_ranges), 1)
        self.assertEqual(result.missing_ranges[0].start, 8)
        self.assertEqual(result.missing_ranges[0].end, 15)
        self.assertEqual(result.missing_ranges[0].shard_indices, (2, 3))
        self.assertEqual(result.unverified_ranges, result.missing_ranges)
        self.assertTrue(
            all(issue.kind is ShardIssueKind.MISSING for issue in result.issues)
        )

    def test_resume_after_switching_source(self):
        data = b"abcdefghijklmno"
        manifest, chunks = _make_manifest(data, 4)
        sealed = self._sealed(manifest)
        first_chunks = {
            location: chunk
            for location, chunk in chunks.items()
            if location in ("part-000", "part-001")
        }
        second_chunks = {
            location: chunk
            for location, chunk in chunks.items()
            if location in ("part-002", "part-003")
        }
        first = _TrackingSource(ARTIFACT_ID, first_chunks)
        second = _TrackingSource(ARTIFACT_ID, second_chunks)
        verifier = ShardVerifier(self.keys)

        first_result = verifier.verify(sealed, first)
        second_result = verifier.verify(second)

        self.assertFalse(first_result.complete)
        self.assertEqual(first.opened, ["part-000", "part-001", "part-002", "part-003"])
        self.assertTrue(second_result.complete)
        self.assertEqual(second.opened, ["part-002", "part-003"])
        self.assertEqual(second_result.reused, (0, 1))
        self.assertEqual(second_result.newly_verified, (2, 3))
        self.assertEqual(second_result.checked_bytes, 7)
        self.assertTrue(
            all(
                receipt.manifest_id == sealed.manifest_id
                for receipt in verifier.receipts
            )
        )

    def test_replayed_manifest_is_rejected(self):
        new_manifest, new_chunks = _make_manifest(b"new-release-data", 4)
        old_manifest, old_chunks = _make_manifest(b"old-release-data", 3, ARTIFACT_ID)
        new_sealed = self._sealed(new_manifest)
        old_sealed = self._sealed(old_manifest)

        verifier = ShardVerifier(self.keys)
        result = verifier.verify(new_sealed, MemoryShardSource(ARTIFACT_ID, new_chunks))
        self.assertTrue(result.complete)

        with self.assertRaises(ManifestMismatchError) as context:
            verifier.verify(old_sealed, MemoryShardSource(ARTIFACT_ID, old_chunks))

        self.assertEqual(context.exception.expected_manifest_id, new_sealed.manifest_id)
        self.assertEqual(context.exception.actual_manifest_id, old_sealed.manifest_id)
        self.assertEqual(verifier.manifest_id, new_sealed.manifest_id)

    def test_swapped_shards_are_misplaced_not_missing(self):
        manifest, chunks = _make_manifest(b"abcdefghijklmno", 4)
        sealed = self._sealed(manifest)
        chunks["part-000"], chunks["part-001"] = (
            chunks["part-001"],
            chunks["part-000"],
        )
        source = MemoryShardSource(ARTIFACT_ID, chunks)

        result = ShardVerifier(self.keys).verify(sealed, source)

        self.assertFalse(result.complete)
        self.assertEqual(result.misplaced_indices, (0, 1))
        self.assertEqual(result.missing_indices, ())
        self.assertEqual(result.missing_ranges, ())
        self.assertEqual(result.short_indices, ())
        self.assertEqual(result.unverified_ranges[0].shard_indices, (0, 1))
        for issue in result.issues:
            self.assertEqual(issue.kind, ShardIssueKind.MISPLACED)
        matches = {issue.shard_index: issue.matches_index for issue in result.issues}
        self.assertEqual(matches, {0: 1, 1: 0})

    def test_swapped_shards_with_different_lengths(self):
        manifest, chunks = _make_manifest(b"abcdefghijklmno", 4)
        sealed = self._sealed(manifest)
        chunks["part-000"], chunks["part-003"] = (
            chunks["part-003"],
            chunks["part-000"],
        )
        source = MemoryShardSource(ARTIFACT_ID, chunks)

        result = ShardVerifier(self.keys).verify(sealed, source)

        self.assertEqual(result.misplaced_indices, (0, 3))
        self.assertEqual(result.missing_indices, ())
        self.assertEqual(
            {issue.shard_index: issue.matches_index for issue in result.issues},
            {0: 3, 3: 0},
        )

    def test_truncated_last_shard_is_not_missing(self):
        manifest, chunks = _make_manifest(b"abcdefghijklmno", 4)
        sealed = self._sealed(manifest)
        chunks["part-003"] = chunks["part-003"][:-1]
        source = MemoryShardSource(ARTIFACT_ID, chunks)

        result = ShardVerifier(self.keys).verify(sealed, source)

        self.assertFalse(result.complete)
        self.assertEqual(result.short_indices, (3,))
        self.assertEqual(result.missing_indices, ())
        self.assertEqual(result.missing_ranges, ())
        self.assertEqual(
            result.unverified_ranges[0].shard_indices,
            (3,),
        )
        self.assertEqual(result.unverified_ranges[0].start, 12)
        self.assertEqual(result.unverified_ranges[0].end, 15)
        self.assertEqual(result.issues[0].kind, ShardIssueKind.LENGTH_SHORT)
        self.assertEqual(result.issues[0].actual_length, 2)

    def test_oversized_last_shard_is_length_long(self):
        manifest, chunks = _make_manifest(b"abcdefghijklmno", 4)
        sealed = self._sealed(manifest)
        chunks["part-003"] += b"x"
        source = MemoryShardSource(ARTIFACT_ID, chunks)

        result = ShardVerifier(self.keys).verify(sealed, source)

        self.assertEqual(result.short_indices, ())
        self.assertEqual(result.issues[0].kind, ShardIssueKind.LENGTH_LONG)
        self.assertEqual(result.issues[0].actual_length, 4)

    def test_artifact_identity_mismatch(self):
        manifest, chunks = _make_manifest(b"abcdefgh", 4)
        sealed = self._sealed(manifest)
        source = _TrackingSource("other-artifact", chunks)

        with self.assertRaises(ArtifactIdentityMismatchError) as context:
            ShardVerifier(self.keys).verify(sealed, source)

        self.assertEqual(context.exception.expected_artifact_id, ARTIFACT_ID)
        self.assertEqual(context.exception.actual_artifact_id, "other-artifact")
        self.assertEqual(source.opened, [])

    def test_directory_source_and_source_switch(self):
        data = b"abcdefghijklmno"
        manifest, chunks = _make_manifest(data, 4)
        sealed = self._sealed(manifest)

        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as first_dir:
            first_root = Path(first_dir)
            for location in ("part-000", "part-001"):
                (first_root / location).write_bytes(chunks[location])
            with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as second_dir:
                second_root = Path(second_dir)
                for location in ("part-002", "part-003"):
                    (second_root / location).write_bytes(chunks[location])

                verifier = ShardVerifier(self.keys)
                first = verifier.verify(
                    sealed,
                    DirectoryShardSource(ARTIFACT_ID, first_root),
                )
                second = verifier.verify(DirectoryShardSource(ARTIFACT_ID, second_root))

        self.assertFalse(first.complete)
        self.assertTrue(second.complete)
        self.assertEqual(second.reused, (0, 1))

    def test_directory_source_rejects_path_traversal(self):
        source = DirectoryShardSource(ARTIFACT_ID, Path(__file__).parent)

        with self.assertRaises(ShardSourceError):
            with source.open("../outside"):
                pass

    def test_from_envelope_verifies_before_parsing(self):
        envelope = Envelope(b"not json", MANIFEST_PAYLOAD_TYPE, {})
        envelope.sign(self.signer)

        with self.assertRaises(ShardManifestError):
            SealedShardManifest.from_envelope(envelope, self.keys)


if __name__ == "__main__":
    unittest.main()
