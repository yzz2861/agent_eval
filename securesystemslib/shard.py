"""Verification of sharded artifacts against a sealed DSSE manifest.

A publisher splits a large artifact into byte ranges, describes every range in
``ShardManifest`` and signs the manifest with a DSSE ``Envelope``.  A receiver
uses ``ShardVerifier`` to verify the signature once, then reads the shards from
one or more ``ShardSource`` instances.

Shard data is hashed incrementally.  Only one read chunk and one digest state
are kept in memory, regardless of the artifact size.  Successfully verified
shards are remembered as ``ShardReceipt`` objects.  A receipt is bound to the
exact signed manifest payload, so changing the source can resume verification,
while presenting another manifest (for example an older, replayed one) is
rejected instead of reusing results from the first manifest.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Protocol, cast, overload

from securesystemslib import exceptions, formats, hash
from securesystemslib.dsse import Envelope
from securesystemslib.signer import Key, Signer

MANIFEST_PAYLOAD_TYPE = "application/vnd.securesystemslib.shard-manifest.v1+json"
MANIFEST_VERSION = 1
DEFAULT_ALGORITHM = "sha256"
DEFAULT_CHUNK_SIZE = 64 * 1024

_MANIFEST_KEYS = frozenset(
    {
        "version",
        "artifact_id",
        "artifact_length",
        "algorithm",
        "shards",
    }
)
_SHARD_KEYS = frozenset({"index", "location", "offset", "length", "digest"})
_VERIFY_ARGUMENTS_WITH_MANIFEST = 2


class ShardError(exceptions.Error):
    """Base class for sharded artifact errors."""


class ShardManifestError(exceptions.FormatError, ShardError):
    """The shard manifest is malformed or inconsistent."""


class ShardSourceError(ShardError):
    """A shard source could not provide a shard."""


class ShardNotFoundError(ShardSourceError):
    """The requested shard is absent from a shard source."""


class ManifestMismatchError(ShardError):
    """A verifier was given a manifest other than the one it is bound to.

    This also covers replay of an older, correctly signed manifest after a
    verifier has already accepted a different manifest.
    """

    def __init__(self, expected_manifest_id: str, actual_manifest_id: str):
        self.expected_manifest_id = expected_manifest_id
        self.actual_manifest_id = actual_manifest_id
        super().__init__(
            "Manifest does not match the manifest bound to this verifier "
            f"(expected {expected_manifest_id}, got {actual_manifest_id})"
        )


class ArtifactIdentityMismatchError(ShardError):
    """A shard source contains a different artifact than the manifest names."""

    def __init__(self, expected_artifact_id: str, actual_artifact_id: str):
        self.expected_artifact_id = expected_artifact_id
        self.actual_artifact_id = actual_artifact_id
        super().__init__(
            "Shard source artifact identity does not match manifest "
            f"(expected {expected_artifact_id!r}, got {actual_artifact_id!r})"
        )


class IncompleteVerificationError(ShardError):
    """A verification result is not complete."""

    def __init__(self, result: VerificationResult):
        self.result = result
        super().__init__(result.summary())


def _check_keys(data: Any, allowed: frozenset[str], where: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ShardManifestError(f"{where} must be a JSON object")

    missing = allowed.difference(data)
    unknown = set(data).difference(allowed)
    if missing:
        raise ShardManifestError(
            f"{where} is missing fields: {', '.join(sorted(missing))}"
        )
    if unknown:
        raise ShardManifestError(
            f"{where} has unknown fields: {', '.join(sorted(unknown))}"
        )

    return data


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ShardManifestError(f"{field} must be a non-empty string")
    return value


def _require_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ShardManifestError(f"{field} must be an integer")
    return value


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ShardManifestError(f"Duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ShardManifestError(f"Non-finite JSON number: {value}")


def _digest_hex(data: bytes, algorithm: str = DEFAULT_ALGORITHM) -> str:
    digest_object = hash.digest(algorithm)
    digest_object.update(data)
    return digest_object.hexdigest()


@dataclass(frozen=True)
class Shard:
    """Description of one contiguous byte range of an artifact.

    Attributes:
        index: Zero-based shard index.
        location: Source-specific name used to retrieve the shard.
        offset: Start offset in the complete artifact.
        length: Exact number of bytes in this shard.
        digest: Lower-case hexadecimal digest of the shard bytes.
    """

    index: int
    location: str
    offset: int
    length: int
    digest: str

    def __post_init__(self) -> None:
        index = _require_int(self.index, "shard index")
        location = _require_string(self.location, "shard location")
        offset = _require_int(self.offset, "shard offset")
        length = _require_int(self.length, "shard length")
        digest = _require_string(self.digest, "shard digest").lower()

        if index < 0:
            raise ShardManifestError("shard index must not be negative")
        if offset < 0:
            raise ShardManifestError("shard offset must not be negative")
        if length <= 0:
            raise ShardManifestError("shard length must be greater than zero")
        try:
            bytes.fromhex(digest)
        except ValueError as e:
            raise ShardManifestError("shard digest must be hexadecimal") from e

        object.__setattr__(self, "index", index)
        object.__setattr__(self, "location", location)
        object.__setattr__(self, "offset", offset)
        object.__setattr__(self, "length", length)
        object.__setattr__(self, "digest", digest)

    @property
    def end(self) -> int:
        """Exclusive end offset of this shard."""

        return self.offset + self.length

    @classmethod
    def from_dict(cls, data: Any) -> Shard:
        """Create a shard description from its JSON dictionary form."""

        data = _check_keys(data, _SHARD_KEYS, "shard")
        return cls(
            index=data["index"],
            location=data["location"],
            offset=data["offset"],
            length=data["length"],
            digest=data["digest"],
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable representation of this shard."""

        return {
            "index": self.index,
            "location": self.location,
            "offset": self.offset,
            "length": self.length,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ShardManifest:
    """Artifact identity and the complete ordered set of its shards.

    The manifest is intentionally complete: a missing shard is represented by
    absence from the source, not by absence from the manifest.  Offsets must be
    contiguous and the last shard must end at ``artifact_length``.
    """

    artifact_id: str
    artifact_length: int
    shards: tuple[Shard, ...]
    algorithm: str = DEFAULT_ALGORITHM
    version: int = MANIFEST_VERSION

    def __post_init__(self) -> None:
        artifact_id = _require_string(self.artifact_id, "artifact_id")
        artifact_length = _require_int(self.artifact_length, "artifact_length")
        algorithm = _require_string(self.algorithm, "algorithm").lower()
        version = _require_int(self.version, "version")

        if version != MANIFEST_VERSION:
            raise ShardManifestError(f"Unsupported shard manifest version: {version}")
        if artifact_length < 0:
            raise ShardManifestError("artifact_length must not be negative")

        shards = tuple(self.shards)
        if any(not isinstance(shard, Shard) for shard in shards):
            raise ShardManifestError("manifest shards must be Shard objects")
        shards = tuple(sorted(shards, key=lambda shard: shard.index))

        object.__setattr__(self, "artifact_id", artifact_id)
        object.__setattr__(self, "artifact_length", artifact_length)
        object.__setattr__(self, "algorithm", algorithm)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "shards", shards)
        self._validate_shards()

    def _validate_shards(self) -> None:
        try:
            digest_size = hash.digest(self.algorithm).digest_size
        except exceptions.UnsupportedAlgorithmError as e:
            raise ShardManifestError(
                f"Unsupported shard digest algorithm: {self.algorithm}"
            ) from e

        expected_indexes = tuple(range(len(self.shards)))
        actual_indexes = tuple(shard.index for shard in self.shards)
        if actual_indexes != expected_indexes:
            raise ShardManifestError(
                "Shard indexes must be unique and contiguous from zero"
            )

        locations: set[str] = set()
        next_offset = 0
        for shard in self.shards:
            if shard.location in locations:
                raise ShardManifestError(f"Duplicate shard location: {shard.location}")
            locations.add(shard.location)

            if shard.offset != next_offset:
                raise ShardManifestError(
                    f"Shard {shard.index} offset {shard.offset} does not "
                    f"start at {next_offset}"
                )
            if len(shard.digest) != digest_size * 2:
                raise ShardManifestError(
                    f"Shard {shard.index} digest has the wrong length for "
                    f"{self.algorithm}"
                )
            next_offset = shard.end

        if next_offset != self.artifact_length:
            raise ShardManifestError(
                f"Shard ranges cover {next_offset} bytes, manifest declares "
                f"{self.artifact_length}"
            )
        if not self.shards and self.artifact_length:
            raise ShardManifestError("A non-empty artifact must have shards")

    @classmethod
    def from_dict(cls, data: Any) -> ShardManifest:
        """Create a manifest from its JSON dictionary form."""

        data = _check_keys(data, _MANIFEST_KEYS, "manifest")
        shards = data["shards"]
        if not isinstance(shards, list):
            raise ShardManifestError("manifest shards must be a list")

        return cls(
            artifact_id=data["artifact_id"],
            artifact_length=data["artifact_length"],
            shards=tuple(Shard.from_dict(shard) for shard in shards),
            algorithm=data["algorithm"],
            version=data["version"],
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> ShardManifest:
        """Parse a UTF-8 JSON manifest, rejecting duplicate object fields."""

        try:
            text = data.decode("utf-8")
            decoded = json.loads(
                text,
                object_pairs_hook=_object_without_duplicates,
                parse_constant=_reject_non_finite,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ShardManifestError("Manifest payload is not valid JSON") from e

        return cls.from_dict(decoded)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable representation of this manifest."""

        return {
            "version": self.version,
            "artifact_id": self.artifact_id,
            "artifact_length": self.artifact_length,
            "algorithm": self.algorithm,
            "shards": [shard.to_dict() for shard in self.shards],
        }

    def to_bytes(self) -> bytes:
        """Return a canonical JSON representation suitable for signing."""

        encoded = formats.encode_canonical(self.to_dict())
        if encoded is None:  # pragma: no cover - encode_canonical returns str
            raise ShardManifestError("Could not encode shard manifest")
        return encoded.encode("utf-8")

    @property
    def fingerprint(self) -> str:
        """SHA-256 of the canonical manifest body, without the signature."""

        return _digest_hex(self.to_bytes())


class SealedShardManifest:
    """A ``ShardManifest`` carried inside a signed DSSE envelope."""

    def __init__(self, manifest: ShardManifest, envelope: Envelope):
        if not isinstance(manifest, ShardManifest):
            raise TypeError("manifest must be a ShardManifest")
        if not isinstance(envelope, Envelope):
            raise TypeError("envelope must be a DSSE Envelope")
        if envelope.payload_type != MANIFEST_PAYLOAD_TYPE:
            raise ShardManifestError(
                f"Unexpected payload type: {envelope.payload_type}"
            )

        parsed = ShardManifest.from_bytes(envelope.payload)
        if parsed != manifest:
            raise ShardManifestError(
                "Manifest object does not match the signed envelope payload"
            )

        self.manifest = manifest
        self.envelope = envelope

    @property
    def manifest_id(self) -> str:
        """Identity of the exact signed manifest payload."""

        return f"{DEFAULT_ALGORITHM}:{_digest_hex(self.envelope.payload)}"

    @classmethod
    def seal(cls, manifest: ShardManifest, signer: Signer) -> SealedShardManifest:
        """Create and sign an envelope for ``manifest``."""

        envelope = Envelope(manifest.to_bytes(), MANIFEST_PAYLOAD_TYPE, {})
        envelope.sign(signer)
        return cls(manifest, envelope)

    @classmethod
    def from_envelope(
        cls,
        envelope: Envelope,
        keys: Iterable[Key],
        threshold: int = 1,
    ) -> SealedShardManifest:
        """Verify ``envelope`` signatures before parsing the manifest body."""

        envelope.verify(list(keys), threshold)
        try:
            manifest = ShardManifest.from_bytes(envelope.payload)
        except ShardManifestError:
            raise
        return cls(manifest, envelope)

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        keys: Iterable[Key],
        threshold: int = 1,
    ) -> SealedShardManifest:
        """Create a sealed manifest from a DSSE envelope dictionary."""

        return cls.from_envelope(Envelope.from_dict(data), keys, threshold)

    def verify(self, keys: Iterable[Key], threshold: int = 1) -> dict[str, Key]:
        """Verify the DSSE signature and return the accepted keys."""

        return self.envelope.verify(list(keys), threshold)

    def to_dict(self) -> dict[str, Any]:
        """Return the DSSE envelope dictionary representation."""

        return self.envelope.to_dict()


class ShardSource(Protocol):
    """A source of shard bytes with an explicit artifact identity."""

    artifact_id: str

    def open(self, location: str) -> AbstractContextManager[BinaryIO]:
        """Open one shard for binary reading."""
        ...  # pragma: no cover


ShardData = bytes | bytearray | memoryview | BinaryIO


class MemoryShardSource:
    """A ``ShardSource`` backed by in-memory bytes or seekable file objects.

    ``BytesIO`` values are rewound before every verification pass, which makes
    it practical to demonstrate source switching and resumed verification.
    File objects supplied by the caller are not closed by this source.
    """

    def __init__(self, artifact_id: str, shards: Mapping[str, ShardData]) -> None:
        if not isinstance(artifact_id, str):
            raise TypeError("artifact_id must be a string")
        self.artifact_id = artifact_id
        self._shards = dict(shards)

    @contextmanager
    def open(self, location: str) -> Iterator[BinaryIO]:
        try:
            data = self._shards[location]
        except KeyError as e:
            raise ShardNotFoundError(f"Missing shard: {location}") from e

        if isinstance(data, (bytes, bytearray, memoryview)):
            with io.BytesIO(bytes(data)) as memory_stream:
                yield memory_stream
            return

        stream = data
        try:
            stream.seek(0)
        except (AttributeError, OSError, ValueError) as e:
            raise ShardSourceError(f"Shard {location} is not a seekable stream") from e
        yield stream


class DirectoryShardSource:
    """A ``ShardSource`` that reads shard files below a local cache directory."""

    def __init__(self, artifact_id: str, root: str | Path) -> None:
        if not isinstance(artifact_id, str):
            raise TypeError("artifact_id must be a string")
        self.artifact_id = artifact_id
        self._root = Path(root).resolve()

    def _path(self, location: str) -> Path:
        relative = PurePosixPath(location)
        if relative.is_absolute() or any(
            part in ("", ".", "..") for part in relative.parts
        ):
            raise ShardSourceError(f"Unsafe shard location: {location!r}")

        path = (self._root / Path(*relative.parts)).resolve()
        try:
            path.relative_to(self._root)
        except ValueError as e:
            raise ShardSourceError(
                f"Shard location escapes cache directory: {location!r}"
            ) from e
        return path

    @contextmanager
    def open(self, location: str) -> Iterator[BinaryIO]:
        path = self._path(location)
        try:
            stream = path.open("rb")
        except FileNotFoundError as e:
            raise ShardNotFoundError(f"Missing shard: {location}") from e
        except OSError as e:
            raise ShardSourceError(f"Can't open shard {location}") from e

        try:
            yield stream
        finally:
            stream.close()


class ShardIssueKind(StrEnum):
    """Reason why a shard could not be verified."""

    MISSING = "missing"
    LENGTH_SHORT = "length-short"
    LENGTH_LONG = "length-long"
    DIGEST_MISMATCH = "digest-mismatch"
    MISPLACED = "misplaced"


@dataclass(frozen=True)
class ShardIssue:
    """A single failed shard, classified independently from other failures."""

    shard: Shard
    kind: ShardIssueKind
    message: str
    actual_length: int | None = None
    actual_digest: str | None = None
    matches_index: int | None = None

    @property
    def shard_index(self) -> int:
        """Index of the manifest shard that failed."""

        return self.shard.index


@dataclass(frozen=True)
class ShardRange:
    """A contiguous half-open byte range ``[start, end)`` of the artifact."""

    start: int
    end: int
    shard_indices: tuple[int, ...]

    @property
    def length(self) -> int:
        """Number of bytes in this range."""

        return self.end - self.start

    def __str__(self) -> str:
        return (
            f"[{self.start}, {self.end}) "
            f"(shards {', '.join(str(i) for i in self.shard_indices)})"
        )


@dataclass(frozen=True)
class ShardReceipt:
    """Proof that one shard was verified against a specific sealed manifest."""

    manifest_id: str
    artifact_id: str
    shard_index: int
    location: str
    offset: int
    length: int
    digest: str

    @classmethod
    def for_shard(
        cls, manifest_id: str, manifest: ShardManifest, shard: Shard
    ) -> ShardReceipt:
        """Create a receipt bound to ``manifest_id`` and ``shard``."""

        return cls(
            manifest_id=manifest_id,
            artifact_id=manifest.artifact_id,
            shard_index=shard.index,
            location=shard.location,
            offset=shard.offset,
            length=shard.length,
            digest=shard.digest,
        )


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of one verification pass.

    ``missing_ranges`` describe only shards that were absent.  Shards that were
    present but had a wrong length, wrong content, or swapped content are
    reported in ``issues`` and in ``unverified_ranges``, but are not silently
    folded into the missing-shard result.
    """

    manifest_id: str
    artifact_id: str
    total_shards: int
    receipts: tuple[ShardReceipt, ...]
    issues: tuple[ShardIssue, ...]
    missing_ranges: tuple[ShardRange, ...]
    unverified_ranges: tuple[ShardRange, ...]
    newly_verified: tuple[int, ...]
    reused: tuple[int, ...]
    checked_bytes: int

    @property
    def complete(self) -> bool:
        """True when every shard in the manifest is verified."""

        return not self.issues and len(self.receipts) == self.total_shards

    @property
    def verified_indices(self) -> tuple[int, ...]:
        """Indexes of all verified shards, including cached receipts."""

        return tuple(receipt.shard_index for receipt in self.receipts)

    @property
    def missing_indices(self) -> tuple[int, ...]:
        """Indexes of shards that were absent from the source."""

        return tuple(
            issue.shard_index
            for issue in self.issues
            if issue.kind is ShardIssueKind.MISSING
        )

    @property
    def misplaced_indices(self) -> tuple[int, ...]:
        """Indexes of shards whose content belongs to another manifest shard."""

        return tuple(
            issue.shard_index
            for issue in self.issues
            if issue.kind is ShardIssueKind.MISPLACED
        )

    @property
    def short_indices(self) -> tuple[int, ...]:
        """Indexes of shards that contained fewer bytes than declared."""

        return tuple(
            issue.shard_index
            for issue in self.issues
            if issue.kind is ShardIssueKind.LENGTH_SHORT
        )

    def require_complete(self) -> None:
        """Raise ``IncompleteVerificationError`` unless complete."""

        if not self.complete:
            raise IncompleteVerificationError(self)

    def summary(self) -> str:
        """Return a short human-readable result description."""

        state = "complete" if self.complete else "incomplete"
        summary = (
            f"Shard verification {state}: {len(self.receipts)}/"
            f"{self.total_shards} verified"
        )
        if self.missing_ranges:
            ranges = ", ".join(str(item) for item in self.missing_ranges)
            summary += f"; missing ranges: {ranges}"
        if self.issues:
            details = ", ".join(
                f"shard {issue.shard_index} {issue.kind.value}" for issue in self.issues
            )
            summary += f"; issues: {details}"
        return summary


class ShardVerifier:
    """Verify shards against one sealed manifest and cache successful checks.

    Create a session with ``ShardVerifier(keys, threshold)`` and pass a sealed
    manifest to :meth:`verify`, or bind a manifest immediately with
    :meth:`for_manifest`.  Reusing the verifier with another source continues
    verification; reusing it with another manifest raises
    ``ManifestMismatchError``.
    """

    def __init__(
        self,
        keys: Iterable[Key],
        threshold: int = 1,
        *,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be greater than zero")

        self._keys = list(keys)
        self._threshold = threshold
        self._chunk_size = chunk_size
        self._sealed_manifest: SealedShardManifest | None = None
        self._manifest: ShardManifest | None = None
        self._manifest_id: str | None = None
        self._receipts: dict[int, ShardReceipt] = {}

    @classmethod
    def for_manifest(
        cls,
        sealed_manifest: SealedShardManifest,
        keys: Iterable[Key],
        threshold: int = 1,
        *,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> ShardVerifier:
        """Create a verifier preloaded with ``sealed_manifest``.

        The manifest is bound only after its signature verifies successfully.
        """

        verifier = cls(keys, threshold, chunk_size=chunk_size)
        verifier._sealed_manifest = sealed_manifest
        return verifier

    @property
    def manifest_id(self) -> str | None:
        """ID of the manifest this verifier is bound to, if any."""

        return self._manifest_id

    @property
    def receipts(self) -> tuple[ShardReceipt, ...]:
        """Receipts for all shards verified so far."""

        return tuple(self._receipts[index] for index in sorted(self._receipts))

    @overload
    def verify(self, source: ShardSource) -> VerificationResult: ...

    @overload
    def verify(
        self, sealed_manifest: SealedShardManifest, source: ShardSource
    ) -> VerificationResult: ...

    def verify(self, *args: Any, **kwargs: Any) -> VerificationResult:
        """Verify a source, optionally supplying the sealed manifest.

        A one-argument call uses the bound manifest.  A two-argument call
        accepts a manifest and a source; this is the session form used to
        detect replay of a different manifest.
        """

        if kwargs:
            if args or not set(kwargs).issubset({"sealed_manifest", "source"}):
                raise TypeError("verify() received unexpected arguments")
            if "sealed_manifest" in kwargs:
                if "source" not in kwargs:
                    raise TypeError("verify() is missing the source argument")
                args = (kwargs["sealed_manifest"], kwargs["source"])
            else:
                args = (kwargs["source"],)

        if len(args) == 1:
            if self._sealed_manifest is None:
                raise TypeError(
                    "verify(source) requires a bound manifest; use "
                    "verify(sealed_manifest, source) or for_manifest()"
                )
            return self._verify(self._sealed_manifest, cast(ShardSource, args[0]))
        if len(args) == _VERIFY_ARGUMENTS_WITH_MANIFEST:
            sealed_manifest, source = args
            if not isinstance(sealed_manifest, SealedShardManifest):
                raise TypeError("first argument must be a SealedShardManifest")
            return self._verify(sealed_manifest, cast(ShardSource, source))

        raise TypeError("verify() takes one or two positional arguments")

    def _verify(
        self, sealed_manifest: SealedShardManifest, source: ShardSource
    ) -> VerificationResult:
        # Signature verification always happens before shard I/O or binding.
        sealed_manifest.verify(self._keys, self._threshold)
        self._bind_manifest(sealed_manifest)

        manifest = self._manifest
        if manifest is None:  # pragma: no cover - _bind_manifest sets it
            raise RuntimeError("verifier has no manifest")

        source_artifact_id = getattr(source, "artifact_id", None)
        if not isinstance(source_artifact_id, str):
            raise TypeError(
                "source must implement ShardSource (for example MemoryShardSource)"
            )
        if source_artifact_id != manifest.artifact_id:
            raise ArtifactIdentityMismatchError(
                manifest.artifact_id, source_artifact_id
            )

        observed: dict[int, tuple[int, str]] = {}
        newly_verified: list[int] = []
        reused: list[int] = []
        checked_bytes = 0

        for shard in manifest.shards:
            if self._has_receipt(shard):
                reused.append(shard.index)
                continue

            try:
                with source.open(shard.location) as stream:
                    actual_length, actual_digest = self._scan(stream)
            except (ShardNotFoundError, FileNotFoundError):
                continue

            observed[shard.index] = (actual_length, actual_digest)
            checked_bytes += actual_length
            if actual_length == shard.length and actual_digest == shard.digest:
                self._receipts[shard.index] = ShardReceipt.for_shard(
                    manifest_id=self._manifest_id or "",
                    manifest=manifest,
                    shard=shard,
                )
                newly_verified.append(shard.index)

        issues = self._classify_issues(manifest, observed)
        receipts = tuple(self._receipts[index] for index in sorted(self._receipts))

        return VerificationResult(
            manifest_id=self._manifest_id or "",
            artifact_id=manifest.artifact_id,
            total_shards=len(manifest.shards),
            receipts=receipts,
            issues=issues,
            missing_ranges=self._ranges(
                manifest,
                tuple(
                    issue.shard_index
                    for issue in issues
                    if issue.kind is ShardIssueKind.MISSING
                ),
            ),
            unverified_ranges=self._ranges(
                manifest, tuple(issue.shard_index for issue in issues)
            ),
            newly_verified=tuple(sorted(newly_verified)),
            reused=tuple(sorted(reused)),
            checked_bytes=checked_bytes,
        )

    def _bind_manifest(self, sealed_manifest: SealedShardManifest) -> None:
        if self._manifest_id is None:
            self._sealed_manifest = sealed_manifest
            self._manifest = sealed_manifest.manifest
            self._manifest_id = sealed_manifest.manifest_id
            return

        expected_manifest_id = self._manifest_id
        if sealed_manifest.manifest_id != expected_manifest_id:
            raise ManifestMismatchError(
                expected_manifest_id, sealed_manifest.manifest_id
            )

    def _has_receipt(self, shard: Shard) -> bool:
        receipt = self._receipts.get(shard.index)
        if receipt is None:
            return False

        manifest = self._manifest
        if manifest is None:  # pragma: no cover - caller checks
            raise RuntimeError("verifier has no manifest")

        if (
            receipt.manifest_id != self._manifest_id
            or receipt.artifact_id != manifest.artifact_id
            or receipt.location != shard.location
            or receipt.offset != shard.offset
            or receipt.length != shard.length
            or receipt.digest != shard.digest
        ):
            del self._receipts[shard.index]
            return False
        return True

    def _scan(self, stream: BinaryIO) -> tuple[int, str]:
        """Hash a stream up to one byte past the largest possible shard."""

        manifest = self._manifest
        if manifest is None:  # pragma: no cover - caller checks
            raise RuntimeError("verifier has no manifest")

        limit = max(shard.length for shard in manifest.shards) + 1
        digest_object = hash.digest(manifest.algorithm)
        actual_length = 0

        while actual_length < limit:
            read_size = min(self._chunk_size, limit - actual_length)
            chunk = stream.read(read_size)
            if not chunk:
                break
            if not isinstance(chunk, (bytes, bytearray, memoryview)):
                raise ShardSourceError("Shard stream returned non-bytes data")
            digest_object.update(chunk)
            actual_length += len(chunk)

        return actual_length, digest_object.hexdigest()

    def _classify_issues(
        self, manifest: ShardManifest, observed: dict[int, tuple[int, str]]
    ) -> tuple[ShardIssue, ...]:
        issues: list[ShardIssue] = []
        for shard in manifest.shards:
            if shard.index in self._receipts:
                continue
            if shard.index not in observed:
                issues.append(
                    ShardIssue(
                        shard=shard,
                        kind=ShardIssueKind.MISSING,
                        message=f"Shard {shard.index} is missing",
                    )
                )
                continue

            actual_length, actual_digest = observed[shard.index]
            issue = self._classify_shard(manifest, shard, actual_length, actual_digest)
            if issue is not None:
                issues.append(issue)
        return tuple(issues)

    @staticmethod
    def _classify_shard(
        manifest: ShardManifest,
        shard: Shard,
        actual_length: int,
        actual_digest: str,
    ) -> ShardIssue | None:
        if actual_length == shard.length and actual_digest == shard.digest:
            return None

        matches = next(
            (
                candidate
                for candidate in manifest.shards
                if candidate.index != shard.index
                and candidate.length == actual_length
                and candidate.digest == actual_digest
            ),
            None,
        )
        if matches is not None:
            return ShardIssue(
                shard=shard,
                kind=ShardIssueKind.MISPLACED,
                message=(
                    f"Shard {shard.index} contains the bytes declared for "
                    f"shard {matches.index} ({matches.location})"
                ),
                actual_length=actual_length,
                actual_digest=actual_digest,
                matches_index=matches.index,
            )

        if actual_length < shard.length:
            return ShardIssue(
                shard=shard,
                kind=ShardIssueKind.LENGTH_SHORT,
                message=(
                    f"Shard {shard.index} is {actual_length} bytes, expected "
                    f"{shard.length}"
                ),
                actual_length=actual_length,
                actual_digest=actual_digest,
            )
        if actual_length > shard.length:
            return ShardIssue(
                shard=shard,
                kind=ShardIssueKind.LENGTH_LONG,
                message=(
                    f"Shard {shard.index} is at least {actual_length} bytes, "
                    f"expected {shard.length}"
                ),
                actual_length=actual_length,
                actual_digest=actual_digest,
            )
        return ShardIssue(
            shard=shard,
            kind=ShardIssueKind.DIGEST_MISMATCH,
            message=f"Shard {shard.index} digest does not match the manifest",
            actual_length=actual_length,
            actual_digest=actual_digest,
        )

    @staticmethod
    def _ranges(
        manifest: ShardManifest, indexes: tuple[int, ...]
    ) -> tuple[ShardRange, ...]:
        if not indexes:
            return ()

        groups: list[list[int]] = []
        for index in sorted(set(indexes)):
            if groups and index == groups[-1][-1] + 1:
                groups[-1].append(index)
            else:
                groups.append([index])

        ranges = []
        for group in groups:
            first = manifest.shards[group[0]]
            last = manifest.shards[group[-1]]
            ranges.append(
                ShardRange(
                    start=first.offset,
                    end=last.end,
                    shard_indices=tuple(group),
                )
            )
        return tuple(ranges)


__all__ = [
    "DEFAULT_ALGORITHM",
    "DEFAULT_CHUNK_SIZE",
    "MANIFEST_PAYLOAD_TYPE",
    "MANIFEST_VERSION",
    "ArtifactIdentityMismatchError",
    "DirectoryShardSource",
    "IncompleteVerificationError",
    "ManifestMismatchError",
    "MemoryShardSource",
    "SealedShardManifest",
    "Shard",
    "ShardError",
    "ShardIssue",
    "ShardIssueKind",
    "ShardManifest",
    "ShardManifestError",
    "ShardNotFoundError",
    "ShardRange",
    "ShardReceipt",
    "ShardSource",
    "ShardSourceError",
    "ShardVerifier",
    "VerificationResult",
]
