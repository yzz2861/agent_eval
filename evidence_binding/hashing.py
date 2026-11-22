"""Hashing helpers used to fingerprint files and record content."""

import hashlib


def sha256_bytes(data):
    """Return the hex-encoded SHA-256 digest of a byte string."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path, chunk_size=65536):
    """Return the hex-encoded SHA-256 digest of a file without loading it twice."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
