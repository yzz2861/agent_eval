"""Forensic evidence export for authorized decryption handover.

This module provides an evidence-oriented export entry point on top of the
regular decryption API.  Instead of only recording whether ``decrypt()``
returned, it binds together, in a single machine-checkable receipt:

* the digest of the encrypted source exhibit,
* the digest of the decrypted derivative,
* the integrity conclusion obtained during decryption,
* the final handover status.

The receipt never contains the password or any key material.  A receipt
produced here can be re-checked independently in another process with
:func:`verify_receipt`, which recomputes both digests from the two files.

If the derivative cannot be written out completely (e.g. a short write on
the output sink), no receipt is issued; only an exception handling record
is written and :class:`msoffcrypto.exceptions.EvidenceExportError` is
raised.
"""

import hashlib
import io
import json
import os
from datetime import datetime, timezone

from msoffcrypto import exceptions

#: Schema identifier stored in every receipt.
RECEIPT_SCHEMA = "msoffcrypto.evidence-receipt/1"

#: Schema identifier stored in every exception handling record.
EXCEPTION_SCHEMA = "msoffcrypto.evidence-exception/1"

#: Handover status recorded in a successfully issued receipt.
STATUS_HANDED_OVER = "handed_over"

#: Status recorded in an exception handling record.
STATUS_FAILED = "failed"

#: Integrity conclusion when the payload HMAC was verified.
INTEGRITY_VERIFIED = "verified"

#: Integrity conclusion when the format has no integrity mechanism.
INTEGRITY_UNAVAILABLE = "unavailable"

_CHUNK_SIZE = 64 * 1024


def _hash_fileobj(fileobj, hash_name):
    """Return (hexdigest, size) of a binary file object, restoring position."""
    position = fileobj.tell()
    fileobj.seek(0)
    hasher = hashlib.new(hash_name)
    size = 0
    while True:
        chunk = fileobj.read(_CHUNK_SIZE)
        if not chunk:
            break
        hasher.update(chunk)
        size += len(chunk)
    fileobj.seek(position)
    return hasher.hexdigest(), size


def _hash_source(source, hash_name):
    """Hash the encrypted source exhibit, given as a path or file object."""
    if isinstance(source, (str, bytes, os.PathLike)):
        with open(source, "rb") as f:
            return _hash_fileobj(f, hash_name)
    return _hash_fileobj(source, hash_name)


def _integrity_conclusion(officefile):
    """Obtain the integrity conclusion for a loaded office file.

    Returns INTEGRITY_VERIFIED for agile-encrypted OOXML files whose payload
    HMAC checks out, and INTEGRITY_UNAVAILABLE for formats without an
    integrity mechanism.  Raises EvidenceExportError when the file carries an
    integrity mechanism but verification fails.
    """
    if getattr(officefile, "type", None) == "agile" and hasattr(officefile, "info"):
        from msoffcrypto.method.ecma376_agile import ECMA376Agile

        info = officefile.info
        with officefile.file.openstream("EncryptedPackage") as stream:
            verified = ECMA376Agile.verify_integrity(
                officefile.secret_key,
                info["keyDataSalt"],
                info["keyDataHashAlgorithm"],
                info["keyDataBlockSize"],
                info["encryptedHmacKey"],
                info["encryptedHmacValue"],
                stream,
            )
        if not verified:
            raise exceptions.EvidenceExportError(
                "Payload integrity verification failed"
            )
        return INTEGRITY_VERIFIED
    return INTEGRITY_UNAVAILABLE


def _write_all(outfile, buf):
    """Write buf to outfile, raising EvidenceExportError on a short write.

    The handover sink is expected to accept the derivative in full; a write
    that reports fewer bytes than handed over is treated as a failed
    handover, never as a partial success.
    """
    written = outfile.write(buf)
    if written is not None and written != len(buf):
        raise exceptions.EvidenceExportError(
            "Short write on derivative output: {} of {} bytes accepted".format(
                written, len(buf)
            )
        )
    flush = getattr(outfile, "flush", None)
    if flush is not None:
        flush()


def _write_record(path, record):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, sort_keys=True)
        f.write("\n")


def _fail(exception_record_path, record, message, cause=None):
    record["schema"] = EXCEPTION_SCHEMA
    record["status"] = STATUS_FAILED
    record["reason"] = message
    record["recorded_at"] = datetime.now(timezone.utc).isoformat()
    if exception_record_path is not None:
        _write_record(exception_record_path, record)
    error = exceptions.EvidenceExportError(message)
    if cause is not None:
        raise error from cause
    raise error


def export_evidence(
    officefile,
    source,
    outfile,
    receipt_path,
    hash_name="sha256",
    exception_record_path=None,
):
    """Decrypt and hand over an office file as a forensic evidence package.

    Args:
        officefile: A loaded office file object (key already loaded via
            ``load_key``).  The password is never read back or recorded.
        source: Path or binary file object of the encrypted original, used
            to compute the source digest.
        outfile: Writable binary sink for the decrypted derivative.  May be
            swapped for any file-like backend (e.g. an in-memory stream);
            a short write aborts the handover.
        receipt_path: Path of the JSON receipt written on success.
        hash_name: Digest algorithm bound into the receipt.
        exception_record_path: Path of the JSON exception handling record
            written on failure.  Defaults to ``receipt_path + ".exception.json"``.

    Returns:
        The receipt as a dict.

    Raises:
        msoffcrypto.exceptions.EvidenceExportError: If integrity
            verification fails, decryption fails, or the derivative cannot
            be written out completely.  No receipt is issued in that case;
            only the exception handling record is left behind.
    """
    if exception_record_path is None:
        exception_record_path = receipt_path + ".exception.json"

    record = {"hash_algorithm": hash_name}

    try:
        record["integrity"] = _integrity_conclusion(officefile)
    except exceptions.EvidenceExportError as e:
        _fail(exception_record_path, record, str(e), cause=e)

    source_digest, source_size = _hash_source(source, hash_name)
    record["source"] = {"digest": source_digest, "size": source_size}

    buffer = io.BytesIO()
    try:
        officefile.decrypt(buffer)
    except Exception as e:
        _fail(
            exception_record_path,
            record,
            "Decryption failed: {}".format(e),
            cause=e,
        )
    derived = buffer.getvalue()
    derived_hasher = hashlib.new(hash_name)
    derived_hasher.update(derived)
    record["derived"] = {
        "digest": derived_hasher.hexdigest(),
        "size": len(derived),
    }

    try:
        _write_all(outfile, derived)
    except Exception as e:
        _fail(
            exception_record_path,
            record,
            "Derivative handover write failed: {}".format(e),
            cause=e,
        )

    record["schema"] = RECEIPT_SCHEMA
    record["status"] = STATUS_HANDED_OVER
    record["generated_at"] = datetime.now(timezone.utc).isoformat()
    _write_record(receipt_path, record)
    return dict(record)


def verify_receipt(receipt_path, source, derived):
    """Independently re-check a handover receipt against both exhibits.

    Recomputes the digests of the encrypted source and the decrypted
    derivative (paths or binary file objects) and compares them with the
    digests bound into the receipt.  Uses only the standard library, so it
    can run in a separate process/environment from the exporter.

    Returns:
        A dict with keys ``ok``, ``source_match``, ``derived_match``,
        ``status`` and ``integrity``.
    """
    with open(receipt_path, "r", encoding="utf-8") as f:
        receipt = json.load(f)

    hash_name = receipt.get("hash_algorithm", "sha256")
    source_digest, _ = _hash_source(source, hash_name)
    derived_digest, _ = _hash_source(derived, hash_name)

    source_match = source_digest == receipt.get("source", {}).get("digest")
    derived_match = derived_digest == receipt.get("derived", {}).get("digest")
    return {
        "ok": bool(source_match and derived_match),
        "source_match": bool(source_match),
        "derived_match": bool(derived_match),
        "status": receipt.get("status"),
        "integrity": receipt.get("integrity"),
    }
