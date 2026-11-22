"""Read-only evidence inventory for access-protected Office files.

This module inspects an Office exhibit using msoffcrypto-tool's format
detection and reports, without ever attempting decryption and without
requiring a password:

* the protection declaration carried by the file (e.g. the EncryptionInfo
  stream of an ECMA-376 encrypted OOXML package, or the encryption flags of
  an OLE97 document),
* the actually readable range of the encrypted stream(s) (declared size vs.
  bytes that can physically be read back),
* the behavior for unrecognized formats (reported, never guessed).

The caller may attach preservation-process confirmation records
(``preservation_records``).  Those personnel statements are stored verbatim
under ``preservation_records``, strictly separated from
``physical_observations``, which only contains facts read back from the
exhibit itself.  ``consistency_notes`` cross-references the two without
mixing them.

Examples:
    >>> import json
    >>> with open("tests/inputs/example_password.docx", "rb") as f:
    ...     report = inspect(f)
    >>> report["assessment"]["protection_declared"]
    True
    >>> report["assessment"]["sealed_content_complete"]
    True
    >>> with open("README.md", "rb") as f:
    ...     report = inspect(f)
    >>> report["physical_observations"]["container"]
    'unrecognized'
"""

import argparse
import hashlib
import io
import json
import logging
import sys
import zipfile

import olefile

from msoffcrypto.format.ooxml import _is_ooxml, _parseinfo

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

SCHEMA = "msoffcrypto-evidence/1"

# Claim values (in a preservation record's "claim" field) that assert the
# sealed original is intact.
_INTACT_CLAIMS = {
    "intact",
    "original_intact",
    "encrypted_original_intact",
    "sealed",
    "seal_intact",
}

_ALG_ID_MAP = {
    0x0000660E: "AES-128",
    0x0000660F: "AES-192",
    0x00006610: "AES-256",
    0x00006801: "RC4",
}


def _tool_version():
    try:
        if sys.version_info >= (3, 8):
            from importlib import metadata

            return metadata.version("msoffcrypto-tool")
        else:
            import pkg_resources

            return pkg_resources.get_distribution("msoffcrypto-tool").version
    except Exception:
        return "unknown"


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _stream_stat(ole, name):
    """Return declared vs. physically readable size of an OLE stream."""
    stat = {"name": name, "declared_size": ole.get_size(name)}
    try:
        with ole.openstream(name) as stream:
            data = stream.read()
    except Exception as e:
        stat["readable_size"] = None
        stat["sha256_readable"] = None
        stat["complete"] = False
        stat["read_error"] = "{}: {}".format(type(e).__name__, e)
    else:
        stat["readable_size"] = len(data)
        stat["sha256_readable"] = _sha256(data)
        stat["complete"] = len(data) == stat["declared_size"]
    return stat


def _summarize_declaration(encryption_type, info):
    """Extract a JSON-safe summary of a parsed EncryptionInfo stream."""
    if encryption_type == "agile":
        return {
            "encryption_type": "agile",
            "cipher": "AES",
            "key_bits": info["passwordKeyBits"],
            "password_hash_algorithm": info["passwordHashAlgorithm"],
            "data_hash_algorithm": info["keyDataHashAlgorithm"],
            "spin_count": info["spinValue"],
        }
    elif encryption_type == "standard":
        header = info["header"]
        return {
            "encryption_type": "standard",
            "cipher": _ALG_ID_MAP.get(
                header["algId"], "algId=0x{:08X}".format(header["algId"])
            ),
            "key_bits": header["keySize"],
            "csp_name": header["cspName"].rstrip("\x00"),
        }
    return {"encryption_type": encryption_type}


def _inspect_ooxml_ole(ole, observations, findings):
    declaration = {
        "present": True,
        "stream": "EncryptionInfo",
        "indicator": "ECMA-376 EncryptionInfo stream",
    }
    stat = _stream_stat(ole, "EncryptionInfo")
    declaration["declared_size"] = stat["declared_size"]
    declaration["readable_size"] = stat["readable_size"]
    declaration["readable"] = stat["complete"]
    declaration["sha256_readable"] = stat["sha256_readable"]
    if not stat["complete"]:
        findings.append("protection_declaration_incomplete")
        declaration["read_error"] = stat.get("read_error")
    else:
        findings.append("protection_declaration_readable")
        try:
            with ole.openstream("EncryptionInfo") as stream:
                encryption_type, info = _parseinfo(stream)
            declaration["parsed"] = True
            declaration.update(_summarize_declaration(encryption_type, info))
        except Exception as e:
            declaration["parsed"] = False
            declaration["parse_error"] = "{}: {}".format(type(e).__name__, e)
            findings.append("protection_declaration_unparseable")
    observations["protection_declaration"] = declaration
    findings.append("protection_declaration_present")

    if ole.exists("EncryptedPackage"):
        pkg = _stream_stat(ole, "EncryptedPackage")
        pkg["role"] = "encrypted payload (ECMA-376 EncryptedPackage)"
        observations["encrypted_stream"] = pkg
        if pkg["complete"]:
            findings.append("encrypted_stream_complete")
        else:
            findings.append("encrypted_stream_truncated")
    else:
        observations["encrypted_stream"] = None
        findings.append("encrypted_stream_missing")


def _inspect_ole97(data, ole, observations, findings):
    from msoffcrypto import OfficeFile

    declaration = {
        "indicator": "encryption flags in the format header "
        "(FIB fEncrypted / Workbook FilePass / CurrentUser)",
    }
    try:
        office = OfficeFile(io.BytesIO(data))
        observations["format"] = office.format
        declaration["present"] = office.is_encrypted()
        declaration["readable"] = True
        declaration["encryption_type"] = getattr(office, "type", None)
    except Exception as e:
        declaration["present"] = None
        declaration["readable"] = False
        declaration["parse_error"] = "{}: {}".format(type(e).__name__, e)
        findings.append("protection_declaration_unparseable")
    observations["protection_declaration"] = declaration
    if declaration["present"]:
        findings.append("protection_declaration_present")
    elif declaration["present"] is False:
        findings.append("protection_declaration_absent")
    # OLE97 encrypts content streams in place; there is no separate
    # EncryptedPackage stream.  Completeness is judged from the stream
    # inventory instead.
    observations["encrypted_stream"] = None


def _inspect_ole(data, observations, findings):
    ole = olefile.OleFileIO(io.BytesIO(data))
    streams = []
    for entry in ole.listdir():
        name = "/".join(entry)
        streams.append(_stream_stat(ole, name))
    observations["streams"] = streams

    if ole.exists("EncryptionInfo"):
        observations["format"] = "ooxml"
        _inspect_ooxml_ole(ole, observations, findings)
    else:
        _inspect_ole97(data, ole, observations, findings)

    if any(not s["complete"] for s in streams):
        findings.append("container_streams_incomplete")


def _assess(observations):
    declaration = observations.get("protection_declaration") or {}
    declared = declaration.get("present")
    encrypted_stream = observations.get("encrypted_stream")
    streams = observations.get("streams") or []

    if encrypted_stream is not None:
        complete = bool(encrypted_stream["complete"])
    elif streams:
        complete = all(s["complete"] for s in streams)
    else:
        complete = None

    explanation = []
    if declared:
        if declaration.get("readable"):
            explanation.append(
                "The protection declaration ({}) is fully readable, which "
                "proves the original file carried an encryption declaration.".format(
                    declaration.get("indicator", "encryption indicator")
                )
            )
        else:
            explanation.append(
                "A protection declaration is present but could not be fully "
                "read or parsed; the original file appears to have carried an "
                "encryption declaration, but its parameters cannot be confirmed."
            )
    elif declared is False:
        explanation.append(
            "No protection declaration was found; the exhibit does not "
            "declare itself as encrypted."
        )
    else:
        explanation.append(
            "The container is not recognized, so no protection declaration "
            "could be established; the format is reported as-is and no "
            "decryption was attempted."
        )

    if complete is True:
        explanation.append(
            "All encrypted stream bytes declared by the container directory "
            "are physically readable. Cryptographic integrity verification "
            "would require the key and was not attempted (no password used)."
        )
    elif complete is False:
        explanation.append(
            "The encrypted stream is incomplete: fewer bytes are physically "
            "readable than the container directory declares. The exhibit "
            "therefore cannot confirm that the sealed content is intact, "
            "even though the protection declaration itself survives."
        )

    return {
        "protection_declared": declared,
        "sealed_content_complete": complete,
        "explanation": " ".join(explanation),
    }


def _record_asserts_intact(record):
    if record.get("asserts_intact") is True:
        return True
    claim = record.get("claim")
    return isinstance(claim, str) and claim.lower() in _INTACT_CLAIMS


def _cross_check(records, assessment):
    notes = []
    complete = assessment["sealed_content_complete"]
    for i, record in enumerate(records):
        if not isinstance(record, dict) or not _record_asserts_intact(record):
            continue
        label = record.get("record_id") or record.get("id") or "#{}".format(i + 1)
        if complete is False:
            notes.append(
                "Preservation record '{}' asserts the sealed original is "
                "intact, but the physical readback shows the encrypted "
                "stream is incomplete; the claim is NOT corroborated by the "
                "exhibit.".format(label)
            )
        elif complete is True:
            notes.append(
                "Preservation record '{}' asserts the sealed original is "
                "intact; the encrypted stream reads back completely, which "
                "is consistent with the claim, but cryptographic integrity "
                "was not verified (no password used).".format(label)
            )
        else:
            notes.append(
                "Preservation record '{}' asserts the sealed original is "
                "intact; the exhibit could not be read, so the claim cannot "
                "be evaluated.".format(label)
            )
    return notes


def inspect(file, preservation_records=None, path=None):
    """Build a read-only evidence inventory for an Office exhibit.

    Args:
        file: A path, or a binary file-like object positioned anywhere.
        preservation_records: Optional list of caller-supplied dicts
            describing preservation-process confirmations (personnel
            statements).  Stored verbatim, separated from physical
            observations.  A record may set ``asserts_intact: true`` or
            ``claim: "intact"`` to state the sealed original is intact.
        path: Optional exhibit label; defaults to ``file.name`` if any.

    Returns:
        A JSON-serializable dict.  Never attempts decryption and never
        requires a password.
    """
    if isinstance(file, (str, bytes)) or hasattr(file, "__fspath__"):
        path = path or str(file)
        with open(file, "rb") as f:
            data = f.read()
    else:
        if path is None:
            path = getattr(file, "name", None)
        file.seek(0)
        data = file.read()

    observations = {}
    findings = []

    exhibit = {
        "path": path,
        "size_bytes": len(data),
        "sha256": _sha256(data),
    }

    blob = io.BytesIO(data)
    if olefile.isOleFile(blob):
        observations["container"] = "ole"
        try:
            _inspect_ole(data, observations, findings)
        except Exception as e:
            observations["container_error"] = "{}: {}".format(type(e).__name__, e)
            findings.append("container_unreadable")
    elif zipfile.is_zipfile(blob):
        observations["container"] = "zip"
        if _is_ooxml(io.BytesIO(data)):
            observations["format"] = "ooxml"
            observations["protection_declaration"] = {
                "present": False,
                "indicator": "ECMA-376 EncryptionInfo stream",
                "detail": "Plain OOXML package; ECMA-376 encryption would "
                "require an OLE container with an EncryptionInfo stream.",
            }
        else:
            observations["format"] = "zip"
            observations["protection_declaration"] = {
                "present": False,
                "indicator": None,
                "detail": "ZIP container is not an OOXML package.",
            }
        observations["streams"] = None
        observations["encrypted_stream"] = None
        findings.append("protection_declaration_absent")
    else:
        observations["container"] = "unrecognized"
        observations["format"] = "unrecognized"
        observations["protection_declaration"] = {"present": None}
        observations["streams"] = None
        observations["encrypted_stream"] = None
        observations["unrecognized_behavior"] = (
            "Container is neither OLE nor ZIP; msoffcrypto-tool raises "
            "FileFormatError for such input. The exhibit is reported as-is; "
            "no format is guessed and no decryption is attempted."
        )
        findings.append("unrecognized_container")

    assessment = _assess(observations)

    records = list(preservation_records or [])
    report = {
        "schema": SCHEMA,
        "tool": {
            "name": "msoffcrypto-tool",
            "version": _tool_version(),
            "mode": "read-only",
            "password_used": False,
        },
        "exhibit": exhibit,
        "physical_observations": observations,
        "findings": findings,
        "assessment": assessment,
        "preservation_records": records,
        "consistency_notes": _cross_check(records, assessment),
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="msoffcrypto-evidence",
        description="Read-only evidence inventory for access-protected "
        "Office files. Never decrypts; no password required.",
    )
    parser.add_argument("infile", help="exhibit file to inspect")
    parser.add_argument(
        "--records",
        metavar="JSON",
        help="JSON file with a list of preservation-process confirmation "
        "records (personnel statements), stored separately from physical "
        "observations",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="emit compact JSON (default is indented)",
    )
    args = parser.parse_args(argv)

    records = None
    if args.records:
        with open(args.records, "r", encoding="utf-8") as f:
            records = json.load(f)
        if not isinstance(records, list):
            raise ValueError("records file must contain a JSON list")

    report = inspect(args.infile, preservation_records=records)
    if args.compact:
        print(json.dumps(report, ensure_ascii=False))
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
