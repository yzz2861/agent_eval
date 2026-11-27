"""Build the sealed-notice example batch and its archival review report.

Two notices are signed with the *same* claimed signing time
(2026-03-10T09:30:00Z, inside the approved window):

* notice A -- a mail-gateway receipt proves it already existed on
  2026-02-20, before the approval window opened; the claim is
  contradicted by external evidence.
* notice B -- no receipt, no independent preservation; the signing time
  rests solely on the signer's own declaration.

Running this script regenerates the key, the signed notices, the case
file and the archived report under forensics/examples/.
"""

import json
import os
from datetime import datetime, timezone

import pgpy
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

from forensics.review import run_case

HERE = os.path.dirname(os.path.abspath(__file__))

CLAIMED_SIGNING_TIME = datetime(2026, 3, 10, 9, 30, 0, tzinfo=timezone.utc)

NOTICE_A_TEXT = (
    "SEALED NOTICE A\n"
    "Custodian transfer batch 2026-014, item 1 of 2.\n"
    "This notice is sealed pending forensic review.\n"
)
NOTICE_B_TEXT = (
    "SEALED NOTICE B\n"
    "Custodian transfer batch 2026-014, item 2 of 2.\n"
    "This notice is sealed pending forensic review.\n"
)


def build_key():
    key = pgpy.PGPKey.new(
        PubKeyAlgorithm.RSAEncryptOrSign, 2048,
        created=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    uid = pgpy.PGPUID.new("Evidence Custodian", email="custodian@example.org")
    key.add_uid(
        uid,
        usage={KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return key


def sign_notice(key, text):
    return key.sign(text.encode("utf-8"), detached=True,
                    created=CLAIMED_SIGNING_TIME)


def main():
    key = build_key()

    pub_path = os.path.join(HERE, "custodian_pub.asc")
    with open(pub_path, "w", encoding="utf-8") as fh:
        fh.write(str(key.pubkey))

    case = {
        "approved_window": {
            "not_before": "2026-03-01T00:00:00+00:00",
            "not_after": "2026-03-31T23:59:59+00:00",
            "issued_by": "compliance-office",
        },
        "notices": [],
    }

    evidence = {
        "notice-a": {
            "external_receipt": {
                "window": {
                    "start": "2026-02-20T08:15:00+00:00",
                    "end": "2026-02-20T08:15:00+00:00",
                },
                "source": "mail-gateway received-headers log",
            },
            "independent_preservation": {
                "window": {
                    "start": "2026-04-02T11:00:00+00:00",
                    "end": "2026-04-02T11:30:00+00:00",
                },
                "source": "third-party timestamping service",
            },
        },
        "notice-b": {},
    }

    for notice_id, text in (("notice-a", NOTICE_A_TEXT),
                            ("notice-b", NOTICE_B_TEXT)):
        notice_path = os.path.join(HERE, notice_id + ".txt")
        sig_path = notice_path + ".sig.asc"
        with open(notice_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        signature = sign_notice(key, text)
        with open(sig_path, "w", encoding="utf-8") as fh:
            fh.write(str(signature))

        entry = {
            "id": notice_id,
            "notice": notice_path,
            "signature": sig_path,
        }
        entry.update(evidence[notice_id])
        case["notices"].append(entry)

    case_path = os.path.join(HERE, "case.json")
    with open(case_path, "w", encoding="utf-8") as fh:
        json.dump(case, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    report_path = os.path.join(HERE, "archive_report.json")
    report = run_case(case_path, pub_path, out_path=report_path)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
