"""Forensic review of OpenPGP-signed sealed notices."""

import argparse
import enum
import json
from dataclasses import dataclass
from datetime import datetime, timezone

import pgpy


def _parse_dt(value):
    if value is None:
        return None
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _fmt(dt):
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat()
class Assessment(enum.Enum):
    """How the claimed signing time holds up against external evidence."""

    PROVEN_BEFORE_APPROVAL = "proven_before_approval"
    CLAIM_CONTRADICTED = "claim_contradicted"
    CORROBORATED = "corroborated"
    SELF_DECLARED_ONLY = "self_declared_only"
    SIGNATURE_INVALID = "signature_invalid"


@dataclass
class EvidenceWindow:
    """An externally observed time window for a notice.

    start is the earliest moment the outside evidence proves the
    notice already existed; end bounds the observation when the
    source only gives an interval.
    """

    kind: str
    start: datetime
    end: datetime = None
    source: str = ""

    def __post_init__(self):
        if self.end is None:
            self.end = self.start

    @classmethod
    def from_dict(cls, kind, data):
        if data is None:
            return None
        window = data.get("window", data)
        return cls(
            kind=kind,
            start=_parse_dt(window["start"]),
            end=_parse_dt(window.get("end")),
            source=data.get("source", ""),
        )

    def to_dict(self):
        return {
            "kind": self.kind,
            "window": {"start": _fmt(self.start), "end": _fmt(self.end)},
            "source": self.source,
        }


@dataclass
class ApprovalWindow:
    """Caller-supplied range inside which signing was permitted."""

    not_before: datetime
    not_after: datetime
    issued_by: str = ""

    @classmethod
    def from_dict(cls, data):
        return cls(
            not_before=_parse_dt(data["not_before"]),
            not_after=_parse_dt(data["not_after"]),
            issued_by=data.get("issued_by", ""),
        )

    def contains(self, moment):
        return self.not_before <= moment <= self.not_after

    def to_dict(self):
        return {
            "not_before": _fmt(self.not_before),
            "not_after": _fmt(self.not_after),
            "issued_by": self.issued_by,
        }


@dataclass
class NoticeReview:
    """Archived forensic record for one signed notice."""

    notice_id: str
    signature_valid: bool
    signer: str = ""
    claimed_signing_time: datetime = None
    external_receipt: EvidenceWindow = None
    independent_preservation: EvidenceWindow = None
    claimed_within_approved_window: bool = False
    assessment: Assessment = Assessment.SELF_DECLARED_ONLY
    assessment_detail: str = ""

    def to_dict(self):
        return {
            "notice_id": self.notice_id,
            "signature_valid": self.signature_valid,
            "signer": self.signer,
            "claimed_signing_time": _fmt(self.claimed_signing_time),
            "external_receipt": (
                self.external_receipt.to_dict() if self.external_receipt else None
            ),
            "independent_preservation": (
                self.independent_preservation.to_dict()
                if self.independent_preservation
                else None
            ),
            "claimed_within_approved_window": self.claimed_within_approved_window,
            "assessment": self.assessment.value,
            "assessment_detail": self.assessment_detail,
        }
def _evidence_windows(receipt, preservation):
    return [w for w in (receipt, preservation) if w is not None]


def review_notice(notice_id, notice_bytes, signature_bytes, key,
                  approval, external_receipt=None,
                  independent_preservation=None):
    """Review one signed notice against its evidence and the approval window.

    external_receipt and independent_preservation are EvidenceWindow
    instances (or None when no such external record exists).  The
    returned NoticeReview keeps the claimed signing time and each
    external window as separate fields so the archive never merges them.
    """
    review = NoticeReview(
        notice_id=notice_id,
        signature_valid=False,
        external_receipt=external_receipt,
        independent_preservation=independent_preservation,
    )

    signature = pgpy.PGPSignature.from_blob(signature_bytes)
    review.claimed_signing_time = signature.created
    review.signer = signature.signer_fingerprint or signature.signer

    try:
        verification = key.verify(notice_bytes, signature)
        review.signature_valid = bool(verification)
    except Exception as exc:  # unverifiable signatures must still be archived
        review.assessment = Assessment.SIGNATURE_INVALID
        review.assessment_detail = "signature could not be verified: {}".format(exc)
        return review

    if not review.signature_valid:
        review.assessment = Assessment.SIGNATURE_INVALID
        review.assessment_detail = "OpenPGP signature does not verify"
        return review

    claimed = review.claimed_signing_time
    review.claimed_within_approved_window = approval.contains(claimed)

    windows = _evidence_windows(external_receipt, independent_preservation)
    earliest_proof = min((w.start for w in windows), default=None)

    if earliest_proof is not None and earliest_proof < approval.not_before:
        review.assessment = Assessment.PROVEN_BEFORE_APPROVAL
        review.assessment_detail = (
            "external evidence proves the notice already existed at {}, "
            "before the approval window opened at {}; the claimed signing "
            "time {} is contradicted".format(
                _fmt(earliest_proof),
                _fmt(approval.not_before),
                _fmt(claimed),
            )
        )
    elif earliest_proof is not None and earliest_proof < claimed:
        review.assessment = Assessment.CLAIM_CONTRADICTED
        review.assessment_detail = (
            "external evidence places the notice at {}, earlier than its own "
            "claimed signing time {}".format(_fmt(earliest_proof), _fmt(claimed))
        )
    elif not windows:
        review.assessment = Assessment.SELF_DECLARED_ONLY
        review.assessment_detail = (
            "no external receipt or independent preservation record; the "
            "signing time rests solely on the signer's own declaration"
        )
    else:
        review.assessment = Assessment.CORROBORATED
        review.assessment_detail = (
            "external evidence is consistent with the claimed signing time {}"
            .format(_fmt(claimed))
        )

    return review


def build_report(reviews, approval, generated_at=None):
    """Assemble the archival report, preserving per-notice distinctions."""
    if generated_at is None:
        generated_at = datetime.now(timezone.utc)
    return {
        "report": "sealed-notice-forensic-review",
        "generated_at": _fmt(generated_at),
        "approved_window": approval.to_dict(),
        "notices": [r.to_dict() for r in reviews],
    }
def _load_case(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def run_case(case_path, key_path, out_path=None):
    case = _load_case(case_path)
    approval = ApprovalWindow.from_dict(case["approved_window"])
    key, _ = pgpy.PGPKey.from_file(key_path)

    reviews = []
    for entry in case["notices"]:
        with open(entry["notice"], "rb") as fh:
            notice_bytes = fh.read()
        with open(entry["signature"], "rb") as fh:
            signature_bytes = fh.read()
        reviews.append(review_notice(
            entry["id"],
            notice_bytes,
            signature_bytes,
            key,
            approval,
            external_receipt=EvidenceWindow.from_dict(
                "external_receipt", entry.get("external_receipt")),
            independent_preservation=EvidenceWindow.from_dict(
                "independent_preservation", entry.get("independent_preservation")),
        ))

    report = build_report(reviews, approval)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Forensic re-review of OpenPGP-signed sealed notices")
    parser.add_argument("case",
                        help="JSON case file: approval window, notices, evidence")
    parser.add_argument("--key", required=True, help="ASCII-armored public key")
    parser.add_argument("--out", help="write the archival report JSON here")
    args = parser.parse_args(argv)

    report = run_case(args.case, args.key, args.out)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
