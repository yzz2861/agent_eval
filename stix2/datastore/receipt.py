"""
Resumable evidence-intake ("receipt") interface for STIX bundle handovers.

Investigators hand over evidence manifests as STIX bundles.  This module
provides a receiver which signs for a bundle only after every object in
it has been reconciled against a pending checklist and the existing data
store:

* Each object is bound to its position within the bundle, the pending
  checklist, and the source of the handover.
* Objects whose ``id``/``modified`` pair already exists in the data
  store with *different* content are quarantined instead of being stored.
* Re-uploading a batch that was already signed for does not produce a
  second receipt.
* If the intake process is interrupted, objects which only reached the
  staging area are not considered signed for; the interrupted batch can
  be resumed by simply submitting it again.
"""

import hashlib
import json
import os

from stix2.base import _STIXBase
from stix2.canonicalization.Canonicalize import canonicalize
from stix2.datastore import DataStoreMixin, make_id
from stix2.parsing import parse
from stix2.serialization import serialize
from stix2.utils import format_datetime, get_timestamp

# Item statuses used while a batch is being reconciled.
STATUS_PENDING = "pending"
STATUS_STORED = "stored"
STATUS_QUARANTINED = "quarantined"


class ReceiptError(Exception):
    """General evidence-intake error."""
    pass


def content_digest(stix_obj):
    """Compute a stable content digest for a STIX object.

    The digest is the SHA-256 hex digest of the JCS-canonicalized JSON
    serialization, so two objects with the same ``id`` and ``modified``
    but different content produce different digests.

    Args:
        stix_obj: A parsed STIX object.

    Returns:
        str: The hex-encoded SHA-256 digest of the object's content.

    """
    canonical = canonicalize(json.loads(serialize(stix_obj)), utf8=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _batch_digest(digests):
    """Compute the identity of a batch from its ordered item digests."""
    return hashlib.sha256("\n".join(digests).encode("utf-8")).hexdigest()


def _extract_objects(bundle):
    """Pull the ordered object list out of a bundle/list/single object."""
    if isinstance(bundle, (dict, _STIXBase)) and bundle.get("type") == "bundle":
        return list(bundle.get("objects", []))
    elif isinstance(bundle, (list, tuple)):
        return list(bundle)
    else:
        return [bundle]


class Receipt(object):
    """A signed receipt for one received batch.

    A receipt only exists once a batch has been fully reconciled and
    committed; it is the proof that the listed items were signed for.

    Attributes:
        data (dict): The receipt content.
        duplicate (bool): True if the batch had already been signed for
            and this is the previously issued receipt.

    """
    def __init__(self, data, duplicate=False):
        self.data = data
        self.duplicate = duplicate

    @property
    def receipt_id(self):
        return self.data["receipt_id"]

    @property
    def batch_digest(self):
        return self.data["batch_digest"]

    @property
    def source(self):
        return self.data["source"]

    @property
    def signed_at(self):
        return self.data["signed_at"]

    @property
    def items(self):
        return self.data["items"]

    @property
    def missing(self):
        return self.data["missing"]

    @property
    def unexpected(self):
        return self.data["unexpected"]

    @property
    def quarantined(self):
        return self.data["quarantined"]

    def to_dict(self):
        """Return the receipt as a plain JSON-serializable dict."""
        return dict(self.data)

    def verify(self, bundle, allow_custom=True, version=None):
        """Verify this receipt against the original bundle.

        Recomputes the content digest of every object in the given
        bundle and compares it, together with the in-bundle order and
        object IDs, against the receipt entries.

        Args:
            bundle: The original STIX bundle (or object list) this
                receipt was issued for.
            allow_custom (bool): Whether to allow custom properties and
                objects when parsing. Default: True.
            version (str): Which STIX2 version to lock the parser to.

        Returns:
            list: Human-readable mismatch descriptions.  An empty list
                means the receipt matches the original bundle.

        """
        objects = _extract_objects(bundle)
        mismatches = []

        if len(objects) != len(self.items):
            mismatches.append(
                "bundle holds %d object(s) but receipt %s covers %d"
                % (len(objects), self.receipt_id, len(self.items)),
            )

        for entry, raw_obj in zip(self.items, objects):
            index = entry["index"]
            obj = raw_obj
            if not isinstance(obj, _STIXBase):
                obj = parse(obj, allow_custom, version=version)

            if obj["id"] != entry["id"]:
                mismatches.append(
                    "item %d: receipt has id %s but bundle has %s"
                    % (index, entry["id"], obj["id"]),
                )

            digest = content_digest(obj)
            if digest != entry["digest"]:
                mismatches.append(
                    "item %d (%s): content digest does not match receipt"
                    % (index, entry["id"]),
                )

        return mismatches


class FileReceiptJournal(object):
    """File-backed journal for the staging area and signed receipts.

    The journal is what makes intake resumable: batches being reconciled
    live in ``sessions/`` (the staging area) and only get a file in
    ``receipts/`` once fully committed.  After a process restart, an
    interrupted batch simply has no receipt, so its staged objects are
    never mistaken for signed ones.

    Args:
        directory (str): Directory holding the journal.  Created if it
            does not exist.

    Attributes:
        directory (str): The journal directory.

    """
    def __init__(self, directory):
        self.directory = directory
        self._sessions_dir = os.path.join(directory, "sessions")
        self._receipts_dir = os.path.join(directory, "receipts")
        os.makedirs(self._sessions_dir, exist_ok=True)
        os.makedirs(self._receipts_dir, exist_ok=True)

    def _read_json(self, path, default):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except IOError:
            return default

    def _write_json(self, path, data):
        tmp_path = path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp_path, path)

    def load_checklist(self):
        """Load the pending checklist: expected IDs and received IDs."""
        return self._read_json(
            os.path.join(self.directory, "checklist.json"),
            {"expected": [], "received": {}},
        )

    def save_checklist(self, checklist):
        self._write_json(
            os.path.join(self.directory, "checklist.json"), checklist,
        )

    def load_session(self, batch_digest):
        """Load the staged (not yet committed) session for a batch."""
        return self._read_json(
            os.path.join(self._sessions_dir, batch_digest + ".json"), None,
        )

    def save_session(self, session):
        self._write_json(
            os.path.join(
                self._sessions_dir, session["batch_digest"] + ".json",
            ),
            session,
        )

    def drop_session(self, batch_digest):
        try:
            os.remove(
                os.path.join(self._sessions_dir, batch_digest + ".json"),
            )
        except OSError:
            pass

    def load_receipt(self, batch_digest):
        """Load the signed receipt for a batch, or None if not signed."""
        return self._read_json(
            os.path.join(self._receipts_dir, batch_digest + ".json"), None,
        )

    def save_receipt(self, receipt):
        self._write_json(
            os.path.join(
                self._receipts_dir, receipt["batch_digest"] + ".json",
            ),
            receipt,
        )

    def load_quarantine(self):
        """Load the log of quarantined (conflicting) objects."""
        return self._read_json(
            os.path.join(self.directory, "quarantine.json"), [],
        )

    def save_quarantine(self, entries):
        self._write_json(
            os.path.join(self.directory, "quarantine.json"), entries,
        )


class BundleReceiver(object):
    """Resumable check-in interface for STIX bundle evidence handovers.

    Args:
        store (DataStoreMixin): The existing data store received objects
            are committed to (and conflicts are checked against).
        journal (FileReceiptJournal): The journal backing the staging
            area, checklist, quarantine log, and signed receipts.
        allow_custom (bool): Whether to allow custom properties and
            objects when parsing. Default: True.
        version (str): Which STIX2 version to lock the parser to.

    """
    def __init__(self, store, journal, allow_custom=True, version=None):
        if not isinstance(store, DataStoreMixin):
            raise TypeError("store must be a DataStoreMixin (source + sink)")
        self.store = store
        self.journal = journal
        self.allow_custom = allow_custom
        self.version = version

    def _parse(self, raw_obj):
        if isinstance(raw_obj, _STIXBase):
            return raw_obj
        return parse(raw_obj, self.allow_custom, version=self.version)

    def _classify(self, stix_obj, digest):
        """Compare an object against the data store.

        Returns:
            tuple: ("absent" | "present" | "conflict", existing digest or
                None).  "conflict" means an object with the same id (and
                ``modified``, for versioned objects) exists in the store
                with different content.

        """
        try:
            versions = self.store.all_versions(stix_obj["id"])
        except Exception as e:
            raise ReceiptError("could not query the data store", e)

        if "modified" in stix_obj:
            for existing in versions:
                if existing.get("modified") == stix_obj["modified"]:
                    existing_digest = content_digest(existing)
                    if existing_digest == digest:
                        return "present", existing_digest
                    return "conflict", existing_digest
            return "absent", None

        for existing in versions:
            existing_digest = content_digest(existing)
            if existing_digest == digest:
                return "present", existing_digest
            return "conflict", existing_digest
        return "absent", None

    def receive(self, bundle, source, expected=None):
        """Sign for a handed-over STIX bundle.

        Reconciles every object against the pending checklist and the
        data store, quarantines conflicts, commits the rest to the
        store, and issues a receipt.  Submitting a batch whose receipt
        already exists returns that receipt flagged as a duplicate,
        without touching the store.  Submitting a batch whose previous
        intake was interrupted resumes it: staged objects are
        re-validated against the store rather than assumed signed.

        Args:
            bundle: The STIX bundle (or object list) being handed over.
            source (str): Identifier of the handover source, bound to
                every receipt entry.
            expected (list): STIX IDs making up the pending checklist.
                Merged into the persistent checklist; IDs never received
                are reported as missing on the receipt.

        Returns:
            Receipt: The signed receipt for this batch.

        """
        objects = [
            self._parse(raw_obj) for raw_obj in _extract_objects(bundle)
        ]
        digests = [content_digest(obj) for obj in objects]
        batch_digest = _batch_digest(digests)

        existing_receipt = self.journal.load_receipt(batch_digest)
        if existing_receipt is not None:
            # Same batch uploaded again: already signed, do not re-sign.
            return Receipt(existing_receipt, duplicate=True)

        checklist = self.journal.load_checklist()
        if expected is not None:
            for stix_id in expected:
                if stix_id not in checklist["expected"]:
                    checklist["expected"].append(stix_id)
            self.journal.save_checklist(checklist)
        expected_ids = set(checklist["expected"])

        session = self.journal.load_session(batch_digest)
        if session is None:
            session = {
                "batch_digest": batch_digest,
                "source": source,
                "items": [
                    {
                        "index": index,
                        "id": obj["id"],
                        "modified": (
                            format_datetime(obj["modified"])
                            if "modified" in obj else None
                        ),
                        "digest": digest,
                        "expected": obj["id"] in expected_ids,
                        "status": STATUS_PENDING,
                    }
                    for index, (obj, digest) in enumerate(
                        zip(objects, digests),
                    )
                ],
                "quarantine": [],
            }
            self.journal.save_session(session)

        # Commit phase.  Every entry is (re-)validated against the
        # current store state, so resuming an interrupted session never
        # trusts staging-area records over what is actually stored.
        for entry, obj in zip(session["items"], objects):
            if entry["status"] == STATUS_QUARANTINED:
                continue

            state, existing_digest = self._classify(obj, entry["digest"])
            if state == "conflict":
                entry["status"] = STATUS_QUARANTINED
                entry["conflict_digest"] = existing_digest
                session["quarantine"].append(
                    {
                        "index": entry["index"],
                        "id": entry["id"],
                        "object": json.loads(serialize(obj)),
                    },
                )
            elif state == "present":
                entry["status"] = STATUS_STORED
                entry["unchanged"] = True
            else:
                self.store.add(obj)
                entry["status"] = STATUS_STORED
                entry["unchanged"] = False
            self.journal.save_session(session)

        for entry in session["items"]:
            if entry["status"] == STATUS_STORED and entry["expected"]:
                checklist["received"][entry["id"]] = batch_digest
        self.journal.save_checklist(checklist)

        quarantined = [
            {
                "index": entry["index"],
                "id": entry["id"],
                "digest": entry["digest"],
                "conflict_digest": entry["conflict_digest"],
            }
            for entry in session["items"]
            if entry["status"] == STATUS_QUARANTINED
        ]
        receipt_data = {
            "type": "evidence-receipt",
            "receipt_id": "receipt--" + make_id(),
            "batch_digest": batch_digest,
            "source": source,
            "signed_at": format_datetime(get_timestamp()),
            "items": [
                {
                    key: entry[key]
                    for key in (
                        "index", "id", "modified", "digest", "expected",
                        "status",
                    )
                }
                for entry in session["items"]
            ],
            "missing": [
                stix_id for stix_id in checklist["expected"]
                if stix_id not in checklist["received"]
            ],
            "unexpected": [
                entry["id"] for entry in session["items"]
                if expected_ids and not entry["expected"]
            ],
            "quarantined": quarantined,
        }

        # The batch is only signed once the receipt exists; the staging
        # area is then cleared so staged objects are never mistaken for
        # signed ones.
        self.journal.save_receipt(receipt_data)
        self.journal.drop_session(batch_digest)

        if quarantined:
            quarantine_log = self.journal.load_quarantine()
            for entry in session["quarantine"]:
                entry["receipt_id"] = receipt_data["receipt_id"]
                quarantine_log.append(entry)
            self.journal.save_quarantine(quarantine_log)

        return Receipt(receipt_data)

    def quarantined(self):
        """List all objects quarantined so far, across batches."""
        return self.journal.load_quarantine()
