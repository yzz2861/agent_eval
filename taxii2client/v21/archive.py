"""Resumable archiving of TAXII 2.1 Collections.

The TAXII 2.1 ``added_after`` filter is strictly exclusive: a client which
only remembers the newest ``date_added`` timestamp it has seen can silently
lose objects when several objects share the same ``date_added`` and the sync
is interrupted in the middle of that group (e.g. across two pages).

The machinery in this module drives a Collection from its ``manifest`` and
``get_objects`` endpoints while persisting an :class:`ArchiveCursor`.  The
cursor keeps both dimensions TAXII exposes for a manifest entry -- the
server-side ``date_added`` (the watermark) and the STIX object ``version`` --
together with the identity of the collection they belong to.  A fetched page
only passes the page gate once every entry on it is backed by a confirmed
object or an explicit "missing" ticket, and the watermark is committed after
the full manifest has been read, so a crash mid-page can never leave a gap.
"""
from __future__ import unicode_literals

import json
import logging

import requests
import six

from ..exceptions import InvalidArgumentsError, TAXIIServiceException, ValidationError
from . import as_pages

log = logging.getLogger(__name__)

# Reasons recorded on pending / missing entries.
REASON_OBJECT_NOT_FOUND = "object_not_found"
REASON_VERSION_NOT_FOUND = "version_not_found"
REASON_TRANSPORT_ERROR = "transport_error"

STATUS_ARCHIVED = "archived"
STATUS_MISSING = "missing"
STATUS_PENDING = "pending"


class ArchiveCursor(object):
    """Persistent bookkeeping for a resumable archive of one Collection.

    The state is JSON-serializable so that it can be written to disk between
    sync runs.  It contains:

    * ``collection_id``/``collection_url``: identity of the collection the
      state belongs to.  A cursor must never be replayed against another
      collection.
    * ``watermark``: the newest fully processed ``date_added`` value.  It is
      only advanced once the whole manifest has been read and every fetched
      page has passed its resolution gate.
    * ``entries``: one record per manifest entry, keyed by
      ``(object id, STIX version)``, carrying the entry's ``date_added``,
      its status, and for unresolved/missing entries a human-readable reason.

    Args:
        collection_id (str): id of the TAXII Collection this cursor tracks.
        collection_url (str): URL of the TAXII Collection this cursor tracks.
        state (dict): Previously persisted cursor state, if resuming a run
            (optional).

    """

    def __init__(self, collection_id, collection_url, state=None):
        self.collection_id = collection_id
        self.collection_url = collection_url.rstrip("/") + "/"
        self.watermark = None
        # Keys are tuples (object_id, version); values are entry records.
        self.entries = {}

        if state is not None:
            self.load_state(state)

    @staticmethod
    def _entry_key(manifest_entry):
        return manifest_entry["id"], manifest_entry["version"]

    def load_state(self, state):
        """Replace this cursor's state with a previously persisted mapping.

        Raises:
            ValidationError: if the persisted state belongs to another
                collection or is malformed.

        """
        if not isinstance(state, dict):
            raise ValidationError("Cursor state must be a JSON object")

        if state.get("collection_id") != self.collection_id or \
                state.get("collection_url") != self.collection_url:
            raise ValidationError(
                "Cursor state is for collection '{}/{}', not '{}/{}'".format(
                    state.get("collection_id"), state.get("collection_url"),
                    self.collection_id, self.collection_url,
                ),
            )

        self.watermark = state.get("watermark")
        entries = {}
        for raw_entry in state.get("entries", []):
            try:
                key = (raw_entry["id"], raw_entry["version"])
            except (KeyError, TypeError):
                raise ValidationError("Cursor entries require 'id' and 'version'")
            entries[key] = dict(raw_entry)
        self.entries = entries

    def to_state(self):
        """Return a JSON-serializable snapshot of this cursor's state."""
        return {
            "collection_id": self.collection_id,
            "collection_url": self.collection_url,
            "watermark": self.watermark,
            "entries": [self.entries[key] for key in sorted(self.entries)],
        }

    def save(self, path):
        """Persist the cursor state to ``path`` as JSON."""
        with open(path, "w") as fd:
            json.dump(self.to_state(), fd, ensure_ascii=False, indent=2,
                      sort_keys=True)

    @classmethod
    def load(cls, path, collection_id, collection_url):
        """Load a cursor previously written with :meth:`save`.

        Args:
            path (str): Path to the JSON state file.
            collection_id (str): id of the collection the caller is about to
                sync.  Must match the persisted identity.
            collection_url (str): URL of the collection the caller is about
                to sync.  Must match the persisted identity.

        """
        with open(path, "r") as fd:
            state = json.load(fd)
        return cls(collection_id, collection_url, state)

    def get_entry(self, object_id, version):
        """Return the record for ``(object_id, version)`` if known."""
        return self.entries.get((object_id, version))

    def remember(self, manifest_entry, status, reason=None, detail=None):
        """Create or update the record for a manifest entry.

        A transition out of the missing state is refused if the cursor
        already holds a newer archived version of the same object: the
        "ticket" must never overwrite a more recent update.

        Args:
            manifest_entry (dict): a TAXII manifest resource, with at least
                ``id``, ``version`` and ``date_added`` fields.
            status (str): one of the ``STATUS_*`` constants.
            reason (str): why the entry is not (yet) archived (optional).
            detail (str): free-form additional information, e.g. the error
                message from a failed request (optional).

        """
        key = self._entry_key(manifest_entry)
        object_id, version = key
        existing = self.entries.get(key)

        if existing is not None and existing.get("status") == STATUS_MISSING \
                and status == STATUS_ARCHIVED and \
                self._has_newer_archived(object_id, version):
            raise ValidationError(
                "Refusing to resolve missing ticket for object '{}' version '{}': "
                "a newer version of the object is already archived".format(object_id, version),
            )

        record = dict(manifest_entry)
        record["status"] = status
        if reason is not None:
            record["reason"] = reason
        elif existing is not None and status != STATUS_MISSING:
            record.pop("reason", None)
        if detail is not None:
            record["detail"] = detail
        elif existing is not None:
            record.pop("detail", None)

        self.entries[key] = record

    def _has_newer_archived(self, object_id, version):
        for (entry_id, entry_version), record in six.iteritems(self.entries):
            if entry_id == object_id and record.get("status") == STATUS_ARCHIVED \
                    and entry_version > version:
                return True
        return False

    def pending_entries(self):
        """Yield every entry record which has not been archived yet."""
        for record in six.itervalues(self.entries):
            if record["status"] != STATUS_ARCHIVED:
                yield record

    def advance_watermark(self, page_entries):
        """Move the watermark past a fully resolved manifest page.

        Callers must gate each page with :meth:`verify_page_resolved` first;
        this method deliberately performs the same check defensively, so the
        watermark can never pass a pending entry.

        Args:
            page_entries (list): the manifest entries of one fetched page.

        Raises:
            ValidationError: if any page entry is still pending.

        """
        page_keys = [self._entry_key(entry) for entry in page_entries]
        for key in page_keys:
            record = self.entries.get(key)
            if record is None or record["status"] == STATUS_PENDING:
                raise ValidationError(
                    "Cannot advance the watermark: manifest entry {} is not "
                    "fully resolved".format(key),
                )

        page_dates = [entry["date_added"] for entry in page_entries]
        newest = max(page_dates)
        if self.watermark is None or newest > self.watermark:
            self.watermark = newest

    def verify_page_resolved(self, page_entries):
        """Assert that every entry of a manifest page has been settled.

        A page is settled once each of its entries is either archived or
        carries an explicit missing ticket.  Pending entries (typically
        transport failures) fail the gate, which keeps the watermark below the
        page and forces a re-fetch on the next run.

        Raises:
            ValidationError: if any page entry is unknown or still pending.

        """
        for entry in page_entries:
            key = self._entry_key(entry)
            record = self.entries.get(key)
            if record is None or record["status"] == STATUS_PENDING:
                raise ValidationError(
                    "Manifest page is not fully resolved: entry {} has no "
                    "confirmed object or missing ticket".format(key),
                )


class ManifestArchive(object):
    """Resumable archiver for a single TAXII 2.1 Collection.

    Each :meth:`run` pages through the collection's manifest (starting at the
    cursor's watermark), confirms every manifest entry against
    ``get_objects``, and only then moves the watermark.  Confirmed STIX
    objects are handed to ``sink`` (by default an in-memory list); transport
    errors leave an entry pending and abort the run so a later invocation
    picks up exactly where it stopped.

    Args:
        collection: a :class:`taxii2client.v21.Collection` with read access.
        cursor (ArchiveCursor): cursor tracking this collection's progress.
        sink (callable): invoked once per confirmed STIX object dict with the
            object as its only argument (optional).
        per_request (int): page size for manifest/object requests (optional).

    """

    def __init__(self, collection, cursor, sink=None, per_request=100):
        if cursor.collection_id != collection.id or \
                cursor.collection_url != collection.url:
            raise InvalidArgumentsError(
                "Cursor is for collection '{}/{}' but the given Collection is "
                "'{}/{}'".format(
                    cursor.collection_id, cursor.collection_url,
                    collection.id, collection.url,
                ),
            )

        self.collection = collection
        self.cursor = cursor
        self.per_request = per_request
        self._objects = []
        self.sink = sink or self._objects.append

    @property
    def objects(self):
        """All objects archived into the default in-memory sink."""
        return list(self._objects)

    def run(self):
        """Perform one (resumable) archive pass.

        Returns:
            ArchiveCursor: the updated cursor, already holding any state
            collected during this run (persist it before the next run).

        Raises:
            TAXIIServiceException: if a transport call fails.  The cursor is
                left in a consistent state with the failing entry pending and
                the watermark unmoved, so calling :meth:`run` again resumes
                without gaps.

        """
        self._retry_unresolved_entries()

        manifest_kwargs = {}
        if self.cursor.watermark is not None:
            # Re-fetch the boundary timestamp: added_after is exclusive, but
            # the watermark is only advanced once an entire timestamp group
            # is resolved, so anything still returned at equality was missed
            # by an earlier interrupted run and is still needed.
            manifest_kwargs["added_after"] = self.cursor.watermark

        seen_pages = []
        try:
            pages = as_pages(self.collection.get_manifest,
                             per_request=self.per_request, **manifest_kwargs)
            for page in pages:
                page_entries = page.get("objects", [])
                if not page_entries:
                    continue

                for manifest_entry in page_entries:
                    self._process_entry(manifest_entry)

                # Page gate: every entry must be confirmed or carry an
                # explicit ticket before the run is allowed to commit any
                # progress for this page.
                self.cursor.verify_page_resolved(page_entries)
                seen_pages.append(page_entries)
        except requests.RequestException as exc:
            raise TAXIIServiceException(
                "Archive interrupted while reading the manifest: {}".format(exc),
            )

        # The watermark is committed once, only after the whole manifest has
        # been read successfully: advancing it page by page would skip
        # same-timestamp objects living on later, unread pages.
        for page_entries in seen_pages:
            self.cursor.advance_watermark(page_entries)

        return self.cursor

    def _retry_unresolved_entries(self):
        # Replay entries left over from a previous run before opening new
        # manifest pages.  Pending entries (transport failures) would block
        # the watermark forever; missing tickets get another chance in case
        # the server has since caught up and published the object.
        for record in list(self.cursor.pending_entries()):
            self._process_entry(record)

    def _process_entry(self, manifest_entry):
        key = (manifest_entry["id"], manifest_entry["version"])
        existing = self.cursor.entries.get(key)
        if existing is not None and existing.get("status") == STATUS_ARCHIVED:
            # An object version is immutable: nothing to do.
            return

        try:
            stix_object = self._fetch_object(
                manifest_entry["id"], manifest_entry["version"],
            )
        except _ObjectMissing as missing:
            self.cursor.remember(
                manifest_entry, STATUS_MISSING,
                reason=missing.reason, detail=missing.detail,
            )
            log.warning(
                "Manifest entry %s could not be confirmed; recording missing "
                "ticket: %s", key, missing.reason,
            )
            return
        except requests.RequestException as exc:
            self.cursor.remember(
                manifest_entry, STATUS_PENDING,
                reason=REASON_TRANSPORT_ERROR, detail=str(exc),
            )
            raise TAXIIServiceException(
                "Archive interrupted at {}: {}".format(key, exc),
            )

        self._store_object(manifest_entry, stix_object)

    def _fetch_object(self, object_id, version):
        envelope = self.collection.get_object(object_id, version=version)
        candidates = [
            obj for obj in envelope.get("objects", [])
            if obj.get("id") == object_id and obj.get("modified") == version
        ]
        if not candidates:
            if not envelope.get("objects"):
                raise _ObjectMissing(
                    REASON_OBJECT_NOT_FOUND,
                    "get_object returned no objects for id '{}' version '{}'"
                    .format(object_id, version),
                )
            raise _ObjectMissing(
                REASON_VERSION_NOT_FOUND,
                "get_object did not include version '{}' of object '{}'"
                .format(version, object_id),
            )
        return candidates[0]

    def _store_object(self, manifest_entry, stix_object):
        # Resolving a missing ticket raises if a newer version of the same
        # object is already archived, so the update can never clobber it.
        self.cursor.remember(manifest_entry, STATUS_ARCHIVED)
        self.sink(stix_object)


class _ObjectMissing(Exception):
    """Internal signal: a manifest entry has no confirmable object."""

    def __init__(self, reason, detail):
        super(_ObjectMissing, self).__init__(detail)
        self.reason = reason
        self.detail = detail
