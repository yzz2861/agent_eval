"""Tests for the resumable TAXII 2.1 archive cursor."""
import datetime
import json
import re
from urllib.parse import parse_qs, urlsplit

import pytest
import responses

from taxii2client import MEDIA_TYPE_TAXII_V21
from taxii2client.exceptions import (
    InvalidArgumentsError, TAXIIServiceException, ValidationError,
)
from taxii2client.v21 import Collection
from taxii2client.v21.archive import (
    ArchiveCursor, ManifestArchive, REASON_OBJECT_NOT_FOUND,
    REASON_TRANSPORT_ERROR, STATUS_ARCHIVED, STATUS_MISSING, STATUS_PENDING,
)

COLLECTION_ID = "91a7b528-80eb-42ed-a74d-c6fbd5a26116"
COLLECTION_URL = (
    "https://example.com/api1/collections/" + COLLECTION_ID + "/"
)
OBJECTS_URL = COLLECTION_URL + "objects/"
MANIFEST_URL = COLLECTION_URL + "manifest/"

# Four objects all joined to the collection at the same second.  The last one
# is the object that can be silently lost when the run stops on the page
# boundary inside this timestamp group.
SAME_DATE_ADDED = "2020-01-01T00:00:00.000Z"
OBJECT_IDS = [
    "indicator--00000000-0000-0000-0000-00000000000{}".format(i)
    for i in range(1, 5)
]
OBJECT_VERSIONS = [
    "2019-12-31T23:59:5{}.000Z".format(i) for i in range(4)
]

COLLECTION_INFO = {
    "id": COLLECTION_ID,
    "title": "Archived Collection",
    "can_read": True,
    "can_write": False,
    "media_types": ["application/stix+json;version=2.1"],
}


class FakeTaxiiServer(object):
    """In-memory TAXII 2.1 server serving a fixed manifest/object data set."""

    def __init__(self, manifest_pages, objects_by_key,
                 fail_object_keys=None, fail_manifest_after=None):
        self.manifest_pages = manifest_pages
        self.objects_by_key = objects_by_key
        self.fail_object_keys = set(fail_object_keys or [])
        # Number of successful manifest responses before the next one fails.
        self.fail_manifest_after = fail_manifest_after
        self.manifest_requests = []
        self.object_requests = []
        self.manifest_successes = 0

    def manifest_callback(self, request):
        params = self._params(request)
        self.manifest_requests.append(params)

        if self.fail_manifest_after is not None and \
                self.manifest_successes >= self.fail_manifest_after:
            return (500, {}, json.dumps({"title": "forced manifest failure"}))

        page_index = self.manifest_successes
        self.manifest_successes += 1
        body = self.manifest_pages[min(page_index, len(self.manifest_pages) - 1)]
        return (200, {"Content-Type": MEDIA_TYPE_TAXII_V21}, json.dumps(body))

    def object_callback(self, request):
        params = self._params(request)
        object_id = request.path_url.split("/objects/", 1)[1].split("/", 1)[0]
        version = params.get("match[version]", [None])[0]
        self.object_requests.append({"id": object_id, "version": version,
                                     "params": params})

        key = (object_id, version)
        if key in self.fail_object_keys:
            return (503, {}, json.dumps({"title": "forced object failure"}))

        obj = self.objects_by_key.get(key)
        if obj is None:
            body = {"objects": []}
        else:
            body = {"objects": [obj]}
        return (200, {"Content-Type": MEDIA_TYPE_TAXII_V21}, json.dumps(body))

    @staticmethod
    def _params(request):
        parsed = urlsplit(request.path_url)
        multi = parse_qs(parsed.query)
        return multi


def stix_object(object_id, version):
    return {
        "type": object_id.split("--", 1)[0],
        "id": object_id,
        "spec_version": "2.1",
        "created": version,
        "modified": version,
        "pattern": "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
        "pattern_type": "stix",
        "valid_from": version,
    }


def manifest_entry(object_id, version, date_added=SAME_DATE_ADDED):
    return {
        "id": object_id,
        "date_added": date_added,
        "version": version,
        "media_type": "application/stix+json;version=2.1",
    }


def build_objects():
    return {
        (object_id, version): stix_object(object_id, version)
        for object_id, version in zip(OBJECT_IDS, OBJECT_VERSIONS)
    }


def build_manifest_pages():
    entries = [
        manifest_entry(object_id, version)
        for object_id, version in zip(OBJECT_IDS, OBJECT_VERSIONS)
    ]
    first_page = {"more": True, "next": "cursor-to-page-2",
                  "objects": entries[:3]}
    second_page = {"more": False, "objects": entries[3:]}
    return [first_page, second_page]


def register_server(server):
    responses.add_callback(
        responses.GET, MANIFEST_URL,
        callback=server.manifest_callback,
        content_type=MEDIA_TYPE_TAXII_V21,
    )
    responses.add_callback(
        responses.GET,
        re.compile(r"^" + re.escape(OBJECTS_URL) + r"[^/]+/\?"),
        callback=server.object_callback,
        content_type=MEDIA_TYPE_TAXII_V21,
    )


def make_collection():
    return Collection(COLLECTION_URL, collection_info=COLLECTION_INFO)


def make_cursor():
    return ArchiveCursor(COLLECTION_ID, COLLECTION_URL)


@responses.activate
def test_interrupted_tie_group_resumes_and_fills_the_gap():
    # First run: both manifest pages are readable, but the service fails on
    # the get_object call for the final same-timestamp object.
    server = FakeTaxiiServer(
        manifest_pages=build_manifest_pages(),
        objects_by_key=build_objects(),
        fail_object_keys=[(OBJECT_IDS[3], OBJECT_VERSIONS[3])],
    )
    register_server(server)
    collection = make_collection()
    cursor = make_cursor()
    archive = ManifestArchive(collection, cursor, per_request=3)

    with pytest.raises(TAXIIServiceException):
        archive.run()

    # The three reachable entries are confirmed; the last object is left
    # pending with an explicit transport ticket and the watermark stays put.
    assert len(archive.objects) == 3
    assert cursor.watermark is None
    assert set(obj["id"] for obj in archive.objects) == set(OBJECT_IDS[:3])
    held_back = cursor.get_entry(OBJECT_IDS[3], OBJECT_VERSIONS[3])
    assert held_back["status"] == STATUS_PENDING
    assert held_back["reason"] == REASON_TRANSPORT_ERROR
    assert held_back["date_added"] == SAME_DATE_ADDED
    assert held_back["version"] == OBJECT_VERSIONS[3]
    assert "503" in held_back["detail"]

    # Second run against the now-healthy service.
    server.fail_object_keys.clear()
    resumed_archive = ManifestArchive(collection, cursor, per_request=3)
    resumed_archive.run()

    # The rerun starts at the (unmoved) watermark and only stores the
    # previously held-back object; the archived versions are not re-stored.
    resumed_ids = [obj["id"] for obj in resumed_archive.objects]
    assert resumed_ids == [OBJECT_IDS[3]]
    fourth_requests = [
        req for req in server.object_requests if req["id"] == OBJECT_IDS[3]
    ]
    # One failed attempt on the first run, one successful retry on the rerun.
    assert len(fourth_requests) == 2
    assert fourth_requests[0]["version"] == OBJECT_VERSIONS[3]
    assert fourth_requests[1]["version"] == OBJECT_VERSIONS[3]
    assert cursor.watermark == SAME_DATE_ADDED
    assert all(
        record["status"] == STATUS_ARCHIVED
        for record in cursor.entries.values()
    )
    assert list(cursor.pending_entries()) == []

    # The rerun still scans the boundary timestamp, because added_after is
    # exclusive and the watermark never advanced past the shared timestamp.
    assert all(req.get("added_after") is None
               for req in server.manifest_requests)
    assert cursor.get_entry(OBJECT_IDS[3], OBJECT_VERSIONS[3])[
        "status"] == STATUS_ARCHIVED


@responses.activate
def test_manifest_page_failure_keeps_watermark_at_shared_timestamp():
    # The second manifest page, still inside the same date_added group,
    # never arrives.  Nothing on that page can be ticketed, so the watermark
    # must not move at all.
    server = FakeTaxiiServer(
        manifest_pages=build_manifest_pages(),
        objects_by_key=build_objects(),
        fail_manifest_after=1,
    )
    register_server(server)
    cursor = make_cursor()
    archive = ManifestArchive(make_collection(), cursor, per_request=3)

    with pytest.raises(TAXIIServiceException):
        archive.run()

    assert len(archive.objects) == 3
    assert cursor.watermark is None
    assert OBJECT_IDS[3] not in [req["id"] for req in server.object_requests]

    server.fail_manifest_after = None
    ManifestArchive(make_collection(), cursor, per_request=3).run()
    assert cursor.watermark == SAME_DATE_ADDED
    assert cursor.get_entry(OBJECT_IDS[3], OBJECT_VERSIONS[3])[
        "status"] == STATUS_ARCHIVED


@responses.activate
def test_explicit_missing_ticket_allows_watermark_to_advance():
    objects = build_objects()
    missing_key = (OBJECT_IDS[2], OBJECT_VERSIONS[2])
    del objects[missing_key]
    server = FakeTaxiiServer(
        manifest_pages=build_manifest_pages(),
        objects_by_key=objects,
    )
    register_server(server)

    cursor = make_cursor()
    archive = ManifestArchive(make_collection(), cursor, per_request=3)
    archive.run()

    missing = cursor.get_entry(*missing_key)
    assert missing["status"] == STATUS_MISSING
    assert missing["reason"] == REASON_OBJECT_NOT_FOUND
    assert cursor.watermark == SAME_DATE_ADDED
    assert len(archive.objects) == 3

    # A later run still queries the boundary timestamp (added_after is
    # exclusive) and can resolve the ticket if the object appears.
    objects[missing_key] = stix_object(*missing_key)
    rerun = ManifestArchive(make_collection(), cursor, per_request=3)
    rerun.run()

    assert [obj["id"] for obj in rerun.objects] == [missing_key[0]]
    assert cursor.get_entry(*missing_key)["status"] == STATUS_ARCHIVED
    boundary_requests = [
        req for req in server.manifest_requests
        if req.get("added_after") == [SAME_DATE_ADDED]
    ]
    assert boundary_requests


def test_resolved_missing_ticket_cannot_clobber_newer_version():
    object_id = OBJECT_IDS[0]
    old_version = "2019-01-01T00:00:00.000Z"
    new_version = "2020-01-01T00:00:00.000Z"
    cursor = make_cursor()

    cursor.remember(manifest_entry(object_id, old_version),
                    STATUS_MISSING, reason=REASON_OBJECT_NOT_FOUND)
    cursor.remember(manifest_entry(object_id, new_version), STATUS_ARCHIVED)

    with pytest.raises(ValidationError):
        cursor.remember(manifest_entry(object_id, old_version),
                        STATUS_ARCHIVED)

    # The ticket and the newer archive both survive the refused transition.
    assert cursor.get_entry(object_id, old_version)["status"] == STATUS_MISSING
    assert cursor.get_entry(object_id, new_version)["status"] == STATUS_ARCHIVED


@responses.activate
def test_archiver_keeps_missing_ticket_when_newer_version_is_archived():
    object_id = OBJECT_IDS[0]
    old_version = "2019-01-01T00:00:00.000Z"
    new_version = "2020-01-01T00:00:00.000Z"
    pages = [{
        "more": False,
        "objects": [
            manifest_entry(object_id, old_version),
            manifest_entry(object_id, new_version),
        ],
    }]
    objects = {
        (object_id, new_version): stix_object(object_id, new_version),
    }
    server = FakeTaxiiServer(manifest_pages=pages, objects_by_key=objects)
    register_server(server)

    cursor = make_cursor()
    archive = ManifestArchive(make_collection(), cursor, per_request=10)
    archive.run()

    # The old version cannot be confirmed yet, so it stays an explicit
    # missing ticket while the newer version is archived normally.
    assert cursor.get_entry(object_id, old_version)["status"] == STATUS_MISSING
    assert cursor.get_entry(object_id, new_version)["status"] == STATUS_ARCHIVED

    # The server catches up and now serves the old version.  The archiver
    # must refuse to resolve the ticket rather than disturb the newer update.
    server.objects_by_key[(object_id, old_version)] = \
        stix_object(object_id, old_version)
    with pytest.raises(ValidationError):
        ManifestArchive(make_collection(), cursor, per_request=10).run()

    assert cursor.get_entry(object_id, old_version)["status"] == STATUS_MISSING
    assert cursor.get_entry(object_id, new_version)["status"] == STATUS_ARCHIVED
    assert [obj["id"] for obj in archive.objects] == [object_id]


def test_watermark_refuses_to_move_with_unresolved_page_entry():
    cursor = make_cursor()
    entries = [
        manifest_entry(OBJECT_IDS[0], OBJECT_VERSIONS[0]),
        manifest_entry(OBJECT_IDS[1], OBJECT_VERSIONS[1]),
    ]
    cursor.remember(entries[0], STATUS_ARCHIVED)
    cursor.remember(entries[1], STATUS_PENDING,
                    reason=REASON_TRANSPORT_ERROR)

    with pytest.raises(ValidationError):
        cursor.advance_watermark(entries)

    assert cursor.watermark is None

    with pytest.raises(ValidationError):
        cursor.verify_page_resolved(entries)

    cursor.remember(entries[1], STATUS_MISSING,
                    reason=REASON_OBJECT_NOT_FOUND)
    cursor.verify_page_resolved(entries)
    cursor.advance_watermark(entries)
    assert cursor.watermark == SAME_DATE_ADDED


def test_cursor_preserves_identity_and_both_dimensions_across_save_load(tmp_path):
    cursor = make_cursor()
    entry = manifest_entry(OBJECT_IDS[0], OBJECT_VERSIONS[0])
    cursor.remember(entry, STATUS_ARCHIVED)
    cursor.advance_watermark([entry])

    path = str(tmp_path / "cursor.json")
    cursor.save(path)
    restored = ArchiveCursor.load(path, COLLECTION_ID, COLLECTION_URL)

    assert restored.collection_id == COLLECTION_ID
    assert restored.collection_url == COLLECTION_URL
    assert restored.watermark == SAME_DATE_ADDED
    record = restored.get_entry(OBJECT_IDS[0], OBJECT_VERSIONS[0])
    assert record["date_added"] == SAME_DATE_ADDED
    assert record["version"] == OBJECT_VERSIONS[0]
    assert record["status"] == STATUS_ARCHIVED

    with pytest.raises(ValidationError):
        ArchiveCursor.load(path, "other-collection-id", COLLECTION_URL)


@responses.activate
def test_run_resumes_from_a_persisted_cursor_file(tmp_path):
    server = FakeTaxiiServer(
        manifest_pages=build_manifest_pages(),
        objects_by_key=build_objects(),
        fail_object_keys=[(OBJECT_IDS[3], OBJECT_VERSIONS[3])],
    )
    register_server(server)
    cursor_path = str(tmp_path / "collection-cursor.json")

    first_cursor = ArchiveCursor(COLLECTION_ID, COLLECTION_URL)
    with pytest.raises(TAXIIServiceException):
        ManifestArchive(make_collection(), first_cursor, per_request=3).run()
    first_cursor.save(cursor_path)

    server.fail_object_keys.clear()
    resumed_cursor = ArchiveCursor.load(
        cursor_path, COLLECTION_ID, COLLECTION_URL,
    )
    resumed = ManifestArchive(make_collection(), resumed_cursor, per_request=3)
    resumed.run()

    assert [obj["id"] for obj in resumed.objects] == [OBJECT_IDS[3]]
    assert resumed_cursor.watermark == SAME_DATE_ADDED
    on_disk = json.loads(open(cursor_path).read())
    assert on_disk["collection_id"] == COLLECTION_ID
    assert len(on_disk["entries"]) == 4

    resumed_cursor.save(cursor_path)
    final_state = json.loads(open(cursor_path).read())
    assert final_state["watermark"] == SAME_DATE_ADDED
    assert all(entry["status"] == STATUS_ARCHIVED
               for entry in final_state["entries"])


def test_archive_rejects_cursor_from_another_collection():
    foreign_cursor = ArchiveCursor("other-collection-id", COLLECTION_URL)
    with pytest.raises(InvalidArgumentsError):
        ManifestArchive(make_collection(), foreign_cursor)


def test_datetime_watermark_is_accepted_as_added_after():
    # Smoke-check the mapping used by the client rather than the archive's
    # string storage directly.
    from taxii2client.common import _filter_kwargs_to_query_params

    params = _filter_kwargs_to_query_params({
        "added_after": datetime.datetime(2020, 1, 1, 0, 0, 0),
    })
    assert params == {"added_after": "2020-01-01T00:00:00Z"}
