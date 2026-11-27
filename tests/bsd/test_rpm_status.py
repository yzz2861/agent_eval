from __future__ import annotations

import io
import struct

from dissect.database.bsd.c_db import c_db
from dissect.database.bsd.db import DB
from dissect.database.bsd.tools.c_rpm import c_rpm
from dissect.database.bsd.tools.rpm import PackageDatabase, Packages

PAGE_SIZE = 512


def _meta(*, root: int = 1, last_pgno: int = 1, flags: int = 0, count: int = 0) -> bytes:
    buf = bytearray(PAGE_SIZE)
    struct.pack_into("<I", buf, 12, c_db.DB_BTREEMAGIC)
    struct.pack_into("<I", buf, 16, c_db.DB_BTREEVERSION)
    struct.pack_into("<I", buf, 20, PAGE_SIZE)
    buf[25] = c_db.P_BTREEMETA
    struct.pack_into("<I", buf, 32, last_pgno)
    struct.pack_into("<I", buf, 40, count)
    struct.pack_into("<I", buf, 44, count)
    struct.pack_into("<I", buf, 48, flags)
    struct.pack_into("<I", buf, 88, root)
    return bytes(buf)


def _item(data: bytes, *, deleted: bool = False) -> bytes:
    item_type = c_db.B_KEYDATA | (c_db.B_DELETE if deleted else 0)
    return struct.pack("<HB", len(data), item_type) + data


def _leaf(pgno: int, page_type: int, items: list[bytes]) -> bytes:
    buf = bytearray(PAGE_SIZE)
    offset = PAGE_SIZE
    lookup = []
    for item in items:
        offset -= len(item)
        buf[offset : offset + len(item)] = item
        lookup.append(offset)

    struct.pack_into("<5IHHBB", buf, 0, 0, 0, pgno, 0, 0, len(items), offset, 1, page_type)
    struct.pack_into(f"<{len(lookup)}H", buf, len(c_db.PAGE), *lookup)
    return bytes(buf)


def _header(name: str, version: str, release: str = "1", installtime: int = 0) -> bytes:
    values = [
        (c_rpm.rpmTag.RPMTAG_NAME.value, 6, name.encode() + b"\x00"),
        (c_rpm.rpmTag.RPMTAG_VERSION.value, 6, version.encode() + b"\x00"),
        (c_rpm.rpmTag.RPMTAG_RELEASE.value, 6, release.encode() + b"\x00"),
    ]
    if installtime:
        values.append((c_rpm.rpmTag.RPMTAG_INSTALLTIME.value, 4, struct.pack(">I", installtime)))

    data = b""
    entries = []
    for tag, tag_type, value in values:
        entries.append((int(tag), tag_type, len(data), 1))
        data += value

    intro = struct.pack(">II", len(entries), len(data))
    index = b"".join(struct.pack(">IIII", *entry) for entry in entries)
    return intro + index + data


def _packages(records: list[tuple[bytes, bool]]) -> bytes:
    items = [_item(data, deleted=deleted) for data, deleted in records]
    return _meta(flags=c_db.BTM_RECNO, count=len(items)) + _leaf(1, c_db.P_LRECNO, items)


def _packages_with_missing_page() -> bytes:
    """A recno tree where page 2 is absent and page 3 holds record 2."""
    meta = _meta(root=1, last_pgno=3, flags=c_db.BTM_RECNO, count=2)
    root = _leaf(1, c_db.P_IRECNO, [struct.pack("<II", 2, 1), struct.pack("<II", 3, 1)])
    missing = bytes(PAGE_SIZE)
    second_leaf = _leaf(3, c_db.P_LRECNO, [_item(_header("foo", "2.0", "r2", installtime=200))])
    return meta + root + missing + second_leaf


def _names(entries: list[tuple[str, int | None, bool]], byteorder: str = "little") -> bytes:
    items = []
    for name, record, deleted in entries:
        items.append(_item(name.encode(), deleted=deleted))
        data = b"" if record is None else record.to_bytes(4, byteorder)
        items.append(_item(data))
    return _meta(count=len(entries)) + _leaf(1, c_db.P_LBTREE, items)


def _names_duplicate(name: str, records: list[tuple[int, bool]]) -> bytes:
    """Build a Name btree with an off-page duplicate data chain."""
    duplicate_items = [_item(struct.pack("<I", record), deleted=deleted) for record, deleted in records]
    total = sum(4 for _ in records)
    pointer = struct.pack("<HBBII", 0, c_db.B_DUPLICATE, 0, 2, total)

    root = _leaf(1, c_db.P_LBTREE, [_item(name.encode()), pointer])
    duplicates = _leaf(2, c_db.P_LDUP, duplicate_items)
    return _meta(root=1, last_pgno=2, count=1) + root + duplicates


def _database(
    records: list[tuple[bytes, bool]],
    entries: list[tuple[str, int | None, bool]],
) -> Packages:
    return Packages(io.BytesIO(_packages(records)), io.BytesIO(_names(entries)))


def test_name_index_and_packages_record_cross_check() -> None:
    """An old index key and a newer main record are kept apart."""
    db = _database(
        [
            (_header("foo", "1.0", "r1", installtime=100), False),
            (_header("foo", "2.0", "r2", installtime=200), False),
            (_header("bar", "1.0", "r3", installtime=50), False),
        ],
        [("foo", 1, True), ("foo", 2, False), ("bar", 3, False)],
    )

    status = db.status("foo")
    assert status.proven
    assert status.version == "2.0"
    assert status.release == "r2"
    assert status.record == 2
    assert status.source == "Packages"

    assert [claim.record for claim in status.record_claims] == [1, 2]
    assert [claim.record for claim in status.index_claims] == [1, 2]
    assert status.index_claims[0].deleted
    assert status.index_claims[0].version == "1.0"
    assert status.index_claims[1].version == "2.0"

    # The old version remains traceable, including where the claim came from.
    assert [(claim.record, claim.source, claim.reason) for claim in status.conflicts] == [
        (1, "Name", "retained-deleted-key"),
        (1, "Packages", "superseded-record"),
    ]


def test_removing_retained_old_index_does_not_change_proven_version() -> None:
    """The main record, not the stale index, determines the current version."""
    records = [
        (_header("foo", "1.0", "r1", installtime=100), False),
        (_header("foo", "2.0", "r2", installtime=200), False),
    ]
    with_old_index = _database(records, [("foo", 1, True), ("foo", 2, False)])
    without_old_index = _database(records, [("foo", 2, False)])

    before = with_old_index.status("foo")
    after = without_old_index.status("foo")
    assert before.version == after.version == "2.0"
    assert before.record == after.record == 2
    assert before.proven
    assert after.proven


def test_removing_old_index_from_same_handle_keeps_version() -> None:
    """Re-reading a mutated Name index must not rely on cached claims."""
    records = [
        (_header("foo", "1.0", "r1", installtime=100), False),
        (_header("foo", "2.0", "r2", installtime=200), False),
    ]
    packages = io.BytesIO(_packages(records))
    names = io.BytesIO(_names([("foo", 1, True), ("foo", 2, False)]))
    db = Packages(packages, names)

    before = db.status("foo")
    replacement = _names([("foo", 2, False)])
    names.seek(0)
    names.write(replacement)
    names.truncate()
    after = db.status("foo")

    assert before.version == after.version == "2.0"
    assert before.record == after.record == 2
    assert len(before.index_claims) == 2
    assert len(after.index_claims) == 1


def test_missing_record_is_unknown() -> None:
    """A live index claim to an absent record cannot fall back to an old version."""
    db = _database([(_header("foo", "1.0", "r1"), False)], [("foo", 5, False)])

    status = db.status("foo")
    assert not status.proven
    assert status.version is None
    assert status.unknown
    assert status.reason == "missing-record"
    assert status.missing == (5,)
    assert status.claims[0].record == 5
    assert status.claims[0].reason == "missing-record"


def test_truncated_record_is_unknown() -> None:
    """A partially readable header must not be treated as a confirmed version."""
    db = _database([(_header("foo", "2.0")[:20], False)], [("foo", 1, False)])

    status = db.status("foo")
    assert not status.proven
    assert status.version is None
    assert status.unknown
    assert status.reason in ("truncated-record", "undecodable-record")
    assert status.claims[0].record == 1


def test_missing_page_is_unknown() -> None:
    """A truncated Packages database leaves the package state unknown."""
    packages = io.BytesIO(_meta(root=1))
    names = io.BytesIO(_names([("foo", 1, False)]))
    db = Packages(packages, names)

    status = db.status("foo")
    assert status.version is None
    assert status.unknown
    assert status.missing_pages == (1,)
    assert status.claims[0].record == 1


def test_missing_page_does_not_renumber_records() -> None:
    """P_IRECNO subtree counts preserve record identity across a gap."""
    packages = io.BytesIO(_packages_with_missing_page())
    names = io.BytesIO(_names([("foo", 2, False)]))
    db = Packages(packages, names)

    records = list(db.records())
    assert [(record.record, record.package.version) for record in records] == [(2, "2.0")]

    status = db.status("foo")
    assert status.version == "2.0"
    assert status.record == 2
    assert status.proven
    assert status.missing_pages == (2,)


def test_deleted_index_key_is_retained_but_not_a_record() -> None:
    """Deleted btree keys stay inspectable without being logical records."""
    db = DB(io.BytesIO(_names([("foo", 1, True), ("foo", 2, False)])))

    assert list(db.records()) == [(b"foo", struct.pack("<I", 2))]
    entries = list(db.entries(include_deleted=True))
    assert len(entries) == 2
    assert entries[0].deleted
    assert entries[0].key == b"foo"
    assert entries[0].page == 1
    assert entries[0].index == 0


def test_offpage_duplicate_index_values_keep_provenance() -> None:
    """Duplicate index values on a P_LDUP page are expanded per value."""
    packages = io.BytesIO(
        _packages(
            [
                (_header("foo", "1.0", "r1", installtime=100), False),
                (_header("foo", "2.0", "r2", installtime=200), False),
            ]
        )
    )
    names = io.BytesIO(_names_duplicate("foo", [(1, True), (2, False)]))
    db = Packages(packages, names)

    status = db.status("foo")
    assert status.version == "2.0"
    assert status.record == 2
    assert [claim.record for claim in status.index_claims] == [1, 2]
    assert status.index_claims[0].deleted
    assert status.index_claims[0].version == "1.0"
    assert status.index_claims[1].version == "2.0"


def test_record_identity_survives_deleted_recno_record() -> None:
    """Skipping a deleted Packages record must not renumber later records."""
    db = _database(
        [
            (_header("foo", "1.0", "r1"), True),
            (_header("foo", "2.0", "r2"), False),
        ],
        [("foo", 2, False)],
    )

    records = list(db.records())
    assert [(record.record, record.package.version) for record in records] == [(2, "2.0")]
    assert db.status("foo").record == 2


def test_recno_keys_are_not_ordinal_positions() -> None:
    """Deleted placeholders keep the original record numbers (42 and 69)."""
    records = [(b"", True)] * 41 + [(b"thanks", False)] + [(b"", True)] * 26 + [(b"haha", False)]
    db = DB(io.BytesIO(_packages(records)))

    assert list(db.records()) == [(42, b"thanks"), (69, b"haha")]


def test_name_record_numbers_can_be_big_endian() -> None:
    """Host byte order is inferred against the main database record numbers."""
    db = Packages(
        io.BytesIO(_packages([(_header("foo", "2.0"), False)])),
        io.BytesIO(_names([("foo", 1, False)], byteorder="big")),
    )

    status = db.status("foo")
    assert status.version == "2.0"
    assert status.record == 1
    assert status.proven


def test_package_database_exposes_statuses() -> None:
    """The combined entry point resolves names from both databases."""
    db = PackageDatabase(
        io.BytesIO(_packages([(_header("foo", "2.0"), False)])), io.BytesIO(_names([("foo", 1, False)]))
    )

    statuses = list(db.statuses())
    assert [status.name for status in statuses] == ["foo"]
    assert statuses[0].version == "2.0"
    assert statuses[0].record == 1
