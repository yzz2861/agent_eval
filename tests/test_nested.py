from __future__ import annotations

from dataclasses import replace
from io import BytesIO
from typing import Any

import pytest

from python_multipart import (
    ApprovalPolicy,
    ApprovalScope,
    NestedMultipartParser,
    NestedReceipt,
    PartPath,
    PartReceipt,
    ReceiveDecision,
    ScopeError,
    parse_nested_form,
)
from python_multipart.exceptions import FormParserError, NestedMultipartError


def pkg_part(
    boundary: bytes,
    name: str,
    package: bytes,
    payload: bytes,
    *,
    cid: bytes | None = None,
    ctype: bytes = b"multipart/mixed",
) -> bytes:
    extra = b""
    if cid is not None:
        extra = b"X-Correlation-ID: " + cid + b"\r\n"
    return (
        b"--"
        + boundary
        + b"\r\n"
        + b'Content-Disposition: form-data; name="'
        + name.encode()
        + b'"\r\n'
        + b"Content-Type: "
        + ctype
        + b"; boundary="
        + package
        + b"\r\n"
        + extra
        + b"\r\n"
        + payload
        + b"--"
        + package
        + b"--\r\n"
    )


def leaf(
    boundary: bytes,
    name: bytes,
    payload: bytes,
    *,
    filename: bytes | None = None,
    cid: bytes | None = None,
    ctype: bytes = b"application/pdf",
    cte: bytes | None = None,
    include_disposition: bool = True,
) -> bytes:
    lines: list[bytes] = []
    if include_disposition:
        disposition = b'Content-Disposition: attachment; name="' + name + b'"'
        if filename is not None:
            disposition += b'; filename="' + filename + b'"'
        lines.append(disposition)
    lines.append(b"Content-Type: " + ctype)
    if cid is not None:
        lines.append(b"X-Correlation-ID: " + cid)
    if cte is not None:
        lines.append(b"Content-Transfer-Encoding: " + cte)
    return b"--" + boundary + b"\r\n" + b"\r\n".join(lines) + b"\r\n\r\n" + payload + b"\r\n"


def sample_body() -> bytes:
    a = b"pkg-a"
    b = b"pkg-b"
    inner_a = leaf(a, b"attachment", b"AAA", filename=b"a.pdf", cid=b"a")
    inner_b = leaf(b, b"attachment", b"BBB", filename=b"b.pdf", cid=b"b")
    top_a = pkg_part(b"outer", "bundle-a", a, inner_a)
    top_b = pkg_part(b"outer", "bundle-b", b, inner_b)
    return top_a + top_b + b"--outer--\r\n"


def sample_policy() -> ApprovalPolicy:
    return ApprovalPolicy(
        scopes=(
            ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
            ApprovalScope(
                path=(0,), name=b"bundle-a", content_type=b"multipart/mixed", allowed_types={b"application/pdf"}
            ),
            ApprovalScope(
                path=(1,), name=b"bundle-b", content_type=b"multipart/mixed", allowed_types={b"application/pdf"}
            ),
            ApprovalScope(path=(0, 0), name=b"attachment", content_type=b"application/pdf", correlation_id=b"a"),
            ApprovalScope(path=(0, 1), name=b"attachment", content_type=b"application/pdf", correlation_id=b"b"),
        ),
        require_declaration=True,
    )


def parse(body: bytes, **kwargs: Any) -> NestedReceipt:
    return parse_nested_form(
        {"Content-Type": b"multipart/form-data; boundary=outer"}, BytesIO(body), chunk_size=7, **kwargs
    )


def test_part_path_and_validation() -> None:
    root = PartPath()
    assert root.is_root
    assert str(root) == "/"
    assert PartPath((0, 2)).parent == (0,)
    assert PartPath("0.2") == (0, 2)
    assert PartPath.parse("0/2").child(1) == (0, 2, 1)
    with pytest.raises(ScopeError):
        PartPath((-1,))
    with pytest.raises(ScopeError):
        ApprovalPolicy(scopes=(ApprovalScope(path=(0,)), ApprovalScope(path=(0,))))


def test_two_attachments_report_their_declaration_packages() -> None:
    receipt = parse(sample_body(), policy=sample_policy())

    assert receipt.complete
    first = receipt.get((0, 0))
    second = receipt.get((1, 0))
    assert first is not None and second is not None
    assert first.name == second.name == b"attachment"
    assert first.file_name == b"a.pdf"
    assert second.file_name == b"b.pdf"
    assert first.decision is ReceiveDecision.ACCEPTED
    assert first.declared_at == (0, 0)
    assert first.declared_in_own_package
    assert first.declared_for_this_part
    assert second.decision is ReceiveDecision.REJECTED
    assert second.reason == "declaration_in_other_package"
    assert second.declared_at == (0, 1)
    assert not second.declared_in_own_package
    assert not second.declared_for_this_part
    assert second.declaration_package == (0,)
    assert second.package_path == (1,)
    assert second.belongs_to == (0, 1)
    assert receipt.get((0,)).path == PartPath((0,))


def test_receipt_waits_for_complete_subtree() -> None:
    body = sample_body()
    marker = b"--pkg-a--"
    split = body.index(marker)
    emitted: list[PartReceipt] = []
    parser = NestedMultipartParser(b"outer", {"on_receipt": emitted.append}, policy=sample_policy())

    parser.write(body[:split])
    assert all(receipt.path != (0, 0) for receipt in emitted)
    assert all(receipt.path != (0,) for receipt in emitted)

    parser.write(body[split:])
    parser.finalize()
    paths = [receipt.path for receipt in emitted]
    assert (0, 0) in paths
    assert (0,) in paths
    assert paths.index(PartPath((0, 0))) < paths.index(PartPath((0,)))


def test_parent_tightening_is_not_widened_by_child_scope() -> None:
    inner_leaf = leaf(b"nested", b"attachment", b"payload", filename=b"nested.pdf")
    inner_pkg = pkg_part(b"pkg-a", "nested", b"nested", inner_leaf, ctype=b"multipart/related")
    package = pkg_part(b"outer", "bundle-a", b"pkg-a", inner_pkg)
    body = package + b"--outer--\r\n"
    policy = ApprovalPolicy(
        scopes=(
            ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
            ApprovalScope(
                path=(0,),
                name=b"bundle-a",
                content_type=b"multipart/mixed",
                allowed_types={b"multipart/related"},
                allowed_nested_types={b"multipart/related"},
            ),
        )
    )

    receipt = parse(body, policy=policy)
    child = receipt.get((0, 0))
    assert child is not None
    assert child.decision is ReceiveDecision.REJECTED
    assert child.reason == "nested_type_not_allowed"
    assert not child.is_package


def test_missing_child_header_policies() -> None:
    inner = leaf(b"pkg-a", b"attachment", b"x", filename=b"x.pdf", cid=b"a", include_disposition=False)
    body = pkg_part(b"outer", "bundle-a", b"pkg-a", inner) + b"--outer--\r\n"
    scopes = (
        ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
        ApprovalScope(path=(0, 0), content_type=b"application/pdf", correlation_id=b"a"),
    )

    rejected = parse(body, scopes=scopes)
    assert rejected.get((0, 0)).reason == "missing_content_disposition"
    assert rejected.get((0, 0)).decision is ReceiveDecision.REJECTED

    with pytest.raises(NestedMultipartError):
        parse(body, scopes=scopes, missing_child_header="error")

    allowed = parse(body, scopes=scopes, missing_child_header="allow")
    assert allowed.get((0, 0)).decision is ReceiveDecision.ACCEPTED
    assert allowed.get((0, 0)).name is None


def test_unknown_encoding_policies() -> None:
    inner = leaf(b"pkg-a", b"attachment", b"x", filename=b"x.pdf", cid=b"a", cte=b"x-rot13")
    body = pkg_part(b"outer", "bundle-a", b"pkg-a", inner) + b"--outer--\r\n"
    scopes = (
        ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
        ApprovalScope(path=(0, 0), name=b"attachment", content_type=b"application/pdf", correlation_id=b"a"),
    )

    rejected = parse(body, scopes=scopes)
    assert rejected.get((0, 0)).reason == "unknown_content_transfer_encoding"
    assert rejected.get((0, 0)).decision is ReceiveDecision.REJECTED

    with pytest.raises(NestedMultipartError):
        parse(body, scopes=scopes, unknown_encoding="error")

    opaque = parse(body, scopes=scopes, unknown_encoding="opaque")
    assert opaque.get((0, 0)).decision is ReceiveDecision.ACCEPTED
    assert "unknown_content_transfer_encoding_opaque" in opaque.get((0, 0)).reasons


def test_same_name_children_are_keyed_by_path_and_local_correlation_id() -> None:
    first = leaf(b"pkg-a", b"attachment", b"one", filename=b"one.pdf", cid=b"one")
    second = leaf(b"pkg-a", b"attachment", b"two", filename=b"two.pdf", cid=b"two")
    body = pkg_part(b"outer", "bundle-a", b"pkg-a", first + second) + b"--outer--\r\n"
    scopes = (
        ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
        ApprovalScope(path=(0, 0), name=b"attachment", content_type=b"application/pdf", correlation_id=b"one"),
        ApprovalScope(path=(0, 1), name=b"attachment", content_type=b"application/pdf", correlation_id=b"two"),
    )

    receipt = parse(body, scopes=scopes, require_declaration=True)
    assert receipt.get((0, 0)).decision is ReceiveDecision.ACCEPTED
    assert receipt.get((0, 1)).decision is ReceiveDecision.ACCEPTED
    assert receipt.get((0, 0)).file_name == b"one.pdf"
    assert receipt.get((0, 1)).file_name == b"two.pdf"


def test_incomplete_child_subtree_is_pending() -> None:
    inner = leaf(b"pkg-a", b"attachment", b"x", filename=b"x.pdf", cid=b"a")
    body = (
        b"--outer\r\n"
        + b'Content-Disposition: form-data; name="bundle-a"\r\n'
        + b"Content-Type: multipart/mixed; boundary=pkg-a\r\n\r\n"
        + inner
        + b"--outer--\r\n"
    )
    scopes = (
        ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
        ApprovalScope(path=(0,), allowed_types={b"application/pdf"}),
    )

    receipt = parse(body, scopes=scopes)
    package = receipt.get((0,))
    child = receipt.get((0, 0))
    assert package is not None and child is not None
    assert not package.complete
    assert package.decision is ReceiveDecision.PENDING
    assert child.decision is ReceiveDecision.PENDING
    assert receipt.complete is False or package.pending


def test_existing_multipart_parser_still_parses_nested_body_as_opaque() -> None:
    from python_multipart import MultipartParser

    events: list[str] = []
    parser = MultipartParser(
        b"outer",
        {
            "on_part_begin": lambda: events.append("begin"),
            "on_part_end": lambda: events.append("end"),
            "on_end": lambda: events.append("root-end"),
        },
    )
    parser.write(sample_body())
    parser.finalize()
    assert events == ["begin", "end", "begin", "end", "root-end"]


def test_parent_scope_with_same_name_does_not_declare_child() -> None:
    inner = leaf(b"pkg-a", b"attachment", b"x", filename=b"x.pdf", cid=b"a")
    body = pkg_part(b"outer", "attachment", b"pkg-a", inner) + b"--outer--\r\n"
    scopes = (
        ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
        ApprovalScope(path=(0,), name=b"attachment", content_type=b"multipart/mixed"),
    )

    receipt = parse(body, scopes=scopes)
    child = receipt.get((0, 0))
    assert child is not None
    assert child.decision is ReceiveDecision.UNDECLARED
    assert child.declared_at is None
    assert child.reason == "not_declared_at_path"


def test_missing_content_type_is_explicit_when_scope_declares_one() -> None:
    inner = b'--pkg-a\r\nContent-Disposition: attachment; name="attachment"\r\nX-Correlation-ID: a\r\n\r\nx\r\n'
    body = pkg_part(b"outer", "bundle-a", b"pkg-a", inner) + b"--outer--\r\n"
    scopes = (
        ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
        ApprovalScope(path=(0, 0), name=b"attachment", content_type=b"application/pdf", correlation_id=b"a"),
    )

    receipt = parse(body, scopes=scopes)
    child = receipt.get((0, 0))
    assert child is not None
    assert child.decision is ReceiveDecision.REJECTED
    assert child.reason == "missing_content_type"


def test_receipt_views_and_serialization() -> None:
    receipt = parse(sample_body(), policy=sample_policy())

    assert len(receipt) == 4
    assert receipt[0].path == (0, 0)
    assert receipt["0/0"].file_name == b"a.pdf"
    assert receipt.by_path[PartPath((1, 0))].name == b"attachment"
    assert [part.path for part in receipt.accepted] == [(0, 0), (0,), (1,)]
    assert [part.path for part in receipt.rejected] == [(1, 0)]
    assert [part.path for part in receipt.packages] == [(0,), (1,)]
    assert [part.path for part in receipt.leaves] == [(0, 0), (1, 0)]
    assert [part.path for part in receipt.walk()] == [(0,), (0, 0), (1,), (1, 0)]

    data = receipt.to_dict()
    assert data["complete"] is True
    assert [root["path"] for root in data["roots"]] == ["0", "1"]
    assert receipt.get((0, 0)).to_dict()["belongs_to"] == "0/0"


def test_streaming_callbacks_and_root_on_end() -> None:
    data_parts: list[tuple[PartPath, bytes]] = []
    packages: list[tuple[PartPath, str | None]] = []
    receipts: list[PartReceipt] = []
    ends: list[bool] = []
    begins: list[bool] = []
    legacy_data: list[bytes] = []
    begin_paths: list[PartPath] = []
    header_maps: list[tuple[PartPath, dict[bytes, bytes]]] = []
    parser = NestedMultipartParser(
        b"outer",
        {
            "on_part_begin": lambda: begins.append(True),
            "on_part_begin_path": begin_paths.append,
            "on_part_headers": lambda path, headers: header_maps.append((path, headers)),
            "on_part_data_path": lambda path, data, start, end: data_parts.append((path, data[start:end])),
            "on_part_data": lambda data, start, end: legacy_data.append(data[start:end]),
            "on_package": lambda path, content_type: packages.append((path, content_type)),
            "on_receipt": receipts.append,
            "on_end": lambda: ends.append(True),
        },
        policy=sample_policy(),
    )
    body = sample_body()
    for index in range(0, len(body), 11):
        parser.write(body[index : index + 11])
    parser.finalize()

    assert len(ends) == 1
    assert len(begins) == 4
    assert packages == [((0,), "multipart/mixed; boundary=pkg-a"), ((1,), "multipart/mixed; boundary=pkg-b")]
    assert (0, 0) in {path for path, _ in data_parts}
    assert (1, 0) in {path for path, _ in data_parts}
    assert b"".join(legacy_data) == b"AAABBB"
    assert begin_paths == [(0,), (0, 0), (1,), (1, 0)]
    assert dict(header_maps)[PartPath((0, 0))][b"x-correlation-id"] == b"a"
    assert [part.path for part in receipts] == [(0, 0), (0,), (1, 0), (1,)]
    second = parser.get_receipt((1, 0))
    assert second is not None
    assert second.decision is ReceiveDecision.REJECTED


def test_encoded_and_depth_limited_packages_stay_opaque() -> None:
    inner = leaf(b"pkg-a", b"attachment", b"x", filename=b"x.pdf", cid=b"a")
    encoded_inner = (
        b"--pkg-a\r\n"
        b'Content-Disposition: form-data; name="bundle-b"\r\n'
        b"Content-Type: multipart/mixed; boundary=pkg-b\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"--pkg-b--\r\n"
    )
    encoded_body = pkg_part(b"outer", "bundle-a", b"pkg-a", inner + encoded_inner) + b"--outer--\r\n"
    receipt = parse(
        encoded_body,
        scopes=(
            ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
            ApprovalScope(path=(0, 0), name=b"attachment", content_type=b"application/pdf", correlation_id=b"a"),
        ),
    )
    encoded = receipt.get((0, 1))
    assert encoded is not None
    assert encoded.reason == "encoded_nested_package"
    assert not encoded.is_package

    shallow = parse(sample_body(), policy=sample_policy(), max_depth=0)
    assert shallow.get((0,)).reason == "max_depth_exceeded"
    assert not shallow.get((0,)).is_package


def test_declaration_mismatch_and_declaration_for_other_part() -> None:
    inner = leaf(b"pkg-a", b"other", b"x", filename=b"x.pdf", cid=b"a")
    body = pkg_part(b"outer", "bundle-a", b"pkg-a", inner) + b"--outer--\r\n"
    mismatch = parse(
        body,
        scopes=(
            ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
            ApprovalScope(path=(0, 0), name=b"attachment", content_type=b"application/pdf", correlation_id=b"a"),
        ),
    )
    assert mismatch.get((0, 0)).reason == "declaration_mismatch"

    first = leaf(b"pkg-a", b"attachment", b"one", filename=b"one.pdf", cid=b"a")
    second = leaf(b"pkg-a", b"attachment", b"two", filename=b"two.pdf", cid=b"b")
    body = pkg_part(b"outer", "bundle-a", b"pkg-a", first + second) + b"--outer--\r\n"
    other = parse(
        body,
        scopes=(
            ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
            ApprovalScope(path=(0, 1), name=b"attachment", content_type=b"application/pdf", correlation_id=b"a"),
        ),
    )
    assert other.get((0, 0)).reason == "declaration_for_other_part"
    assert other.get((0, 0)).declared_in_own_package
    assert not other.get((0, 0)).declared_for_this_part


def test_ambiguous_declarations_are_rejected() -> None:
    parts = b"".join(
        leaf(b"pkg-a", b"attachment", bytes([index]), filename=bytes([index]) + b".pdf", cid=b"same")
        for index in range(3)
    )
    body = pkg_part(b"outer", "bundle-a", b"pkg-a", parts) + b"--outer--\r\n"
    receipt = parse(
        body,
        scopes=(
            ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
            ApprovalScope(path=(0, 0), name=b"attachment", content_type=b"application/pdf", correlation_id=b"same"),
            ApprovalScope(path=(0, 1), name=b"attachment", content_type=b"application/pdf", correlation_id=b"same"),
        ),
    )
    third = receipt.get((0, 2))
    assert third is not None
    assert third.reason == "ambiguous_declaration"


def test_helper_errors_and_parser_limits() -> None:
    from python_multipart import create_nested_form_parser

    with pytest.raises(ValueError):
        create_nested_form_parser({})
    with pytest.raises(FormParserError):
        create_nested_form_parser({"Content-Type": b"application/json"})
    with pytest.raises(FormParserError):
        create_nested_form_parser({"Content-Type": b"multipart/form-data"})
    with pytest.raises(ValueError):
        parse_nested_form({"Content-Type": b"multipart/form-data; boundary=outer"}, BytesIO(b""), chunk_size=0)
    with pytest.raises(ValueError):
        parse_nested_form(
            {"Content-Type": b"multipart/form-data; boundary=outer", "Content-Length": b"-1"}, BytesIO(b"")
        )

    parser = NestedMultipartParser(b"outer", max_size=10)
    assert parser.write(b"--outer--\r\n") == 10
    parser.finalize()
    with pytest.raises(FormParserError):
        parser.write(b"x")


def test_parent_type_and_depth_limits_cannot_be_widened() -> None:
    inner = leaf(b"pkg-a", b"attachment", b"x", filename=b"x.txt", cid=b"a", ctype=b"text/plain")
    body = pkg_part(b"outer", "bundle-a", b"pkg-a", inner) + b"--outer--\r\n"

    type_limited = parse(
        body,
        scopes=(
            ApprovalScope(path=(), allowed_types={b"application/pdf"}, allowed_nested_types={b"multipart/mixed"}),
            ApprovalScope(path=(0,), name=b"bundle-a", content_type=b"multipart/mixed", allowed_types={b"text/plain"}),
        ),
    )
    package = type_limited.get((0,))
    assert package is not None
    assert package.reason == "type_not_allowed"
    assert not package.is_package
    assert type_limited.get((0, 0)) is None

    nested = (
        b"--pkg-a\r\n"
        b'Content-Disposition: form-data; name="inner"\r\n'
        b"Content-Type: multipart/mixed; boundary=inner\r\n\r\n"
        b"--inner--\r\n"
    )
    body = pkg_part(b"outer", "bundle-a", b"pkg-a", nested) + b"--outer--\r\n"
    depth_limited = parse(
        body,
        scopes=(
            ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
            ApprovalScope(path=(0,), name=b"bundle-a", content_type=b"multipart/mixed", max_depth=1),
        ),
    )
    inner_part = depth_limited.get((0, 0))
    assert inner_part is not None
    assert inner_part.reason == "max_depth_exceeded"


def test_model_helper_branches() -> None:
    scope = ApprovalScope(
        path=0,
        name="attachment",
        correlation_id="cid",
        allowed_types="Application/PDF",
        allowed_nested_types="Multipart/Mixed",
        max_depth=0,
    )
    assert scope.path == (0,)
    assert scope.name == b"attachment"
    assert scope.allowed_type_set == frozenset({"application/pdf"})
    assert scope.allowed_nested_type_set == frozenset({"multipart/mixed"})
    assert scope.package_path == ()
    assert scope.local_id == b"cid"
    assert scope.local_correlation_id == b"cid"

    assert PartPath("").is_root
    assert PartPath("/").is_root
    assert PartPath(None).is_root
    assert PartPath(3) == (3,)
    assert PartPath((0, 1)).indices == (0, 1)
    with pytest.raises(ScopeError):
        PartPath((0,)).child(-1)
    with pytest.raises(ScopeError):
        ApprovalScope(path=(0,), max_depth=-1)

    policy = ApprovalPolicy(scopes=scope)
    assert policy.scope_at(0) is scope
    assert policy.allowed_nested_type_set is None
    with pytest.raises(ScopeError):
        ApprovalPolicy(missing_child_header="bad")  # type: ignore[arg-type]
    with pytest.raises(ScopeError):
        ApprovalPolicy(unknown_encoding="bad")  # type: ignore[arg-type]
    with pytest.raises(ScopeError):
        ApprovalPolicy(max_depth=-1)
    with pytest.raises(ScopeError):
        ApprovalPolicy(scopes=(object(),))  # type: ignore[arg-type]

    NestedMultipartParser(b"x", policy=ApprovalPolicy(max_depth=None), scopes=(ApprovalScope(path=(), max_depth=2),))
    NestedMultipartParser(b"x", policy=ApprovalPolicy(max_depth=2), scopes=(ApprovalScope(path=()),))


def test_receipt_alias_views() -> None:
    receipt = parse(sample_body(), policy=sample_policy())
    first = receipt.get((0, 0))
    second_package = receipt.get((1,))
    assert first is not None and second_package is not None
    assert first.field_name == b"attachment"
    assert first.filename == b"a.pdf"
    assert first.is_file
    assert first.path_string == "0/0"
    assert first.declaration_scope == (0, 0)
    assert first.local_id == b"a"
    assert first.local_correlation_id == b"a"
    assert first.correlation_scope == (0,)
    assert first.accepted
    assert not first.rejected
    assert not first.undeclared
    assert not first.pending
    assert second_package.has_rejected_children
    assert list(receipt)[0].path == (0, 0)
    assert receipt.undeclared == ()
    assert receipt.pending == ()


def test_missing_name_and_correlation_header_fallback() -> None:
    inner = (
        b"--pkg-a\r\n"
        b'Content-Disposition: attachment; filename="x.pdf"\r\n'
        b"Content-Type: application/pdf\r\n"
        b"X-Part-Id: a\r\n\r\n"
        b"x\r\n"
    )
    body = pkg_part(b"outer", "bundle-a", b"pkg-a", inner) + b"--outer--\r\n"
    scopes = (
        ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),
        ApprovalScope(path=(0, 0), content_type=b"application/pdf", correlation_id=b"a"),
    )

    receipt = parse(body, scopes=scopes)
    child = receipt.get((0, 0))
    assert child is not None
    assert child.reason == "missing_name"
    assert child.correlation_id == b"a"


def test_nested_structure_rejections() -> None:
    missing = (
        b"--outer\r\n"
        b'Content-Disposition: form-data; name="bundle"\r\n'
        b"Content-Type: multipart/mixed\r\n\r\n"
        b"payload\r\n"
        b"--outer--\r\n"
    )
    receipt = parse(missing, scopes=(ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),))
    assert receipt.get((0,)).reason == "missing_boundary"
    assert not receipt.get((0,)).is_package

    long_boundary = b"x" * 300
    invalid = (
        b"--outer\r\n"
        b'Content-Disposition: form-data; name="bundle"\r\n'
        b"Content-Type: multipart/mixed; boundary=" + long_boundary + b"\r\n\r\n" + b"payload\r\n" + b"--outer--\r\n"
    )
    receipt = parse(invalid, scopes=(ApprovalScope(path=(), allowed_nested_types={b"multipart/mixed"}),))
    assert receipt.get((0,)).reason.startswith("invalid_nested_boundary")


def test_incomplete_rejected_part_records_incomplete_subtree() -> None:
    body = (
        b"--outer\r\n"
        b'Content-Disposition: form-data; name="field"\r\n'
        b"Content-Type: text/plain\r\n"
        b"Content-Transfer-Encoding: x-unknown\r\n\r\n"
        b"payload"
    )
    parser = NestedMultipartParser(b"outer", policy=ApprovalPolicy(require_declaration=False))
    parser.write(body)
    parser.finalize()

    part = parser.receipt.get((0,))
    assert part is not None
    assert part.pending
    assert "incomplete_subtree" in part.reasons


def test_optional_declaration_decisions() -> None:
    neighbor = parse(sample_body(), policy=replace(sample_policy(), require_declaration=False))
    second = neighbor.get((1, 0))
    assert second is not None
    assert second.decision is ReceiveDecision.ACCEPTED
    assert "declaration_in_other_package" in second.reasons

    body = b'--outer\r\nContent-Disposition: form-data; name="field"\r\n\r\nvalue\r\n--outer--\r\n'
    receipt = parse(body, require_declaration=False)
    assert receipt.get((0,)).decision is ReceiveDecision.ACCEPTED


def test_constructor_variants_and_limits() -> None:
    root_scope = ApprovalScope(path=())
    policy = ApprovalPolicy(scopes=root_scope)
    parsers = (
        NestedMultipartParser(b"x", policy=policy),
        NestedMultipartParser(b"x", scope=policy),
        NestedMultipartParser(b"x", scope=root_scope),
        NestedMultipartParser(b"x", scope=[root_scope]),
        NestedMultipartParser(b"x", declarations=[root_scope]),
        NestedMultipartParser(b"x", policy=policy, scopes=(ApprovalScope(path=(0,)),)),
        NestedMultipartParser(
            b"x",
            policy=ApprovalPolicy(allowed_nested_types={b"multipart/mixed"}),
            allowed_types={b"application/pdf"},
            nested_types={b"multipart/related"},
            correlation_id_header="X-Part-Id",
            unknown_encoding="opaque",
            missing_child_header="allow",
            require_declaration=False,
            max_depth=2,
        ),
    )
    for parser in parsers:
        assert parser.receipts == ()
        parser.close()
        parser.finalize()
        parser._root.finalize()
        assert parser.receipt.complete is False

    with pytest.raises(ScopeError):
        NestedMultipartParser(b"x", policy=policy, scope=policy)
    with pytest.raises(ValueError):
        NestedMultipartParser(b"x", max_size=0)
