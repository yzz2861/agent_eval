#!/usr/bin/env python
"""Demonstration of grant-scoped XML reads for an import service.

The fixture contains only placeholder values.  Two stand-in processors receive
isolated views, and the script prints exactly which values they saw together
with the evidence left by denied lookups and a rejected DTD.
"""

from __future__ import print_function

import gc
import hashlib
import json
import os
import sys
import traceback
import types

from defusedxml.scoped import AccessDenied, ManagedReader, ReadGrant, ScopedReadError

HERE = os.path.dirname(os.path.abspath(__file__))
XML_PATH = os.path.join(HERE, "xmltestdata", "scoped-import.xml")

ORDERS_ONLY = (
    "ORD-PLACEHOLDER-1",
    "ORD-PLACEHOLDER-2",
    "ORDER-CUSTOMER-PLACEHOLDER-1",
    "ORDER-CUSTOMER-PLACEHOLDER-2",
    "111.11",
    "222.22",
)
BILLING_ONLY = ("INV-PLACEHOLDER-1", "BILLING-ACCOUNT-PLACEHOLDER", "333.33")
AUDIT_ONLY = ("AUDIT-ONLY-PLACEHOLDER",)


def element_values(root):
    values = []
    if root.text and root.text.strip():
        values.append(root.text.strip())
    values.extend(root.attrib.values())
    for child in root:
        values.extend(element_values(child))
    return values


def element_tags(root):
    tags = [root.tag]
    for child in root:
        tags.extend(element_tags(child))
    return tags


def view_payload(view):
    values = []
    tags = []
    boundaries = []
    for segment in view:
        if segment.present:
            values.extend(element_values(segment.root))
            tags.extend(element_tags(segment.root))
        boundaries.append(segment.boundary.as_dict())
    return {
        "values": sorted(set(values)),
        "tags": sorted(set(tags)),
        "boundaries": boundaries,
        "missing": sorted("/".join(path) for path in view.missing_paths),
        "grant_id": view.authorization.grant_id,
    }


def reachable_strings(root, max_depth=12):
    """Collect strings reachable from an object, including debugger-visible refs."""
    seen = set()
    strings = []

    def walk(value, depth):
        if depth > max_depth:
            return
        if isinstance(value, str):
            strings.append(value)
            return
        if isinstance(value, bytes):
            strings.append(value.decode("utf-8", "replace"))
            return
        if value is None or isinstance(value, (bool, int, float)):
            return
        if isinstance(
            value,
            (
                type,
                types.ModuleType,
                types.FrameType,
                types.FunctionType,
                types.BuiltinFunctionType,
            ),
        ):
            return
        ident = id(value)
        if ident in seen:
            return
        seen.add(ident)
        if isinstance(value, dict):
            for key, item in value.items():
                walk(key, depth + 1)
                walk(item, depth + 1)
            return
        if isinstance(value, (tuple, list, set, frozenset)):
            for item in value:
                walk(item, depth + 1)
            return
        try:
            references = gc.get_referents(value)
        except TypeError:
            return
        for item in references:
            walk(item, depth + 1)

    walk(root, 0)
    return strings


class OrdersStub(object):
    """Stand-in business processor that is only allowed to read orders."""

    name = "orders"

    def consume(self, view):
        return view_payload(view)


class BillingStub(object):
    """Stand-in business processor that is only allowed to read billing."""

    name = "billing"

    def consume(self, view):
        return view_payload(view)


def make_reader():
    return ManagedReader(
        [
            ReadGrant(
                "orders",
                allowed=["import/orders/order", "import/returns"],
                required=["import/orders/order", "import/returns"],
            ),
            ReadGrant(
                "billing",
                allowed=["import/billing/invoice", "import/credit-notes"],
                required=["import/billing/invoice", "import/credit-notes"],
            ),
        ]
    )


def main():
    reader = make_reader()
    with reader.open(XML_PATH) as source:
        document = source.parse()
        for name in ("orders", "billing"):
            opened_grant = source.grants[name]
            view = document.views[name]
            assert opened_grant.grant_id == view.authorization.grant_id
            assert source.source.sha256 == view.source.sha256
        assert document.source.sha256 == document.views["orders"].source.sha256

        orders = OrdersStub().consume(document.views["orders"])
        billing = BillingStub().consume(document.views["billing"])

    print("source: {} bytes sha256={}".format(document.source.size, document.source.sha256))
    print("events: {}".format(document.event_count))
    print(
        "orders.grant= {} boundary-count={}".format(orders["grant_id"], len(orders["boundaries"]))
    )
    print("orders.boundaries = {}".format(json.dumps(orders["boundaries"])))
    print("orders.tags = {}".format(json.dumps(orders["tags"])))
    print("orders.values = {}".format(json.dumps(orders["values"])))
    print("orders.missing= {}".format(json.dumps(orders["missing"])))
    print(
        "billing.grant= {} boundary-count={}".format(
            billing["grant_id"], len(billing["boundaries"])
        )
    )
    print("billing.boundaries = {}".format(json.dumps(billing["boundaries"])))
    print("billing.tags = {}".format(json.dumps(billing["tags"])))
    print("billing.values = {}".format(json.dumps(billing["values"])))
    print("billing.missing= {}".format(json.dumps(billing["missing"])))

    orders_seen = set(orders["values"])
    billing_seen = set(billing["values"])
    assert orders_seen == set(ORDERS_ONLY)
    assert billing_seen == set(BILLING_ONLY)
    assert not orders_seen.intersection(BILLING_ONLY + AUDIT_ONLY)
    assert not billing_seen.intersection(ORDERS_ONLY + AUDIT_ONLY)
    assert "billing" not in orders["tags"] and "audit" not in orders["tags"]
    assert "orders" not in billing["tags"] and "audit" not in billing["tags"]
    assert order_boundary_is_closed(orders, "import/orders/order")
    assert order_boundary_is_closed(billing, "import/billing/invoice")
    assert "import/returns" in orders["missing"]
    assert "import/credit-notes" in billing["missing"]

    orders_view = document.views["orders"]
    denied_path = "import/billing/invoice"
    try:
        orders_view.segment(denied_path)
    except AccessDenied as exc:
        denied_error = exc
        denied_traceback = traceback.format_exc()
    else:  # pragma: no cover
        raise AssertionError("denied path was readable")

    evidence = denied_error.evidence.as_dict()
    expected_digest = hashlib.sha256(denied_path.encode("utf-8")).hexdigest()[:16]
    assert denied_error.args == ()
    assert str(denied_error) == "requested tree segment is not available"
    assert evidence["path_digest"] == expected_digest
    assert evidence["grant_id"] == orders["grant_id"]
    assert orders_view.evidence[-1].kind == "access_denied"

    debug_view = repr(orders_view)
    debug_strings = reachable_strings(orders_view)
    denied_surface = " ".join(
        [str(denied_error), repr(denied_error), denied_traceback, debug_view] + debug_strings
    )
    assert "BILLING-ACCOUNT-PLACEHOLDER" not in denied_surface
    assert "INV-PLACEHOLDER-1" not in denied_surface
    assert "AUDIT-ONLY-PLACEHOLDER" not in denied_surface

    print("denied: {}".format(str(denied_error)))
    print("denied.evidence= {}".format(json.dumps(evidence, sort_keys=True)))
    print("denied.traceback-or-debug-leak= False")
    print(
        "orders.evidence= {}".format(
            json.dumps([entry.as_dict() for entry in orders_view.evidence], sort_keys=True)
        )
    )

    bad_xml = (
        b'<!DOCTYPE import [<!ENTITY probe "DTD-PAYLOAD-PLACEHOLDER">]>'
        b"<import><orders><order><customer>&probe;</customer></order></orders></import>"
    )
    bad_reader = make_reader()
    try:
        bad_reader.fromstring(bad_xml, name="dtd-probe.xml").parse()
    except ScopedReadError as exc:
        failure_error = exc
        failure_traceback = traceback.format_exc()
    else:  # pragma: no cover
        raise AssertionError("DTD source was accepted")

    failure_surface = " ".join(
        [str(failure_error), repr(failure_error), failure_traceback, repr(failure_error.evidence)]
    )
    assert failure_error.code == "dtd_forbidden"
    assert "DTD-PAYLOAD-PLACEHOLDER" not in failure_surface
    assert bad_reader.audit[-1].kind == "parse_failure"
    print(
        "rejected: code={} evidence={}".format(
            failure_error.code, json.dumps(failure_error.evidence.as_dict(), sort_keys=True)
        )
    )
    print("rejected.traceback-leak= False")
    print("verification: passed")
    return 0


def order_boundary_is_closed(payload, path):
    matched = [item for item in payload["boundaries"] if item["path"] == path]
    return bool(matched) and all(
        item["present"] and item["start_event"] < item["end_event"] for item in matched
    )


if __name__ == "__main__":
    sys.exit(main())
