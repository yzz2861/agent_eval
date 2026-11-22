from __future__ import print_function

import gc
import hashlib
import os
import traceback
import types
import unittest

from defusedxml.scoped import AccessDenied, ManagedReader, ReadGrant, ScopedReadError

HERE = os.path.dirname(os.path.abspath(__file__))
XML_PATH = os.path.join(HERE, "xmltestdata", "scoped-import.xml")

ORDERS_ONLY = {
    "ORD-PLACEHOLDER-1",
    "ORD-PLACEHOLDER-2",
    "ORDER-CUSTOMER-PLACEHOLDER-1",
    "ORDER-CUSTOMER-PLACEHOLDER-2",
    "111.11",
    "222.22",
}
BILLING_ONLY = {"INV-PLACEHOLDER-1", "BILLING-ACCOUNT-PLACEHOLDER", "333.33"}
AUDIT_ONLY = {"AUDIT-ONLY-PLACEHOLDER"}


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


def view_values(view):
    values = []
    for segment in view:
        if segment.present:
            values.extend(element_values(segment.root))
    return set(values)


def view_tags(view):
    tags = []
    for segment in view:
        if segment.present:
            tags.extend(element_tags(segment.root))
    return set(tags)


def reachable_strings(root, max_depth=12):
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


def library_traceback_strings(error, max_depth=8):
    values = []
    traceback_obj = error.__traceback__
    while traceback_obj is not None:
        frame = traceback_obj.tb_frame
        if frame.f_code.co_filename.endswith(os.path.join("defusedxml", "scoped.py")):
            for value in frame.f_locals.values():
                values.extend(reachable_strings(value, max_depth=max_depth))
        traceback_obj = traceback_obj.tb_next
    return values


def make_reader(**kwargs):
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
        ],
        **kwargs,
    )


class ScopedReadTests(unittest.TestCase):
    def setUp(self):
        self.reader = make_reader()
        with self.reader.open(XML_PATH) as source:
            self.source = source
            self.document = source.parse()
        self.orders = self.document.views["orders"]
        self.billing = self.document.views["billing"]

    def test_values_are_isolated(self):
        self.assertEqual(view_values(self.orders), ORDERS_ONLY)
        self.assertEqual(view_values(self.billing), BILLING_ONLY)
        self.assertFalse(view_values(self.orders) & (BILLING_ONLY | AUDIT_ONLY))
        self.assertFalse(view_values(self.billing) & (ORDERS_ONLY | AUDIT_ONLY))
        self.assertEqual(view_tags(self.orders), {"order", "customer", "total"})
        self.assertEqual(view_tags(self.billing), {"invoice", "account", "amount"})

    def test_grant_flow_reaches_view(self):
        for name in ("orders", "billing"):
            opened = self.source.grants[name]
            view = self.document.views[name]
            self.assertIs(opened, view.authorization)
            self.assertEqual(opened.grant_id, view.authorization.grant_id)
            self.assertEqual(opened.source_digest, view.source.sha256)
            self.assertIs(self.source.source, view.source)
            self.assertEqual(self.document.source.sha256, view.source.sha256)
            self.assertEqual(view.event_count, self.document.event_count)

    def test_boundaries_for_each_occurrence(self):
        orders = self.orders.segments("import/orders/order")
        self.assertEqual(len(orders), 2)
        for segment in orders:
            self.assertTrue(segment.present)
            self.assertEqual(segment.root.tag, "order")
            self.assertTrue(segment.boundary.present)
            self.assertLess(segment.boundary.start_event, segment.boundary.end_event)
            self.assertGreater(segment.boundary.start_line, 0)
        invoices = self.billing.segments("import/billing/invoice")
        self.assertEqual(len(invoices), 1)
        self.assertEqual(invoices[0].grant_id, self.billing.authorization.grant_id)

    def test_missing_item_hint(self):
        returns = self.orders.segment("import/returns")
        self.assertTrue(returns.missing)
        self.assertFalse(returns.boundary.present)
        self.assertEqual(returns.boundary.reason, "not_found")
        self.assertIn(("import", "returns"), self.orders.missing_paths)
        self.assertFalse(self.orders.requirements[("import", "returns")])
        credit_notes = self.billing.segment("import/credit-notes")
        self.assertTrue(credit_notes.missing)

    def test_denied_lookup_is_constant_and_evidence_is_safe(self):
        denied_path = "import/billing/invoice"
        with self.assertRaises(AccessDenied) as ctx:
            self.orders.segment(denied_path)
        exc = ctx.exception
        self.assertEqual(exc.args, ())
        self.assertEqual(str(exc), "requested tree segment is not available")
        self.assertEqual(repr(exc), "AccessDenied()")
        self.assertNotIsInstance(exc, (KeyError, IndexError, AttributeError, LookupError))
        digest = hashlib.sha256(denied_path.encode("utf-8")).hexdigest()[:16]
        self.assertEqual(exc.evidence.path_digest, digest)
        self.assertEqual(exc.evidence.grant_id, self.orders.authorization.grant_id)
        self.assertEqual(self.orders.evidence[-1].kind, "access_denied")
        self.assertEqual(self.orders.evidence[-1].path_digest, digest)

    def test_denied_values_do_not_leak_via_traceback_or_debug_refs(self):
        try:
            self.orders.segment("import/billing/invoice")
        except AccessDenied as exc:
            error = exc
            tb = traceback.format_exc()
        surface = " ".join(
            [str(error), repr(error), tb, repr(self.orders)] + reachable_strings(self.orders)
        )
        for marker in BILLING_ONLY | AUDIT_ONLY:
            self.assertNotIn(marker, surface)
            self.assertNotIn(marker, " ".join(library_traceback_strings(error)))
        with self.assertRaises(TypeError):
            vars(self.orders)

    def test_missing_lookup_does_not_require_generic_exception(self):
        segment = self.orders["import/returns"]
        self.assertTrue(segment.missing)
        self.assertEqual(segment.boundary.reason, "not_found")

    def test_denied_branch_inside_grant_is_pruned(self):
        xml = (
            b'<import><orders><order id="ORD-1">VISIBLE-BEFORE'
            b"<customer>VISIBLE-CUSTOMER</customer>"
            b"<internal><token>HIDDEN-TOKEN-PLACEHOLDER</token></internal>"
            b"HIDDEN-TAIL-PLACEHOLDER"
            b"<total>10.00</total>VISIBLE-AFTER-TOTAL"
            b"</order></orders></import>"
        )
        reader = ManagedReader(
            [
                ReadGrant(
                    "orders",
                    allowed=["import/orders/order"],
                    denied=["import/orders/order/internal"],
                )
            ]
        )
        document = reader.fromstring(xml).parse()
        view = document.views["orders"]
        order = view.segment("import/orders/order")
        self.assertEqual(set(element_tags(order.root)), {"order", "customer", "total"})
        self.assertNotIn("HIDDEN-TOKEN-PLACEHOLDER", " ".join(view_values(view)))
        self.assertNotIn("HIDDEN-TAIL-PLACEHOLDER", order.to_xml())
        self.assertNotIn("internal", order.to_xml())
        self.assertEqual(order.root.text, "VISIBLE-BEFORE")
        self.assertEqual(order.root.find("total").tail, "VISIBLE-AFTER-TOTAL")
        with self.assertRaises(AccessDenied):
            view.segment("import/orders/order/internal")

    def test_defused_dtd_rejection_does_not_echo_payload(self):
        bad_xml = (
            b'<!DOCTYPE import [<!ENTITY probe "DTD-PAYLOAD-PLACEHOLDER">]>'
            b"<import><orders><order><customer>&probe;</customer></order></orders></import>"
        )
        reader = make_reader()
        try:
            reader.fromstring(bad_xml, name="rejected.xml").parse()
        except ScopedReadError as exc:
            error = exc
            tb = traceback.format_exc()
        self.assertEqual(error.code, "dtd_forbidden")
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        surface = " ".join([str(error), repr(error), tb, repr(error.evidence)])
        self.assertNotIn("DTD-PAYLOAD-PLACEHOLDER", surface)
        self.assertNotIn("DTD-PAYLOAD-PLACEHOLDER", " ".join(library_traceback_strings(error)))
        self.assertEqual(reader.audit[-1].kind, "parse_failure")

    def test_defused_entity_rejection_does_not_echo_payload(self):
        bad_xml = b'<!DOCTYPE import [<!ENTITY probe "ENTITY-PAYLOAD-PLACEHOLDER">]>' b"<import/>"
        reader = make_reader(forbid_dtd=False)
        try:
            reader.fromstring(bad_xml).parse()
        except ScopedReadError as exc:
            error = exc
            tb = traceback.format_exc()
        self.assertEqual(error.code, "entities_forbidden")
        surface = " ".join([str(error), repr(error), tb, repr(error.evidence)])
        self.assertNotIn("ENTITY-PAYLOAD-PLACEHOLDER", surface)

    def test_nested_required_path_has_boundaries(self):
        reader = ManagedReader(
            [
                ReadGrant(
                    "orders",
                    allowed=["import/orders/order"],
                    required=["import/orders/order/customer"],
                )
            ]
        )
        document = reader.read(XML_PATH)
        view = document.views["orders"]
        path = ("import", "orders", "order", "customer")
        self.assertTrue(view.requirements[path])
        customers = view.segments(path)
        self.assertEqual(len(customers), 2)
        for segment in customers:
            self.assertTrue(segment.root.text.startswith("ORDER-CUSTOMER-PLACEHOLDER"))
            self.assertLess(segment.boundary.start_event, segment.boundary.end_event)

    def test_defused_external_reference_rejection_does_not_echo_payload(self):
        bang = bytes([33])
        bad_xml = (
            b"<"
            + bang
            + b"DOCTYPE import [<"
            + bang
            + b'ENTITY ext SYSTEM "file:///etc/passwd">]>'
            b"<import><orders><order><customer>&ext;</customer></order></orders></import>"
        )
        reader = make_reader(forbid_dtd=False, forbid_entities=False)
        try:
            reader.fromstring(bad_xml).parse()
        except ScopedReadError as exc:
            error = exc
            tb = traceback.format_exc()
        self.assertEqual(error.code, "external_reference_forbidden")
        surface = " ".join([str(error), repr(error), tb, repr(error.evidence)])
        self.assertNotIn("/etc/passwd", surface)

    def test_grant_path_validation(self):
        with self.assertRaises(ValueError):
            ReadGrant("x", allowed=["import", "import/orders"])
        with self.assertRaises(ValueError):
            ReadGrant("x", allowed=["import/orders"], denied=["import"])
        with self.assertRaises(ValueError):
            ReadGrant("x", allowed=["import/orders"], required=["import/billing"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
