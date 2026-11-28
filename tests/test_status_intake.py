# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
from datetime import datetime

from asn1crypto import ocsp
from asn1crypto.status_intake import (
    APPLIED,
    CONFLICT,
    DUPLICATE_CORRECTION,
    DUPLICATE_NOTICE,
    PENDING,
    STALE,
    ApprovedCorrection,
    CorrectionNotice,
    StatusIntakeLedger,
    declarations_from_status_material,
)
from asn1crypto.util import timezone
from ._unittest_compat import patch

patch()


ISSUER_NAME_HASH = b'\x11' * 20
ISSUER_KEY_HASH = b'\x22' * 20
RESPONDER_KEY_HASH = b'\x33' * 20
T0 = datetime(2026, 11, 28, 1, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 11, 28, 2, 0, 0, tzinfo=timezone.utc)
T2 = datetime(2026, 11, 28, 3, 0, 0, tzinfo=timezone.utc)


def _cert_status(status, this_update):
    if status == 'revoked':
        return ocsp.CertStatus(('revoked', ocsp.RevokedInfo({
            'revocation_time': this_update,
            'revocation_reason': 'key_compromise',
        })))
    if status == 'unknown':
        return ocsp.CertStatus(('unknown', ocsp.StatusUnknown()))
    return ocsp.CertStatus(('good', ocsp.StatusGood()))


def make_single_response(serial_number, status='good', this_update=T0, next_update=None):
    """
    Builds a synthetic, DER round-tripped OCSP SingleResponse.  No real
    certificate or signature is involved, but the value is genuine ASN.1
    material by the time the intake layer sees it.
    """

    fields = {
        'cert_id': ocsp.CertId({
            'hash_algorithm': {'algorithm': 'sha1'},
            'issuer_name_hash': ISSUER_NAME_HASH,
            'issuer_key_hash': ISSUER_KEY_HASH,
            'serial_number': serial_number,
        }),
        'cert_status': _cert_status(status, this_update),
        'this_update': this_update,
    }
    if next_update is not None:
        fields['next_update'] = next_update
    return ocsp.SingleResponse.load(ocsp.SingleResponse(fields).dump())


def make_ocsp_response(*single_responses, **kwargs):
    """
    Wraps synthetic SingleResponse values in a synthetic BasicOCSPResponse.
    The signature bytes are placeholder material: this test suite exercises
    intake semantics, not signature verification.
    """

    produced_at = kwargs.get('produced_at', T0)
    response_data = ocsp.ResponseData({
        'responder_id': ocsp.ResponderId(name='by_key', value=RESPONDER_KEY_HASH),
        'produced_at': produced_at,
        'responses': list(single_responses),
    })
    basic = ocsp.BasicOCSPResponse({
        'tbs_response_data': response_data,
        'signature_algorithm': {'algorithm': 'sha256_rsa'},
        'signature': b'\x00' * 32,
    })
    response = ocsp.OCSPResponse({
        'response_status': 'successful',
        'response_bytes': ocsp.ResponseBytes({
            'response_type': 'basic_ocsp_response',
            'response': basic,
        }),
    })
    return ocsp.OCSPResponse.load(response.dump())


def declaration_for(**kwargs):
    response = make_single_response(**kwargs)
    return declarations_from_status_material(response)[0]


class StatusIntakeTests(unittest.TestCase):

    def setUp(self):
        self.ledger = StatusIntakeLedger(clock=lambda: T2)

    def _register_declaration(self, serial_number=1, status='good', this_update=T0):
        result = self.ledger.add_declaration(
            make_single_response(serial_number, status=status, this_update=this_update)
        )
        return result.declaration

    def _register_order(self, declaration, order_id='order-1', responsibility='intake', materials=2):
        self.ledger.add_order(order_id, declaration.declaration_id, responsibility=responsibility)
        material_ids = []
        for index in range(materials):
            material_id = '%s-material-%d' % (order_id, index + 1)
            self.ledger.add_material(material_id, order_id=order_id, signed_at=T0)
            material_ids.append(material_id)
        return self.ledger.orders[order_id], material_ids

    def _correction(self, correction_id, declaration, order_ids, version,
                    responsibility='back-office', approval_ref='approval-1', **kwargs):
        if isinstance(order_ids, str):
            order_ids = [order_ids]
        return ApprovedCorrection(
            correction_id,
            declaration.declaration_id,
            order_ids,
            version,
            responsibility=responsibility,
            approval_ref=approval_ref,
            effective_at=kwargs.pop('effective_at', T1),
            **kwargs
        )

    # ------------------------------------------------------------------
    # Batch intake
    # ------------------------------------------------------------------

    def test_two_batches_update_in_place_without_duplicating_declarations(self):
        first = make_ocsp_response(
            make_single_response(101, this_update=T0),
            make_single_response(102, this_update=T0),
        )
        result = self.ledger.ingest_batch('batch-1', first)
        self.assertEqual(2, result.counts['added'])
        self.assertEqual(2, len(self.ledger.declarations))

        second = make_ocsp_response(
            make_single_response(101, this_update=T0),
            make_single_response(102, status='revoked', this_update=T1),
            make_single_response(103, this_update=T1),
        )
        result = self.ledger.ingest_batch('batch-2', second)
        self.assertEqual(1, result.counts['duplicate'])
        self.assertEqual(1, result.counts['updated'])
        self.assertEqual(1, result.counts['added'])
        self.assertEqual(3, len(self.ledger.declarations))

        revised = [item for item in self.ledger.declarations.values() if item.serial_number == 102][0]
        self.assertEqual('revoked', revised.status_name)
        self.assertEqual('key_compromise', revised.status['revocation_reason'])
        self.assertEqual(2, len(self.ledger.declaration_history[revised.declaration_id]))

        # Replaying the second batch changes neither the declaration set nor the
        # revision history.
        result = self.ledger.ingest_batch('batch-2', second)
        self.assertEqual(3, result.counts['duplicate'])
        self.assertEqual(3, len(self.ledger.declarations))
        self.assertEqual(2, len(self.ledger.declaration_history[revised.declaration_id]))

    def test_declaration_identity_is_stable_across_wrappers_and_batches(self):
        single = make_single_response(201, this_update=T0)
        response = make_ocsp_response(single, produced_at=T0)

        from_single = declarations_from_status_material(single, batch_id='a')[0]
        from_response = declarations_from_status_material(response, batch_id='b')[0]
        from_response_native = declarations_from_status_material(response.native, batch_id='b-native')[0]
        from_data = declarations_from_status_material(response.response_data, batch_id='c')[0]
        from_native = declarations_from_status_material(single.native, batch_id='d')[0]

        self.assertEqual(from_single.declaration_id, from_response.declaration_id)
        self.assertEqual(from_single.declaration_id, from_response_native.declaration_id)
        self.assertEqual(from_single.declaration_id, from_data.declaration_id)
        self.assertEqual(from_single.declaration_id, from_native.declaration_id)

    def test_older_declaration_batch_arriving_late_is_stale(self):
        newer = self.ledger.ingest_batch('batch-newer', make_ocsp_response(
            make_single_response(250, status='revoked', this_update=T2)
        ))
        older = self.ledger.ingest_batch('batch-older', make_ocsp_response(
            make_single_response(250, this_update=T0)
        ))

        self.assertEqual(1, newer.counts['added'])
        self.assertEqual(1, older.counts['stale'])
        declaration = list(self.ledger.declarations.values())[0]
        self.assertEqual('revoked', declaration.status_name)
        self.assertEqual(1, len(self.ledger.declaration_history[declaration.declaration_id]))

    def test_same_declaration_revision_with_different_status_conflicts(self):
        first = self.ledger.add_declaration(make_single_response(301, 'good', T0))
        second = self.ledger.add_declaration(make_single_response(301, 'revoked', T0))

        self.assertEqual('added', first.outcome)
        self.assertEqual(CONFLICT, second.outcome)
        self.assertEqual('good', self.ledger.declarations[first.declaration.declaration_id].status)
        self.assertEqual(1, len(self.ledger.declaration_history[first.declaration.declaration_id]))

    # ------------------------------------------------------------------
    # Correction binding
    # ------------------------------------------------------------------

    def test_correction_binds_declaration_order_and_version(self):
        declaration = self._register_declaration()
        order, material_ids = self._register_order(declaration)
        correction = self._correction('corr-1', declaration, order.order_id, 1)

        result = self.ledger.submit(CorrectionNotice('notice-1', correction, issued_at=T1))

        self.assertEqual(APPLIED, result.outcome)
        self.assertEqual([order.order_id], result.applied_orders)
        self.assertEqual([material_ids[0]], result.consumed_materials)
        self.assertEqual(1, len(result.bindings))
        binding = result.bindings[0]
        self.assertEqual(correction.correction_id, binding.correction_id)
        self.assertEqual(declaration.declaration_id, binding.declaration_id)
        self.assertEqual(declaration.version, binding.declaration_version)
        self.assertEqual(order.order_id, binding.order_id)
        self.assertEqual(1, binding.version)
        self.assertEqual('approval-1', binding.approval_ref)
        self.assertEqual('back-office', order.responsibility)
        self.assertEqual(1, order.version)
        self.assertEqual(binding, self.ledger.current_binding(declaration.declaration_id, order.order_id))

    def test_duplicate_notice_and_redelivered_correction_claim_only_one_material(self):
        declaration = self._register_declaration()
        order, _ = self._register_order(declaration, materials=2)
        correction = self._correction('corr-1', declaration, order.order_id, 1)

        first = self.ledger.submit(CorrectionNotice('notice-1', correction))
        duplicate_notice = self.ledger.submit(CorrectionNotice('notice-1', correction))
        duplicate_correction = self.ledger.submit(CorrectionNotice('notice-2', correction))

        self.assertEqual(APPLIED, first.outcome)
        self.assertEqual(DUPLICATE_NOTICE, duplicate_notice.outcome)
        self.assertEqual(DUPLICATE_CORRECTION, duplicate_correction.outcome)
        self.assertEqual([], duplicate_notice.consumed_materials)
        self.assertEqual([], duplicate_correction.consumed_materials)
        self.assertEqual(1, self.ledger.inventory_snapshot(order.order_id)['claimed'])
        self.assertEqual(1, self.ledger.available_material_count(order.order_id))
        self.assertEqual(1, len(self.ledger.bindings))
        self.assertEqual(1, order.version)

    def test_out_of_order_older_correction_does_not_regress_order(self):
        declaration = self._register_declaration()
        order, _ = self._register_order(declaration, materials=2)
        newer = self._correction('corr-1', declaration, order.order_id, 2, responsibility='team-new')
        older = self._correction('corr-1', declaration, order.order_id, 1, responsibility='team-old')

        applied = self.ledger.submit(CorrectionNotice('notice-new', newer, issued_at=T2))
        stale = self.ledger.submit(CorrectionNotice('notice-old', older, issued_at=T0))
        stale_again = self.ledger.submit(CorrectionNotice('notice-old-2', older, issued_at=T0))

        self.assertEqual(APPLIED, applied.outcome)
        self.assertEqual(STALE, stale.outcome)
        self.assertEqual(STALE, stale_again.outcome)
        self.assertEqual('team-new', order.responsibility)
        self.assertEqual(1, order.version)
        self.assertEqual(2, self.ledger.current_binding(declaration.declaration_id, order.order_id).version)
        self.assertEqual(1, len(self.ledger.bindings))
        self.assertEqual(1, self.ledger.available_material_count(order.order_id))

    def test_redelivery_with_a_new_local_correction_id_is_still_idempotent(self):
        declaration = self._register_declaration()
        order, _ = self._register_order(declaration, materials=2)
        original = self._correction('corr-local-1', declaration, order.order_id, 1)
        reissued = self._correction('corr-local-2', declaration, order.order_id, 1)

        first = self.ledger.submit(CorrectionNotice('notice-1', original))
        second = self.ledger.submit(CorrectionNotice('notice-2', reissued))

        self.assertEqual(APPLIED, first.outcome)
        self.assertEqual(DUPLICATE_CORRECTION, second.outcome)
        self.assertEqual([], second.consumed_materials)
        self.assertEqual(1, self.ledger.inventory_snapshot(order.order_id)['claimed'])
        self.assertEqual(1, self.ledger.available_material_count(order.order_id))
        self.assertEqual(1, len(self.ledger.bindings))

    def test_correction_sent_before_material_arrives_is_replayed(self):
        declaration = declaration_for(serial_number=401)
        correction = ApprovedCorrection(
            'corr-early',
            declaration.declaration_id,
            ['order-early'],
            1,
            responsibility='replayed-team',
            approval_ref='approval-early',
            effective_at=T1,
        )

        pending = self.ledger.submit(CorrectionNotice('notice-early', correction, issued_at=T0))
        self.assertEqual(PENDING, pending.outcome)
        self.assertEqual(1, len(self.ledger.pending_notices()))

        self.ledger.add_declaration(declaration)
        self.assertEqual(1, len(self.ledger.pending_notices()))

        self.ledger.add_order('order-early', declaration.declaration_id, responsibility='intake')
        self.assertEqual(1, len(self.ledger.pending_notices()))

        self.ledger.add_material('material-early', order_id='order-early', signed_at=T0)

        self.assertEqual([], self.ledger.pending_notices())
        stored = self.ledger.notices['notice-early'].result
        self.assertEqual(APPLIED, stored.outcome)
        self.assertEqual('replayed-team', self.ledger.orders['order-early'].responsibility)
        self.assertEqual(1, self.ledger.orders['order-early'].version)
        self.assertEqual(1, self.ledger.inventory_snapshot('order-early')['claimed'])

    def test_pending_corrections_are_replayed_by_version_not_arrival(self):
        declaration = declaration_for(serial_number=402)
        newer = ApprovedCorrection(
            'corr-late', declaration.declaration_id, ['order-late'], 2,
            responsibility='team-v2', approval_ref='approval-2', effective_at=T2,
        )
        older = ApprovedCorrection(
            'corr-late', declaration.declaration_id, ['order-late'], 1,
            responsibility='team-v1', approval_ref='approval-1', effective_at=T0,
        )

        # v2 is delivered before v1, and both arrive before their prerequisites.
        self.assertEqual(PENDING, self.ledger.submit(CorrectionNotice('notice-v2', newer, issued_at=T2)).outcome)
        self.assertEqual(PENDING, self.ledger.submit(CorrectionNotice('notice-v1', older, issued_at=T0)).outcome)
        self.assertEqual(2, len(self.ledger.pending_notices()))

        self.ledger.add_declaration(declaration)
        self.ledger.add_order('order-late', declaration.declaration_id, responsibility='intake')
        self.ledger.add_materials('order-late', ['late-1', 'late-2'], signed_at=T0)

        order = self.ledger.orders['order-late']
        self.assertEqual([], self.ledger.pending_notices())
        self.assertEqual('team-v2', order.responsibility)
        self.assertEqual(2, order.version)
        self.assertEqual([1, 2], [binding.version for binding in self.ledger.bindings_for_order('order-late')])
        self.assertEqual(0, self.ledger.available_material_count('order-late'))

    def test_one_declaration_can_support_two_orders(self):
        declaration = self._register_declaration()
        first_order, first_materials = self._register_order(declaration, 'order-a', materials=2)
        second_order, second_materials = self._register_order(declaration, 'order-b', materials=2)

        first = self._correction('corr-a', declaration, first_order.order_id, 1, responsibility='team-a')
        result_a = self.ledger.submit(CorrectionNotice('notice-a', first))
        self.assertEqual(APPLIED, result_a.outcome)
        self.assertEqual('team-a', first_order.responsibility)
        self.assertEqual('intake', second_order.responsibility)
        self.assertEqual(2, self.ledger.available_material_count(second_order.order_id))
        self.assertEqual(1, len(self.ledger.bindings_for_declaration(declaration.declaration_id)))

        second = self._correction('corr-b', declaration, second_order.order_id, 1, responsibility='team-b')
        result_b = self.ledger.submit(CorrectionNotice('notice-b', second))
        self.assertEqual(APPLIED, result_b.outcome)
        self.assertEqual('team-b', second_order.responsibility)

        both = self._correction(
            'corr-both',
            declaration,
            [first_order.order_id, second_order.order_id],
            2,
            responsibility='shared-team',
        )
        result_both = self.ledger.submit(CorrectionNotice('notice-both', both))

        self.assertEqual(APPLIED, result_both.outcome)
        self.assertEqual([first_order.order_id, second_order.order_id], result_both.applied_orders)
        self.assertEqual('shared-team', first_order.responsibility)
        self.assertEqual('shared-team', second_order.responsibility)
        self.assertEqual(2, first_order.version)
        self.assertEqual(2, second_order.version)
        self.assertEqual(4, len(self.ledger.bindings_for_declaration(declaration.declaration_id)))
        self.assertEqual(sorted(first_materials + second_materials), sorted([
            binding.material_id for binding in self.ledger.bindings
        ]))
        self.assertEqual(0, self.ledger.available_material_count(first_order.order_id))
        self.assertEqual(0, self.ledger.available_material_count(second_order.order_id))

    def test_material_shortfall_is_atomic_and_pending(self):
        declaration = self._register_declaration()
        first_order, _ = self._register_order(declaration, 'order-a', materials=1)
        second_order, _ = self._register_order(declaration, 'order-b', materials=0)
        correction = self._correction(
            'corr-both',
            declaration,
            [first_order.order_id, second_order.order_id],
            1,
        )

        result = self.ledger.submit(CorrectionNotice('notice-both', correction))
        self.assertEqual(PENDING, result.outcome)
        self.assertEqual(0, first_order.version)
        self.assertEqual(0, second_order.version)
        self.assertEqual(1, self.ledger.available_material_count(first_order.order_id))
        self.assertEqual(1, len(self.ledger.pending_notices()))

        self.ledger.add_material('order-b-material', order_id=second_order.order_id, signed_at=T0)
        self.assertEqual([], self.ledger.pending_notices())
        self.assertEqual(1, first_order.version)
        self.assertEqual(1, second_order.version)
        self.assertEqual(0, self.ledger.available_material_count(first_order.order_id))
        self.assertEqual(0, self.ledger.available_material_count(second_order.order_id))

    # ------------------------------------------------------------------
    # Scope / conflict protection
    # ------------------------------------------------------------------

    def test_correction_does_not_touch_other_orders_or_their_receipts(self):
        declaration = self._register_declaration()
        first_order, _ = self._register_order(declaration, 'order-a', materials=3)
        second_order, _ = self._register_order(declaration, 'order-b', materials=3)
        correction = self._correction('corr-a', declaration, first_order.order_id, 1)

        self.ledger.submit(CorrectionNotice('notice-a', correction))

        self.assertEqual(1, self.ledger.inventory_snapshot(first_order.order_id)['claimed'])
        self.assertEqual(0, self.ledger.inventory_snapshot(second_order.order_id)['claimed'])
        self.assertEqual(3, self.ledger.available_material_count(second_order.order_id))
        self.assertEqual(0, second_order.version)
        self.assertEqual('intake', second_order.responsibility)
        self.assertEqual([], self.ledger.bindings_for_order(second_order.order_id))

    def test_ingesting_another_batch_does_not_replay_corrections(self):
        declaration = self._register_declaration()
        order, _ = self._register_order(declaration, materials=2)
        correction = self._correction('corr-1', declaration, order.order_id, 1)
        self.ledger.submit(CorrectionNotice('notice-1', correction))

        self.ledger.ingest_batch('batch-later', make_ocsp_response(
            make_single_response(999, this_update=T2)
        ))

        self.assertEqual('back-office', order.responsibility)
        self.assertEqual(1, order.version)
        self.assertEqual(1, self.ledger.inventory_snapshot(order.order_id)['claimed'])
        self.assertEqual(1, len(self.ledger.bindings_for_order(order.order_id)))

    def test_same_correction_version_with_different_content_conflicts(self):
        declaration = self._register_declaration()
        order, _ = self._register_order(declaration, materials=2)
        first = self._correction('corr-1', declaration, order.order_id, 1, responsibility='team-a')
        changed = self._correction('corr-1', declaration, order.order_id, 1, responsibility='team-b')

        self.assertEqual(APPLIED, self.ledger.submit(CorrectionNotice('notice-a', first)).outcome)
        conflict = self.ledger.submit(CorrectionNotice('notice-b', changed))

        self.assertEqual(CONFLICT, conflict.outcome)
        self.assertEqual('team-a', order.responsibility)
        self.assertEqual(1, order.version)
        self.assertEqual(1, self.ledger.inventory_snapshot(order.order_id)['claimed'])

    def test_notice_identifier_cannot_be_reused_for_a_different_correction(self):
        declaration = self._register_declaration()
        order, _ = self._register_order(declaration, materials=2)
        first = self._correction('corr-1', declaration, order.order_id, 1, responsibility='team-a')
        second = self._correction('corr-2', declaration, order.order_id, 1, responsibility='team-b')

        self.ledger.submit(CorrectionNotice('notice-shared', first))
        conflict = self.ledger.submit(CorrectionNotice('notice-shared', second))

        self.assertEqual(CONFLICT, conflict.outcome)
        self.assertEqual('team-a', order.responsibility)
        self.assertEqual(1, self.ledger.inventory_snapshot(order.order_id)['claimed'])

    def test_correction_for_wrong_order_declaration_is_rejected(self):
        declaration = self._register_declaration()
        other_declaration = self._register_declaration(serial_number=2)
        order, _ = self._register_order(declaration, materials=1)
        correction = self._correction('corr-1', other_declaration, order.order_id, 1)

        result = self.ledger.submit(CorrectionNotice('notice-1', correction))

        self.assertEqual('rejected', result.outcome)
        self.assertEqual('intake', order.responsibility)
        self.assertEqual(0, order.version)
        self.assertEqual(1, self.ledger.available_material_count(order.order_id))


if __name__ == '__main__':
    unittest.main()
