# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import unittest

import filetype
from filetype.disposition import (
    Confirmation,
    Consumer,
    DispositionPolicy,
    FileHint,
    PublicationQueue,
    QuarantineArbiter,
)


FIXTURES = os.path.dirname(os.path.abspath(__file__)) + '/fixtures'


class PolicyTests(unittest.TestCase):
    def test_rules_match_mime_extension_and_consumer(self):
        policy = DispositionPolicy(default=['review'])
        policy.require('zip', 'archive.shell')
        policy.require('application/zip', 'archive.contents')
        policy.require(
            'application/zip', 'vendor.review', consumer='vendor')

        hint = filetype.guess(FIXTURES + '/sample.zip')
        self.assertEqual(
            policy.requirements_for(hint),
            frozenset(['archive.shell', 'archive.contents']))
        self.assertEqual(
            policy.requirements_for(hint, 'vendor'),
            frozenset([
                'archive.shell', 'archive.contents', 'vendor.review']))
        self.assertEqual(
            policy.requirements_for('application/zip'),
            frozenset(['archive.contents']))
        self.assertEqual(
            policy.requirements_for('png'), frozenset(['review']))

    def test_empty_hint_can_use_a_wildcard_rule(self):
        policy = DispositionPolicy()
        policy.require(FileHint(), 'manual.review')
        policy.require('*', 'all.review')
        self.assertEqual(
            policy.requirements_for(None),
            frozenset(['manual.review', 'all.review']))


class AdjudicationTests(unittest.TestCase):
    def make_arbiter(self, default=None):
        policy = DispositionPolicy(default=default)
        policy.require('application/zip', [
            'archive.shell', 'archive.contents'])
        queue = PublicationQueue()
        arbiter = QuarantineArbiter(policy, queue)
        return arbiter, queue

    def admit_zip(self, arbiter, asset_id, content_id=None):
        return arbiter.admit_file(
            asset_id, FIXTURES + '/sample.zip', content_id=content_id)

    def test_partial_third_party_confirmation_stays_pending(self):
        arbiter, queue = self.make_arbiter()
        self.admit_zip(arbiter, 'asset-a', content_id='sha256:a')
        observer = Consumer(
            'outside-vendor', ['archive.shell'], external=True)

        result = arbiter.acknowledge(
            'asset-a', observer, ['archive.shell'],
            confirmation_id='receipt-1', content_id='sha256:a')

        self.assertTrue(result.accepted)
        self.assertFalse(result.released)
        self.assertEqual(
            result.missing, frozenset(['archive.contents']))
        self.assertEqual(
            arbiter.decision('asset-a').status, 'pending')
        self.assertEqual(len(queue), 0)

    def test_shell_claim_keeps_publication_quiet(self):
        arbiter, queue = self.make_arbiter()
        self.admit_zip(arbiter, 'asset-a', content_id='sha256:a')
        published = []
        arbiter.subscribe(published.append)
        shell_consumer = Consumer('shell-only', ['archive.shell'])

        result = arbiter.acknowledge(
            'asset-a', shell_consumer, ['archive.shell'],
            confirmation_id='shell-1', content_id='sha256:a')

        self.assertTrue(result.accepted)
        self.assertFalse(result.released)
        self.assertEqual(result.counted_capabilities,
                         frozenset(['archive.shell']))
        self.assertEqual(len(queue), 0)
        self.assertEqual(published, [])

    def test_remaining_scope_releases_and_notifies_once(self):
        arbiter, queue = self.make_arbiter()
        self.admit_zip(arbiter, 'asset-a', content_id='sha256:a')
        published = []
        arbiter.subscribe(published.append)

        shell = Consumer('shell-scanner', ['archive.shell'])
        handler = Consumer(
            'fake-handler', ['archive.shell', 'archive.contents'])
        arbiter.acknowledge(
            'asset-a', shell, ['archive.shell'],
            confirmation_id='shell-1', content_id='sha256:a')
        result = arbiter.acknowledge(
            'asset-a', handler, ['archive.contents'],
            confirmation_id='contents-1', content_id='sha256:a')

        self.assertTrue(result.released)
        self.assertEqual(result.missing, frozenset())
        self.assertEqual(len(queue), 1)
        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].asset_id, 'asset-a')
        self.assertEqual(
            published[0].released_by, ('shell-1', 'contents-1'))
        self.assertEqual(
            published[0].evidence['archive.contents'], ('contents-1',))

        repeated = arbiter.acknowledge(
            'asset-a', handler, ['archive.contents'],
            confirmation_id='contents-1', content_id='sha256:a')
        self.assertTrue(repeated.accepted)
        self.assertTrue(repeated.duplicate)
        self.assertEqual(len(queue), 1)
        self.assertEqual(len(published), 1)

    def test_late_receipt_for_another_asset_is_rejected(self):
        arbiter, queue = self.make_arbiter()
        self.admit_zip(arbiter, 'asset-a', content_id='sha256:a')
        self.admit_zip(arbiter, 'asset-b', content_id='sha256:b')
        handler = Consumer('handler', ['archive.shell'])

        first = arbiter.acknowledge(
            'asset-a', handler, ['archive.shell'],
            confirmation_id='shared-receipt', content_id='sha256:a')
        late = arbiter.acknowledge(
            'asset-b', handler, ['archive.shell'],
            confirmation_id='shared-receipt', content_id='sha256:b')

        self.assertTrue(first.accepted)
        self.assertFalse(late.accepted)
        self.assertEqual(late.reason, 'confirmation_id_conflict')
        self.assertEqual(
            arbiter.decision('asset-b').status, 'pending')
        self.assertEqual(len(queue), 0)

    def test_late_receipt_after_release_cannot_release_another_asset(self):
        policy = DispositionPolicy()
        policy.require('application/zip', 'inspect.all')
        queue = PublicationQueue()
        arbiter = QuarantineArbiter(policy, queue)
        self.admit_zip(arbiter, 'asset-a', content_id='sha256:a')
        self.admit_zip(arbiter, 'asset-b', content_id='sha256:b')
        handler = Consumer('handler', ['inspect.all'])

        first = arbiter.acknowledge(
            'asset-a', handler, ['inspect.all'],
            confirmation_id='released-receipt', content_id='sha256:a')
        late = arbiter.acknowledge(
            'asset-b', handler, ['inspect.all'],
            confirmation_id='released-receipt', content_id='sha256:b')

        self.assertTrue(first.released)
        self.assertFalse(late.accepted)
        self.assertEqual(late.reason, 'confirmation_id_conflict')
        self.assertEqual(
            arbiter.decision('asset-b').status, 'pending')
        self.assertEqual(len(queue), 1)

    def test_content_id_mismatch_is_rejected(self):
        arbiter, queue = self.make_arbiter()
        self.admit_zip(arbiter, 'asset-a', content_id='sha256:a')
        handler = Consumer('handler', ['archive.shell'])

        result = arbiter.acknowledge(
            'asset-a', handler, ['archive.shell'],
            confirmation_id='wrong-content', content_id='sha256:b')

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, 'content_id_mismatch')
        self.assertEqual(len(queue), 0)

    def test_consumer_cannot_overclaim_declared_capabilities(self):
        arbiter, queue = self.make_arbiter()
        self.admit_zip(arbiter, 'asset-a', content_id='sha256:a')
        vendor = Consumer('vendor', ['archive.shell'], external=True)

        result = arbiter.acknowledge(
            'asset-a', vendor, ['archive.contents'],
            confirmation_id='vendor-overclaim', content_id='sha256:a')

        self.assertFalse(result.accepted)
        self.assertEqual(
            result.reason, 'consumer_capability_mismatch')
        self.assertEqual(len(queue), 0)

    def test_registered_consumer_is_checked_by_name(self):
        arbiter, queue = self.make_arbiter()
        self.admit_zip(arbiter, 'asset-a', content_id='sha256:a')
        arbiter.register_consumer(
            Consumer('vendor', ['archive.shell'], external=True))

        result = arbiter.acknowledge(
            'asset-a', 'vendor', ['archive.contents'],
            confirmation_id='vendor-overclaim', content_id='sha256:a')

        self.assertFalse(result.accepted)
        self.assertEqual(
            result.reason, 'consumer_capability_mismatch')

    def test_confirmation_object_keeps_asset_correlation(self):
        arbiter, queue = self.make_arbiter()
        self.admit_zip(arbiter, 'asset-a', content_id='sha256:a')
        self.admit_zip(arbiter, 'asset-b', content_id='sha256:b')
        handler = Consumer(
            'handler', ['archive.shell', 'archive.contents'])
        receipt = Confirmation(
            'asset-a', handler,
            ['archive.shell', 'archive.contents'],
            confirmation_id='full-a', content_id='sha256:a')

        result = arbiter.acknowledge(receipt)

        self.assertTrue(result.released)
        self.assertEqual(
            arbiter.decision('asset-b').status, 'pending')
        self.assertEqual(len(queue), 1)

    def test_receiver_specific_requirements_are_applied(self):
        policy = DispositionPolicy()
        policy.require('application/zip', 'archive.shell')
        policy.require(
            'application/zip', 'vendor.review', consumer='vendor')
        arbiter = QuarantineArbiter(policy)

        asset = arbiter.admit_file(
            'asset-a', FIXTURES + '/sample.zip',
            consumer='vendor', content_id='sha256:a')

        self.assertEqual(asset.receiver, 'vendor')
        self.assertEqual(
            asset.required,
            frozenset(['archive.shell', 'vendor.review']))

        result = arbiter.acknowledge(
            'asset-a', Consumer('vendor', ['archive.shell']),
            ['archive.shell'], confirmation_id='vendor-shell',
            content_id='sha256:a')
        self.assertFalse(result.released)
        self.assertEqual(
            result.missing, frozenset(['vendor.review']))

    def test_unknown_asset_receipt_is_audited_without_publishing(self):
        arbiter, queue = self.make_arbiter()
        handler = Consumer('handler', ['archive.shell'])

        result = arbiter.acknowledge(
            'missing-asset', handler, ['archive.shell'],
            confirmation_id='orphan', content_id='sha256:x')

        self.assertFalse(result.accepted)
        self.assertEqual(result.reason, 'unknown_asset')
        self.assertEqual(len(arbiter.rejections), 1)
        self.assertEqual(arbiter.rejections[0].confirmation_id, 'orphan')
        self.assertEqual(len(queue), 0)

    def test_no_requirements_waits_for_manual_review(self):
        arbiter, queue = self.make_arbiter()
        arbiter.admit('asset-a', 'application/octet-stream')
        handler = Consumer('handler', ['anything'])

        result = arbiter.acknowledge(
            'asset-a', handler, ['anything'],
            confirmation_id='ignored-1')
        decision = arbiter.decision('asset-a')

        self.assertTrue(result.accepted)
        self.assertFalse(result.released)
        self.assertEqual(decision.status, 'review')
        self.assertEqual(decision.reason, 'no_requirements')
        self.assertEqual(len(queue), 0)


if __name__ == '__main__':
    unittest.main()
