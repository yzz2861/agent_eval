# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import unittest

import filetype
from filetype.impact import assess, render_markdown, render_text
from filetype.types import Type, TYPES


FIXTURES = os.path.dirname(os.path.abspath(__file__)) + '/fixtures'


class LegacyJpeg(Type):
    """Third-party matcher that shadows the built-in JPEG matcher."""

    MIME = 'image/x-legacy-jpeg'
    EXTENSION = 'legacy-jpg'

    def __init__(self):
        super(LegacyJpeg, self).__init__(
            mime=LegacyJpeg.MIME,
            extension=LegacyJpeg.EXTENSION,
        )

    def match(self, buf):
        return (len(buf) > 2 and
                buf[0] == 0xFF and
                buf[1] == 0xD8 and
                buf[2] == 0xFF)


class FooType(Type):
    """A newly supported legitimate format."""

    MIME = 'application/x-foo'
    EXTENSION = 'foo'

    def __init__(self):
        super(FooType, self).__init__(
            mime=FooType.MIME,
            extension=FooType.EXTENSION,
        )

    def match(self, buf):
        return bytes(buf[:4]) == b'FOO\x00'


class BrokenType(Type):
    """A third-party matcher that raises for every input."""

    MIME = 'application/x-broken'
    EXTENSION = 'broken'

    def __init__(self):
        super(BrokenType, self).__init__(
            mime=BrokenType.MIME,
            extension=BrokenType.EXTENSION,
        )

    def match(self, buf):
        raise RuntimeError('third-party matcher exploded')


def routes_before():
    return {
        'name': 'before-routes',
        'routes': {
            'image/jpeg': {
                'queue': 'image-strong',
                'capability': 10,
            },
            'application/x-foo': {
                'queue': 'new-strong',
                'capability': 8,
            },
        },
    }


def routes_after():
    return {
        'name': 'after-routes',
        'routes': {
            'image/jpeg': {
                'queue': 'image-strong',
                'capability': 10,
            },
            'image/x-legacy-jpeg': {
                'queue': 'legacy-weak',
                'capability': 2,
            },
            'application/x-foo': {
                'queue': 'new-medium',
                'capability': 6,
            },
        },
    }


class TestRankedMatches(unittest.TestCase):

    def test_returns_every_match_in_registration_order(self):
        candidates = filetype.match_all(
            b'\xff\xd8\xff\x00',
            matchers=[LegacyJpeg(), filetype.types[2]],
        )
        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0].extension, 'legacy-jpg')
        self.assertEqual(candidates[0].rank, 1)
        self.assertEqual(candidates[1].extension, 'jpg')
        self.assertEqual(candidates[1].rank, 2)

    def test_records_matcher_exception_and_continues(self):
        candidates = filetype.match_all(
            b'\xff\xd8\xff\x00',
            matchers=[BrokenType(), filetype.types[2]],
            on_error='record',
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(len(candidates.errors), 1)
        self.assertIn('BrokenType', candidates.errors[0].matcher_name)
        self.assertEqual(candidates.errors[0].rank, 1)

    def test_match_with_rank_keeps_first_match_behavior(self):
        candidate = filetype.match_with_rank(
            b'\xff\xd8\xff\x00',
            matchers=[LegacyJpeg(), filetype.types[2]],
        )
        self.assertEqual(candidate.extension, 'legacy-jpg')
        self.assertEqual(candidate.rank, 1)


class TestImpactAssessment(unittest.TestCase):

    def test_new_format_is_separate_from_downgrade(self):
        report = assess(
            samples={'new.foo': b'FOO\x00payload'},
            before=list(TYPES),
            after=[FooType()] + list(TYPES),
            before_routes=routes_before(),
            after_routes=routes_after(),
        )

        record = report['samples'][0]
        self.assertEqual(record['decision'], 'new_format')
        self.assertTrue(record['isolation_changed'])
        self.assertEqual(report['summary']['new_format'], 1)
        self.assertEqual(report['summary']['downgrade'], 0)
        self.assertEqual(
            report['changed_isolation_decisions'][0]['decision'],
            'new_format',
        )

    def test_shadowed_legacy_type_is_reported_as_downgrade(self):
        report = assess(
            samples={'photo.jpg': b'\xff\xd8\xff\x00legacy'},
            before=list(TYPES),
            after=[LegacyJpeg()] + list(TYPES),
            before_routes=routes_before(),
            after_routes=routes_after(),
        )

        record = report['samples'][0]
        self.assertEqual(record['decision'], 'downgrade')
        self.assertEqual(record['before']['type']['extension'], 'jpg')
        self.assertEqual(record['after']['type']['extension'], 'legacy-jpg')
        self.assertEqual(record['before']['route']['queue'], 'image-strong')
        self.assertEqual(record['after']['route']['queue'], 'legacy-weak')
        self.assertEqual(report['summary']['downgrade'], 1)
        self.assertEqual(report['summary']['new_format'], 0)

    def test_route_config_change_downgrades_existing_type(self):
        after_routes = routes_after()
        after_routes['routes']['image/jpeg'] = {
            'queue': 'legacy-weak',
            'capability': 2,
        }
        report = assess(
            samples={'photo.jpg': b'\xff\xd8\xff\x00legacy'},
            before=list(TYPES),
            after=list(TYPES),
            before_routes=routes_before(),
            after_routes=after_routes,
        )

        record = report['samples'][0]
        self.assertEqual(record['decision'], 'downgrade')
        self.assertFalse(record['detection_changed'])
        self.assertTrue(record['isolation_changed'])

    def test_unrouted_new_format_is_not_counted_as_legal(self):
        report = assess(
            samples={'new.foo': b'FOO\x00payload'},
            before=list(TYPES),
            after=[FooType()] + list(TYPES),
            before_routes=routes_before(),
            after_routes={
                'image/jpeg': {'queue': 'image-strong', 'capability': 10},
            },
        )

        self.assertEqual(report['samples'][0]['decision'], 'new_unrouted')
        self.assertEqual(report['summary']['new_format'], 0)
        self.assertEqual(report['summary']['unrouted_new_formats'], 0)

    def test_new_format_without_any_routing_table(self):
        report = assess(
            samples={"new.foo": b'FOO\x00payload'},
            before=list(TYPES),
            after=[FooType()] + list(TYPES),
        )

        record = report['samples'][0]
        self.assertEqual(record['decision'], 'new_format')
        self.assertFalse(record['routed'])
        self.assertEqual(report['summary']['new_formats'], 1)
        self.assertEqual(report['summary']['unrouted_new_formats'], 1)

    def test_exception_locates_sample_and_both_routing_configs(self):
        report = assess(
            samples={'photo.jpg': b'\xff\xd8\xff\x00legacy'},
            before=list(TYPES),
            after=[BrokenType()] + list(TYPES),
            before_routes=routes_before(),
            after_routes=routes_after(),
        )

        self.assertEqual(report['errors']['affected_samples'], ['photo.jpg'])
        self.assertEqual(report['errors']['total'], 1)
        error = report['errors']['items'][0]
        self.assertEqual(error['sample'], 'photo.jpg')
        self.assertEqual(error['side'], 'after')
        self.assertIn('BrokenType', error['matcher'])
        self.assertIn('third-party matcher exploded', error['message'])
        detail = report['errors']['affected_sample_details'][0]
        self.assertEqual(detail['name'], 'photo.jpg')
        self.assertEqual(
            detail['prefix_sha256'],
            report['samples'][0]['prefix_sha256'],
        )

        before_config = report['routing_configs']['before']
        after_config = report['routing_configs']['after']
        self.assertIn('config', before_config)
        self.assertIn('config', after_config)
        self.assertEqual(before_config['name'], 'before-routes')
        self.assertEqual(after_config['name'], 'after-routes')
        self.assertNotEqual(before_config['sha256'], after_config['sha256'])
        error_configs = report['errors']['routing_configs']
        self.assertEqual(
            error_configs['before']['sha256'], before_config['sha256']
        )
        self.assertEqual(
            error_configs['after']['sha256'], after_config['sha256']
        )

    def test_registration_order_swap_changes_isolation_decision(self):
        samples = {'photo.jpg': b'\xff\xd8\xff\x00legacy'}
        before = assess(
            samples=samples,
            before=list(TYPES),
            after=[LegacyJpeg()] + list(TYPES),
            before_routes=routes_before(),
            after_routes=routes_after(),
        )
        after = assess(
            samples=samples,
            before=list(TYPES),
            after=list(TYPES) + [LegacyJpeg()],
            before_routes=routes_before(),
            after_routes=routes_after(),
        )

        self.assertEqual(before['samples'][0]['decision'], 'downgrade')
        self.assertEqual(after['samples'][0]['decision'], 'unchanged')
        self.assertEqual(
            before['samples_sha256'], after['samples_sha256']
        )
        self.assertEqual(
            before['changed_isolation_decisions'][0]['sample'],
            'photo.jpg',
        )
        self.assertEqual(after['changed_isolation_decisions'], [])
        self.assertTrue(before['samples'][0]['precedence_changed'])

    def test_text_report_keeps_new_formats_and_downgrades_separate(self):
        report = assess(
            samples={
                'photo.jpg': b'\xff\xd8\xff\x00legacy',
                'new.foo': b'FOO\x00payload',
            },
            before=list(TYPES),
            after=[LegacyJpeg(), FooType()] + list(TYPES),
            before_routes=routes_before(),
            after_routes=routes_after(),
        )

        text = render_text(report)
        self.assertIn('New legitimate formats', text)
        self.assertIn('Legacy files moved to a weaker queue', text)
        self.assertIn('new.foo', text)
        self.assertIn('photo.jpg', text)

        markdown = render_markdown(report)
        self.assertIn('## New legitimate formats', markdown)
        self.assertIn('## Legacy files moved to a weaker queue', markdown)

    def test_fixture_prefixes_are_compared_in_same_order(self):
        samples = []
        for name in ('sample.jpg', 'sample.png', 'sample.gif'):
            path = os.path.join(FIXTURES, name)
            with open(path, 'rb') as fp:
                samples.append((name, fp.read(8192)))

        report = assess(
            samples=samples,
            before=list(TYPES),
            after=list(TYPES),
            before_routes=routes_before(),
            after_routes=routes_after(),
        )
        self.assertEqual(
            [record['name'] for record in report['samples']],
            ['sample.jpg', 'sample.png', 'sample.gif'],
        )
        self.assertEqual(report['summary']['downgrade'], 0)


    def test_route_config_accepts_rule_lists(self):
        report = assess(
            samples={"photo.jpg": b'\xff\xd8\xff\x00legacy'},
            before=list(TYPES),
            after=list(TYPES),
            before_routes=[
                {'mime': 'image/jpeg', 'queue': 'image-strong',
                 'capability': 10},
            ],
            after_routes=[
                {'extension': 'jpg', 'queue': 'image-weak',
                 'capability': 1},
            ],
        )
        self.assertEqual(report['samples'][0]['decision'], 'downgrade')

    def test_queue_capability_map_resolves_route_strength(self):
        report = assess(
            samples={"photo.jpg": b'\xff\xd8\xff\x00legacy'},
            before=list(TYPES),
            after=list(TYPES),
            before_routes={
                'capabilities': {'image-strong': 10, 'image-weak': 1},
                'routes': {'image/jpeg': 'image-strong'},
            },
            after_routes={
                'queues': {
                    'image-strong': {'capability': 10},
                    'image-weak': {'capability': 1},
                },
                'routes': {'image/jpeg': 'image-weak'},
            },
        )
        self.assertEqual(report['samples'][0]['decision'], 'downgrade')

if __name__ == '__main__':
    unittest.main()
