import os
import tempfile
import unittest
from bottle import ConfigDict


class TestConfDict(unittest.TestCase):
    def test_isadict(self):
        """ ConfigDict should behaves like a normal dict. """
        # It is a dict-subclass, so this kind of pointless, but it doen't hurt.
        d, m = dict(), ConfigDict()
        d['key'], m['key'] = 'value', 'value'
        d['k2'], m['k2'] = 'v1', 'v1'
        d['k2'], m['k2'] = 'v2', 'v2'
        self.assertEqual(d.keys(), m.keys())
        self.assertEqual(list(d.values()), list(m.values()))
        self.assertEqual(d.get('key'), m.get('key'))
        self.assertEqual(d.get('cay'), m.get('cay'))
        self.assertEqual(list(iter(d)), list(iter(m)))
        self.assertEqual([k for k in d], [k for k in m])
        self.assertEqual(len(d), len(m))
        self.assertEqual('key' in d, 'key' in m)
        self.assertEqual('cay' in d, 'cay' in m)
        self.assertRaises(KeyError, lambda: m['cay'])
        self.assertEqual(d.setdefault('key', "Val2"), m.setdefault('key', "Val2"))
        self.assertEqual(d.setdefault('key', "Val3"), m.setdefault('key', "Val3"))
        self.assertEqual(d.get('key'), m.get('key'))
        with self.assertRaises(KeyError):
            del m['No key']

    def test_write(self):
        c = ConfigDict()
        c['key'] = 'value'
        self.assertEqual(c['key'], 'value')
        self.assertTrue('key' in c)
        c['key'] = 'value2'
        self.assertEqual(c['key'], 'value2')

    def test_update(self):
        c = ConfigDict()
        c['key'] = 'value'
        c.update(key='value2', key2='value3')
        self.assertEqual(c['key'], 'value2')
        self.assertEqual(c['key2'], 'value3')

    def test_string_save_keys(self):
        c = ConfigDict()
        with self.assertRaises(TypeError):
            c[5] = 'value'
        with self.assertRaises(TypeError):
            c.load_dict({5: 'value'})

    def test_namespaces(self):
        c = ConfigDict()
        c.update('a.b', key='value')
        self.assertEqual(c['a.b.key'], 'value')

    def test_meta(self):
        c = ConfigDict()
        c.meta_set('bool', 'filter', bool)
        c.meta_set('int', 'filter', int)
        c['bool'] = 'I am so true!'
        c['int'] = '6'
        self.assertTrue(c['bool'] is True)
        self.assertEqual(c['int'], 6)
        self.assertRaises(ValueError, lambda: c.update(int='not an int'))

    def test_load_dict(self):
        c = ConfigDict()
        d = dict(a=dict(b=dict(foo=5, bar=6), baz=7))
        c.load_dict(d)
        self.assertEqual(c['a.b.foo'], 5)
        self.assertEqual(c['a.b.bar'], 6)
        self.assertEqual(c['a.baz'], 7)
        # unicode keys (see issue #720)
        try:
            key = unichr(12354)
        except NameError:
            key = chr(12354)
        c = ConfigDict()
        c.load_dict({key: 'value'})
        self.assertEqual('value', c[key])
        c = ConfigDict()
        c.load_dict({key: {'subkey': 'value'}})
        self.assertEqual('value', c[key + '.subkey'])

    def test_load_module(self):
        c = ConfigDict()
        c.load_module('test.example_settings', True)
        self.assertEqual(c['A.B.C'], 3)

        c = ConfigDict()
        c.load_module('test.example_settings', False)
        self.assertEqual(c['A']['B']['C'], 3)

    def test_overlay(self):
        source = ConfigDict()
        source['key'] = 'source'
        intermediate = source._make_overlay()
        overlay = intermediate._make_overlay()

        # Overlay contains values from source
        self.assertEqual(overlay['key'], 'source')
        self.assertEqual(overlay.get('key'), 'source')
        self.assertTrue('key' in overlay)

        # Overlay is updated with source
        source['key'] = 'source2'
        self.assertEqual(source['key'], 'source2')
        self.assertEqual(overlay['key'], 'source2')

        # Overlay 'overlays' source (hence the name)
        overlay['key'] = 'overlay'
        self.assertEqual(source['key'], 'source2')
        self.assertEqual(intermediate['key'], 'source2')
        self.assertEqual(overlay['key'], 'overlay')

        # Deleting an overlayed key restores the value from source
        del overlay['key']
        self.assertEqual(source['key'], 'source2')
        self.assertEqual(overlay['key'], 'source2')

        # Deleting a virtual key is actually not possible.
        with self.assertRaises(KeyError):
            del overlay['key']

        # Deleting a key in the source also removes it from overlays.
        del source['key']
        self.assertTrue('key' not in overlay)
        self.assertTrue('key' not in intermediate)
        self.assertTrue('key' not in source)

        # New keys in source are copied to overlay
        source['key2'] = 'source'
        self.assertEqual(source['key2'], 'source')
        self.assertEqual(intermediate['key2'], 'source')
        self.assertEqual(overlay['key2'], 'source')

        # New keys in overlay do not change the source
        overlay['key3'] = 'overlay'
        self.assertEqual(overlay['key3'], 'overlay')
        self.assertTrue('key3' not in intermediate)
        self.assertTrue('key3' not in source)

        # Setting the same key in the source does not affect the overlay
        # because it already has this key.
        source['key3'] = 'source'
        self.assertEqual(source['key3'], 'source')
        self.assertEqual(intermediate['key3'], 'source')
        self.assertEqual(overlay['key3'], 'overlay')

        # But as soon as the overlayed key is deleted, it gets the
        # copy from the source
        del overlay['key3']
        self.assertEqual(source['key3'], 'source')
        self.assertEqual(overlay['key3'], 'source')

    def test_gc_overlays(self):
        root = ConfigDict()
        overlay = root._make_overlay()
        del overlay
        import gc; gc.collect()
        root._make_overlay()  # This triggers the weakref-collect
        self.assertEqual(len(root._overlays), 1)

    def test_overlay_set_rolls_back_when_listener_fails(self):
        root = ConfigDict()
        first = root._make_overlay()
        second = root._make_overlay()
        root['key'] = 'old'

        def fail(config, key, value):
            if key == 'key':
                raise RuntimeError('listener failed')

        second._add_change_listener(fail)

        with self.assertRaises(RuntimeError):
            root['key'] = 'new'

        self.assertEqual(root['key'], 'old')
        self.assertEqual(first['key'], 'old')
        self.assertEqual(second['key'], 'old')
        self.assertNotIn('key', root._virtual_keys)
        self.assertIn('key', first._virtual_keys)
        self.assertIn('key', second._virtual_keys)

    def test_overlay_delete_rolls_back_when_listener_fails(self):
        root = ConfigDict()
        first = root._make_overlay()
        second = root._make_overlay()
        root['key'] = 'old'

        def fail(config, key, value):
            if key == 'key':
                raise RuntimeError('listener failed')

        second._add_change_listener(fail)

        with self.assertRaises(RuntimeError):
            del root['key']

        self.assertEqual(root['key'], 'old')
        self.assertEqual(first['key'], 'old')
        self.assertEqual(second['key'], 'old')
        self.assertNotIn('key', root._virtual_keys)
        self.assertIn('key', first._virtual_keys)
        self.assertIn('key', second._virtual_keys)

    def test_overlay_restore_rolls_back_when_nested_listener_fails(self):
        root = ConfigDict()
        middle = root._make_overlay()
        leaf = middle._make_overlay()
        root['key'] = 'root'
        middle['key'] = 'override'

        def fail(config, key, value):
            if key == 'key':
                raise RuntimeError('listener failed')

        leaf._add_change_listener(fail)

        with self.assertRaises(RuntimeError):
            del middle['key']

        self.assertEqual(root['key'], 'root')
        self.assertEqual(middle['key'], 'override')
        self.assertEqual(leaf['key'], 'override')
        self.assertNotIn('key', middle._virtual_keys)
        self.assertIn('key', leaf._virtual_keys)

    def test_nested_overlay_restore_receives_inherited_value(self):
        root = ConfigDict()
        root['key'] = 'root'
        middle = root._make_overlay()
        leaf = middle._make_overlay()
        middle['key'] = 'override'

        self.assertEqual(leaf['key'], 'override')

        del middle['key']

        self.assertEqual(root['key'], 'root')
        self.assertEqual(middle['key'], 'root')
        self.assertEqual(leaf['key'], 'root')
        self.assertIn('key', middle._virtual_keys)
        self.assertIn('key', leaf._virtual_keys)

    def test_overlay_filter_failure_keeps_virtual_override_state(self):
        root = ConfigDict()
        first = root._make_overlay()
        second = root._make_overlay()
        root['key'] = 'old'
        root.meta_set('key', 'filter', lambda value: (_ for _ in ()).throw(ValueError()))

        with self.assertRaises(ValueError):
            first['key'] = 'new'

        self.assertEqual(root['key'], 'old')
        self.assertEqual(first['key'], 'old')
        self.assertEqual(second['key'], 'old')
        self.assertIn('key', first._virtual_keys)
        self.assertIn('key', second._virtual_keys)

    def test_root_filter_failure_discards_queued_listener_writes(self):
        root = ConfigDict()
        first = root._make_overlay()
        second = root._make_overlay()
        root['key'] = 'old'
        root.meta_set('key', 'filter', lambda value: (_ for _ in ()).throw(ValueError()))

        def queue_write(config, key, value):
            if key == 'key':
                config['queued'] = 'value'

        root._add_change_listener(queue_write)

        with self.assertRaises(ValueError):
            root['key'] = 'new'

        self.assertNotIn('queued', root)
        self.assertNotIn('queued', first)
        self.assertNotIn('queued', second)

    def test_explicit_overlay_is_not_changed_by_parent_propagation(self):
        root = ConfigDict()
        first = root._make_overlay()
        first_child = first._make_overlay()
        second = root._make_overlay()
        root['key'] = 'root'
        first['key'] = 'override'

        root['key'] = 'new root'

        self.assertEqual(root['key'], 'new root')
        self.assertEqual(first['key'], 'override')
        self.assertEqual(first_child['key'], 'override')
        self.assertEqual(second['key'], 'new root')
        self.assertNotIn('key', first._virtual_keys)
        self.assertIn('key', first_child._virtual_keys)
        self.assertIn('key', second._virtual_keys)

        del root['key']

        self.assertNotIn('key', root)
        self.assertEqual(first['key'], 'override')
        self.assertEqual(first_child['key'], 'override')
        self.assertNotIn('key', second)
        self.assertNotIn('key', first._virtual_keys)
        self.assertIn('key', first_child._virtual_keys)
        self.assertNotIn('key', second._virtual_keys)

        del first['key']

        self.assertNotIn('key', first)
        self.assertNotIn('key', first_child)
        self.assertNotIn('key', first._virtual_keys)
        self.assertNotIn('key', first_child._virtual_keys)

    def test_listeners_observe_a_consistent_overlay_tree(self):
        root = ConfigDict()
        root['key'] = 'old'
        first = root._make_overlay()
        second = root._make_overlay()
        observed = []

        def observe(config, key, value):
            if key == 'key':
                observed.append((
                    root.get('key'), first.get('key'), second.get('key')
                ))

        root._add_change_listener(observe)
        first._add_change_listener(observe)
        second._add_change_listener(observe)

        root['key'] = 'new'

        self.assertEqual(observed, [('new', 'new', 'new')] * 3)

    def test_listener_writes_are_deferred_until_propagation_finishes(self):
        root = ConfigDict()
        root['key'] = 'old'
        root['queued'] = 'before'
        first = root._make_overlay()
        second = root._make_overlay()
        events = []

        def listener(config, key, value):
            events.append(('notify', key))
            if key == 'key' and config is root:
                config['queued'] = 'value'
                events.append(('queued', root['queued'], second['queued']))

        root._add_change_listener(listener)
        first._add_change_listener(listener)
        second._add_change_listener(listener)

        root['key'] = 'value'

        self.assertEqual(root['queued'], 'value')
        self.assertEqual(first['queued'], 'value')
        self.assertEqual(second['queued'], 'value')
        self.assertEqual(events, [
            ('notify', 'key'),
            ('queued', 'before', 'before'),
            ('notify', 'key'),
            ('notify', 'key'),
            ('notify', 'queued'),
            ('notify', 'queued'),
            ('notify', 'queued'),
        ])

    def test_failed_propagation_discards_queued_listener_writes(self):
        root = ConfigDict()
        root['key'] = 'old'
        first = root._make_overlay()
        second = root._make_overlay()

        def queue_write(config, key, value):
            if key == 'key':
                config['queued'] = 'value'

        def fail(config, key, value):
            if key == 'key':
                raise RuntimeError('listener failed')

        root._add_change_listener(queue_write)
        second._add_change_listener(fail)

        with self.assertRaises(RuntimeError):
            root['key'] = 'new'

        self.assertNotIn('queued', root)
        self.assertNotIn('queued', first)
        self.assertNotIn('queued', second)

    def test_listener_can_queue_delete_until_propagation_finishes(self):
        root = ConfigDict()
        root['key'] = 'old'
        root['remove'] = 'before'
        first = root._make_overlay()
        second = root._make_overlay()

        def queue_delete(config, key, value):
            if key == 'key':
                del config['remove']

        root._add_change_listener(queue_delete)

        root['key'] = 'new'

        self.assertNotIn('remove', root)
        self.assertNotIn('remove', first)
        self.assertNotIn('remove', second)

    def test_failed_queued_write_keeps_successful_primary_change(self):
        root = ConfigDict()
        root['key'] = 'old'
        first = root._make_overlay()
        second = root._make_overlay()
        root.meta_set('queued', 'filter',
                      lambda value: (_ for _ in ()).throw(ValueError()))

        def queue_failing_write(config, key, value):
            if key == 'key':
                config['queued'] = 'value'

        root._add_change_listener(queue_failing_write)

        with self.assertRaises(ValueError):
            root['key'] = 'new'

        self.assertEqual(root['key'], 'new')
        self.assertEqual(first['key'], 'new')
        self.assertEqual(second['key'], 'new')
        self.assertNotIn('queued', root)


class TestINIConfigLoader(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.config_file = tempfile.NamedTemporaryFile(suffix='.example.ini',
                                                       delete=False)
        self.config_file.write(b'[DEFAULT]\n'
                               b'default: 45\n'
                               b'[bottle]\n'
                               b'port = 8080\n'
                               b'[ROOT]\n'
                               b'namespace.key = test\n'
                               b'[NameSpace.Section]\n'
                               b'sub.namespace.key = test2\n'
                               b'default = otherDefault\n'
                               b'[compression]\n'
                               b'status=single\n')
        self.config_file.flush()

    @classmethod
    def tearDownClass(self):
        self.config_file.close()
        os.unlink(self.config_file.name)

    def test_load_config(self):
        c = ConfigDict()
        c.load_config(self.config_file.name)
        self.assertDictEqual({
            'compression.default': '45',
            'compression.status': 'single',
            'default': '45',
            'namespace.key': 'test',
            'namespace.section.default': 'otherDefault',
            'namespace.section.sub.namespace.key': 'test2',
            'port': '8080'}, c)
