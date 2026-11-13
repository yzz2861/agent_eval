# -*- coding: utf-8 -*-
# '瓶' means "Bottle"

import unittest
from bottle import FormsDict, touni, tob

class TestFormsDict(unittest.TestCase):
    def test_attr_access(self):
        """ FomsDict.attribute returs string values as unicode. """
        d = FormsDict(py3='瓶')
        self.assertEqual('瓶', d.py3)
        self.assertEqual('瓶', d["py3"])

    def test_attr_missing(self):
        """ FomsDict.attribute returs u'' on missing keys. """
        d = FormsDict()
        self.assertEqual('', d.missing)

    def test_duplicate_keys_consistent_last_value(self):
        """ FormsDict: repeated keys keep all values, and item, attribute
            and get() access consistently return the last value. """
        d = FormsDict()
        d.append('key', 'first')
        d.append('key', 'last')
        self.assertEqual('last', d['key'])
        self.assertEqual('last', d.key)
        self.assertEqual('last', d.get('key'))
        self.assertEqual(['first', 'last'], d.getall('key'))
