from __future__ import print_function

import json
import os
import sys
import unittest

_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

import olefile
from olefile.forensic_demo import build_synthetic_review_view


class ForensicPropertyViewTests(unittest.TestCase):
    def setUp(self):
        self.view = build_synthetic_review_view()

    def test_preserves_every_section_and_physical_source(self):
        self.assertEqual(3, len(self.view.sections))
        self.assertEqual([0, 1, 2], [section.index for section in self.view.sections])
        self.assertTrue(all(section.fmtid for section in self.view.sections))
        for prop in self.view.properties:
            self.assertIsNotNone(prop.source.value_offset)
            self.assertIsNotNone(prop.source.entry_offset)
            self.assertIn('section=', prop.reference)
            self.assertIn('pid=', prop.reference)

    def test_duplicate_display_names_remain_independent(self):
        hits = self.view.find(name=u'核验人')
        self.assertEqual(2, len(hits))
        self.assertEqual([0, 1], sorted(prop.section_index for prop in hits))
        self.assertEqual({2, 18}, {prop.property_id for prop in hits})
        self.assertEqual({u'周核验', u'郑旧档'}, {prop.value for prop in hits})
        group = self.view.duplicate_name_groups[u'核验人']
        self.assertEqual(2, len(group))
        issue_codes = {issue.code for issue in self.view.issues}
        self.assertIn('duplicate_name', issue_codes)

    def test_aliases_are_preserved_from_duplicate_dictionary_pid(self):
        legacy = self.view.find(name=u'核验人', section_index=1)
        self.assertEqual(1, len(legacy))
        self.assertIn(u'核验员（旧别名）', legacy[0].aliases)
        dictionary = self.view.sections[1].dictionaries[0]
        self.assertEqual(2, len(dictionary.names_for_property_id(18)))

    def test_actual_type_tags_are_preserved(self):
        reviewer = self.view.find(name=u'核验人', section_index=0)[0]
        checker = self.view.find(name=u'复核人')[0]
        unknown = self.view.find(property_id=0x4E21)[0]
        self.assertEqual(31, reviewer.property_type)
        self.assertEqual('VT_LPWSTR', reviewer.type_name)
        self.assertEqual(30, checker.property_type)
        self.assertEqual('VT_LPSTR', checker.type_name)
        self.assertEqual(19, unknown.property_type)
        self.assertEqual('VT_UI4', unknown.type_name)

    def test_missing_encoding_and_unmapped_ids_are_queryable(self):
        codes = self.view.issues_by_code()
        self.assertTrue(codes['missing_encoding_evidence'])
        self.assertTrue(codes['unmapped_property_id'])
        unknown = self.view.find(property_id=0x4E21)[0]
        self.assertIn(unknown, self.view.unmapped_properties)
        gap_name = self.view.sections[2].name_dictionary[0]
        self.assertEqual('undecoded_without_codepage', gap_name.encoding_status)
        self.assertFalse(gap_name.encoding_authoritative)
        self.assertTrue(gap_name.raw_name)

    def test_citation_status_distinguishes_unique_ambiguous_and_physical_only(self):
        unique = self.view.find(name=u'复核人')[0]
        duplicate = self.view.find(name=u'核验人', section_index=0)[0]
        unknown = self.view.find(property_id=0x4E21)[0]
        unverified = self.view.find(property_id=9)[0]
        self.assertEqual('unique-name-reference', self.view.citation_for(unique)['status'])
        self.assertEqual('section-qualified-reference-required',
                         self.view.citation_for(duplicate)['status'])
        self.assertEqual('physical-reference-only-unmapped-id',
                         self.view.citation_for(unknown)['status'])
        self.assertEqual('physical-reference-only-encoding-unverified',
                         self.view.citation_for(unverified)['status'])

    def test_audit_dict_is_json_serializable(self):
        payload = json.dumps(self.view.to_dict(), ensure_ascii=False)
        self.assertIn(u'核验人', payload)
        self.assertIn('duplicate_name', payload)


class OleFileIntegrationTests(unittest.TestCase):
    def test_real_doc_standard_stream(self):
        path = os.path.join(_thismodule_dir, 'images', 'test-ole-file.doc')
        ole = olefile.OleFileIO(path)
        try:
            view = ole.get_property_set_view('\x05SummaryInformation')
            self.assertGreaterEqual(len(view.sections), 1)
            author = view.find(property_id=4)
            self.assertTrue(author)
            self.assertEqual('Laurence Ipsum', author[0].value)
            props = ole.getproperties('\x05SummaryInformation')
            self.assertEqual(b'Laurence Ipsum', props[4])
        finally:
            ole.close()


if __name__ == '__main__':
    unittest.main()
