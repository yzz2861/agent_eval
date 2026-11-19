"""Test oletools.common.provenance source-mapping API.

Builds small nested containers (SMC1 format) and checks that IOCs found in
derived content can be traced back to the original sample bytes, including
through decoding steps, concatenation and non-reversible transforms.
"""

import base64
import binascii
import unittest
import zlib

from oletools.common.provenance import (
    MemberRef,
    ProvenanceMap,
    aggregate_iocs,
    base64_decode,
    build_simple_container,
    decode_text,
    find_iocs,
    hex_decode,
    read_simple_container,
    zlib_decompress,
)


def open_member(data, prov_map, member):
    """Slice a member out of its container, tracking provenance."""
    return (data[member.start:member.end],
            prov_map.member(member.name, member.start, member.end,
                            member.occurrence))


class TestThreeLayerContainer(unittest.TestCase):
    """IOC inside hex-encoded payload nested three containers deep."""

    ORIGIN = 'sample.bin'
    URL = 'http://update.example-service.com/patch.exe'

    @classmethod
    def setUpClass(cls):
        cls.inner_text = ('Version 9 see ' + cls.URL + ' end').encode('ascii')
        cls.inner_hex = binascii.hexlify(cls.inner_text)
        layer3 = build_simple_container([('payload', cls.inner_hex)])
        layer2 = build_simple_container([('middle', layer3)])
        cls.root = build_simple_container([('outer', layer2)])

    def extract(self):
        prov_map = ProvenanceMap.for_data(self.root, origin=self.ORIGIN)
        data = self.root
        for _layer in range(3):
            member = read_simple_container(data)[0]
            data, prov_map = open_member(data, prov_map, member)
        raw, prov_map = hex_decode(data, prov_map)
        text, prov_map = decode_text(raw, prov_map, 'ascii')
        return text, prov_map

    def test_ioc_text_unchanged(self):
        text, prov_map = self.extract()
        entries = find_iocs(text, prov_map)
        urls = [e for e in entries if e.ioc_type == 'URL']
        self.assertEqual(len(urls), 1)
        # IOC value is exactly the text from the decoded content
        self.assertEqual(urls[0].value, self.URL)

    def test_provenance_maps_back_to_original_bytes(self):
        text, prov_map = self.extract()
        url = [e for e in find_iocs(text, prov_map)
               if e.ioc_type == 'URL'][0]
        provenance = url.provenance
        self.assertFalse(provenance.uncertain)
        self.assertEqual(provenance.origin, self.ORIGIN)
        self.assertEqual(len(provenance.ranges), 1)
        rng = provenance.ranges[0]
        # full member identity chain of the three nested containers
        self.assertEqual(rng.path, (MemberRef('outer', 0),
                                    MemberRef('middle', 0),
                                    MemberRef('payload', 0)))
        # decoding steps are recorded in order
        self.assertEqual([s.name for s in rng.steps],
                         ['hex-decode', 'text-decode'])
        # the source range points at the hex text inside the original file
        url_start = self.inner_text.index(self.URL.encode('ascii'))
        expected = self.inner_hex[2 * url_start:
                                  2 * (url_start + len(self.URL))]
        self.assertEqual(self.root[rng.start:rng.end], expected)
        # and the report rendering mentions origin and member path
        desc = provenance.describe()
        self.assertIn(self.ORIGIN, desc)
        self.assertIn('outer[0]/middle[0]/payload[0]', desc)


class TestCrossFragmentConcat(unittest.TestCase):
    """URL split across two members, only complete after concatenation."""

    FRAG_A = b'http://harmless.exam'
    FRAG_B = b'ple.com/cross-fragment'
    URL = 'http://harmless.example.com/cross-fragment'

    def test_concat_provenance_is_range_set(self):
        root = build_simple_container([('part1', self.FRAG_A),
                                       ('part2', self.FRAG_B)])
        prov_map = ProvenanceMap.for_data(root, origin='sample.bin')
        members = read_simple_container(root)
        _d1, p1 = open_member(root, prov_map, members[0])
        _d2, p2 = open_member(root, prov_map, members[1])
        cat = ProvenanceMap.concat([p1, p2])
        text = (self.FRAG_A + self.FRAG_B).decode('ascii')
        entries = find_iocs(text, cat)
        urls = [e for e in entries if e.ioc_type == 'URL']
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0].value, self.URL)
        provenance = urls[0].provenance
        self.assertFalse(provenance.uncertain)
        # many-to-one: the single URL maps to a set of two ranges
        self.assertEqual(len(provenance.ranges), 2)
        paths = [r.path for r in provenance.ranges]
        self.assertIn((MemberRef('part1', 0),), paths)
        self.assertIn((MemberRef('part2', 0),), paths)
        # each range recovers its original fragment from the sample
        recovered = b''.join(root[r.start:r.end] for r in provenance.ranges)
        self.assertEqual(recovered, self.FRAG_A + self.FRAG_B)


class TestSameNamedNestedObjects(unittest.TestCase):
    """Two nested objects with identical names must stay distinct evidence,
    even when they carry the same duplicate IOC."""

    URL = b'http://dup.example.com/x'

    def test_same_name_not_merged_duplicate_ioc_aggregated(self):
        inner_a = build_simple_container([('obj', self.URL)])
        inner_b = build_simple_container([('obj', self.URL)])
        root = build_simple_container([('obj', inner_a), ('obj', inner_b)])
        prov_map = ProvenanceMap.for_data(root, origin='sample.bin')
        entries = []
        for outer in read_simple_container(root):
            data1, p1 = open_member(root, prov_map, outer)
            inner = read_simple_container(data1)[0]
            data2, p2 = open_member(data1, p1, inner)
            text, p3 = decode_text(data2, p2, 'ascii')
            entries += [e for e in find_iocs(text, p3)
                        if e.ioc_type == 'URL']
        # two pieces of evidence, not merged
        self.assertEqual(len(entries), 2)
        paths = [e.provenance.ranges[0].path for e in entries]
        self.assertEqual(len(set(paths)), 2)
        self.assertIn((MemberRef('obj', 0), MemberRef('obj', 0)), paths)
        self.assertIn((MemberRef('obj', 1), MemberRef('obj', 0)), paths)
        # each provenance recovers the IOC bytes from its own member
        for entry in entries:
            rng = entry.provenance.ranges[0]
            self.assertEqual(root[rng.start:rng.end], self.URL)
        # duplicate IOC values may be aggregated for display...
        groups = aggregate_iocs(entries)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].value, self.URL.decode('ascii'))
        # ...but every source is preserved completely
        self.assertEqual(len(groups[0].entries), 2)
        prov_paths = [p.ranges[0].path for p in groups[0].provenances]
        self.assertEqual(len(set(prov_paths)), 2)


class TestUncertainTransforms(unittest.TestCase):
    """Non-reversible transforms must flag uncertainty instead of
    fabricating a single offset."""

    def test_zlib_whole_member_envelope(self):
        payload = b'go to http://hidden.example.com/now'
        comp = zlib.compress(payload)
        root = build_simple_container([('blob', comp)])
        prov_map = ProvenanceMap.for_data(root, origin='sample.bin')
        member = read_simple_container(root)[0]
        data, p1 = open_member(root, prov_map, member)
        raw, p2 = zlib_decompress(data, p1)
        text, p3 = decode_text(raw, p2, 'ascii')
        url = [e for e in find_iocs(text, p3) if e.ioc_type == 'URL'][0]
        self.assertEqual(url.value, 'http://hidden.example.com/now')
        provenance = url.provenance
        self.assertTrue(provenance.uncertain)
        # conservative envelope: the whole compressed member, nothing more
        self.assertEqual(len(provenance.ranges), 1)
        rng = provenance.ranges[0]
        self.assertEqual(rng.path, (MemberRef('blob', 0),))
        self.assertEqual(root[rng.start:rng.end], comp)
        self.assertEqual([s.name for s in rng.steps],
                         ['zlib-decompress', 'text-decode'])

    def test_base64_approximate_envelope(self):
        payload = b'http://b64.example.com/abc'
        enc = base64.b64encode(payload)
        root = build_simple_container([('b64', enc)])
        prov_map = ProvenanceMap.for_data(root, origin='sample.bin')
        member = read_simple_container(root)[0]
        data, p1 = open_member(root, prov_map, member)
        raw, p2 = base64_decode(data, p1)
        text, p3 = decode_text(raw, p2, 'ascii')
        url = [e for e in find_iocs(text, p3) if e.ioc_type == 'URL'][0]
        self.assertEqual(url.value, 'http://b64.example.com/abc')
        provenance = url.provenance
        self.assertTrue(provenance.uncertain)
        # the envelope stays inside the base64 member of the original file
        self.assertGreaterEqual(len(provenance.ranges), 1)
        for rng in provenance.ranges:
            self.assertEqual(rng.path, (MemberRef('b64', 0),))
            self.assertGreaterEqual(rng.start, member.start)
            self.assertLessEqual(rng.end, member.end)
        merged = b''.join(root[r.start:r.end] for r in provenance.ranges)
        self.assertTrue(merged)  # evidence bytes are recoverable


class TestIOCTextPreserved(unittest.TestCase):
    """IOC values are reported exactly as found: no defanging, no case
    folding, no normalization."""

    def test_value_verbatim(self):
        text = 'ref HTTP://ExAmPle.COM/AbC?x=1 and 10.1.2.3 done'
        prov_map = ProvenanceMap.for_data(text.encode('ascii'),
                                          origin='sample.bin')
        entries = find_iocs(text, prov_map)
        values = [(e.ioc_type, e.value) for e in entries]
        self.assertIn(('URL', 'HTTP://ExAmPle.COM/AbC?x=1'), values)
        self.assertIn(('IPv4', '10.1.2.3'), values)


# just in case somebody calls this file as a script
if __name__ == '__main__':
    unittest.main()
