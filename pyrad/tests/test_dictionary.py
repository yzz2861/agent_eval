import unittest
import operator
import os
import tempfile
from io import StringIO

from . import home
from pyrad.dictionary import Attribute
from pyrad.dictionary import Dictionary
from pyrad.dictionary import ParseError
from pyrad.tools import DecodeAttr
from pyrad.dictfile import DictFile


class AttributeTests(unittest.TestCase):
    def testInvalidDataType(self):
        self.assertRaises(ValueError, Attribute, 'name', 'code', 'datatype')

    def testConstructionParameters(self):
        attr = Attribute('name', 'code', 'integer', False, 'vendor')
        self.assertEqual(attr.name, 'name')
        self.assertEqual(attr.code, 'code')
        self.assertEqual(attr.type, 'integer')
        self.assertEqual(attr.is_sub_attribute, False)
        self.assertEqual(attr.vendor, 'vendor')
        self.assertEqual(len(attr.values), 0)
        self.assertEqual(len(attr.sub_attributes), 0)

    def testNamedConstructionParameters(self):
        attr = Attribute(name='name', code='code', datatype='integer',
                         vendor='vendor')
        self.assertEqual(attr.name, 'name')
        self.assertEqual(attr.code, 'code')
        self.assertEqual(attr.type, 'integer')
        self.assertEqual(attr.vendor, 'vendor')
        self.assertEqual(len(attr.values), 0)

    def testValues(self):
        attr = Attribute('name', 'code', 'integer', False, 'vendor',
                         dict(pie='custard', shake='vanilla'))
        self.assertEqual(len(attr.values), 2)
        self.assertEqual(attr.values['shake'], 'vanilla')


class DictionaryInterfaceTests(unittest.TestCase):
    def testEmptyDictionary(self):
        dict = Dictionary()
        self.assertEqual(len(dict), 0)

    def testContainment(self):
        dict = Dictionary()
        self.assertEqual('test' in dict, False)
        self.assertEqual(dict.has_key('test'), False)
        dict.attributes['test'] = 'dummy'
        self.assertEqual('test' in dict, True)
        self.assertEqual(dict.has_key('test'), True)

    def testReadonlyContainer(self):
        dict = Dictionary()
        self.assertRaises(TypeError,
                          operator.setitem, dict, 'test', 'dummy')
        self.assertRaises(AttributeError,
                          operator.attrgetter('clear'), dict)
        self.assertRaises(AttributeError,
                          operator.attrgetter('update'), dict)


class DictionaryParsingTests(unittest.TestCase):

    simple_dict_values = [
        ('Test-String', 1, 'string'),
        ('Test-Octets', 2, 'octets'),
        ('Test-Integer', 0x03, 'integer'),
        ('Test-Ip-Address', 4, 'ipaddr'),
        ('Test-Ipv6-Address', 5, 'ipv6addr'),
        ('Test-If-Id', 6, 'ifid'),
        ('Test-Date', 7, 'date'),
        ('Test-Abinary', 8, 'abinary'),
        ('Test-Tlv', 9, 'tlv'),
        ('Test-Tlv-Str', 1, 'string'),
        ('Test-Tlv-Int', 2, 'integer'),
        ('Test-Integer64', 10, 'integer64'),
        ('Test-Integer64-Hex', 10, 'integer64'),
        ('Test-Integer64-Oct', 10, 'integer64'),
    ]

    def setUp(self):
        self.path = os.path.join(home, 'data')
        self.dict = Dictionary(os.path.join(self.path, 'simple'))

    def testParseEmptyDictionary(self):
        dict = Dictionary(StringIO(''))
        self.assertEqual(len(dict), 0)

    def testParseMultipleDictionaries(self):
        dict = Dictionary(StringIO(''))
        self.assertEqual(len(dict), 0)
        one = StringIO('ATTRIBUTE Test-First 1 string')
        two = StringIO('ATTRIBUTE Test-Second 2 string')
        dict = Dictionary(StringIO(''), one, two)
        self.assertEqual(len(dict), 2)

    def testParseSimpleDictionary(self):
        self.assertEqual(len(self.dict), len(self.simple_dict_values))
        for (attr, code, type) in self.simple_dict_values:
            attr = self.dict[attr]
            self.assertEqual(attr.code, code)
            self.assertEqual(attr.type, type)

    def testAttributeTooFewColumnsError(self):
        try:
            self.dict.ReadDictionary(
                    StringIO('ATTRIBUTE Oops-Too-Few-Columns'))
        except ParseError as e:
            self.assertEqual('attribute' in str(e), True)
        else:
            self.fail()

    def testAttributeTooFewColumnsErrorHasFile(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'dictionary.broken')
            with open(path, 'w') as fd:
                fd.write('\nATTRIBUTE Oops-Too-Few-Columns\n')
            with self.assertRaises(ParseError) as cm:
                self.dict.ReadDictionary(path)
        self.assertEqual(cm.exception.file, 'dictionary.broken')
        self.assertEqual(cm.exception.line, 2)
        self.assertTrue(str(cm.exception).startswith('dictionary.broken(2): '))

    def testAttributeUnknownTypeError(self):
        try:
            self.dict.ReadDictionary(StringIO('ATTRIBUTE Test-Type 1 dummy'))
        except ParseError as e:
            self.assertEqual('dummy' in str(e), True)
        else:
            self.fail()

    def testAttributeUnknownVendorError(self):
        try:
            self.dict.ReadDictionary(StringIO('ATTRIBUTE Test-Type 1 Simplon'))
        except ParseError as e:
            self.assertEqual('Simplon' in str(e), True)
        else:
            self.fail()

    def testAttributeConcatFlag(self):
        # FreeRADIUS compatibility, the values are not concatenated
        self.dict.ReadDictionary(StringIO('ATTRIBUTE Test-Concat 99 octets concat'))
        self.assertEqual(self.dict['Test-Concat'].type, 'octets')
        self.assertEqual(self.dict.attrindex['Test-Concat'], 99)

    def testNestedTlvIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO('ATTRIBUTE Test-Nested 1.2.3 string'))
        self.assertFalse('Test-Nested' in self.dict)
        self.assertIn('Test-Nested', self.dict.skipped_attributes)
        self.assertIn('nested TLV', cm.output[0])

    def testSubTlvIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                'ATTRIBUTE Test-Top 90 tlv\n'
                'ATTRIBUTE Test-Inner 90.3 tlv\n'
                'ATTRIBUTE Test-Inner-Str 90.3.1 string\n'
                'ATTRIBUTE Test-Top-Str 90.1 string'))
        self.assertFalse('Test-Inner' in self.dict)
        self.assertFalse('Test-Inner-Str' in self.dict)
        self.assertEqual(self.dict['Test-Top'].sub_attributes, {1: 'Test-Top-Str'})
        self.assertIn('nested TLV', cm.output[0])

    def testSkippedCodeKeepsTopLevelAttribute(self):
        with self.assertLogs('pyrad', 'WARNING'):
            self.dict.ReadDictionary(StringIO(
                'ATTRIBUTE Test-Bool 200 bool\n'
                'ATTRIBUTE Test-Integer-200 200 integer'))
        self.assertEqual(self.dict.attrindex['Test-Integer-200'], 200)

    def testSubAttributeOfUnknownTlvError(self):
        with self.assertRaises(ParseError) as cm:
            self.dict.ReadDictionary(StringIO('ATTRIBUTE Test-Sub 99.1 string'))
        self.assertIn('unknown TLV 99', str(cm.exception))

    def testSubAttributeOfTlvOfOtherVendor(self):
        self.dict.ReadDictionary(StringIO(
            'VENDOR Test-Vendor 42\n'
            'ATTRIBUTE Test-Vendor-Tlv 9 tlv Test-Vendor\n'
            'ATTRIBUTE Test-Std-Sub 9.3 string'))
        # 9 is Test-Tlv of the standard space in the simple dictionary
        self.assertIs(self.dict['Test-Std-Sub'].parent, self.dict['Test-Tlv'])
        self.assertEqual(self.dict['Test-Tlv'].sub_attributes[3],
                         'Test-Std-Sub')
        self.assertNotIn(3, self.dict['Test-Vendor-Tlv'].sub_attributes)
        with self.assertRaises(ParseError) as cm:
            self.dict.ReadDictionary(StringIO(
                'BEGIN-VENDOR Test-Vendor\n'
                'ATTRIBUTE Test-Vendor-Sub 90.1 string\n'
                'END-VENDOR Test-Vendor'))
        self.assertIn('unknown TLV 90', str(cm.exception))
        self.assertEqual(cm.exception.line, 2)

    def testSubAttributeOfTlvInOtherFile(self):
        dict = Dictionary(
            StringIO('ATTRIBUTE Test-Tlv 9 tlv'),
            StringIO('ATTRIBUTE Test-Tlv-Str 9.1 string'))
        self.assertIs(dict['Test-Tlv-Str'].parent, dict['Test-Tlv'])
        self.assertEqual(dict['Test-Tlv'].sub_attributes, {1: 'Test-Tlv-Str'})

    def testSubAttributeOfSkippedAttributeInOtherFile(self):
        with self.assertLogs('pyrad', 'WARNING'):
            dict = Dictionary(
                StringIO('ATTRIBUTE Test-Extended 241 extended'),
                StringIO('ATTRIBUTE Test-Ext-String 241.5 string'))
        self.assertIn('Test-Ext-String', dict.skipped_attributes)

    def testRedefinedSkippedAttributeAsTlv(self):
        with self.assertLogs('pyrad', 'WARNING'):
            dict = Dictionary(StringIO('ATTRIBUTE Test-Bool 200 bool'))
        dict.ReadDictionary(StringIO(
            'ATTRIBUTE Test-Tlv 200 tlv\n'
            'ATTRIBUTE Test-Tlv-Str 200.1 string'))
        self.assertEqual(dict['Test-Tlv'].sub_attributes, {1: 'Test-Tlv-Str'})

    def testAttributeFreeRadiusFlags(self):
        self.dict.ReadDictionary(StringIO(
            'ATTRIBUTE Test-Secret 90 octets secret\n'
            'ATTRIBUTE Test-Virtual 1000 integer virtual\n'
            'ATTRIBUTE Test-Password 91 string encrypt=1,secret'))
        self.assertEqual(self.dict['Test-Secret'].type, 'octets')
        self.assertEqual(self.dict['Test-Secret'].vendor, '')
        self.assertEqual(self.dict.attrindex['Test-Virtual'], 1000)
        self.assertEqual(self.dict['Test-Password'].encrypt, 1)

    def testAttributeArrayIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                'ATTRIBUTE Test-Array 90 ipaddr array'))
        self.assertFalse('Test-Array' in self.dict)
        self.assertIn('array flag', cm.output[0])

    def testAttributeVendorNamedLikeFlag(self):
        self.dict.ReadDictionary(StringIO(
            'VENDOR secret 42\n'
            'ATTRIBUTE Test-Type 1 integer secret'))
        self.assertEqual(self.dict['Test-Type'].vendor, 'secret')
        self.assertEqual(self.dict.attrindex['Test-Type'], (42, 1))

    def testUnsupportedDataTypeIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                'ATTRIBUTE Test-Extended 241 extended\n'
                'ATTRIBUTE Test-Evs 241.26 evs\n'
                'ATTRIBUTE Test-Ext-String 241.5 string\n'
                'VALUE Test-Ext-String Any any\n'
                'ATTRIBUTE Test-Ext-Vsa 241.26.42.1 string\n'
                'ATTRIBUTE Test-After 90 string'))
        for attr in ('Test-Extended', 'Test-Evs', 'Test-Ext-String',
                     'Test-Ext-Vsa'):
            self.assertFalse(attr in self.dict)
            self.assertIn(attr, self.dict.skipped_attributes)
        self.assertEqual(self.dict.attrindex['Test-After'], 90)
        self.assertEqual(len(cm.output), 1)
        self.assertIn('Skipped 4 unsupported dictionary attributes',
                      cm.output[0])
        self.assertIn('data type extended', cm.output[0])

    def testParseFreeRadiusDictionary(self):
        with self.assertLogs('pyrad', 'WARNING'):
            dict = Dictionary(os.path.join(self.path, 'freeradius'))
        self.assertEqual(dict['User-Password'].encrypt, 1)
        self.assertEqual(dict['CHAP-Password'].type, 'octets')
        self.assertEqual(dict['Tunnel-Password'].has_tag, True)
        self.assertEqual(dict['Tunnel-Password'].encrypt, 2)
        self.assertEqual(dict.attrindex['Proxy-To-Realm'], 1031)
        self.assertEqual(dict.attrindex['FreeRADIUS-Proxied-To'], (11344, 1))
        self.assertEqual(dict['EAP-Message'].type, 'octets')
        self.assertEqual(dict.skipped_attributes, set([
            'Vendor-Specific', 'Mobile-Node-Home-Address-IPv4',
            'Extended-Attribute-1', 'Extended-Attribute-5',
            'Extended-Vendor-Specific-1', 'Extended-Vendor-Specific-5',
            'Allowed-Called-Station-Id', 'FreeRADIUS-Attr',
            'FreeRADIUS-EAP-FAST-PAC', 'FreeRADIUS-EAP-FAST-PAC-Key',
            'WiMAX-Capability', 'WiMAX-Release', 'WiMAX-DNS-Server',
            'Lucent-Max-Shared-Users', 'DHCP-Router-Address']))

    def testAttributeOptions(self):
        self.dict.ReadDictionary(StringIO(
            'ATTRIBUTE Option-Type 1 string has_tag,encrypt=1'))
        self.assertEqual(self.dict['Option-Type'].has_tag, True)
        self.assertEqual(self.dict['Option-Type'].encrypt, 1)

    def testAttributeEncryptionError(self):
        try:
            self.dict.ReadDictionary(StringIO(
                'ATTRIBUTE Test-Type 1 string encrypt=4'))
        except ParseError as e:
            self.assertEqual('encrypt' in str(e), True)
        else:
            self.fail()

    def testValueTooFewColumnsError(self):
        try:
            self.dict.ReadDictionary(StringIO('VALUE Oops-Too-Few-Columns'))
        except ParseError as e:
            self.assertEqual('value' in str(e), True)
        else:
            self.fail()

    def testValueForUnknownAttributeIsIgnored(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                'VALUE Test-Attribute Test-Text 1'))
        self.assertFalse('Test-Attribute' in self.dict)
        self.assertIn('unknown attribute Test-Attribute', cm.output[0])

    def testIntegerValueParsing(self):
        self.assertEqual(len(self.dict['Test-Integer'].values), 0)
        self.dict.ReadDictionary(StringIO('VALUE Test-Integer Value-Six 5'))
        self.assertEqual(len(self.dict['Test-Integer'].values), 1)
        self.assertEqual(
                DecodeAttr('integer',
                           self.dict['Test-Integer'].values['Value-Six']),
                5)

    def testDateValueParsing(self):
        self.dict.ReadDictionary(StringIO('VALUE Test-Date Epoch-Plus-One 1'))
        self.assertEqual(self.dict['Test-Date'].values['Epoch-Plus-One'],
                         b'\x00\x00\x00\x01')

    def testIllegalValueError(self):
        self.dict.ReadDictionary(StringIO(
            'ATTRIBUTE Test-Byte 20 byte\n'
            'ATTRIBUTE Test-Ether 21 ether'))
        for (attr, value) in [('Test-Integer', '010'),
                              ('Test-Integer', 'abc'),
                              ('Test-Date', 'tomorrow'),
                              ('Test-Byte', '256'),
                              ('Test-Ether', 'not-a-mac'),
                              ('Test-Ip-Address', '1.2.3.400')]:
            with self.subTest(attr=attr, value=value):
                with self.assertRaises(ParseError) as cm:
                    self.dict.ReadDictionary(StringIO(
                        '\nVALUE %s Test-Value %s' % (attr, value)))
                self.assertEqual(cm.exception.line, 2)
                self.assertIn(attr, str(cm.exception))

    def testIllegalAttributeCodeError(self):
        for code in ['0X1A', 'abc', '9.x']:
            with self.subTest(code=code):
                with self.assertRaises(ParseError) as cm:
                    self.dict.ReadDictionary(StringIO(
                        '\nATTRIBUTE Test-Code %s string' % code))
                self.assertEqual(cm.exception.line, 2)
                self.assertIn(code, str(cm.exception))

    def testIllegalVendorCodeError(self):
        with self.assertRaises(ParseError) as cm:
            self.dict.ReadDictionary(StringIO('\nVENDOR Simplon abc'))
        self.assertEqual(cm.exception.line, 2)
        self.assertIn('abc', str(cm.exception))

    def testInteger64ValueParsing(self):
        self.assertEqual(len(self.dict['Test-Integer64'].values), 0)
        self.dict.ReadDictionary(StringIO('VALUE Test-Integer64 Value-Six 5'))
        self.assertEqual(len(self.dict['Test-Integer64'].values), 1)
        self.assertEqual(
                DecodeAttr('integer64',
                           self.dict['Test-Integer64'].values['Value-Six']),
                5)

    def testStringValueParsing(self):
        self.assertEqual(len(self.dict['Test-String'].values), 0)
        self.dict.ReadDictionary(StringIO(
            'VALUE Test-String Value-Custard custardpie'))
        self.assertEqual(len(self.dict['Test-String'].values), 1)
        self.assertEqual(
                DecodeAttr('string',
                           self.dict['Test-String'].values['Value-Custard']),
                'custardpie')

    def testOctetValueParsing(self):
        self.assertEqual(len(self.dict['Test-Octets'].values), 0)
        self.dict.ReadDictionary(StringIO(
                        'ATTRIBUTE Test-Octets 1 octets\n'
                        'VALUE Test-Octets Value-A 65\n'      # "A"
                        'VALUE Test-Octets Value-B 0x42\n'))  # "B"
        self.assertEqual(len(self.dict['Test-Octets'].values), 2)
        self.assertEqual(
                DecodeAttr('octets',
                           self.dict['Test-Octets'].values['Value-A']),
                b'A')
        self.assertEqual(
                DecodeAttr('octets',
                           self.dict['Test-Octets'].values['Value-B']),
                b'B')

    def testTlvParsing(self):
        self.assertEqual(len(self.dict['Test-Tlv'].sub_attributes), 2)
        self.assertEqual(self.dict['Test-Tlv'].sub_attributes, {1: 'Test-Tlv-Str', 2: 'Test-Tlv-Int'})

    def testSubTlvParsing(self):
        for (attr, _, _) in self.simple_dict_values:
            if attr.startswith('Test-Tlv-'):
                self.assertEqual(self.dict[attr].is_sub_attribute, True)
                self.assertEqual(self.dict[attr].parent, self.dict['Test-Tlv'])
            else:
                self.assertEqual(self.dict[attr].is_sub_attribute, False)
                self.assertEqual(self.dict[attr].parent, None)

        # tlv with vendor
        full_dict = Dictionary(os.path.join(self.path, 'full'))
        self.assertEqual(full_dict['Simplon-Tlv-Str'].is_sub_attribute, True)
        self.assertEqual(full_dict['Simplon-Tlv-Str'].parent, full_dict['Simplon-Tlv'])
        self.assertEqual(full_dict['Simplon-Tlv-Int'].is_sub_attribute, True)
        self.assertEqual(full_dict['Simplon-Tlv-Int'].parent, full_dict['Simplon-Tlv'])

    def testVenderTooFewColumnsError(self):
        try:
            self.dict.ReadDictionary(StringIO('VENDOR Simplon'))
        except ParseError as e:
            self.assertEqual('vendor' in str(e), True)
        else:
            self.fail()

    def testVendorParsing(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        self.dict.ReadDictionary(StringIO('VENDOR Simplon 42'))
        self.assertEqual(self.dict.vendors['Simplon'], 42)
        self.dict.ReadDictionary(StringIO(
                        'ATTRIBUTE Test-Type 1 integer Simplon'))
        self.assertEqual(self.dict.attrindex['Test-Type'], (42, 1))

    def testVendorOptionError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        try:
            self.dict.ReadDictionary(StringIO('VENDOR Simplon 42 badoption'))
        except ParseError as e:
            self.assertEqual('option' in str(e), True)
        else:
            self.fail()

    def testVendorFormatError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        try:
            self.dict.ReadDictionary(StringIO(
                'VENDOR Simplon 42 format=5,4'))
        except ParseError as e:
            self.assertEqual('format' in str(e), True)
        else:
            self.fail()

    def testVendorFormatIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                'VENDOR WiMAX 24757 format=1,1,c\n'
                'VENDOR Lucent 4846 format=2,1\n'
                'VENDOR USR 429 format=4,0\n'
                'VENDOR Simplon 42 format=1,1\n'
                'ATTRIBUTE WiMAX-Release 1 string WiMAX\n'
                'BEGIN-VENDOR Lucent\n'
                'ATTRIBUTE Lucent-Max-Shared-Users 2 integer\n'
                'END-VENDOR Lucent\n'
                'BEGIN-VENDOR USR\n'
                'ATTRIBUTE USR-Last-Number-Dialed-Out 102 string\n'
                'END-VENDOR USR\n'
                'BEGIN-VENDOR Simplon\n'
                'ATTRIBUTE Test-Type 1 integer\n'
                'END-VENDOR Simplon'))
        self.assertEqual(self.dict.vendors['WiMAX'], 24757)
        for attr in ('WiMAX-Release', 'Lucent-Max-Shared-Users',
                     'USR-Last-Number-Dialed-Out'):
            self.assertFalse(attr in self.dict)
            self.assertIn(attr, self.dict.skipped_attributes)
        self.assertEqual(self.dict.attrindex['Test-Type'], (42, 1))
        self.assertIn('Skipped 3 unsupported dictionary attributes (vendor format)',
                      cm.output[0])

    def testVendorFormatSyntaxError(self):
        self.assertRaises(ParseError, self.dict.ReadDictionary,
                          StringIO('ATTRIBUTE Test-Type 1 integer Simplon'))
        try:
            self.dict.ReadDictionary(StringIO(
                'VENDOR Simplon 42 format=a,1'))
        except ParseError as e:
            self.assertEqual('Syntax' in str(e), True)
        else:
            self.fail()

    def testBeginVendorTooFewColumns(self):
        try:
            self.dict.ReadDictionary(StringIO('BEGIN-VENDOR'))
        except ParseError as e:
            self.assertEqual('begin-vendor' in str(e), True)
        else:
            self.fail()

    def testBeginVendorUnknownVendor(self):
        try:
            self.dict.ReadDictionary(StringIO('BEGIN-VENDOR Simplon'))
        except ParseError as e:
            self.assertEqual('Simplon' in str(e), True)
        else:
            self.fail()

    def testBeginVendorOptionError(self):
        with self.assertRaises(ParseError) as cm:
            self.dict.ReadDictionary(StringIO(
                            'VENDOR Simplon 42\n'
                            'BEGIN-VENDOR Simplon parent=Oops'))
        self.assertIn('parent=Oops', str(cm.exception))

    def testBeginVendorFormatIsSkipped(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            self.dict.ReadDictionary(StringIO(
                            'VENDOR Simplon 42\n'
                            'BEGIN-VENDOR Simplon format=Extended-Vendor-Specific-5\n'
                            'ATTRIBUTE Test-Evs 1 integer\n'
                            'END-VENDOR Simplon\n'
                            'BEGIN-VENDOR Simplon\n'
                            'ATTRIBUTE Test-Type 1 integer\n'
                            'END-VENDOR Simplon'))
        self.assertFalse('Test-Evs' in self.dict)
        self.assertEqual(self.dict.attrindex['Test-Type'], (42, 1))
        self.assertIn('extended vendor-specific attribute', cm.output[0])

    def testBeginVendorParsing(self):
        self.dict.ReadDictionary(StringIO(
                        'VENDOR Simplon 42\n'
                        'BEGIN-VENDOR Simplon\n'
                        'ATTRIBUTE Test-Type 1 integer'))
        self.assertEqual(self.dict.attrindex['Test-Type'], (42, 1))

    def testEndVendorUnknownVendor(self):
        try:
            self.dict.ReadDictionary(StringIO('END-VENDOR'))
        except ParseError as e:
            self.assertEqual('end-vendor' in str(e), True)
        else:
            self.fail()

    def testEndVendorUnbalanced(self):
        try:
            self.dict.ReadDictionary(StringIO(
                            'VENDOR Simplon 42\n'
                            'BEGIN-VENDOR Simplon\n'
                            'END-VENDOR Oops\n'))
        except ParseError as e:
            self.assertEqual('Oops' in str(e), True)
        else:
            self.fail()

    def testEndVendorParsing(self):
        self.dict.ReadDictionary(StringIO(
                        'VENDOR Simplon 42\n'
                        'BEGIN-VENDOR Simplon\n'
                        'END-VENDOR Simplon\n'
                        'ATTRIBUTE Test-Type 1 integer'))
        self.assertEqual(self.dict.attrindex['Test-Type'], 1)

    def testInclude(self):
        try:
            self.dict.ReadDictionary(StringIO(
                    '$INCLUDE this_file_does_not_exist\n'
                    'VENDOR Simplon 42\n'
                    'BEGIN-VENDOR Simplon\n'
                    'END-VENDOR Simplon\n'
                    'ATTRIBUTE Test-Type 1 integer'))
        except IOError as e:
            self.assertEqual('this_file_does_not_exist' in str(e), True)
        else:
            self.fail()

    def testDictFilePostParse(self):
        f = DictFile(StringIO(
                'VENDOR Simplon 42\n'))
        for _ in f:
            pass
        self.assertEqual(f.File(), '')
        self.assertEqual(f.Line(), -1)

    def testDictFileParseError(self):
        tmpdict = Dictionary()
        try:
            tmpdict.ReadDictionary(os.path.join(self.path, 'dictfiletest'))
        except ParseError as e:
            self.assertEqual('dictfiletest' in str(e), True)
        else:
            self.fail()


class DictFileIncludeTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def write(self, name, content):
        path = os.path.join(self.tmpdir.name, name)
        with open(path, 'w') as fd:
            fd.write(content)
        return path

    def testSelfInclude(self):
        path = self.write('dictionary', '\n$INCLUDE dictionary\n')
        with self.assertRaises(ParseError) as cm:
            list(DictFile(path))
        self.assertEqual(cm.exception.file, 'dictionary')
        self.assertEqual(cm.exception.line, 2)
        self.assertIn('Recursive include', str(cm.exception))

    def testCyclicInclude(self):
        path = self.write('dictionary', '$INCLUDE dictionary.a\n')
        self.write('dictionary.a', 'ATTRIBUTE Test-A 1 string\n'
                                   '$INCLUDE sub/../dictionary.b\n')
        os.mkdir(os.path.join(self.tmpdir.name, 'sub'))
        self.write('dictionary.b', '$INCLUDE dictionary.a\n')
        with self.assertRaises(ParseError) as cm:
            Dictionary(path)
        self.assertEqual(cm.exception.file, 'dictionary.b')
        self.assertEqual(cm.exception.line, 1)

    def testIncludeTwice(self):
        path = self.write('dictionary', '$INCLUDE dictionary.a\n'
                                        '$INCLUDE dictionary.a\n')
        self.write('dictionary.a', 'ATTRIBUTE Test-A 1 string\n')
        self.assertEqual(list(DictFile(path)),
                         ['ATTRIBUTE Test-A 1 string\n'] * 2)

    def testOptionalInclude(self):
        path = self.write('dictionary', '$INCLUDE- dictionary.a\n'
                                        '$INCLUDE- dictionary.missing\n'
                                        'ATTRIBUTE Test-B 2 string\n')
        self.write('dictionary.a', 'ATTRIBUTE Test-A 1 string\n')
        dict = Dictionary(path)
        self.assertEqual(dict.attrindex['Test-A'], 1)
        self.assertEqual(dict.attrindex['Test-B'], 2)

    def testIncludeMissingFile(self):
        path = self.write('dictionary', '$INCLUDE dictionary.missing\n')
        self.assertRaises(IOError, Dictionary, path)


class IncludeSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def write(self, name, content):
        path = os.path.join(self.tmpdir.name, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fd:
            fd.write(content)
        return path

    def testParentTraversalIncludeRejected(self):
        outside = os.path.join(os.path.dirname(self.tmpdir.name),
                               'outside-dictionary')
        with open(outside, 'w') as fd:
            fd.write('ATTRIBUTE Evil 1 string\n')
        self.addCleanup(os.unlink, outside)
        path = self.write('dictionary',
                          '$INCLUDE ../outside-dictionary\n')
        with self.assertRaises(ParseError) as cm:
            list(DictFile(path))
        self.assertEqual(cm.exception.file, 'dictionary')
        self.assertEqual(cm.exception.line, 1)
        self.assertEqual(cm.exception.scope, 'dictionary')
        self.assertIn('outside of the dictionary directory',
                      str(cm.exception))
        # the error reports file and line, never the dictionary contents
        self.assertNotIn('Evil', str(cm.exception))

    def testParentTraversalFromNestedDirectoryRejected(self):
        outside = os.path.join(os.path.dirname(self.tmpdir.name),
                               'outside-dictionary')
        with open(outside, 'w') as fd:
            fd.write('ATTRIBUTE Evil 1 string\n')
        self.addCleanup(os.unlink, outside)
        path = self.write('dictionary', '$INCLUDE sub/inner\n')
        self.write('sub/inner', '$INCLUDE ../../outside-dictionary\n')
        with self.assertRaises(ParseError) as cm:
            list(DictFile(path))
        self.assertEqual(cm.exception.file, 'inner')
        self.assertIn('outside of the dictionary directory',
                      str(cm.exception))

    def testAbsoluteIncludeOutsideRootRejected(self):
        outside = os.path.join(self.tmpdir.name, 'allowed')
        path = self.write('dictionary', '$INCLUDE %s\n' % outside)
        self.write('allowed', 'ATTRIBUTE Ok 1 string\n')
        self.assertEqual(len(Dictionary(path)), 1)
        other = self.write('dictionary.abs',
                           '$INCLUDE %s\n'
                           % os.path.join(os.path.dirname(self.tmpdir.name),
                                          'outside-dictionary'))
        with open(os.path.join(os.path.dirname(self.tmpdir.name),
                               'outside-dictionary'), 'w') as fd:
            fd.write('ATTRIBUTE Evil 1 string\n')
        self.addCleanup(os.unlink,
                        os.path.join(os.path.dirname(self.tmpdir.name),
                                     'outside-dictionary'))
        with self.assertRaises(ParseError):
            list(DictFile(other))

    def testIncludeInsideRootAllowed(self):
        path = self.write('dictionary', '$INCLUDE sub/inner\n')
        self.write('sub/inner',
                   '$INCLUDE ../sibling\nATTRIBUTE Inner 2 string\n')
        self.write('sibling', 'ATTRIBUTE Sibling 3 string\n')
        dict = Dictionary(path)
        self.assertEqual(dict.attrindex['Inner'], 2)
        self.assertEqual(dict.attrindex['Sibling'], 3)

    def testSymlinkEscapingRootRejected(self):
        target = os.path.join(os.path.dirname(self.tmpdir.name),
                              'outside-dictionary')
        with open(target, 'w') as fd:
            fd.write('ATTRIBUTE Evil 1 string\n')
        self.addCleanup(os.unlink, target)
        os.symlink(target, os.path.join(self.tmpdir.name, 'link'))
        path = self.write('dictionary', '$INCLUDE link\n')
        with self.assertRaises(ParseError) as cm:
            list(DictFile(path))
        self.assertIn('outside of the dictionary directory',
                      str(cm.exception))

    def testIncludeDepthLimit(self):
        self.write('d0', '$INCLUDE d1\n')
        for index in range(1, 110):
            self.write('d%d' % index, '$INCLUDE d%d\n' % (index + 1))
        self.write('d110', 'ATTRIBUTE Deep 1 string\n')
        with self.assertRaises(ParseError) as cm:
            list(DictFile(os.path.join(self.tmpdir.name, 'd0')))
        self.assertIn('depth limit', str(cm.exception))
        self.assertNotEqual(cm.exception.line, -1)

    def testIncludeSnapshotRecordsGraph(self):
        path = self.write('dictionary',
                          '$INCLUDE sub/inner\nATTRIBUTE Root 1 string\n')
        self.write('sub/inner', 'ATTRIBUTE Inner 2 string\n')
        dict = Dictionary(path)
        self.assertEqual(len(dict.include_snapshots), 1)
        snapshot = dict.include_snapshots[0]
        root = os.path.realpath(path)
        inner = os.path.realpath(
            os.path.join(self.tmpdir.name, 'sub', 'inner'))
        self.assertEqual(snapshot.files, (root, inner))
        self.assertEqual(snapshot.included_by[root], '')
        self.assertEqual(snapshot.included_by[inner], root)
        self.assertEqual(snapshot.include_lines[inner], (root, 1))
        # the snapshot is read-only
        with self.assertRaises(TypeError):
            snapshot.included_by[root] = 'tampered'
        with self.assertRaises(AttributeError):
            snapshot.files = ()

    def testSnapshotIsPerReadDictionaryCall(self):
        first = self.write('first', 'ATTRIBUTE First 1 string\n')
        second = self.write('second', 'ATTRIBUTE Second 2 string\n')
        dict = Dictionary(first)
        dict.ReadDictionary(second)
        self.assertEqual(len(dict.include_snapshots), 2)
        self.assertEqual(len(dict.include_snapshots[0]), 1)
        self.assertEqual(len(dict.include_snapshots[1]), 1)


class DuplicateDefinitionTests(unittest.TestCase):
    def testDuplicateCodeKeepsAliasAndWarns(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            dict = Dictionary(StringIO(
                'ATTRIBUTE First-Name 10 string\n'
                'ATTRIBUTE Second-Name 10 integer\n'))
        # both names stay usable, the later one wins the reverse lookup
        self.assertEqual(dict['First-Name'].type, 'string')
        self.assertEqual(dict['Second-Name'].type, 'integer')
        self.assertEqual(dict.attrindex['First-Name'], 10)
        self.assertEqual(dict.attrindex['Second-Name'], 10)
        self.assertEqual(dict.attrindex.GetBackward(10), 'Second-Name')
        self.assertIn('duplicate attribute code', cm.output[0])
        self.assertIn('Second-Name', cm.output[0])
        # the source of both definitions is recorded
        self.assertEqual(dict.SourceOf('First-Name')[1], 1)
        self.assertEqual(dict.SourceOf('Second-Name')[1], 2)

    def testRedefinitionSameNameReplacesAndWarns(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            dict = Dictionary(StringIO(
                'ATTRIBUTE Same-Name 10 string\n'
                'ATTRIBUTE Same-Name 11 octets\n'))
        self.assertEqual(dict['Same-Name'].type, 'octets')
        self.assertEqual(dict.attrindex['Same-Name'], 11)
        self.assertFalse(dict.attrindex.HasBackward(10))
        self.assertEqual(dict.SourceOf('Same-Name')[1], 2)
        self.assertIn('duplicate attribute', cm.output[0])

    def testRedefinedTlvDropsOldSubAttributes(self):
        with self.assertLogs('pyrad', 'WARNING'):
            dict = Dictionary(StringIO(
                'ATTRIBUTE Parent 7 tlv\n'
                'ATTRIBUTE Parent-Str 7.1 string\n'
                'ATTRIBUTE Parent 7 octets\n'))
        self.assertEqual(dict['Parent'].type, 'octets')
        self.assertNotIn('Parent-Str', dict)
        self.assertFalse(dict.attrindex.HasBackward((7, 1)))

    def testSubAttributeCodeOverride(self):
        with self.assertLogs('pyrad', 'WARNING'):
            dict = Dictionary(StringIO(
                'ATTRIBUTE Parent 7 tlv\n'
                'ATTRIBUTE Old-Sub 7.1 string\n'
                'ATTRIBUTE New-Sub 7.1 integer\n'))
        self.assertEqual(dict['Old-Sub'].type, 'string')
        self.assertEqual(dict['New-Sub'].type, 'integer')
        self.assertIs(dict['New-Sub'].parent, dict['Parent'])
        self.assertEqual(dict['Parent'].sub_attributes[1], 'New-Sub')
        self.assertEqual(dict.attrindex.GetBackward((7, 1)), 'New-Sub')

    def testTlvAliasSharesSubAttributes(self):
        with self.assertLogs('pyrad', 'WARNING'):
            dict = Dictionary(StringIO(
                'ATTRIBUTE Tlv-One 7 tlv\n'
                'ATTRIBUTE Tlv-Sub 7.1 string\n'
                'ATTRIBUTE Tlv-Two 7 tlv\n'))
        self.assertEqual(dict['Tlv-One'].sub_attributes,
                         {1: 'Tlv-Sub'})
        self.assertIs(dict['Tlv-Two'].sub_attributes,
                      dict['Tlv-One'].sub_attributes)
        self.assertIs(dict['Tlv-Sub'].parent, dict['Tlv-One'])
        self.assertEqual(dict.attrindex.GetBackward(7), 'Tlv-Two')


    def testDuplicateWarningDoesNotEchoDictionary(self):
        with self.assertLogs('pyrad', 'WARNING') as cm:
            Dictionary(StringIO(
                'ATTRIBUTE Secret-Attr 1 string\n'
                'ATTRIBUTE Other-Attr 1 string\n'))
        self.assertNotIn('ATTRIBUTE', cm.output[0])


class ScopeConsistencyTests(unittest.TestCase):
    def testSubAttributeOfTlvOfOtherVendorRejected(self):
        dict = Dictionary(StringIO(
            'VENDOR Vendor-A 100\n'
            'VENDOR Vendor-B 200\n'
            'BEGIN-VENDOR Vendor-A\n'
            'ATTRIBUTE A-Tlv 5 tlv\n'
            'END-VENDOR Vendor-A\n'))
        with self.assertRaises(ParseError) as cm:
            dict.ReadDictionary(StringIO(
                'BEGIN-VENDOR Vendor-B\n'
                'ATTRIBUTE B-Sub 5.1 string\n'
                'END-VENDOR Vendor-B\n'))
        self.assertEqual(cm.exception.line, 2)
        self.assertEqual(cm.exception.scope, 'Vendor-B')
        self.assertIn('unknown TLV 5', str(cm.exception))

    def testVendorTlvSubAttributeOutsideVendorRejected(self):
        dict = Dictionary(StringIO(
            'VENDOR Vendor-A 100\n'
            'BEGIN-VENDOR Vendor-A\n'
            'ATTRIBUTE A-Tlv 5 tlv\n'
            'END-VENDOR Vendor-A\n'))
        with self.assertRaises(ParseError) as cm:
            dict.ReadDictionary(StringIO(
                'ATTRIBUTE Std-Sub 5.1 string\n'))
        self.assertEqual(cm.exception.scope, '')
        self.assertIn('unknown TLV 5', str(cm.exception))

    def testSubAttributeOfStandardTlvFromVendorRejected(self):
        dict = Dictionary(StringIO('ATTRIBUTE Std-Tlv 5 tlv\n'))
        with self.assertRaises(ParseError) as cm:
            dict.ReadDictionary(StringIO(
                'VENDOR Vendor-A 100\n'
                'BEGIN-VENDOR Vendor-A\n'
                'ATTRIBUTE A-Sub 5.1 string\n'
                'END-VENDOR Vendor-A\n'))
        self.assertIn('unknown TLV 5', str(cm.exception))

    def testMissingParentTlvReportsScope(self):
        with self.assertRaises(ParseError) as cm:
            Dictionary(StringIO('ATTRIBUTE Orphan 99.1 string\n'))
        self.assertEqual(cm.exception.line, 1)
        self.assertEqual(cm.exception.scope, '')
        self.assertIn('unknown TLV 99', str(cm.exception))

    def testValidVendorTlvStillParses(self):
        dict = Dictionary(StringIO(
            'VENDOR Vendor-A 100\n'
            'BEGIN-VENDOR Vendor-A\n'
            'ATTRIBUTE A-Tlv 5 tlv\n'
            'ATTRIBUTE A-Sub 5.1 string\n'
            'END-VENDOR Vendor-A\n'))
        self.assertIs(dict['A-Sub'].parent, dict['A-Tlv'])
        self.assertEqual(dict['A-Tlv'].sub_attributes, {1: 'A-Sub'})
        self.assertEqual(dict.SourceOf('A-Sub')[2], 'Vendor-A')

    def testParseErrorCarriesScopeName(self):
        with self.assertRaises(ParseError) as cm:
            Dictionary(StringIO(
                'VENDOR Vendor-A 100\n'
                'BEGIN-VENDOR Vendor-A\n'
                'ATTRIBUTE Bad 1 not-a-type\n'
                'END-VENDOR Vendor-A\n'))
        self.assertEqual(cm.exception.scope, 'Vendor-A')
        self.assertEqual(cm.exception.line, 3)
        self.assertNotIn('not-a-type\n', str(cm.exception))


class DefinitionSourceTests(unittest.TestCase):
    def testSourceFromFiles(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = os.path.join(tmpdir, 'dictionary')
            inc = os.path.join(tmpdir, 'included')
            with open(inc, 'w') as fd:
                fd.write('VENDOR Simplon 42\n')
            with open(root, 'w') as fd:
                fd.write('$INCLUDE included\n'
                         'ATTRIBUTE Root-Attr 1 string\n')
            dict = Dictionary(root)
            self.assertEqual(dict.SourceOf('Simplon'),
                             ('included', 1, 'included'))
            self.assertEqual(dict.SourceOf('Root-Attr'),
                             ('dictionary', 2, 'dictionary'))

    def testSourceFromFileLikeObject(self):
        dict = Dictionary(StringIO('ATTRIBUTE Attr 1 string\n'))
        file, line, scope = dict.SourceOf('Attr')
        self.assertEqual(file, '')
        self.assertEqual(line, 1)
        self.assertEqual(scope, '')

    def testSourceOfUnknownName(self):
        dict = Dictionary(StringIO(''))
        self.assertIsNone(dict.SourceOf('Unknown'))
