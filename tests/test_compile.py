import sys
import unittest
import asn1tools
from copy import deepcopy
import shutil
import os

from asn1tools import compiler as asn1_compiler

sys.path.append('tests/files')
sys.path.append('tests/files/ietf')
sys.path.append('tests/files/3gpp')

from extensibility_implied import EXPECTED as EXTENSIBILITY_IMPLIED
from extensibility_implied_pp import EXPECTED as EXTENSIBILITY_IMPLIED_PP
from all_types_automatic_tags import EXPECTED as ALL_TYPES_AUTOMATIC_TAGS
from all_types_automatic_tags_pp import EXPECTED as ALL_TYPES_AUTOMATIC_TAGS_PP
from module_tags_explicit import EXPECTED as MODULE_TAGS_EXPLICIT
from module_tags_explicit_pp import EXPECTED as MODULE_TAGS_EXPLICIT_PP
from module_tags_implicit import EXPECTED as MODULE_TAGS_IMPLICIT
from module_tags_implicit_pp import EXPECTED as MODULE_TAGS_IMPLICIT_PP
from module_tags_automatic import EXPECTED as MODULE_TAGS_AUTOMATIC
from module_tags_automatic_pp import EXPECTED as MODULE_TAGS_AUTOMATIC_PP
from x683 import EXPECTED as X683
from x683_pp import EXPECTED as X683_PP
from parameterization import EXPECTED as PARAMETERIZATION
from parameterization_pp import EXPECTED as PARAMETERIZATION_PP
from time_types import EXPECTED as TIME_TYPES
from time_types_pp import EXPECTED as TIME_TYPES_PP
from asn1tools.limits import CompileLimits
from asn1tools.limits import LimitExceeded
from asn1tools.limits import ParameterizationCycleError


class Asn1ToolsCompileTest(unittest.TestCase):

    maxDiff = None

    def test_pre_process_extensibility_implied(self):
        actual = asn1tools.pre_process_dict(deepcopy(EXTENSIBILITY_IMPLIED))
        self.assertEqual(actual, EXTENSIBILITY_IMPLIED_PP)

    def test_pre_process_all_types_automatic_tags(self):
        actual = asn1tools.pre_process_dict(deepcopy(ALL_TYPES_AUTOMATIC_TAGS))
        self.assertEqual(actual, ALL_TYPES_AUTOMATIC_TAGS_PP)

    def test_pre_process_module_tags_explicit(self):
        actual = asn1tools.pre_process_dict(deepcopy(MODULE_TAGS_EXPLICIT))
        self.assertEqual(actual, MODULE_TAGS_EXPLICIT_PP)

    def test_pre_process_module_tags_implicit(self):
        actual = asn1tools.pre_process_dict(deepcopy(MODULE_TAGS_IMPLICIT))
        self.assertEqual(actual, MODULE_TAGS_IMPLICIT_PP)

    def test_pre_process_module_tags_automatic(self):
        actual = asn1tools.pre_process_dict(deepcopy(MODULE_TAGS_AUTOMATIC))
        self.assertEqual(actual, MODULE_TAGS_AUTOMATIC_PP)

    def test_pre_process_x683(self):
        actual = asn1tools.pre_process_dict(deepcopy(X683))
        self.assertEqual(actual, X683_PP)

    def test_pre_process_parameterization(self):
        actual = asn1tools.pre_process_dict(deepcopy(PARAMETERIZATION))
        self.assertEqual(actual, PARAMETERIZATION_PP)

    def test_pre_process_time_types(self):
        actual = asn1tools.pre_process_dict(deepcopy(TIME_TYPES))
        self.assertEqual(actual, TIME_TYPES_PP)

    def test_unsupported_codec(self):
        with self.assertRaises(asn1tools.CompileError) as cm:
            asn1tools.compile_files('tests/files/foo.asn', 'bad_codec')

        self.assertEqual(str(cm.exception), "Unsupported codec 'bad_codec'.")

    def test_encode_decode_bad_type_name(self):
        foo = asn1tools.compile_files('tests/files/foo.asn')

        # Encode.
        with self.assertRaises(asn1tools.EncodeError) as cm:
            foo.encode('BadTypeName', b'')

        self.assertEqual(
            str(cm.exception),
            "Type 'BadTypeName' not found in types dictionary.")

        # Decode.
        with self.assertRaises(asn1tools.DecodeError) as cm:
            foo.decode('BadTypeName', b'')

        self.assertEqual(
            str(cm.exception),
            "Type 'BadTypeName' not found in types dictionary.")

    def test_encoding(self):
        asn1tools.compile_files('tests/files/foo.asn', encoding='ascii')

    def test_import_imported(self):
        asn1tools.compile_files('tests/files/import_imported.asn')

    def test_missing_type(self):
        with self.assertRaises(asn1tools.CompileError) as cm:
            asn1tools.compile_string('A DEFINITIONS ::= BEGIN A ::= B END')

        self.assertEqual(str(cm.exception), "Type 'B' not found in module 'A'.")

    def test_missing_value(self):
        with self.assertRaises(asn1tools.CompileError) as cm:
            asn1tools.compile_string(
                'A DEFINITIONS ::= BEGIN A ::= INTEGER (1..a) END',
                'uper')

        self.assertEqual(str(cm.exception), "Value 'a' not found in module 'A'.")

    def test_missing_import_type(self):
        with self.assertRaises(asn1tools.CompileError) as cm:
            asn1tools.compile_string(
                'A DEFINITIONS ::= BEGIN IMPORTS B FROM C; D ::= SEQUENCE { a B } END '
                'C DEFINITIONS ::= BEGIN END',
                'uper')

        self.assertEqual(str(cm.exception),
                         "Type 'B' imported by module 'A' not found in module 'C'.")

    def test_missing_import_value(self):
        with self.assertRaises(asn1tools.CompileError) as cm:
            asn1tools.compile_string(
                'A DEFINITIONS ::= BEGIN IMPORTS b FROM C; D ::= INTEGER (b..1) END '
                'C DEFINITIONS ::= BEGIN END',
                'uper')

        self.assertEqual(str(cm.exception),
                         "Value 'b' imported by module 'A' not found in module 'C'.")

    def test_missing_import_type_module(self):
        with self.assertRaises(asn1tools.CompileError) as cm:
            asn1tools.compile_string(
                'A DEFINITIONS ::= BEGIN IMPORTS B FROM C; D ::= SEQUENCE { a B } END ',
                'uper')

        self.assertEqual(str(cm.exception),
                         "Module 'A' cannot import type 'B' from missing module 'C'.")

    def test_missing_import_value_module(self):
        with self.assertRaises(asn1tools.CompileError) as cm:
            asn1tools.compile_string(
                'A DEFINITIONS ::= BEGIN IMPORTS b FROM C; D ::= INTEGER (b..1) END ',
                'uper')

        self.assertEqual(str(cm.exception),
                         "Module 'A' cannot import value 'b' from missing module 'C'.")

    def test_duplicated_type(self):
        """Duplicated types are not part of types dictionary.

        """

        spec = asn1tools.compile_string(
            "Foo DEFINITIONS ::= BEGIN Fum ::= INTEGER END "
            "Bar DEFINITIONS ::= BEGIN Fum ::= BOOLEAN END "
            "Fie DEFINITIONS ::= BEGIN Fum ::= REAL END ")

        self.assertEqual(spec.types, {})

    def test_cache(self):
        cache_dir = 'test_cache'

        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)

        foo = asn1tools.compile_files('tests/files/foo.asn',
                                      cache_dir=cache_dir)
        foo_cached = asn1tools.compile_files('tests/files/foo.asn',
                                             cache_dir=cache_dir)

        encoded = foo.encode('Question',
                             {'id': 1, 'question': '???'})
        encoded_cached = foo_cached.encode('Question',
                                           {'id': 1, 'question': '???'})

        self.assertEqual(encoded, encoded_cached)

    def test_missing_parameterized_type(self):
        with self.assertRaises(asn1tools.CompileError) as cm:
            asn1tools.compile_string(
                'A DEFINITIONS ::= BEGIN'
                '  B ::= NULL '
                '  B-Integer ::= B { INTEGER } '
                'END ',
                'uper')

        self.assertEqual(str(cm.exception),
                         "Type 'B' in module 'A' is not parameterized.")

    def test_wrong_parameterized_type_number_of_parameters(self):
        with self.assertRaises(asn1tools.CompileError) as cm:
            asn1tools.compile_string(
                'A DEFINITIONS ::= BEGIN'
                '  B { C, D } ::= SEQUENCE { '
                '    a C, '
                '    b D '
                '  } '
                '  B-Integer ::= B { INTEGER } '
                'END ',
                'uper')

        self.assertEqual(
            str(cm.exception),
            "Parameterized type 'B' in module 'A' takes 2 parameters, "
            "but 1 are given in type 'B-Integer' in module 'A'.")

    def test_missing_parameterized_value(self):
        with self.assertRaises(asn1tools.CompileError) as cm:
            asn1tools.compile_string(
                'A DEFINITIONS ::= BEGIN'
                '  A { a } ::= INTEGER (a..5) '
                '  B ::= A { missing-value } '
                'END ',
                'uper')

        self.assertEqual(str(cm.exception),
                         "Value 'missing-value' not found in module 'A'.")

    def test_self_referencing_parameterized_type_compiles(self):
        spec = (
            'X683 DEFINITIONS ::= BEGIN '
            'List1 { ElementTypeParam } ::= SEQUENCE { '
            '  elem ElementTypeParam, '
            '  next List1 { ElementTypeParam } OPTIONAL '
            '} '
            'IntegerList1 ::= List1 { INTEGER } '
            'END ')

        foo = asn1tools.compile_string(spec)
        encoded = foo.encode('IntegerList1', {
            'elem': 7,
            'next': {'elem': 8}
        })

        self.assertEqual(
            foo.decode('IntegerList1', encoded),
            {'elem': 7, 'next': {'elem': 8}})

    def test_parameterization_substitution_limit(self):
        spec = (
            'A DEFINITIONS ::= BEGIN '
            'P { T } ::= SEQUENCE { a T, b T } '
            'Top ::= P { P { P { P { INTEGER } } } } '
            'END ')

        with self.assertRaises(LimitExceeded) as cm:
            asn1tools.compile_string(
                spec,
                limits=CompileLimits(max_parameter_substitutions=2))

        self.assertEqual(cm.exception.stage,
                         'parameterization-expansion')
        self.assertEqual(cm.exception.location['module'], 'A')
        self.assertEqual(cm.exception.location['type'], 'Top')
        self.assertEqual(cm.exception.location['referenced-type'], 'P')

    def test_parameterization_generated_type_limit(self):
        spec = (
            'A DEFINITIONS ::= BEGIN '
            'P { T } ::= SEQUENCE { a T } '
            'Top ::= P { P { P { INTEGER } } } '
            'END ')

        with self.assertRaises(LimitExceeded) as cm:
            asn1tools.compile_string(
                spec,
                limits=CompileLimits(max_generated_types=1))

        self.assertEqual(cm.exception.stage,
                         'parameterization-expansion')
        self.assertEqual(cm.exception.what, 'generated types')

    def test_parameterization_node_limit_stops_exponential_bomb(self):
        expression = 'INTEGER'

        for _ in range(18):
            expression = 'P { ' + expression + ' }'

        spec = (
            'A DEFINITIONS ::= BEGIN '
            'P { T } ::= SEQUENCE { a T, b T } '
            'Top ::= ' + expression + ' END ')

        with self.assertRaises(LimitExceeded) as cm:
            asn1tools.compile_string(spec)

        self.assertIn(cm.exception.stage,
                      ('parse', 'parameterization-expansion'))
        self.assertIsInstance(cm.exception, asn1tools.CompileError)

    def test_parameterization_cycle_detected(self):
        spec = (
            'A DEFINITIONS ::= BEGIN '
            'P { T } ::= SEQUENCE { a T } '
            'Q { T } ::= P { Q { T } } '
            'Top ::= Q { INTEGER } '
            'END ')

        with self.assertRaises(ParameterizationCycleError) as cm:
            asn1tools.compile_string(spec)

        self.assertEqual(cm.exception.stage,
                         'parameterization-expansion')
        self.assertEqual(cm.exception.location['module'], 'A')
        self.assertIn('Circular parameterized type expansion',
                      str(cm.exception))

    def test_cross_module_parameterized_import(self):
        foo = asn1tools.compile_files(
            'tests/files/parameterization.asn')

        self.assertEqual(
            set(foo.modules),
            {'Parameterization',
             'Parameterization2',
             'Parameterization3'})
        self.assertIn('S', foo.modules['Parameterization'])

        encoded = foo.encode('F', [])
        self.assertEqual(foo.decode('F', encoded), [])

    def test_cross_module_recursive_parameterized_import(self):
        spec = (
            'M1 DEFINITIONS ::= BEGIN '
            'Box { T } ::= SEQUENCE { '
            '  value T, '
            '  next Box { T } OPTIONAL '
            '} '
            'END '
            'M2 DEFINITIONS ::= BEGIN '
            'IMPORTS Box FROM M1; '
            'IntBox ::= Box { INTEGER } '
            'END ')

        foo = asn1tools.compile_string(spec)
        encoded = foo.encode('IntBox', {'value': 5})

        self.assertEqual(foo.decode('IntBox', encoded),
                         {'value': 5})

    def test_large_schema_within_default_limits(self):
        asn1tools.compile_files('tests/files/3gpp/rrc_14_4_0.asn')

    def test_cache_hit_does_not_bypass_limits(self):
        if not asn1_compiler.has_diskcache:
            self.skipTest('diskcache is not installed')

        cache_dir = 'test_cache_limits'

        if os.path.exists(cache_dir):
            shutil.rmtree(cache_dir)

        spec_path = os.path.join(cache_dir + '_input.asn')

        if os.path.exists(spec_path):
            os.remove(spec_path)

        try:
            with open(spec_path, 'w') as fout:
                fout.write(
                    'A DEFINITIONS ::= BEGIN '
                    'B ::= INTEGER '
                    'END ')

            strict = CompileLimits(max_nodes=1)

            with self.assertRaises(LimitExceeded):
                asn1tools.compile_files(spec_path,
                                        cache_dir=cache_dir,
                                        limits=strict)

            # Populate the cache with default limits.
            asn1tools.compile_files(spec_path, cache_dir=cache_dir)

            # A cache hit must still enforce the strict active limits.
            with self.assertRaises(LimitExceeded) as cm:
                asn1tools.compile_files(spec_path,
                                        cache_dir=cache_dir,
                                        limits=strict)

            self.assertEqual(cm.exception.stage, 'parse')
        finally:
            if os.path.exists(cache_dir):
                shutil.rmtree(cache_dir)

            if os.path.exists(spec_path):
                os.remove(spec_path)


if __name__ == '__main__':
    unittest.main()
