from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestScopeAuditContract(dlint.test.base.BaseTest):

    def test_version_normalization_and_comparison(self):
        scope = dlint.scope
        self.assertEqual(scope.normalize_version('py38'), (3, 8))
        self.assertEqual(scope.normalize_version(38), (3, 8))
        self.assertEqual(scope.normalize_version('python 3.8'), (3, 8))
        self.assertTrue(scope.PythonVersion(3, 8) == (3, 8))
        self.assertTrue(scope.PythonVersion('2.7') < (3, 0))

    def test_syntax_gates_cover_modern_constructs(self):
        scope = dlint.scope
        fstring = 'x = f' + chr(34) + '{1}' + chr(34) + '\n'
        walrus = 'if (x := 1):\n    pass\n'
        async_def = 'async def f():\n    await g()\n'
        annotation = 'x: int = 1\n'
        self.assertFalse(scope.syntax_supported(fstring, '3.5'))
        self.assertTrue(scope.syntax_supported(fstring, '3.6'))
        self.assertFalse(scope.syntax_supported(walrus, '3.7'))
        self.assertTrue(scope.syntax_supported(walrus, '3.8'))
        self.assertFalse(scope.syntax_supported(async_def, '3.4'))
        self.assertTrue(scope.syntax_supported(async_def, '3.5'))
        self.assertFalse(scope.syntax_supported(annotation, '3.5'))
        self.assertTrue(scope.syntax_supported(annotation, '3.6'))

    def test_python2_syntax_remains_parseable(self):
        scope = dlint.scope
        source = 'try:\n    pass\nexcept ValueError, exc:\n    pass\n'
        self.assertTrue(scope.syntax_supported(source, '2.7'))
        self.assertFalse(scope.syntax_supported(source, '3.8'))

    def test_rule_applicability_is_not_no_findings(self):
        scope = dlint.scope
        source = 'value = input(' + chr(34) + 'x' + chr(34) + ')\n'
        report = [{
            'filename': 'app.py',
            'lineno': 1,
            'code': 'DUO108',
            'message': 'DUO108 use of input',
        }]
        result = scope.audit_scope(
            {'app.py': source},
            report,
            versions=['2.7', '3.8'],
            rules=['DUO108', 'DUO101'],
        )
        self.assertEqual([e.code for e in result['2.7'].eligible], ['DUO108'])
        self.assertEqual(result['3.8'].eligible, [])
        self.assertEqual(result['3.8'].no_findings, [])
        self.assertEqual(
            [e.code for e in result['3.8'].rule_not_applicable],
            ['DUO108', 'DUO101'],
        )

    def test_syntax_unsupported_is_separate_from_clean(self):
        scope = dlint.scope
        source = 'x = f' + chr(34) + '{1}' + chr(34) + '\n'
        result = scope.audit_scope(
            {'app.py': source},
            [{
                'filename': 'app.py',
                'lineno': 1,
                'code': 'DUO105',
                'message': 'DUO105 finding',
            }],
            versions=['3.5', '3.6'],
            rules=['DUO105'],
        )
        self.assertEqual(result['3.5'].no_findings, [])
        self.assertEqual(
            [e.code for e in result['3.5'].syntax_unsupported],
            ['DUO105'],
        )
        self.assertEqual([e.code for e in result['3.6'].eligible], ['DUO105'])

    def test_rule_not_enabled_is_separate(self):
        scope = dlint.scope
        result = scope.audit_scope(
            {'app.py': 'exec(' + chr(34) + 'x' + chr(34) + ')\n'},
            [{
                'filename': 'app.py',
                'lineno': 1,
                'code': 'DUO105',
                'message': 'DUO105 finding',
            }],
            versions=['3.8'],
            rules=['DUO102'],
        )
        self.assertEqual([e.code for e in result['3.8'].rule_not_enabled], ['DUO105'])
        self.assertEqual(result['3.8'].eligible, [])
        self.assertEqual([e.code for e in result['3.8'].no_findings], ['DUO102'])

    def test_versions_can_be_audited_independently(self):
        scope = dlint.scope
        result = scope.audit_scope(
            {
                'py2.py': 'x = 1\n',
                'py3.py': 'x = f' + chr(34) + '{1}' + chr(34) + '\n',
            },
            [],
            versions=['2.7', '3.5', '3.6'],
        )
        self.assertEqual(result['2.7'].syntax_unsupported_scope_ids, ['py3.py'])
        self.assertEqual(result['3.5'].syntax_unsupported_scope_ids, ['py3.py'])
        self.assertEqual(result['3.6'].syntax_unsupported_scope_ids, [])

    def test_common_result_is_opt_in_and_omits_skipped_fragment(self):
        scope = dlint.scope
        report = [{
            'filename': 'app.py',
            'lineno': 1,
            'code': 'DUO108',
            'message': 'DUO108 finding',
        }]
        result = scope.audit_scope(
            {'app.py': 'input(' + chr(34) + 'x' + chr(34) + ')\n'},
            report,
            versions=['2.7', '3.8'],
            rules=['DUO108'],
        )
        self.assertEqual(len(result['2.7'].eligible), 1)
        self.assertEqual(len(result['3.8'].eligible), 0)
        self.assertEqual(result.common_eligible(), [])

    def test_report_text_and_tuple_inputs(self):
        scope = dlint.scope
        source = 'exec(' + chr(34) + 'x' + chr(34) + ')\n'
        text_result = scope.audit_scope(
            {'app.py': source},
            'app.py:1:0: DUO105 use of exec\n',
            versions=['3.8'],
            rules=['DUO105'],
        )
        self.assertTrue(text_result['3.8'].is_eligible('DUO105'))
        tuple_result = scope.audit_scope(
            source,
            [(1, 0, 'DUO105 use of exec', dlint.linters.BadExecUseLinter)],
            versions=['3.8'],
            rules=['DUO105'],
        )
        self.assertEqual(len(tuple_result['3.8'].eligible), 1)

    def test_missing_source_is_not_clean(self):
        scope = dlint.scope
        result = scope.audit_scope(
            {'app.py': 'x = 1\n', 'other.py': 'y = 2\n'},
            [{
                'filename': 'missing.py',
                'lineno': 1,
                'code': 'DUO105',
                'message': 'DUO105 finding',
            }],
            versions=['3.8'],
            rules=['DUO105'],
        )
        self.assertEqual([e.code for e in result['3.8'].missing_source], ['DUO105'])
        self.assertFalse(any(e.filename == 'missing.py' for e in result['3.8'].no_findings))

    def test_verify_findings_rejects_non_reproducible_item(self):
        scope = dlint.scope
        result = scope.audit_scope(
            {'app.py': 'print(1)\n'},
            [{
                'filename': 'app.py',
                'lineno': 1,
                'code': 'DUO105',
                'message': 'DUO105 finding',
            }],
            versions=['3.8'],
            rules=['DUO105'],
            verify_findings=True,
        )
        self.assertEqual(result['3.8'].eligible, [])
        self.assertEqual(
            result['3.8'].no_findings[0].reason,
            'finding_not_reproduced',
        )

    def test_summary_keeps_categories_separate(self):
        scope = dlint.scope
        result = scope.audit_scope(
            {'app.py': 'x = 1\n'},
            [],
            versions=['3.8'],
            rules=['DUO105'],
        )
        summary = result.summary()
        self.assertEqual(summary['versions'], ['3.8'])
        self.assertEqual(summary['syntax_unsupported']['3.8'], [])
        self.assertEqual(summary['rule_not_enabled']['3.8'], [])
        self.assertEqual(len(summary['no_findings']['3.8']), 1)


if __name__ == '__main__':
    unittest.main()
