#------------------------------------------------------------------------------
# elftools tests
#
# Offline system-library audit tests.
#
# This code is in the public domain.
#------------------------------------------------------------------------------
import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from elftools.elf.syslib_audit import (
    STATUS_PENDING_EVIDENCE,
    STATUS_SIGNED_OFF,
    SyslibAuditError,
    audit,
    audit_artifacts,
    main,
    parse_elf_artifact,
    parse_environment,
)


FIXTURE = os.path.join(
    'test', 'testfiles_for_unittests', 'lib_versioned64.so.elf')


def _provider(soname, version, *, images=None, versions=None,
              provider='vendor', path=None, **extra):
    candidate = {
        'soname': soname,
        'provider': provider,
        'version': version,
        'path': path or f'/system/lib/{soname}',
        'arch': 'x86_64',
        'elf_class': 64,
        'endianness': 'little',
    }
    if images is not None:
        candidate['images'] = list(images)
    if versions is not None:
        candidate['symbol_versions'] = list(versions)
    candidate.update(extra)
    return candidate


def _environment(target_images, providers, **extra):
    environment = {
        'id': 'test-image-set',
        'hardware_images': [
            {'id': 'hw-atlas', 'arch': 'x86_64', 'elf_class': 64,
             'endianness': 'little'},
            {'id': 'hw-borealis', 'arch': 'x86_64', 'elf_class': 64,
             'endianness': 'little'},
        ],
        'target_images': list(target_images),
        'search_paths': ['/system/lib'],
        'providers': providers,
    }
    environment.update(extra)
    return environment


class TestElfMetadata(unittest.TestCase):
    def test_dynamic_dependencies_and_symbol_versions(self):
        artifact = parse_elf_artifact(FIXTURE)

        self.assertEqual(artifact.needed, ['libz.so.1', 'libc.so.6'])
        self.assertEqual(
            artifact.required_versions['libz.so.1'], ['ZLIB_1.2.3.5'])
        self.assertEqual(
            set(artifact.required_versions['libc.so.6']),
            {'GLIBC_2.2.5', 'GLIBC_2.4'})
        self.assertIn(
            {'name': 'puts', 'version': 'GLIBC_2.2.5', 'hidden': False},
            artifact.required_symbols['libc.so.6'])
        self.assertEqual(artifact.identity.machine, 'EM_X86_64')
        self.assertEqual(artifact.identity.elf_class, 64)
        self.assertEqual(artifact.defined_versions[0], 'lib_versioned.so.1')


class TestSystemLibraryAudit(unittest.TestCase):
    def setUp(self):
        self.providers = [
            _provider(
                'libz.so.1', '1.2.11', images=['hw-borealis'],
                versions=['ZLIB_1.2.3.5'], provider='zlib'),
            _provider(
                'libz.so.1', '1.2.13', images=['hw-borealis'],
                versions=['ZLIB_1.2.3.5'], provider='zlib'),
            _provider(
                'libc.so.6', '2.31', images=['hw-atlas', 'hw-borealis'],
                versions=['GLIBC_2.2.5', 'GLIBC_2.4'], provider='glibc'),
            _provider(
                'libc.so.6', '2.35', images=['hw-atlas', 'hw-borealis'],
                versions=['GLIBC_2.2.5', 'GLIBC_2.4'], provider='glibc'),
        ]

    def test_complete_image_environment_is_signed_off(self):
        result = audit(
            FIXTURE, _environment(['hw-borealis'], self.providers))

        self.assertEqual(result['status'], STATUS_SIGNED_OFF)
        self.assertTrue(result['signed_off'])
        self.assertFalse(result['needs_evidence'])

        dependencies = {
            dependency['soname']: dependency
            for dependency in result['artifacts'][0]['dependencies']
        }
        libz = dependencies['libz.so.1']
        libc = dependencies['libc.so.6']

        self.assertEqual(libz['status'], STATUS_SIGNED_OFF)
        self.assertTrue(libz['image_specific'])
        self.assertEqual(libz['only_on_hardware_images'], ['hw-borealis'])
        self.assertEqual(len(libz['candidates']), 2)
        self.assertEqual(libz['selected']['provider_version'], '1.2.13')
        self.assertEqual(
            [candidate['selected'] for candidate in libz['candidates']],
            [False, True])

        self.assertFalse(libc['image_specific'])
        self.assertEqual(len(libc['candidates']), 2)
        self.assertEqual(libc['selected']['provider_version'], '2.35')
        self.assertEqual(
            set(libc['selected']['exported_symbol_versions']),
            {'GLIBC_2.2.5', 'GLIBC_2.4'})

    def test_other_image_needs_missing_evidence(self):
        result = audit(
            FIXTURE, _environment(['hw-atlas'], self.providers))

        self.assertEqual(result['status'], STATUS_PENDING_EVIDENCE)
        self.assertTrue(result['needs_evidence'])
        dependencies = {
            dependency['soname']: dependency
            for dependency in result['artifacts'][0]['dependencies']
        }
        libz = dependencies['libz.so.1']
        libc = dependencies['libc.so.6']

        self.assertEqual(libz['status'], STATUS_PENDING_EVIDENCE)
        self.assertIsNone(libz['selected'])
        self.assertEqual(libz['unresolved_images'], ['hw-atlas'])
        self.assertEqual(libz['only_on_hardware_images'], ['hw-borealis'])
        self.assertTrue(libz['evidence_missing'])
        self.assertTrue(any(
            'only declared for hardware image' in reason
            for reason in libz['reasons']))

        # The same sample still keeps the provider actually selected on the
        # image where its dependency is declared.
        self.assertEqual(libc['status'], STATUS_SIGNED_OFF)
        self.assertEqual(libc['selected']['provider_version'], '2.35')

    def test_missing_external_library_reports_evidence_only(self):
        env = _environment(['hw-borealis'], [
            _provider(
                'libc.so.6', '2.35', images=['hw-borealis'],
                versions=['GLIBC_2.2.5', 'GLIBC_2.4'], provider='glibc'),
        ])
        real_open = open
        with mock.patch('builtins.open', wraps=real_open) as mocked_open:
            result = audit(FIXTURE, env)

        opened_paths = [
            os.fspath(call.args[0])
            for call in mocked_open.call_args_list
            if call.args
        ]
        self.assertFalse(any(
            path.startswith('/system/lib') for path in opened_paths))

        libz = {
            dependency['soname']: dependency
            for dependency in result['artifacts'][0]['dependencies']
        }['libz.so.1']
        self.assertTrue(libz['external'])
        self.assertEqual(libz['candidates'], [])
        self.assertIsNone(libz['selected'])
        self.assertTrue(any(
            'not opened' in reason for reason in libz['reasons']))
        self.assertEqual(result['status'], STATUS_PENDING_EVIDENCE)

    def test_unverified_candidate_is_not_selected(self):
        providers = list(self.providers)
        providers.append(_provider(
            'libz.so.1', '1.3.1', images=['hw-borealis'],
            versions=['ZLIB_1.2.3.5'], provider='zlib',
            verified=False))
        result = audit(FIXTURE, _environment(['hw-borealis'], providers))
        libz = result['artifacts'][0]['dependencies'][0]

        self.assertEqual(libz['soname'], 'libz.so.1')
        self.assertEqual(libz['selected']['provider_version'], '1.2.13')
        rejected = [
            candidate for candidate in libz['candidates']
            if candidate['provider_version'] == '1.3.1'
        ][0]
        self.assertFalse(rejected['selected'])
        self.assertFalse(
            rejected['evaluations']['hw-borealis']['eligible'])

    def test_multi_image_audit_keeps_per_image_selection(self):
        providers = [
            _provider('libz.so.1', '1.2.11', images=['hw-atlas'],
                      versions=['ZLIB_1.2.3.5'], provider='zlib'),
            _provider('libz.so.1', '1.2.13',
                      images=['hw-borealis'],
                      versions=['ZLIB_1.2.3.5'], provider='zlib'),
            _provider('libc.so.6', '2.35',
                      images=['hw-atlas', 'hw-borealis'],
                      versions=['GLIBC_2.2.5', 'GLIBC_2.4'],
                      provider='glibc'),
        ]
        result = audit(
            FIXTURE, _environment(['hw-atlas', 'hw-borealis'], providers))
        self.assertEqual(result['status'], STATUS_SIGNED_OFF)
        libz = result['artifacts'][0]['dependencies'][0]
        self.assertIsNone(libz['selected'])
        self.assertEqual(
            libz['selected_by_image']['hw-atlas'][
                'provider_version'], '1.2.11')
        self.assertEqual(
            libz['selected_by_image']['hw-borealis'][
                'provider_version'], '1.2.13')
        self.assertFalse(libz['image_specific'])
        self.assertEqual(
            [candidate['selected_for_images']
             for candidate in libz['candidates']],
            [['hw-atlas'], ['hw-borealis']])

    def test_architecture_mismatch_is_pending(self):
        providers = []
        for provider in self.providers:
            provider = dict(provider)
            provider['arch'] = 'aarch64'
            providers.append(provider)
        result = audit(FIXTURE, _environment(['hw-borealis'], providers))

        self.assertEqual(result['status'], STATUS_PENDING_EVIDENCE)
        libz = result['artifacts'][0]['dependencies'][0]
        self.assertTrue(any(
            'architecture' in reason for reason in libz['reasons']))

    def test_target_image_need_not_be_predeclared(self):
        env = _environment(['hw-new'], [])
        parsed = parse_environment(env)
        self.assertEqual(parsed.target_images, ('hw-new',))
        self.assertIsNotNone(parsed.image_by_id('hw-new'))

    def test_mapping_form_keeps_all_versions(self):
        env = {
            'id': 'mapping-form',
            'hardware_images': {
                'hw-atlas': {'arch': 'x86_64', 'elf_class': 64,
                             'endianness': 'little'},
            },
            'target_images': ['hw-atlas'],
            'libraries': {
                'libc.so.6': [
                    _provider('libc.so.6', '2.31',
                              versions=['GLIBC_2.2.5', 'GLIBC_2.4']),
                    _provider('libc.so.6', '2.35',
                              versions=['GLIBC_2.2.5', 'GLIBC_2.4']),
                ],
                'libz.so.1': _provider(
                    'libz.so.1', '1.2.13',
                    versions=['ZLIB_1.2.3.5']),
            },
        }
        result = audit(FIXTURE, env)
        libc = [
            dependency for dependency
            in result['artifacts'][0]['dependencies']
            if dependency['soname'] == 'libc.so.6'
        ][0]
        self.assertEqual(len(libc['candidates']), 2)
        self.assertEqual(libc['selected']['provider_version'], '2.35')
        self.assertEqual(result['status'], STATUS_SIGNED_OFF)

    def test_missing_version_evidence_is_not_signed_off(self):
        env = _environment(['hw-borealis'], [
            _provider('libc.so.6', '2.35', versions=['GLIBC_2.2.5']),
            _provider('libz.so.1', '1.2.13', versions=['ZLIB_1.2.3.5']),
        ])
        result = audit(FIXTURE, env)
        libc = [
            dependency for dependency
            in result['artifacts'][0]['dependencies']
            if dependency['soname'] == 'libc.so.6'
        ][0]

        self.assertEqual(result['status'], STATUS_PENDING_EVIDENCE)
        self.assertEqual(
            libc['candidates'][0]['evaluations']['hw-borealis'][
                'missing_symbol_versions'],
            ['GLIBC_2.4'])

    def test_symbol_evidence_can_supply_version_nodes(self):
        env = _environment(['hw-borealis'], [
            {
                'soname': 'libz.so.1', 'provider': 'zlib',
                'version': '1.2.13',
                'path': '/system/lib/libz.so.1',
                'images': ['hw-borealis'],
                'arch': 'x86_64',
                'symbols': {'gzoffset': ['ZLIB_1.2.3.5']},
            },
            {
                'soname': 'libc.so.6', 'provider': 'glibc',
                'version': '2.35',
                'path': '/system/lib/libc.so.6',
                'images': ['hw-borealis'],
                'arch': 'x86_64',
                'symbols': {
                    'puts': ['GLIBC_2.2.5'],
                    '__stack_chk_fail': ['GLIBC_2.4'],
                    '__cxa_finalize': ['GLIBC_2.2.5'],
                },
            },
        ])
        result = audit(FIXTURE, env)
        self.assertEqual(result['status'], STATUS_SIGNED_OFF)

    def test_bare_soname_map_is_accepted(self):
        env = {
            'hardware_images': ['hw-atlas'],
            'target_images': ['hw-atlas'],
            'libz.so.1': [_provider(
                'libz.so.1', '1.2.13',
                versions=['ZLIB_1.2.3.5'])],
            'libc.so.6': [_provider(
                'libc.so.6', '2.35',
                versions=['GLIBC_2.2.5', 'GLIBC_2.4'])],
        }
        result = audit(FIXTURE, env)
        self.assertEqual(result['status'], STATUS_SIGNED_OFF)

    def test_provider_release_list_expands_to_candidates(self):
        env = _environment(['hw-borealis'], [
            {
                'soname': 'libz.so.1', 'provider': 'zlib',
                'path': '/system/lib/libz.so.1',
                'images': ['hw-borealis'],
                'arch': 'x86_64',
                'versions': ['1.2.11', '1.2.13'],
                'symbol_versions': ['ZLIB_1.2.3.5'],
            },
            _provider('libc.so.6', '2.35',
                      versions=['GLIBC_2.2.5', 'GLIBC_2.4']),
        ])
        result = audit(FIXTURE, env)
        libz = result['artifacts'][0]['dependencies'][0]
        self.assertEqual(
            [candidate['provider_version']
             for candidate in libz['candidates']],
            ['1.2.11', '1.2.13'])
        self.assertEqual(libz['selected']['provider_version'],
                         '1.2.13')

    def test_provider_sequence_is_accepted(self):
        parsed = parse_environment([
            _provider('libc.so.6', '2.35',
                      versions=['GLIBC_2.2.5', 'GLIBC_2.4']),
        ])
        self.assertEqual(parsed.providers[0].soname, 'libc.so.6')

    def test_invalid_environment_is_rejected(self):
        with self.assertRaises(SyslibAuditError):
            parse_environment({'providers': [{'version': '1.0'}]})

    def test_audit_artifacts_accepts_parsed_inputs(self):
        artifact = parse_elf_artifact(FIXTURE)
        result = audit_artifacts(
            [artifact], _environment(['hw-borealis'], self.providers))
        self.assertEqual(result['status'], STATUS_SIGNED_OFF)
        self.assertEqual(
            result['environment']['providers'][0]['soname'], 'libz.so.1')


class TestCheckedInExamples(unittest.TestCase):
    def test_report_examples_are_current(self):
        example_dir = os.path.join('examples', 'syslib_audit')
        sample = os.path.join(example_dir, 'sample_versioned.so.elf')
        cases = [
            ('env_signed.json', 'report_signed.json',
             STATUS_SIGNED_OFF),
            ('env_pending.json', 'report_pending.json',
             STATUS_PENDING_EVIDENCE),
        ]
        for env_name, report_name, expected in cases:
            with self.subTest(report=report_name):
                result = audit(sample, os.path.join(example_dir, env_name))
                with open(os.path.join(example_dir, report_name),
                          encoding='utf-8') as stream:
                    stored = json.load(stream)
                self.assertEqual(result['status'], expected)
                self.assertEqual(stored['status'], expected)
                self.assertEqual(
                    stored['artifacts'][0]['dependencies'][1][
                        'selected']['provider_version'],
                    '2.35')


class TestSyslibAuditCli(unittest.TestCase):
    def test_cli_json_and_exit_codes(self):
        env = _environment(['hw-borealis'], [
            _provider('libc.so.6', '2.35',
                      versions=['GLIBC_2.2.5', 'GLIBC_2.4']),
            _provider('libz.so.1', '1.2.13',
                      versions=['ZLIB_1.2.3.5']),
        ])
        env_path = os.path.join(
            os.environ.get('TMPDIR', '.'), 'syslib-audit-test-env.json')
        with open(env_path, 'w', encoding='utf-8') as stream:
            json.dump(env, stream)
        try:
            proc = subprocess.run(
                [sys.executable, '-m', 'elftools.elf.syslib_audit',
                 FIXTURE, '--environment', env_path],
                check=False, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True)
        finally:
            os.unlink(env_path)

        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(report['status'], STATUS_SIGNED_OFF)
        self.assertEqual(
            report['artifacts'][0]['dependencies'][0]['selected'][
                'provider_version'], '1.2.13')

    def test_main_returns_pending_exit_code(self):
        env_path = os.path.join(
            os.environ.get('TMPDIR', '.'), 'syslib-audit-test-env-pending.json')
        with open(env_path, 'w', encoding='utf-8') as stream:
            json.dump(_environment(['hw-borealis'], []), stream)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                code = main([
                    FIXTURE, '--environment', env_path,
                    '--format', 'json'])
        finally:
            os.unlink(env_path)
        self.assertEqual(code, 2)


if __name__ == '__main__':
    unittest.main()
