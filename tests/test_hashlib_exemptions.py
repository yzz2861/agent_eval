#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import datetime
import unittest

import dlint


class TestHashlibExemptions(dlint.test.base.BaseTest):
    FILENAME = 'storage/buckets.py'

    @staticmethod
    def audit_result(message):
        return dlint.linters.base.Flake8Result(
            lineno=1,
            col_offset=0,
            message=dlint.linters.hashlib_exemptions.AUDIT_ERROR_TEMPLATE.format(message)
        )

    @staticmethod
    def hash_result(lineno, col_offset=11):
        return dlint.linters.base.Flake8Result(
            lineno=lineno,
            col_offset=col_offset,
            message=dlint.linters.BadHashlibUseLinter._error_tmpl
        )

    def test_exact_approved_hash_call_is_exempt(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-1',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                    'function_start_line': 23,
                    'function_end_line': 24,
                    'lineno': 24,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2030-01-01',
                },
            ]

            def bucket_one(data):
                return hashlib.md5(data).hexdigest()

            def bucket_key(data):
                return hashlib.md5(data).hexdigest()

            def bucket_three(data):
                return hashlib.md5(data).hexdigest()
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(
            filename=self.FILENAME,
            today=datetime.date(2026, 11, 28)
        )
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=21,
                col_offset=11,
                message=dlint.linters.BadHashlibUseLinter._error_tmpl
            ),
            dlint.linters.base.Flake8Result(
                lineno=27,
                col_offset=11,
                message=dlint.linters.BadHashlibUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_expired_exemption_reports_check_result(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-2',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                    'function_start_line': 20,
                    'function_end_line': 21,
                    'lineno': 21,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2026-10-01',
                },
            ]

            def bucket_key(data):
                return hashlib.md5(data).hexdigest()
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(
            filename=self.FILENAME,
            today=datetime.date(2026, 11, 28)
        )
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=21,
                col_offset=11,
                message=dlint.linters.BadHashlibUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_nested_hash_call_does_not_inherit_function_exemption(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-3',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'da715d3ff3083e90b0110c94d79eec7d64dc55ebc89d66275df88bfd8923ff1d',
                    'function_start_line': 20,
                    'function_end_line': 24,
                    'lineno': 24,
                    'col_offset': 15,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'outer_bucket',
                    'valid_until': '2030-01-01',
                },
            ]

            def outer_bucket(data):
                def inner_bucket(inner_data):
                    return hashlib.md5(inner_data).hexdigest()

                return hashlib.md5(data).hexdigest()
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(
            filename=self.FILENAME,
            today=datetime.date(2026, 11, 28)
        )
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.hash_result(22, 15),
            self.hash_result(24),
            self.audit_result('exemption does not match a current check result'),
        ]

        assert result == expected

    def test_nested_function_can_have_its_own_exemption(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-15',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'a64e8a90e018709aa04e2f38c80915342fb203aad28d6ef2579cd0373ef7f797',
                    'function_start_line': 21,
                    'function_end_line': 22,
                    'lineno': 22,
                    'col_offset': 15,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'outer_bucket.inner_bucket',
                    'valid_until': '2030-01-01',
                },
            ]

            def outer_bucket(data):
                def inner_bucket(inner_data):
                    return hashlib.md5(inner_data).hexdigest()

                return hashlib.sha1(data).hexdigest()
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(
            filename=self.FILENAME,
            today=datetime.date(2026, 11, 28)
        )
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.hash_result(24),
        ]

        assert result == expected

    def test_same_named_local_function_does_not_reuse_exemption(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-4',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                    'function_start_line': 21,
                    'function_end_line': 22,
                    'lineno': 22,
                    'col_offset': 15,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'first_container.bucket_key',
                    'valid_until': '2030-01-01',
                },
            ]

            def first_container():
                def bucket_key(data):
                    return hashlib.md5(data).hexdigest()
                return bucket_key

            def second_container():
                def bucket_key(data):
                    return hashlib.md5(data).hexdigest()
                return bucket_key
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(
            filename=self.FILENAME,
            today=datetime.date(2026, 11, 28)
        )
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            dlint.linters.base.Flake8Result(
                lineno=27,
                col_offset=15,
                message=dlint.linters.BadHashlibUseLinter._error_tmpl
            ),
        ]

        assert result == expected

    def test_relocated_function_does_not_reuse_exemption(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-5',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                    'function_start_line': 21,
                    'function_end_line': 22,
                    'lineno': 22,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2030-01-01',
                },
            ]

            def unused():
                return None

            def bucket_key(data):
                return hashlib.md5(data).hexdigest()
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(
            filename=self.FILENAME,
            today=datetime.date(2026, 11, 28)
        )
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.hash_result(24),
            self.audit_result('exemption does not match a current check result'),
        ]

        assert result == expected

    def test_modified_function_does_not_reuse_exemption(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-11',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_start_line': 20,
                    'function_end_line': 21,
                    'lineno': 21,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'function_fingerprint': 'stale-fingerprint',
                    'valid_until': '2030-01-01',
                },
            ]

            def bucket_key(data):
                return hashlib.sha1(data).hexdigest()
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(
            filename=self.FILENAME,
            today=datetime.date(2026, 11, 28)
        )
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.hash_result(21),
            self.audit_result('exemption does not match a current check result'),
        ]

        assert result == expected

    def test_non_file_bucketing_purpose_is_rejected(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-6',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                    'function_start_line': 20,
                    'function_end_line': 21,
                    'lineno': 21,
                    'col_offset': 11,
                    'purpose': 'security',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2030-01-01',
                },
            ]

            def bucket_key(data):
                return hashlib.md5(data).hexdigest()
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(filename=self.FILENAME)
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.hash_result(21),
            self.audit_result('DUO130 exemptions are limited to file bucketing'),
        ]

        assert result == expected

    def test_exemption_without_filename_does_not_suppress_result(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-7',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                    'function_start_line': 20,
                    'function_end_line': 21,
                    'lineno': 21,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2030-01-01',
                },
            ]

            def bucket_key(data):
                return hashlib.md5(data).hexdigest()
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(
            today=datetime.date(2026, 11, 28)
        )
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.hash_result(21),
            self.audit_result('exemption does not match a current check result'),
        ]

        assert result == expected

    def test_different_filename_does_not_reuse_exemption(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-13',
                    'check_code': 'DUO130',
                    'filename': 'storage/other.py',
                    'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                    'function_start_line': 20,
                    'function_end_line': 21,
                    'lineno': 21,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2030-01-01',
                },
            ]

            def bucket_key(data):
                return hashlib.md5(data).hexdigest()
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(
            filename=self.FILENAME,
            today=datetime.date(2026, 11, 28)
        )
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.hash_result(21),
            self.audit_result('exemption does not match a current check result'),
        ]

        assert result == expected

    def test_absolute_filename_matches_repository_relative_exemption(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-16',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                    'function_start_line': 20,
                    'function_end_line': 21,
                    'lineno': 21,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2030-01-01',
                },
            ]

            def bucket_key(data):
                return hashlib.md5(data).hexdigest()
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(
            filename='/repo/storage/buckets.py',
            today=datetime.date(2026, 11, 28)
        )
        linter.visit(python_node)

        assert linter.get_results() == []

    def test_invalid_exemption_fields_are_rejected(self):
        python_node = self.get_ast_node(
            """
            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-8',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                    'function_start_line': 4,
                    'function_end_line': 6,
                    'lineno': 5,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2030-01-01',
                    'ticket': 'SEC-1',
                },
            ]

            def bucket_key(data):
                return data
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(filename=self.FILENAME)
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.audit_result('invalid DUO130 exemption fields'),
        ]

        assert result == expected

    def test_unmatched_exemption_without_hash_result_is_reported(self):
        python_node = self.get_ast_node(
            """
            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-14',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                    'function_start_line': 4,
                    'function_end_line': 5,
                    'lineno': 5,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2030-01-01',
                },
            ]

            def bucket_key(data):
                return data
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(filename=self.FILENAME)
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.audit_result('exemption does not match a current check result'),
        ]

        assert result == expected

    def test_dynamic_exemption_values_are_rejected(self):
        python_node = self.get_ast_node(
            """
            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-10',
                    'check_code': 'DUO' + '130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                    'function_start_line': 4,
                    'function_end_line': 6,
                    'lineno': 5,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2030-01-01',
                },
            ]

            def bucket_key(data):
                return data
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(filename=self.FILENAME)
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.audit_result('DUO130 exemption values must be static literals'),
        ]

        assert result == expected

    def test_duplicate_exemption_entries_are_rejected(self):
        first_exemption = """{
                'approval_id': 'SEC-9',
                'check_code': 'DUO130',
                'filename': 'storage/buckets.py',
                'function_fingerprint': 'f1c05d8b92fc8d0c021d86b61d39338be5b5f0bd2854019b6158d2d32116c007',
                'function_start_line': 4,
                'function_end_line': 6,
                'lineno': 5,
                'col_offset': 11,
                'purpose': 'file_bucketing',
                'qualified_name': 'bucket_key',
                'valid_until': '2030-01-01',
            }"""
        second_exemption = first_exemption.replace('SEC-9', 'SEC-14')
        python_node = self.get_ast_node(
            """
            DLINT_DUO130_EXEMPTIONS = [
                {},
                {},
            ]

            def bucket_key(data):
                return data
            """.format(first_exemption, second_exemption)
        )

        linter = dlint.linters.BadHashlibUseLinter(filename=self.FILENAME)
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.audit_result('duplicate DUO130 exemption entries are not permitted'),
        ]

        assert result == expected

    def test_duplicate_approval_identifier_is_rejected(self):
        python_node = self.get_ast_node(
            """
            DLINT_DUO130_EXEMPTIONS = [
                {
                    'approval_id': 'SEC-12',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'first-fingerprint',
                    'function_start_line': 4,
                    'function_end_line': 6,
                    'lineno': 5,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2030-01-01',
                },
                {
                    'approval_id': 'SEC-12',
                    'check_code': 'DUO130',
                    'filename': 'storage/buckets.py',
                    'function_fingerprint': 'second-fingerprint',
                    'function_start_line': 4,
                    'function_end_line': 6,
                    'lineno': 6,
                    'col_offset': 11,
                    'purpose': 'file_bucketing',
                    'qualified_name': 'bucket_key',
                    'valid_until': '2030-01-01',
                },
            ]

            def bucket_key(data):
                return data
            """
        )

        linter = dlint.linters.BadHashlibUseLinter(filename=self.FILENAME)
        linter.visit(python_node)

        result = linter.get_results()
        expected = [
            self.audit_result('duplicate DUO130 approval identifiers are not permitted'),
        ]

        assert result == expected


if __name__ == "__main__":
    unittest.main()
