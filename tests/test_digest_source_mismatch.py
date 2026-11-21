#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestDigestSourceMismatch(dlint.test.base.BaseTest):

    @staticmethod
    def get_linter(**kwargs):
        kwargs.setdefault('original_parameters', {'content'})
        kwargs.setdefault('integrity_comparison_points', {'verify_digest'})
        return dlint.linters.DigestSourceMismatchLinter(**kwargs)

    def assert_sources_reported(self, results, source_names):
        assert len(results) == 1
        for source_name in source_names:
            assert '"{}"'.format(source_name) in results[0].message

    def test_direct_digest_source_mismatch(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            def receive_file(download_url: bytes, content: bytes):
                url_digest = hashlib.sha256(download_url).hexdigest()
                content_digest = hashlib.sha256(content).hexdigest()
                return verify_digest(content_digest, url_digest)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        results = linter.get_results()
        self.assert_sources_reported(results, ['content', 'download_url'])
        assert results[0].lineno == 7
        assert 'DUO139' in results[0].message

    def test_assignment_alias_and_hash_builder(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            def receive_file(download_url: bytes, content: bytes):
                url = download_url
                hasher = hashlib.sha256()
                hasher.update(url)
                url_digest = hasher.hexdigest()
                content_digest = hashlib.sha256(content).hexdigest()
                return verify_digest(content_digest, url_digest)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        self.assert_sources_reported(
            linter.get_results(),
            ['content', 'download_url'],
        )

    def test_closure_and_parameter_binding(self):
        python_node = self.get_ast_node(
            """
            import hashlib
            import hmac

            def make_checker(expected):
                def check(actual):
                    return hmac.compare_digest(expected, actual)
                return check

            def receive_file(download_url: bytes, content: bytes):
                content_digest = hashlib.sha256(content).hexdigest()
                url_digest = hashlib.sha256(download_url).hexdigest()
                checker = make_checker(content_digest)
                return checker(url_digest)
            """
        )

        linter = self.get_linter(
            integrity_comparison_points={'hmac.compare_digest'},
        )
        linter.visit(python_node)

        self.assert_sources_reported(
            linter.get_results(),
            ['content', 'download_url'],
        )

    def test_keyword_parameter_binding_at_comparison_function(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            def check_integrity(expected, actual):
                assert expected == actual

            def receive_file(download_url: bytes, content: bytes):
                content_digest = hashlib.sha256(content).hexdigest()
                url_digest = hashlib.sha256(download_url).hexdigest()
                return check_integrity(expected=content_digest, actual=url_digest)
            """
        )

        linter = self.get_linter(
            integrity_comparison_points={'check_integrity'},
        )
        linter.visit(python_node)

        results = linter.get_results()
        self.assert_sources_reported(results, ['content', 'download_url'])
        assert results[0].lineno == 10

    def test_same_source_is_allowed(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            def receive_file(download_url: bytes, content: bytes):
                first = hashlib.sha256(content).hexdigest()
                second = first
                return verify_digest(first, second)
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        assert linter.get_results() == []

    def test_cache_keys_and_deduplication_are_allowed(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            def receive_file(download_url: bytes, content: bytes):
                cache = {}
                seen = set()
                cache[hashlib.sha256(download_url).hexdigest()] = content
                cache.setdefault(hashlib.sha256(content).hexdigest(), content)
                seen.add(hashlib.sha256(content).hexdigest())
                return cache, seen
            """
        )

        linter = self.get_linter()
        linter.visit(python_node)

        assert linter.get_results() == []

    def test_instance_configuration_overrides_defaults(self):
        python_node = self.get_ast_node(
            """
            import hashlib

            def receive_file(download_url: bytes, payload: bytes):
                payload_digest = hashlib.sha256(payload).hexdigest()
                url_digest = hashlib.sha256(download_url).hexdigest()
                return finish_integrity_check(payload_digest, url_digest)
            """
        )

        linter = dlint.linters.DigestSourceMismatchLinter()
        linter.original_parameters = {'payload'}
        linter.integrity_comparison_points = {
            'finish_integrity_check',
        }
        linter.visit(python_node)

        self.assert_sources_reported(
            linter.get_results(),
            ['payload', 'download_url'],
        )


if __name__ == "__main__":
    unittest.main()
