#!/usr/bin/env python

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

import unittest

import dlint


class TestBadTempfileIdentityUse(dlint.test.base.BaseTest):

    def run_linter(self, source):
        python_node = self.get_ast_node(source)
        linter = dlint.linters.BadTempfileIdentityUseLinter()
        linter.visit(python_node)
        return linter

    def expected(self, lineno, col_offset=0):
        return dlint.linters.base.Flake8Result(
            lineno=lineno,
            col_offset=col_offset,
            message=dlint.linters.BadTempfileIdentityUseLinter._error_tmpl,
        )

    def test_close_then_name_use(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            tmp.close()
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(5)]

    def test_context_exit_then_name_use(self):
        linter = self.run_linter(
            """
            import tempfile

            with tempfile.NamedTemporaryFile() as tmp:
                tmp.write(b"data")
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(4)]

    def test_live_object_name_use_is_safe(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            consume(tmp.name)
            """
        )

        assert linter.get_results() == []

    def test_persistent_file_survives_close(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile(delete=False)
            tmp.close()
            consume(tmp.name)
            """
        )

        assert linter.get_results() == []

    def test_object_alias_close(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            alias = tmp
            alias.close()
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(6)]

    def test_path_alias_after_close(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            path = tmp.name
            tmp.close()
            consume(path)
            """
        )

        assert linter.get_results() == [self.expected(6)]

    def test_reassignment_releases_path_identity(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            path = tmp.name
            tmp = None
            consume(path)
            """
        )

        assert linter.get_results() == [self.expected(6)]

    def test_reassignment_to_new_tempfile_keeps_new_identity(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            tmp = tempfile.NamedTemporaryFile()
            consume(tmp.name)
            """
        )

        assert linter.get_results() == []

    def test_finally_cleanup(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            try:
                work()
            finally:
                tmp.close()
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(8, 4)]

    def test_except_cleanup_that_reraises_is_not_followed(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            try:
                work()
            except Exception:
                tmp.close()
                raise
            consume(tmp.name)
            """
        )

        assert linter.get_results() == []

    def test_except_cleanup_that_continues_is_followed(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            try:
                work()
            except Exception:
                tmp.close()
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(8, 4)]

    def test_conditional_close(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            if cleanup:
                tmp.close()
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(6, 4)]

    def test_unknown_object_call_is_a_boundary(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            hand_off(tmp)
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(5)]
        assert len(linter.boundaries) == 1

    def test_unknown_path_call_is_a_boundary(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            path = tmp.name
            hand_off(path)
            consume(path)
            """
        )

        assert linter.get_results() == []
        assert len(linter.boundaries) == 2

    def test_unknown_path_call_does_not_move_later_close(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            path = tmp.name
            hand_off(path)
            tmp.close()
            consume(path)
            """
        )

        assert linter.get_results() == [self.expected(7)]

    def test_known_benign_helpers_do_not_create_boundaries(self):
        linter = self.run_linter(
            """
            import os
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            path = tmp.name
            print(path)
            os.path.exists(path)
            """
        )

        assert linter.get_results() == []
        assert linter.boundaries == []

    def test_same_module_close_helper(self):
        linter = self.run_linter(
            """
            import tempfile

            def cleanup(tmp):
                tmp.close()

            tmp = tempfile.NamedTemporaryFile()
            cleanup(tmp)
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(8)]

    def test_same_module_factory_helper(self):
        linter = self.run_linter(
            """
            import tempfile

            def make_temp():
                tmp = tempfile.NamedTemporaryFile()
                return tmp

            tmp = make_temp()
            tmp.close()
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(9)]

    def test_only_the_first_identity_loss_is_reported(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.NamedTemporaryFile()
            path = tmp.name
            tmp.close()
            consume(path)
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(6)]

    def test_import_aliases(self):
        linter = self.run_linter(
            """
            import tempfile as tf

            tmp = tf.NamedTemporaryFile()
            tmp.close()
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(5)]

    def test_mkstemp_path_survives_descriptor_close(self):
        linter = self.run_linter(
            """
            import os
            import tempfile

            fd, path = tempfile.mkstemp()
            os.close(fd)
            consume(path)
            """
        )

        assert linter.get_results() == []

    def test_mkstemp_path_after_unlink(self):
        linter = self.run_linter(
            """
            import os
            import tempfile

            fd, path = tempfile.mkstemp()
            os.remove(path)
            consume(path)
            """
        )

        assert linter.get_results() == [self.expected(6)]

    def test_temporary_directory_cleanup(self):
        linter = self.run_linter(
            """
            import tempfile

            tmp = tempfile.TemporaryDirectory()
            tmp.cleanup()
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(5)]

    def test_source_only_no_file_access(self):
        linter = self.run_linter(
            """
            import tempfile

            with tempfile.NamedTemporaryFile() as tmp:
                pass
            consume(tmp.name)
            """
        )

        assert linter.get_results() == [self.expected(4)]


if __name__ == "__main__":
    unittest.main()
