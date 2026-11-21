#
# SPDX-License-Identifier: Apache-2.0
import textwrap

import testtools

from bandit.plugins import file_permission_window


def _source(text):
    return textwrap.dedent(text).lstrip("\n")


def _line(source, needle):
    for lineno, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return lineno
    raise AssertionError("line containing %r not found" % needle)


class FilePermissionWindowTests(testtools.TestCase):
    def _analyze(self, source):
        return file_permission_window.analyze_source(source)

    def test_restricted_write_then_widen_then_return(self):
        source = _source("""
            import os
            import tempfile

            def build():
                fd, name = tempfile.mkstemp()
                os.write(fd, b"payload")
                os.chmod(name, 0o644)
                return name
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual(_line(source, "return name"), finding.lineno)
        self.assertEqual("HIGH", finding.severity)
        self.assertEqual("HIGH", finding.confidence)
        self.assertIn("does not undo the exposure", finding.text)

    def test_handover_before_close(self):
        source = _source("""
            import os
            import tempfile

            def build():
                with tempfile.NamedTemporaryFile() as tmp:
                    tmp.write(b"payload")
                    os.chmod(tmp.name, 0o644)
                    return tmp.name
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return tmp.name"), findings[0].lineno)

    def test_handover_after_close(self):
        source = _source("""
            import os
            import tempfile

            def build():
                with tempfile.NamedTemporaryFile() as tmp:
                    tmp.write(b"payload")
                    os.chmod(tmp.name, 0o640)
                return tmp.name
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return tmp.name"), findings[0].lineno)
        self.assertEqual("MEDIUM", findings[0].severity)

    def test_later_restriction_does_not_undo_early_publication(self):
        source = _source("""
            import os
            import tempfile

            def build():
                fd, name = tempfile.mkstemp()
                os.write(fd, b"payload")
                os.chmod(name, 0o644)
                handoff(name)
                os.chmod(name, 0o600)
                return name
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "handoff(name)"), findings[0].lineno)
        self.assertIn("widened on line", findings[0].text)

    def test_narrowing_before_publication_is_silent(self):
        source = _source("""
            import os
            import tempfile

            def build():
                fd, name = tempfile.mkstemp()
                os.write(fd, b"payload")
                os.chmod(name, 0o644)
                os.chmod(name, 0o600)
                return name
            """)
        self.assertEqual([], self._analyze(source))

    def test_unrelated_chmod_is_not_correlated(self):
        source = _source("""
            import os
            import tempfile

            def build():
                fd, name = tempfile.mkstemp()
                os.write(fd, b"payload")
                os.chmod("/srv/shared/other", 0o644)
                return name
            """)
        self.assertEqual([], self._analyze(source))

    def test_unknown_chmod_mode_is_not_certain(self):
        source = _source("""
            import os
            import tempfile

            def build(mode):
                fd, name = tempfile.mkstemp()
                os.write(fd, b"payload")
                os.chmod(name, mode)
                return name
            """)
        self.assertEqual([], self._analyze(source))

    def test_unknown_creation_mode_is_silent(self):
        source = _source("""
            import os

            def build(path):
                out = open(path, "w")
                out.write("payload")
                os.chmod(path, 0o644)
                return path
            """)
        self.assertEqual([], self._analyze(source))

    def test_explicit_umask_context_nested_with_open(self):
        source = _source("""
            import os

            def build(path):
                with umask(0o077):
                    with open(path, "w") as out:
                        out.write("payload")
                    os.chmod(path, 0o644)
                    return path
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return path"), findings[0].lineno)
        self.assertEqual("MEDIUM", findings[0].confidence)

    def test_nested_handles_share_the_same_file(self):
        source = _source("""
            import os
            import tempfile

            def build():
                with tempfile.NamedTemporaryFile() as tmp:
                    with open(tmp.name, "wb") as out:
                        out.write(b"payload")
                    os.chmod(tmp.name, 0o644)
                return tmp.name
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return tmp.name"), findings[0].lineno)
        self.assertEqual("HIGH", findings[0].severity)

    def test_descriptor_alias_and_fchmod(self):
        source = _source("""
            import os

            def build(path):
                fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
                os.write(fd, b"payload")
                os.fchmod(fd, 0o644)
                return fd
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return fd"), findings[0].lineno)

    def test_path_object_and_literal_path_are_linked(self):
        source = _source("""
            import os
            from pathlib import Path

            def build(path):
                out = Path(path)
                out.write_text("payload")
                out.chmod(0o600)
                os.chmod(path, 0o644)
                return out
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return out"), findings[0].lineno)

    def test_explicit_restriction_before_widening(self):
        source = _source("""
            import os

            def build(path):
                out = open(path, "w")
                out.write("payload")
                os.chmod(path, 0o600)
                os.chmod(path, 0o644)
                return path
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return path"), findings[0].lineno)

    def test_permissive_creation_is_not_a_widening(self):
        source = _source("""
            import os

            def build(path):
                fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o644)
                os.write(fd, b"payload")
                return path
            """)
        self.assertEqual([], self._analyze(source))

    def test_no_restricted_content_written(self):
        source = _source("""
            import os
            import tempfile

            def build():
                fd, name = tempfile.mkstemp()
                os.chmod(name, 0o644)
                return name
            """)
        self.assertEqual([], self._analyze(source))

    def test_return_before_widening_is_not_early_publication(self):
        source = _source("""
            import os
            import tempfile

            def build():
                fd, name = tempfile.mkstemp()
                os.write(fd, b"payload")
                return name
                os.chmod(name, 0o644)
            """)
        self.assertEqual([], self._analyze(source))

    def test_fdopen_shares_descriptor_identity(self):
        source = _source("""
            import os
            import tempfile

            def build():
                fd, name = tempfile.mkstemp()
                with os.fdopen(fd, "wb") as out:
                    out.write(b"payload")
                os.chmod(name, 0o644)
                return name
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return name"), findings[0].lineno)

    def test_first_publication_in_a_window_is_reported_once(self):
        source = _source("""
            import os
            import tempfile

            def build():
                fd, name = tempfile.mkstemp()
                os.write(fd, b"payload")
                os.chmod(name, 0o644)
                handoff(name)
                mirror(name)
                os.chmod(name, 0o600)
                return name
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "handoff(name)"), findings[0].lineno)

    def test_finally_restriction_after_return_does_not_suppress(self):
        source = _source("""
            import os
            import tempfile

            def build():
                fd, name = tempfile.mkstemp()
                os.write(fd, b"payload")
                os.chmod(name, 0o644)
                try:
                    return name
                finally:
                    os.chmod(name, 0o600)
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return name"), findings[0].lineno)

    def test_nested_umask_contexts(self):
        source = _source("""
            import os

            def build(path):
                with umask(0o022):
                    with umask(0o077):
                        with open(path, "w") as out:
                            out.write("payload")
                        os.chmod(path, 0o644)
                        return path
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return path"), findings[0].lineno)
        self.assertEqual("MEDIUM", findings[0].confidence)

    def test_branch_dependent_widening_is_conservative(self):
        source = _source("""
            import os
            import tempfile

            def build(condition):
                fd, name = tempfile.mkstemp()
                os.write(fd, b"payload")
                if condition:
                    os.chmod(name, 0o644)
                else:
                    os.chmod(name, 0o600)
                return name
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return name"), findings[0].lineno)
        self.assertEqual("MEDIUM", findings[0].confidence)

    def test_open_opener_sets_creation_permissions(self):
        source = _source("""
            import os
            from functools import partial

            def build(path):
                opener = partial(os.open, mode=0o600)
                with open(path, "w", opener=opener) as out:
                    out.write("payload")
                os.chmod(path, 0o644)
                return path
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "return path"), findings[0].lineno)
        self.assertEqual("HIGH", findings[0].confidence)

    def test_peak_exposure_survives_a_later_wider_but_narrower_mode(self):
        source = _source("""
            import os
            import tempfile

            def build():
                fd, name = tempfile.mkstemp()
                os.write(fd, b"payload")
                os.chmod(name, 0o644)
                os.chmod(name, 0o640)
                return name
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual("HIGH", findings[0].severity)

    def test_module_local_publish_helper_is_correlated(self):
        source = _source("""
            import os
            import tempfile

            def publish(path):
                return path

            def build():
                fd, name = tempfile.mkstemp()
                os.write(fd, b"payload")
                os.chmod(name, 0o644)
                publish(name)
            """)
        findings = self._analyze(source)
        self.assertEqual(1, len(findings))
        self.assertEqual(_line(source, "publish(name)"), findings[0].lineno)
        self.assertEqual("MEDIUM", findings[0].confidence)
