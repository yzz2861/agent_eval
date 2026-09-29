import hashlib
import os
import textwrap

from sqlalchemy import text

from alembic import command
from alembic import util
from alembic.runtime import integrity
from alembic.script import ScriptDirectory
from alembic.testing import eq_
from alembic.testing.env import _get_staging_directory
from alembic.testing.env import _sqlite_file_db
from alembic.testing.env import _sqlite_testing_config
from alembic.testing.env import clear_staging_env
from alembic.testing.env import staging_env
from alembic.testing.fixtures import TestBase
from alembic.util import sqla_compat


class DigestComputationTest(TestBase):
    def setUp(self):
        self.env = staging_env()
        self.cfg = _sqlite_testing_config()

    def tearDown(self):
        clear_staging_env()

    def _write_bytes(self, name, data):
        path = os.path.join(_get_staging_directory(), name)
        with open(path, "wb") as file_:
            file_.write(data)
        return path

    def test_digest_is_sha256_of_exact_file_bytes(self):
        data = (
            b"# coding: utf-8\n"
            b"revision = 'abc123'\n"
            b"doc = 'm\xc3\xa9il'\n"
        )
        path = self._write_bytes("some_rev.py", data)
        eq_(
            integrity.revision_content_digest(path),
            "sha256:" + hashlib.sha256(data).hexdigest(),
        )

    def test_digest_distinguishes_newline_styles(self):
        lf_path = self._write_bytes("lf_rev.py", b"a = 1\nb = 2\n")
        crlf_path = self._write_bytes("crlf_rev.py", b"a = 1\r\nb = 2\r\n")
        assert integrity.revision_content_digest(
            lf_path
        ) != integrity.revision_content_digest(crlf_path)
        same_path = self._write_bytes("lf_rev_copy.py", b"a = 1\nb = 2\n")
        eq_(
            integrity.revision_content_digest(lf_path),
            integrity.revision_content_digest(same_path),
        )

    def _linear_revisions(self):
        script_dir = ScriptDirectory.from_config(self.cfg)
        a, b, c = util.rev_id(), util.rev_id(), util.rev_id()
        script_dir.generate_revision(a, "a", refresh=True, head="base")
        script_dir.generate_revision(b, "b", refresh=True, head=a)
        script_dir.generate_revision(c, "c", refresh=True, head=b)
        return a, b, c

    def test_graph_signature_is_canonical_json(self):
        a, b, c = self._linear_revisions()
        script_dir = ScriptDirectory.from_config(self.cfg)
        script = script_dir.get_revision(b)
        eq_(
            integrity.revision_graph_signature(script),
            '{"depends_on":[],"down_revision":["%s"]}' % a,
        )

    def test_ancestor_walk_follows_depends_on(self):
        a, b, c = self._linear_revisions()
        d = util.rev_id()
        script_dir = ScriptDirectory.from_config(self.cfg)
        script_dir.generate_revision(
            d, "d", refresh=True, head="base", depends_on=c
        )
        script_dir = ScriptDirectory.from_config(self.cfg)
        found, missing = integrity._ancestor_walk(
            integrity._script_map(script_dir), (d,)
        )
        eq_(found, {a, b, c, d})
        eq_(missing, set())

    def test_ancestor_walk_across_merge(self):
        a, b, c = self._linear_revisions()
        d, e = util.rev_id(), util.rev_id()
        script_dir = ScriptDirectory.from_config(self.cfg)
        script_dir.generate_revision(d, "d", refresh=True, head=b, splice=True)
        script_dir.generate_revision(e, "e", refresh=True, head=(c, d))
        script_dir = ScriptDirectory.from_config(self.cfg)
        found, missing = integrity._ancestor_walk(
            integrity._script_map(script_dir), (e,)
        )
        eq_(found, {a, b, c, d, e})
        eq_(missing, set())


class RevisionDigestCommandTest(TestBase):
    def setUp(self):
        self.env = staging_env()
        self.cfg = _sqlite_testing_config()
        script_dir = ScriptDirectory.from_config(self.cfg)
        self.a, self.b, self.c = (
            util.rev_id(),
            util.rev_id(),
            util.rev_id(),
        )
        script_dir.generate_revision(self.a, "a", refresh=True, head="base")
        script_dir.generate_revision(self.b, "b", refresh=True, head=self.a)
        script_dir.generate_revision(self.c, "c", refresh=True, head=self.b)

    def tearDown(self):
        clear_staging_env()

    def _enable_verification(self):
        self.cfg.set_main_option("verify_revision_digests", "true")

    def _new_revision(self, rev_id, head, splice=False, depends_on=None):
        script_dir = ScriptDirectory.from_config(self.cfg)
        script_dir.generate_revision(
            rev_id,
            "rev %s" % rev_id,
            refresh=True,
            head=head,
            splice=splice,
            depends_on=depends_on,
        )

    def _revision_path(self, rev_id):
        script_dir = ScriptDirectory.from_config(self.cfg)
        return script_dir.get_revision(rev_id).path

    def _remove_pyc(self, path):
        pyc_path = util.pyc_file_from_path(path)
        if pyc_path and os.access(pyc_path, os.F_OK):
            os.unlink(pyc_path)

    def _read_revision_bytes(self, rev_id):
        with open(self._revision_path(rev_id), "rb") as file_:
            return file_.read()

    def _write_revision_bytes(self, rev_id, data):
        path = self._revision_path(rev_id)
        with open(path, "wb") as file_:
            file_.write(data)
        self._remove_pyc(path)

    def _rewrite_file(self, rev_id, content):
        path = self._revision_path(rev_id)
        with open(path, "wb") as file_:
            file_.write(textwrap.dedent(content).encode("utf-8"))
        self._remove_pyc(path)

    def _delete_file(self, rev_id):
        path = self._revision_path(rev_id)
        os.unlink(path)
        self._remove_pyc(path)

    def _tamper_content(self, rev_id):
        # rewrite an applied revision file, keeping its revision id and
        # its position in the graph
        script_dir = ScriptDirectory.from_config(self.cfg)
        script = script_dir.get_revision(rev_id)
        self._rewrite_file(
            rev_id,
            '''\
            """tampered revision"""

            revision = {rev!r}
            down_revision = {down!r}


            def upgrade():
                pass


            def downgrade():
                pass
            '''.format(rev=rev_id, down=script.down_revision),
        )

    def _recorded_digests(self):
        eng = _sqlite_file_db()
        with eng.connect() as conn:
            if not sqla_compat._connectable_has_table(
                conn, integrity.DEFAULT_DIGEST_TABLE, None
            ):
                return None
            return {
                row[0]: (row[1], row[2])
                for row in conn.execute(
                    text(
                        "select revision, content_digest, graph_signature "
                        "from %s" % integrity.DEFAULT_DIGEST_TABLE
                    )
                )
            }

    def _current_heads(self):
        eng = _sqlite_file_db()
        with eng.connect() as conn:
            if not sqla_compat._connectable_has_table(
                conn, "alembic_version", None
            ):
                return ()
            return tuple(
                row[0]
                for row in conn.execute(
                    text("select version_num from alembic_version")
                )
            )

    def test_upgrade_records_digests(self):
        self._enable_verification()
        command.upgrade(self.cfg, "heads")
        recorded = self._recorded_digests()
        eq_(set(recorded), {self.a, self.b, self.c})
        script_dir = ScriptDirectory.from_config(self.cfg)
        for rev_id in (self.a, self.b, self.c):
            script = script_dir.get_revision(rev_id)
            content_digest, graph_signature = recorded[rev_id]
            assert content_digest.startswith("sha256:")
            eq_(
                content_digest,
                integrity.revision_content_digest(script.path),
            )
            eq_(
                graph_signature,
                integrity.revision_graph_signature(script),
            )

    def test_no_digests_when_disabled(self):
        command.upgrade(self.cfg, "heads")
        eq_(self._recorded_digests(), None)
        # with the mechanism disabled, tampering goes undetected
        self._tamper_content(self.b)
        command.upgrade(self.cfg, "heads")
        eq_(self._recorded_digests(), None)

    def test_new_revision_upgrades_normally(self):
        self._enable_verification()
        command.upgrade(self.cfg, "heads")
        d = util.rev_id()
        self._new_revision(d, self.c)
        command.upgrade(self.cfg, "heads")
        eq_(self._current_heads(), (d,))
        eq_(set(self._recorded_digests()), {self.a, self.b, self.c, d})

    def test_tampered_applied_revision_is_blocked(self):
        self._enable_verification()
        command.upgrade(self.cfg, "heads")
        d = util.rev_id()
        self._new_revision(d, self.c)
        self._tamper_content(self.b)
        try:
            command.upgrade(self.cfg, "heads")
            assert False, "expected RevisionIntegrityError"
        except integrity.RevisionIntegrityError as exc:
            eq_([rev for rev, _, _ in exc.changed], [self.b])
            eq_(exc.missing, [])
            assert "Revision content changed" in str(exc)
        # the pending upgrade was not executed
        eq_(self._current_heads(), (self.c,))
        eq_(set(self._recorded_digests()), {self.a, self.b, self.c})

    def test_missing_revision_file_is_reported(self):
        self._enable_verification()
        command.upgrade(self.cfg, "heads")
        self._delete_file(self.b)
        try:
            command.upgrade(self.cfg, "heads")
            assert False, "expected RevisionIntegrityError"
        except integrity.RevisionIntegrityError as exc:
            eq_(exc.missing, [self.b])
            eq_(exc.changed, [])
            assert "Revision files missing" in str(exc)
        eq_(self._current_heads(), (self.c,))

    def test_graph_structure_change_is_reported(self):
        self._enable_verification()
        command.upgrade(self.cfg, "heads")
        # rewrite b so that it no longer refers to a; this both changes
        # the file content and orphans a from the applied lineage
        self._rewrite_file(
            self.b,
            '''\
            """tampered revision"""

            revision = %r
            down_revision = None


            def upgrade():
                pass


            def downgrade():
                pass
            ''' % self.b,
        )
        try:
            command.upgrade(self.cfg, "heads")
            assert False, "expected RevisionIntegrityError"
        except integrity.RevisionIntegrityError as exc:
            eq_([rev for rev, _, _ in exc.changed], [self.b])
            struct = dict(exc.structure_changed)
            eq_(set(struct), {self.a, self.b})
            assert "no longer an ancestor" in struct[self.a]
            assert "down_revision/depends_on differ" in struct[self.b]
            message = str(exc)
            assert "Revision content changed" in message
            assert "Revision graph structure changed" in message
        eq_(self._current_heads(), (self.c,))

    def test_baseline_required_for_existing_db(self):
        # database with applied history but verification not yet enabled
        command.upgrade(self.cfg, "heads")
        eq_(self._recorded_digests(), None)

        # enabling verification must not implicitly trust the current
        # files nor create the digest table on its own
        self._enable_verification()
        d = util.rev_id()
        self._new_revision(d, self.c)
        try:
            command.upgrade(self.cfg, "heads")
            assert False, "expected CommandError"
        except util.CommandError as exc:
            assert "no digest baseline has been recorded" in str(exc)
            assert "alembic baseline" in str(exc)
        eq_(self._recorded_digests(), None)
        eq_(self._current_heads(), (self.c,))

        # explicit baseline establishes the trusted state
        command.baseline(self.cfg)
        eq_(set(self._recorded_digests()), {self.a, self.b, self.c})

        # now the pending upgrade proceeds and records the new revision
        command.upgrade(self.cfg, "heads")
        eq_(self._current_heads(), (d,))
        eq_(set(self._recorded_digests()), {self.a, self.b, self.c, d})

    def test_baseline_accepts_intentional_change(self):
        self._enable_verification()
        command.upgrade(self.cfg, "heads")
        self._tamper_content(self.b)
        try:
            command.upgrade(self.cfg, "heads")
            assert False, "expected RevisionIntegrityError"
        except integrity.RevisionIntegrityError:
            pass
        # an intentional change is accepted by re-establishing the
        # baseline explicitly
        command.baseline(self.cfg)
        d = util.rev_id()
        self._new_revision(d, self.c)
        command.upgrade(self.cfg, "heads")
        eq_(self._current_heads(), (d,))
        eq_(set(self._recorded_digests()), {self.a, self.b, self.c, d})

    def test_downgrade_removes_digests(self):
        self._enable_verification()
        command.upgrade(self.cfg, "heads")
        eq_(set(self._recorded_digests()), {self.a, self.b, self.c})
        command.downgrade(self.cfg, self.a)
        eq_(set(self._recorded_digests()), {self.a})
        command.downgrade(self.cfg, "base")
        eq_(set(self._recorded_digests()), set())

    def test_stamp_records_digests(self):
        self._enable_verification()
        command.stamp(self.cfg, self.b)
        eq_(set(self._recorded_digests()), {self.a, self.b})
        self._tamper_content(self.a)
        try:
            command.upgrade(self.cfg, "heads")
            assert False, "expected RevisionIntegrityError"
        except integrity.RevisionIntegrityError as exc:
            eq_([rev for rev, _, _ in exc.changed], [self.a])

    def test_verify_command(self):
        self._enable_verification()
        command.upgrade(self.cfg, "heads")
        command.verify(self.cfg)
        self._tamper_content(self.c)
        try:
            command.verify(self.cfg)
            assert False, "expected RevisionIntegrityError"
        except integrity.RevisionIntegrityError as exc:
            eq_([rev for rev, _, _ in exc.changed], [self.c])

    def test_verify_command_requires_baseline(self):
        command.upgrade(self.cfg, "heads")
        try:
            command.verify(self.cfg)
            assert False, "expected CommandError"
        except util.CommandError as exc:
            assert "no digest baseline has been recorded" in str(exc)

    def test_depends_on_revisions_are_verified(self):
        self._enable_verification()
        d = util.rev_id()
        self._new_revision(d, "base", depends_on=self.c)
        command.upgrade(self.cfg, "heads")
        eq_(set(self._recorded_digests()), {self.a, self.b, self.c, d})
        self._tamper_content(self.c)
        try:
            command.upgrade(self.cfg, "heads")
            assert False, "expected RevisionIntegrityError"
        except integrity.RevisionIntegrityError as exc:
            eq_([rev for rev, _, _ in exc.changed], [self.c])

    def test_merge_heads_follow_same_rules(self):
        self._enable_verification()
        d, e = util.rev_id(), util.rev_id()
        self._new_revision(d, self.b, splice=True)
        self._new_revision(e, d)
        command.upgrade(self.cfg, "heads")
        eq_(
            set(self._recorded_digests()),
            {self.a, self.b, self.c, d, e},
        )

        # a rewritten applied revision on one branch is blocked
        original = self._read_revision_bytes(d)
        self._tamper_content(d)
        try:
            command.upgrade(self.cfg, "heads")
            assert False, "expected RevisionIntegrityError"
        except integrity.RevisionIntegrityError as exc:
            eq_([rev for rev, _, _ in exc.changed], [d])
        eq_(set(self._current_heads()), {self.c, e})

        # a new legitimate merge revision upgrades as usual
        self._write_revision_bytes(d, original)
        m = util.rev_id()
        command.merge(self.cfg, [self.c, e], message="merge", rev_id=m)
        command.upgrade(self.cfg, "heads")
        eq_(self._current_heads(), (m,))
        eq_(
            set(self._recorded_digests()),
            {self.a, self.b, self.c, d, e, m},
        )
