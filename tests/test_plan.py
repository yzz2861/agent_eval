"""Tests for the structured migration planner (:mod:`alembic.plan`)."""

from io import BytesIO
from io import TextIOWrapper

from sqlalchemy import create_engine

from alembic import command
from alembic import plan as plan_module
from alembic import util
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.testing import assert_raises
from alembic.testing import assert_raises_message
from alembic.testing import eq_
from alembic.testing import is_false
from alembic.testing import is_true
from alembic.testing import mock
from alembic.testing.env import _sqlite_testing_config
from alembic.testing.env import clear_staging_env
from alembic.testing.env import env_file_fixture
from alembic.testing.env import staging_env
from alembic.testing.fixtures import TestBase
from alembic.util.sqla_compat import _connectable_has_table


class PlanFixture:
    """Branch graph fixture shared by the plan tests.

    a1 -> a2 -> a3            (branch label "main")
    b1 -> b2 -> b3            (branch label "feature", b2 depends_on a2)
    m1 = merge(a3, b3)
    """

    @classmethod
    def setup_class(cls):
        cls.env = env = staging_env()
        cls.cfg = _sqlite_testing_config()
        cls.a1 = env.generate_revision(
            "a1", "rev a1", head="base", branch_labels="main", refresh=True
        )
        cls.a2 = env.generate_revision("a2", "rev a2", head="a1", refresh=True)
        cls.a3 = env.generate_revision("a3", "rev a3", head="a2", refresh=True)
        cls.b1 = env.generate_revision(
            "b1", "rev b1", head="base", branch_labels="feature", refresh=True
        )
        cls.b2 = env.generate_revision(
            "b2", "rev b2", head="b1", depends_on="a2", refresh=True
        )
        cls.b3 = env.generate_revision("b3", "rev b3", head="b2", refresh=True)
        cls.m1 = env.generate_revision(
            "m1", "merge a3 b3", head=("a3", "b3"), refresh=True
        )

    @classmethod
    def teardown_class(cls):
        clear_staging_env()

    def script(self):
        return ScriptDirectory.from_config(self.cfg)


class BuildPlanTest(PlanFixture, TestBase):
    def test_upgrade_from_base_to_heads(self):
        plan = plan_module.build_plan(self.script(), "heads")

        eq_(plan.direction, "upgrade")
        eq_(plan.initial_heads, ())
        eq_(plan.final_heads, ("m1",))
        eq_(
            {step.revision for step in plan.steps},
            {"a1", "a2", "a3", "b1", "b2", "b3", "m1"},
        )
        is_true(all(step.direction == "upgrade" for step in plan.steps))

    def test_step_order_respects_dependencies(self):
        plan = plan_module.build_plan(self.script(), "heads")
        order = [step.revision for step in plan.steps]

        for first, second in [
            ("a1", "a2"),
            ("a2", "a3"),
            ("a2", "b2"),  # depends_on
            ("b1", "b2"),
            ("b2", "b3"),
            ("a3", "m1"),
            ("b3", "m1"),
        ]:
            is_true(order.index(first) < order.index(second))

    def test_linear_branch_actions(self):
        plan = plan_module.build_plan(self.script(), "a3", current_heads=())
        eq_([step.revision for step in plan.steps], ["a1", "a2", "a3"])
        eq_(
            [step.branch_action for step in plan.steps],
            ["create_branch", "update", "update"],
        )
        step1, step2, step3 = plan.steps
        eq_(step1.source_revisions, ())
        eq_(step1.destination_revisions, ("a1",))
        eq_(step1.heads_before, ())
        eq_(step1.heads_after, ("a1",))
        eq_(
            step1.version_table_mutations,
            (("insert", None, "a1"),),
        )
        eq_(
            step2.version_table_mutations,
            (("update", "a1", "a2"),),
        )
        eq_(step3.heads_before, ("a2",))
        eq_(step3.heads_after, ("a3",))

    def test_merge_branch_action(self):
        plan = plan_module.build_plan(self.script(), "heads")
        merge_step = plan.steps[-1]
        eq_(merge_step.revision, "m1")
        eq_(merge_step.branch_action, "merge_branches")
        eq_(merge_step.destination_revisions, ("m1",))
        eq_(merge_step.heads_after, ("m1",))
        actions = [mut.action for mut in merge_step.version_table_mutations]
        eq_(actions, ["delete", "update"])

    def test_create_branch_action(self):
        plan = plan_module.build_plan(
            self.script(), "heads", current_heads=("a3",)
        )
        # b1 starts a new, independent branch
        b1_step = next(s for s in plan.steps if s.revision == "b1")
        eq_(b1_step.branch_action, "create_branch")
        eq_(
            b1_step.version_table_mutations,
            (("insert", None, "b1"),),
        )

    def test_relative_target(self):
        plan = plan_module.build_plan(
            self.script(), "+1", current_heads=("a1",)
        )
        eq_([step.revision for step in plan.steps], ["a2"])
        eq_(plan.final_heads, ("a2",))

    def test_downgrade_to_base(self):
        plan = plan_module.build_plan(
            self.script(), "base", current_heads=("m1",), direction="downgrade"
        )
        eq_(plan.direction, "downgrade")
        eq_(plan.initial_heads, ("m1",))
        eq_(plan.final_heads, ())
        eq_(
            {step.revision for step in plan.steps},
            {"a1", "a2", "a3", "b1", "b2", "b3", "m1"},
        )
        is_true(all(step.direction == "downgrade" for step in plan.steps))
        # last step deletes the final row from the version table
        eq_(plan.steps[-1].branch_action, "delete_branch")

    def test_downgrade_unmerge(self):
        plan = plan_module.build_plan(
            self.script(), "a3", current_heads=("m1",), direction="downgrade"
        )
        unmerge_step = plan.steps[0]
        eq_(unmerge_step.revision, "m1")
        eq_(unmerge_step.branch_action, "unmerge_branches")
        eq_(unmerge_step.heads_before, ("m1",))
        eq_(set(unmerge_step.heads_after), {"a3", "b3"})

    def test_already_at_target(self):
        plan = plan_module.build_plan(
            self.script(), "heads", current_heads=("m1",)
        )
        is_true(plan.is_empty)
        eq_(plan.steps, ())
        eq_(plan.final_heads, ("m1",))

    def test_missing_revision(self):
        assert_raises(
            util.RevisionNotFoundError,
            plan_module.build_plan,
            self.script(),
            "nonexistent",
        )

    def test_missing_current_head(self):
        assert_raises(
            util.RevisionNotFoundError,
            plan_module.build_plan,
            self.script(),
            "heads",
            current_heads=("nonexistent",),
        )

    def test_unreachable_downgrade(self):
        # b3 is not an ancestor of a3
        assert_raises(
            util.UnreachableRangeError,
            plan_module.build_plan,
            self.script(),
            "b3",
            current_heads=("a3",),
            direction="downgrade",
        )

    def test_invalid_direction(self):
        assert_raises_message(
            util.PlanError,
            "Unknown plan direction",
            plan_module.build_plan,
            self.script(),
            "heads",
            direction="sideways",
        )

    def test_errors_are_command_errors(self):
        # all plan errors are catchable as util.CommandError so the
        # CLI reports them gracefully
        for exc in (
            util.AmbiguousTargetError,
            util.RevisionNotFoundError,
            util.UnreachableRangeError,
        ):
            is_true(issubclass(exc, util.CommandError))

    def test_render(self):
        plan = plan_module.build_plan(self.script(), "a3", current_heads=())
        rendered = plan.render()
        assert "Current heads: (base)" in rendered
        assert "Target: a3 (upgrade)" in rendered
        assert "Step 1: upgrade (base) -> a1" in rendered
        assert "version table: create_branch" in rendered
        assert "INSERT a1" in rendered
        assert "UPDATE a1 -> a2" in rendered
        assert "Final heads: a3" in rendered

    def test_render_verbose(self):
        plan = plan_module.build_plan(self.script(), "a3", current_heads=())
        rendered = plan.render(verbose=True)
        assert "heads after step: a1" in rendered

    def test_render_empty(self):
        plan = plan_module.build_plan(
            self.script(), "heads", current_heads=("m1",)
        )
        assert "No migrations to run" in plan.render()


class BranchLabelTest(TestBase):
    """Two labeled branches without a merge point."""

    @classmethod
    def setup_class(cls):
        cls.env = env = staging_env()
        cls.cfg = _sqlite_testing_config()
        env.generate_revision(
            "a1", "rev a1", head="base", branch_labels="main", refresh=True
        )
        env.generate_revision("a2", "rev a2", head="a1", refresh=True)
        env.generate_revision(
            "b1",
            "rev b1",
            head="base",
            branch_labels="feature",
            refresh=True,
        )
        env.generate_revision("b2", "rev b2", head="b1", refresh=True)

    @classmethod
    def teardown_class(cls):
        clear_staging_env()

    def test_branch_label_target(self):
        script = ScriptDirectory.from_config(self.cfg)
        plan = plan_module.build_plan(script, "feature@head")
        eq_(plan.final_heads, ("b2",))
        eq_({step.revision for step in plan.steps}, {"b1", "b2"})

    def test_branch_label_relative_target(self):
        script = ScriptDirectory.from_config(self.cfg)
        plan = plan_module.build_plan(
            script, "feature@+1", current_heads=("b1",)
        )
        eq_([step.revision for step in plan.steps], ["b2"])
        eq_(plan.final_heads, ("b2",))


class AmbiguousTargetTest(TestBase):
    """A graph with two unmerged heads makes 'head' ambiguous."""

    @classmethod
    def setup_class(cls):
        cls.env = env = staging_env()
        cls.cfg = _sqlite_testing_config()
        env.generate_revision("a1", "rev a1", head="base", refresh=True)
        env.generate_revision("b1", "rev b1", head="base", refresh=True)

    @classmethod
    def teardown_class(cls):
        clear_staging_env()

    def test_ambiguous_target(self):
        script = ScriptDirectory.from_config(self.cfg)
        assert_raises_message(
            util.AmbiguousTargetError,
            "Multiple head revisions are present for given argument " "'head'",
            plan_module.build_plan,
            script,
            "head",
        )

    def test_ambiguous_target_is_command_error(self):
        script = ScriptDirectory.from_config(self.cfg)
        assert_raises(
            util.CommandError, plan_module.build_plan, script, "head"
        )


class PlanMatchesRealMigrationTest(PlanFixture, TestBase):
    """Compare the plan against actually running the migrations on a
    temporary database, step by step."""

    def _env_file_fixture(self):
        import alembic

        alembic.mock_event_listener = None
        env_file_fixture("""
import alembic
from sqlalchemy import MetaData, engine_from_config, pool

target_metadata = MetaData()


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            on_version_apply=alembic.mock_event_listener,
        )
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
""")

    def _run_with_listener(self, cmd, revision):
        with mock.patch("alembic.mock_event_listener", mock.Mock()) as m:
            cmd(self.cfg, revision)
        return [
            (call.kwargs["step"], tuple(sorted(call.kwargs["heads"])))
            for call in m.call_args_list
        ]

    def _current_heads(self):
        url = self.cfg.get_main_option("sqlalchemy.url")
        engine = create_engine(url)
        with engine.connect() as conn:
            return MigrationContext.configure(conn).get_current_heads()

    def test_plan_matches_real_upgrade(self):
        self._env_file_fixture()
        script = self.script()
        plan = plan_module.build_plan(script, "heads")

        applied = self._run_with_listener(command.upgrade, "heads")

        eq_(len(applied), len(plan.steps))
        for plan_step, (info, heads) in zip(plan.steps, applied):
            # same revision, same direction
            eq_(info.up_revision_id, plan_step.revision)
            eq_(info.is_upgrade, plan_step.direction == "upgrade")
            # same version table state after the step
            eq_(heads, plan_step.heads_after)

        eq_(tuple(sorted(self._current_heads())), plan.final_heads)

    def test_plan_matches_real_downgrade(self):
        self._env_file_fixture()
        command.upgrade(self.cfg, "heads")
        eq_(tuple(sorted(self._current_heads())), ("m1",))

        script = self.script()
        plan = plan_module.build_plan(
            script, "base", current_heads=("m1",), direction="downgrade"
        )

        applied = self._run_with_listener(command.downgrade, "base")

        eq_(len(applied), len(plan.steps))
        for plan_step, (info, heads) in zip(plan.steps, applied):
            eq_(info.up_revision_id, plan_step.revision)
            eq_(info.is_upgrade, False)
            eq_(heads, plan_step.heads_after)

        eq_(tuple(sorted(self._current_heads())), plan.final_heads)
        eq_(plan.final_heads, ())


class PlanCommandTest(PlanFixture, TestBase):
    def _buf_fixture(self):
        buf = BytesIO()
        wrapper = TextIOWrapper(buf, encoding="ascii", line_buffering=True)
        wrapper.getvalue = buf.getvalue
        return wrapper

    def _run_plan(self, *arg, **kw):
        self.cfg.stdout = buf = self._buf_fixture()
        command.plan(self.cfg, *arg, **kw)
        return buf.getvalue().decode("ascii", "replace").strip()

    def test_command_offline_current_heads(self):
        output = self._run_plan("heads", current_heads="")
        assert "Current heads: (base)" in output
        assert "Final heads: m1" in output

    def test_command_offline_multiple_heads(self):
        output = self._run_plan("heads", current_heads="a3, b1")
        assert "Current heads: a3, b1" in output

    def test_command_reads_db_without_creating_version_table(self):
        url = self.cfg.get_main_option("sqlalchemy.url")
        engine = create_engine(url)
        with engine.begin() as conn:
            conn.exec_driver_sql("drop table if exists alembic_version")

        output = self._run_plan("heads")
        assert "Current heads: (base)" in output
        assert "Final heads: m1" in output

        # the version table must not have been created
        with engine.connect() as conn:
            is_false(_connectable_has_table(conn, "alembic_version", None))

    def test_command_reads_current_heads_from_db(self):
        command.stamp(self.cfg, "a2")
        output = self._run_plan("a3")
        assert "Current heads: a2" in output
        assert "Step 1: upgrade a2 -> a3" in output
        assert "Final heads: a3" in output
        command.stamp(self.cfg, "base")

    def test_command_downgrade(self):
        output = self._run_plan(
            "base", direction="downgrade", current_heads="m1"
        )
        assert "Target: base (downgrade)" in output
        assert "Step 1: downgrade m1 -> a3, b3" in output
        assert "Final heads: (base)" in output

    def test_command_range_not_allowed(self):
        assert_raises_message(
            util.CommandError,
            "Range revision not allowed",
            command.plan,
            self.cfg,
            "a1:a3",
        )

    def test_command_error_from_env(self):
        # resolution failure through the env.py / database path
        assert_raises(
            util.RevisionNotFoundError,
            command.plan,
            self.cfg,
            "nonexistent",
        )
