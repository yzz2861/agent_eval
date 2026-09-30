from io import StringIO

from sqlalchemy import inspect

from alembic import config
from alembic import command
from alembic import util
from alembic.runtime.plan import build_migration_plan
from alembic.script import ScriptDirectory
from alembic.testing import assert_raises_message
from alembic.testing import eq_
from alembic.testing.env import _sqlite_file_db
from alembic.testing.env import _sqlite_testing_config
from alembic.testing.env import clear_staging_env
from alembic.testing.env import env_file_fixture
from alembic.testing.env import staging_env
from alembic.testing.fixtures import TestBase


class PlanTest(TestBase):
    def setUp(self):
        from pathlib import Path

        Path("scratch/scripts/foo.db").unlink(missing_ok=True)
        self.env = staging_env()
        self.cfg = _sqlite_testing_config()
        self.script = ScriptDirectory.from_config(self.cfg)

        self.a = self.env.generate_revision("a", "a")
        self.b = self.env.generate_revision("b", "b", head=self.a.revision)
        self.c1 = self.env.generate_revision(
            "c1", "c1", head=self.b.revision, splice=True
        )
        self.d1 = self.env.generate_revision("d1", "d1", head=self.c1.revision)
        self.c2 = self.env.generate_revision(
            "c2",
            "c2",
            head=self.b.revision,
            splice=True,
            branch_labels="c2branch",
        )
        self.d2 = self.env.generate_revision("d2", "d2", head=self.c2.revision)
        self.e = self.env.generate_revision(
            "e",
            "merge",
            head=(self.d1.revision, self.d2.revision),
        )
        self.f = self.env.generate_revision("f", "f", head=self.e.revision)

        self.script = ScriptDirectory.from_config(self.cfg)

    def tearDown(self):
        clear_staging_env()

    def _plan(self, target="heads", current=(), **kw):
        return build_migration_plan(self.script, target, current=current, **kw)

    def _state(self):
        engine = self.cfg.attributes.get("engine") or _sqlite_file_db()
        with engine.connect() as connection:
            return tuple(
                row[0]
                for row in connection.exec_driver_sql(
                    "SELECT version_num FROM alembic_version ORDER BY "
                    "version_num"
                )
            )

    def _record_version_states_env(self, states):
        self.cfg.attributes["plan_states"] = states
        env_file_fixture(f"""
from sqlalchemy import engine_from_config


def record_version_state(ctx, step, heads, run_args):
    connection = ctx.connection
    rows = connection.exec_driver_sql(
        "SELECT version_num FROM alembic_version ORDER BY version_num"
    )
    context.config.attributes["plan_states"].append(
        tuple(row[0] for row in rows)
    )


engine = engine_from_config(
    config.get_section(config.config_ini_section),
    prefix="sqlalchemy.",
)
connection = engine.connect()
context.configure(
    connection=connection,
    on_version_apply=record_version_state,
)
try:
    with context.begin_transaction():
        context.run_migrations()
finally:
    connection.close()
    engine.dispose()
""")

    def test_plan_does_not_invoke_migration_functions(self):
        def fail():
            raise AssertionError("migration function was invoked")

        for revision_id in (
            "a",
            "b",
            "c1",
            "d1",
            "c2",
            "d2",
            "e",
            "f",
        ):
            module = self.script.get_revision(revision_id).module
            module.upgrade = fail
            module.downgrade = fail

        plan = self._plan()
        eq_(len(plan.steps), 8)

    def test_branch_and_merge_actions(self):
        plan = self._plan(current=(self.b.revision,))

        by_revision = {step.revision_id: step for step in plan.steps}
        eq_(
            by_revision[self.c1.revision].kind,
            "create_branch",
        )
        eq_(
            [
                action.operation
                for action in by_revision[
                    self.c1.revision
                ].version_table_actions
            ],
            ["insert"],
        )
        eq_(
            by_revision[self.c2.revision].kind,
            "move",
        )
        eq_(by_revision[self.e.revision].kind, "merge_branches")
        eq_(
            [
                action.operation
                for action in by_revision[
                    self.e.revision
                ].version_table_actions
            ],
            ["delete", "update"],
        )
        eq_(
            by_revision[self.e.revision].source_revisions,
            (self.d1.revision, self.d2.revision),
        )
        eq_(
            by_revision[self.e.revision].destination_revisions,
            (self.e.revision,),
        )

    def test_unmerge_and_delete_actions(self):
        plan = self._plan(
            target=self.b.revision,
            current=(self.f.revision,),
            direction="downgrade",
        )
        by_revision = {step.revision_id: step for step in plan.steps}

        eq_(by_revision[self.e.revision].kind, "unmerge_branches")
        eq_(
            [
                action.operation
                for action in by_revision[
                    self.e.revision
                ].version_table_actions
            ],
            ["insert", "update"],
        )
        eq_(by_revision[self.c1.revision].kind, "delete_branch")
        eq_(
            by_revision[self.c1.revision].destination_revisions,
            (self.d2.revision,),
        )

    def test_branch_label_relative_target(self):
        plan = self._plan("c2branch@c2")
        eq_(
            tuple(step.revision_id for step in plan.steps),
            (self.a.revision, self.b.revision, self.c2.revision),
        )

    def test_real_upgrade_matches_each_planned_state(self):
        plan = self._plan(current=(self.b.revision,))
        command.stamp(self.cfg, self.b.revision)

        for step in plan.steps:
            eq_(self._state(), step.source_revisions)
            command.upgrade(self.cfg, step.revision_id)
            eq_(self._state(), step.destination_revisions)

        eq_(self._state(), plan.final_revisions)

    def test_real_downgrade_matches_each_planned_state(self):
        command.stamp(self.cfg, self.f.revision)
        plan = self._plan(
            self.b.revision,
            current=(self.f.revision,),
            direction="downgrade",
        )
        states = []
        self._record_version_states_env(states)
        initial_state = self._state()
        command.downgrade(self.cfg, self.b.revision)

        eq_(initial_state, plan.steps[0].source_revisions)
        eq_(
            states,
            [step.destination_revisions for step in plan.steps],
        )
        eq_(self._state(), plan.final_revisions)

    def test_online_plan_queries_current_without_creating_table(self):
        engine = _sqlite_file_db()
        with engine.connect() as connection:
            assert (
                "alembic_version" not in inspect(connection).get_table_names()
            )

        plan = command.plan(self.cfg, self.f.revision)
        eq_(plan.current_revisions, ())

        with engine.connect() as connection:
            assert (
                "alembic_version" not in inspect(connection).get_table_names()
            )

        command.stamp(self.cfg, self.b.revision)
        plan = command.plan(self.cfg, self.f.revision)
        eq_(plan.current_revisions, (self.b.revision,))

    def test_json_output(self):
        self.cfg.stdout = StringIO()
        plan = command.plan(
            self.cfg,
            self.b.revision,
            current=[self.a.revision],
            json=True,
        )
        output = self.cfg.stdout.getvalue()
        assert '"direction": "upgrade"' in output
        assert '"revision_id": "b"' in output
        eq_(plan.final_revisions, (self.b.revision,))

    def test_cli_current_argument(self):
        options = config.CommandLine().parser.parse_args(
            [
                "plan",
                "heads",
                "--current",
                self.a.revision,
                "--current",
                self.b.revision,
                "--downgrade",
                "--json",
            ]
        )
        eq_(
            options.current,
            [self.a.revision, self.b.revision],
        )
        assert options.downgrade is True
        assert options.json is True

    def test_ambiguous_target(self):
        assert_raises_message(
            util.AmbiguousPlanTargetError,
            "Ambiguous",
            self._plan,
            "+1",
            (self.b.revision,),
        )

    def test_missing_target_revision(self):
        error = assert_raises_message(
            util.UnknownPlanRevisionError,
            "No such revision or branch 'missing'",
            self._plan,
            "missing",
        )
        eq_(error.scope, "target")

    def test_missing_current_revision(self):
        error = assert_raises_message(
            util.UnknownPlanRevisionError,
            "No such revision or branch 'missing'",
            self._plan,
            "heads",
            ("missing",),
        )
        eq_(error.scope, "current")

    def test_invalid_current_head(self):
        assert_raises_message(
            util.InvalidPlanStateError,
            "Current revisions must be active heads",
            self._plan,
            "heads",
            (self.a.revision, self.b.revision),
        )

    def test_unreachable_downgrade_target(self):
        assert_raises_message(
            util.UnreachablePlanTargetError,
            "is not an ancestor",
            self._plan,
            self.c1.revision,
            (self.b.revision,),
            direction="downgrade",
        )


class PlanDependsOnTest(TestBase):
    def setUp(self):
        self.env = staging_env()
        self.cfg = _sqlite_testing_config()
        self.script = ScriptDirectory.from_config(self.cfg)
        self.a1 = self.env.generate_revision("a1", "a1", head="base")
        self.b1 = self.env.generate_revision(
            "b1", "b1", head="base", depends_on=self.a1.revision
        )
        self.bmerge = self.env.generate_revision(
            "bmerge",
            "merge",
            head=(self.a1.revision, self.b1.revision),
        )
        self.script = ScriptDirectory.from_config(self.cfg)

    def tearDown(self):
        clear_staging_env()

    def test_depends_on_actions(self):
        plan = build_migration_plan(
            self.script, self.bmerge.revision, current=()
        )
        revision_ids = tuple(step.revision_id for step in plan.steps)
        eq_(set(revision_ids), {"a1", "b1", "bmerge"})
        eq_(revision_ids[-1], "bmerge")
        eq_(
            plan.steps[1].destination_revisions,
            (self.b1.revision,),
        )
        eq_(plan.final_revisions, (self.bmerge.revision,))
