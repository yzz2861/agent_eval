from __future__ import annotations

from pathlib import Path

from sqlalchemy import Column
from sqlalchemy import create_engine
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import types as sqltypes

from alembic import command
from alembic.autogenerate import checks
from alembic.autogenerate.api import produce_migrations
from alembic.migration import MigrationContext
from alembic.operations import ops
from alembic.testing import assert_raises
from alembic.testing import eq_
from alembic.testing.env import _sqlite_testing_config
from alembic.testing.env import clear_staging_env
from alembic.testing.env import staging_env
from alembic.testing.fixtures import TestBase
from alembic.util import MigrationRiskCheckError


class MigrationRiskCheckTest(TestBase):
    def _report(self, operation_tree, context=None):
        script = ops.MigrationScript("rev", operation_tree, ops.DowngradeOps())
        return checks.check_migration_script(script, migration_context=context)

    def _finding_dicts(self, report):
        return [
            {
                "level": finding.level.value,
                "operation": finding.operation,
                "object_name": finding.object_name,
                "path": list(finding.path),
                "direction": finding.direction,
                "branch": finding.branch,
            }
            for finding in report.findings
        ]

    def test_drop_table_and_column_path(self):
        report = self._report(
            ops.UpgradeOps(
                ops=[
                    ops.DropTableOp("table_one", schema="s"),
                    ops.ModifyTableOps(
                        "table_two",
                        [ops.DropColumnOp("table_two", "col")],
                    ),
                ]
            )
        )

        eq_(
            self._finding_dicts(report),
            [
                {
                    "level": "danger",
                    "operation": "drop_table",
                    "object_name": "s.table_one",
                    "path": ["upgrades", "0", "drop_table"],
                    "direction": "upgrades",
                    "branch": "upgrades",
                },
                {
                    "level": "danger",
                    "operation": "drop_column",
                    "object_name": "table_two.col",
                    "path": [
                        "upgrades",
                        "1",
                        "alter_table",
                        "table_two",
                        "0",
                        "drop_column",
                    ],
                    "direction": "upgrades",
                    "branch": "upgrades",
                },
            ],
        )

    def test_batch_drop_column_path(self):
        context = MigrationContext.configure(
            dialect_name="sqlite",
            opts={"render_as_batch": True},
        )
        report = self._report(
            ops.UpgradeOps(
                ops=[
                    ops.ModifyTableOps(
                        "table_one",
                        [ops.DropColumnOp("table_one", "col")],
                    )
                ]
            ),
            context,
        )

        eq_(
            report.findings[0].path,
            (
                "upgrades",
                "0",
                "batch_alter_table",
                "table_one",
                "0",
                "drop_column",
            ),
        )

    def test_downgrade_branch(self):
        report = self._report(
            ops.UpgradeOps(),
            None,
        )
        script = ops.MigrationScript(
            "rev",
            ops.UpgradeOps(),
            ops.DowngradeOps(ops=[ops.DropTableOp("table_one")]),
        )
        report = checks.check_migration_script(script)

        eq_(
            self._finding_dicts(report),
            [
                {
                    "level": "danger",
                    "operation": "drop_table",
                    "object_name": "table_one",
                    "path": ["downgrades", "0", "drop_table"],
                    "direction": "downgrades",
                    "branch": "downgrades",
                }
            ],
        )

    def test_type_narrowing_widening_and_unknown(self):
        narrowing = ops.AlterColumnOp(
            "t",
            "c",
            existing_type=String(10),
            modify_type=String(5),
        )
        widening = ops.AlterColumnOp(
            "t",
            "d",
            existing_type=String(10),
            modify_type=String(20),
        )
        unknown = ops.AlterColumnOp(
            "t",
            "e",
            existing_type=String(10),
            modify_type=sqltypes.JSON(),
        )
        report = self._report(
            ops.UpgradeOps(
                ops=[ops.ModifyTableOps("t", [narrowing, widening, unknown])]
            )
        )

        eq_(
            [finding.level.value for finding in report.findings],
            ["danger", "unknown"],
        )
        eq_(
            [finding.object_name for finding in report.findings],
            ["t.c", "t.e"],
        )

    def test_user_type_callback_overrides_default(self):
        def type_callback(context, existing_type, new_type):
            return False

        context = MigrationContext.configure(
            dialect_name="sqlite",
            opts={
                "migration_risk_type_fn": type_callback,
            },
        )
        report = self._report(
            ops.UpgradeOps(
                ops=[
                    ops.ModifyTableOps(
                        "t",
                        [
                            ops.AlterColumnOp(
                                "t",
                                "c",
                                existing_type=String(10),
                                modify_type=String(5),
                            )
                        ],
                    )
                ]
            ),
            context,
        )

        eq_(report.findings, [])

    def test_missing_existing_type_is_unknown_not_safe(self):
        report = self._report(
            ops.UpgradeOps(
                ops=[
                    ops.ModifyTableOps(
                        "t",
                        [
                            ops.AlterColumnOp(
                                "t",
                                "c",
                                modify_type=String(10),
                            )
                        ],
                    )
                ]
            )
        )
        eq_(len(report.findings), 1)
        eq_(report.findings[0].level, checks.RiskLevel.UNKNOWN)

    def test_uninstantiated_types_remain_unknown(self):
        report = self._report(
            ops.UpgradeOps(
                ops=[
                    ops.ModifyTableOps(
                        "t",
                        [
                            ops.AlterColumnOp(
                                "t",
                                "c",
                                existing_type=sqltypes.TypeEngine,
                                modify_type=sqltypes.TypeEngine,
                            )
                        ],
                    )
                ]
            )
        )
        eq_(report.findings[0].level, checks.RiskLevel.UNKNOWN)

    def test_dialect_type_strategy(self):
        @checks.register_type_narrowing_strategy("sqlite", replace=True)
        def strategy(context, existing_type, new_type):
            return checks.TypeRisk.UNKNOWN

        context = MigrationContext.configure(dialect_name="sqlite")
        try:
            report = self._report(
                ops.UpgradeOps(
                    ops=[
                        ops.ModifyTableOps(
                            "t",
                            [
                                ops.AlterColumnOp(
                                    "t",
                                    "c",
                                    existing_type=String(10),
                                    modify_type=String(5),
                                )
                            ],
                        )
                    ]
                ),
                context,
            )
            eq_(report.findings[0].level, checks.RiskLevel.UNKNOWN)
        finally:
            checks._type_narrowing_strategies.pop("sqlite")

    def test_unknown_callback_result_remains_unknown(self):
        context = MigrationContext.configure(
            dialect_name="sqlite",
            opts={"migration_risk_type_fn": lambda *args: "unexpected"},
        )
        report = self._report(
            ops.UpgradeOps(
                ops=[
                    ops.ModifyTableOps(
                        "t",
                        [
                            ops.AlterColumnOp(
                                "t",
                                "c",
                                existing_type=String(10),
                                modify_type=String(5),
                            )
                        ],
                    )
                ]
            ),
            context,
        )
        eq_(report.findings[0].level, checks.RiskLevel.UNKNOWN)

    def test_custom_checker_and_checker_error_are_separate(self):
        class CustomOp(ops.MigrateOperation):
            pass

        @checks.register_operation_checker(CustomOp)
        def custom_checker(context, operation, path):
            return checks.RiskLevel.WARNING

        @checks.register_operation_checker(CustomOp)
        def broken_checker(context, operation, path):
            raise RuntimeError("boom")

        report = self._report(ops.UpgradeOps(ops=[CustomOp()]))

        eq_(
            [finding.level.value for finding in report.findings],
            ["warning"],
        )
        eq_(len(report.errors), 1)
        eq_(report.errors[0].error_type, "RuntimeError")
        eq_(report.errors[0].message, "boom")

    def test_multi_engine_branches_use_each_context(self):
        sqlite_context = MigrationContext.configure(dialect_name="sqlite")
        postgresql_context = MigrationContext.configure(
            dialect_name="postgresql"
        )
        script = ops.MigrationScript(
            "rev",
            [
                ops.UpgradeOps(
                    ops=[ops.DropTableOp("sqlite_table")],
                    upgrade_token="sqlite_upgrades",
                ),
                ops.UpgradeOps(
                    ops=[ops.DropTableOp("postgres_table")],
                    upgrade_token="postgres_upgrades",
                ),
            ],
            [
                ops.DowngradeOps(downgrade_token="sqlite_downgrades"),
                ops.DowngradeOps(downgrade_token="postgres_downgrades"),
            ],
        )
        report = checks.check_migration_script(
            script,
            migration_contexts=[sqlite_context, postgresql_context],
        )
        eq_(
            [finding.branch for finding in report.findings],
            ["sqlite_upgrades", "postgres_upgrades"],
        )
        eq_(
            [finding.object_name for finding in report.findings],
            ["sqlite_table", "postgres_table"],
        )

    def test_autogenerate_real_output_batch_and_multibranch(self):
        engine = create_engine("sqlite://")
        old_metadata = MetaData()
        Table(
            "account",
            old_metadata,
            Column("id", Integer),
            Column("name", String(20)),
            Column("legacy", String(20)),
        )
        old_metadata.create_all(engine)

        new_metadata = MetaData()
        Table(
            "account",
            new_metadata,
            Column("id", Integer),
            Column("short", String(10), nullable=False),
            Column("legacy", String(10)),
        )

        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={
                    "target_metadata": new_metadata,
                    "render_as_batch": True,
                    "upgrade_token": "engine1_upgrades",
                    "downgrade_token": "engine1_downgrades",
                },
            )
            script = produce_migrations(context, new_metadata)
            script.upgrade_ops.upgrade_token = "engine1_upgrades"
            script.downgrade_ops.downgrade_token = "engine1_downgrades"
            report = checks.check_migration_script(
                script,
                migration_contexts=[context],
            )

        upgrade = [
            finding
            for finding in report.findings
            if finding.direction == "upgrades"
        ]
        downgrade = [
            finding
            for finding in report.findings
            if finding.direction == "downgrades"
        ]
        eq_(
            {(finding.operation, finding.branch) for finding in upgrade},
            {
                ("drop_column", "engine1_upgrades"),
                ("alter_column", "engine1_upgrades"),
            },
        )
        eq_(
            {(finding.operation, finding.branch) for finding in downgrade},
            {("drop_column", "engine1_downgrades")},
        )
        batch_paths = [
            finding.path
            for finding in report.findings
            if "batch_alter_table" in finding.path
        ]
        assert batch_paths


class RevisionRiskCheckTest(TestBase):
    def setUp(self):
        self.env = staging_env()
        self.cfg = _sqlite_testing_config()
        self.cfg.set_main_option("revision_environment", "true")

    def tearDown(self):
        clear_staging_env()

    def _env_fixture(self):
        engine = create_engine("sqlite://")

        def process_revision_directives(context, revision, directives):
            directives[0].upgrade_ops.ops.append(ops.DropTableOp("table_one"))
            directives[0].downgrade_ops.ops.append(
                ops.CreateTableOp(
                    "table_one",
                    [Column("id", Integer)],
                )
            )

        def run_env(self):
            from alembic import context

            with engine.connect() as connection:
                context.configure(
                    connection=connection,
                    process_revision_directives=(process_revision_directives),
                )
                with context.begin_transaction():
                    context.run_migrations()

        from unittest import mock

        return mock.patch(
            "alembic.script.base.ScriptDirectory.run_env", run_env
        )

    def test_report_only_does_not_block_file(self):
        with self._env_fixture():
            script = command.revision(
                self.cfg,
                message="risk report only",
                migration_risk_check=True,
                migration_risk_check_levels=[],
            )
        report = self.cfg.attributes["migration_risk_report"]
        assert script is not None
        eq_(report.findings[0].level, checks.RiskLevel.DANGER)
        assert Path(script.path).exists()

    def test_danger_blocks_before_revision_file_is_written(self):
        versions = Path(self.env.dir) / "versions"
        with self._env_fixture():
            try:
                command.revision(
                    self.cfg,
                    message="risk block",
                    migration_risk_check=True,
                )
            except MigrationRiskCheckError as error:
                report = error.report
            else:
                raise AssertionError("expected risk check failure")
        eq_(report.findings[0].operation, "drop_table")
        assert not list(versions.glob("*risk_block*"))

    def test_json_report_file_is_machine_readable(self, tmp_path):
        import json

        report_path = tmp_path / "risk.json"
        try:
            with self._env_fixture():
                command.revision(
                    self.cfg,
                    message="risk json",
                    migration_risk_check=True,
                    migration_risk_report_file=report_path,
                )
        except MigrationRiskCheckError:
            pass
        else:
            raise AssertionError("expected risk check failure")

        data = json.loads(report_path.read_text())
        eq_(data["findings"][0]["operation"], "drop_table")
        eq_(data["findings"][0]["path"][0], "upgrades")

    def test_ini_enables_report_only_check(self):
        self.cfg.set_main_option("migration_risk_check", "true")
        self.cfg.set_main_option("migration_risk_check_levels", "")
        with self._env_fixture():
            script = command.revision(self.cfg, message="ini risk report")
        assert Path(script.path).exists()
        assert self.cfg.attributes["migration_risk_report"].findings
