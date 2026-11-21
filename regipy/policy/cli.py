"""CLI for evidence-bound policy explanations."""

import json
import logging
import os
from typing import Any, Optional

import click

from regipy.policy.engine import build_policy_report
from regipy.policy.extract import evidence_for_hive, extract_policy_records
from regipy.policy.models import (
    PolicyContext,
    PolicyContextException,
    load_records,
    load_roles,
    load_rules,
)
from regipy.policy.render import render_report
from regipy.registry import RegistryHive
from regipy.utils import _setup_logging

logger = logging.getLogger(__name__)


def _load_json(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise click.ClickException(f"could not read {path}: {exc}") from exc
    except ValueError as exc:
        raise click.ClickException(f"invalid JSON in {path}: {exc}") from exc


def _unique_evidence_id(prefix: str, path: str, used: set) -> str:
    base = f"{prefix}:{os.path.basename(path)}"
    candidate = base
    index = 2
    while candidate in used:
        candidate = f"{base}#{index}"
        index += 1
    used.add(candidate)
    return candidate


def _add_hive(
    policy_context: PolicyContext,
    hive_path: str,
    scope: str,
    evidence_id: Optional[str],
    used_evidence_ids: set,
    max_records: Optional[int],
    compute_sha256: bool,
) -> str:
    if evidence_id:
        resolved_id = evidence_id
        if resolved_id in used_evidence_ids:
            raise click.ClickException(f"duplicate evidence id: {resolved_id}")
        used_evidence_ids.add(resolved_id)
    else:
        resolved_id = _unique_evidence_id(scope, hive_path, used_evidence_ids)

    hive = RegistryHive(hive_path)
    evidence = evidence_for_hive(
        hive,
        hive_path,
        evidence_id=resolved_id,
        scope=scope,
        compute_sha256=compute_sha256,
    )
    policy_context.evidence.append(evidence)
    policy_context.records.extend(
        extract_policy_records(
            hive,
            evidence.evidence_id,
            scope=scope,
            max_records=max_records,
        )
    )
    return evidence.evidence_id


@click.command()
@click.option(
    "-c",
    "--context",
    "context_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=False,
    help="Full policy context JSON (evidence, roles, records and optional rules).",
)
@click.option(
    "--roles",
    "roles_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=False,
    help="Delegated role context JSON. Required unless --context already supplies roles.",
)
@click.option(
    "--rules",
    "rules_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=False,
    help="Interpretation rule JSON. If omitted, regipy's built-in rules are used.",
)
@click.option(
    "--records",
    "records_path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    required=False,
    help="Synthetic or pre-extracted policy record JSON.",
)
@click.option(
    "--machine-hive",
    "machine_hives",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    help="Machine hive (for example SOFTWARE) to extract policy values from.",
)
@click.option(
    "--user-hive",
    "user_hives",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    help="User hive (for example NTUSER.DAT) to extract policy values from.",
)
@click.option(
    "--machine-evidence-id",
    multiple=True,
    help="Evidence id for each --machine-hive, in order. Defaults to machine:<filename>.",
)
@click.option(
    "--user-evidence-id",
    multiple=True,
    help="Evidence id for each --user-hive, in order. Defaults to user:<filename>.",
)
@click.option(
    "--share-machine-evidence/--no-share-machine-evidence",
    default=True,
    help="Make machine evidence visible to every delegated role (default: on).",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(exists=False, dir_okay=False, resolve_path=True),
    required=False,
    help="Write the report to this path instead of stdout.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown", "md"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Report format.",
)
@click.option(
    "--strict-rules",
    is_flag=True,
    default=False,
    help="Treat records without a matching rule as unbound instead of raw observations.",
)
@click.option(
    "--include-observed/--no-include-observed",
    default=True,
    show_default=True,
    help="Keep unmatched records as clearly marked raw observations.",
)
@click.option(
    "--max-records",
    type=int,
    default=None,
    help="Maximum policy records to extract from each hive.",
)
@click.option(
    "--no-sha256",
    is_flag=True,
    default=False,
    help="Do not hash evidence files.",
)
@click.option(
    "--fail-on-unbound",
    is_flag=True,
    default=False,
    help="Exit non-zero when at least one context could not be bound.",
)
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbosity")
def policy_explain(
    context_path,
    roles_path,
    rules_path,
    records_path,
    machine_hives,
    user_hives,
    machine_evidence_id,
    user_evidence_id,
    share_machine_evidence,
    output_path,
    output_format,
    strict_rules,
    include_observed,
    max_records,
    no_sha256,
    fail_on_unbound,
    verbose,
):
    """Explain policy values using only the delegated role/evidence bindings.

    Every conclusion names its role, evidence item, and evaluated conditions.
    Roles or records that cannot be bound are emitted under unbound_contexts.
    """
    _setup_logging(verbose=verbose)

    if context_path:
        try:
            policy_context = PolicyContext.from_json_file(context_path)
        except (PolicyContextException, OSError) as exc:
            raise click.ClickException(str(exc)) from exc
    else:
        policy_context = PolicyContext()

    if roles_path:
        roles, shared = load_roles(_load_json(roles_path))
        policy_context.roles = roles
        policy_context.shared_evidence_ids = list(dict.fromkeys(policy_context.shared_evidence_ids + shared))

    if records_path:
        policy_context.records.extend(load_records(_load_json(records_path)))

    if rules_path:
        policy_context.rules = load_rules(_load_json(rules_path))

    used_evidence_ids = {item.evidence_id for item in policy_context.evidence}
    machine_ids = []
    for index, hive_path in enumerate(machine_hives):
        explicit_id = machine_evidence_id[index] if index < len(machine_evidence_id) else None
        machine_ids.append(
            _add_hive(
                policy_context,
                hive_path,
                "machine",
                explicit_id,
                used_evidence_ids,
                max_records,
                not no_sha256,
            )
        )
    for index, hive_path in enumerate(user_hives):
        explicit_id = user_evidence_id[index] if index < len(user_evidence_id) else None
        _add_hive(
            policy_context,
            hive_path,
            "user",
            explicit_id,
            used_evidence_ids,
            max_records,
            not no_sha256,
        )

    if share_machine_evidence and machine_ids:
        policy_context.shared_evidence_ids = list(dict.fromkeys(policy_context.shared_evidence_ids + machine_ids))

    if not policy_context.roles:
        raise click.ClickException("no delegated roles supplied; pass --roles or include roles in --context")
    if not policy_context.records:
        raise click.ClickException("no policy records supplied; pass --records or one or more --machine-hive/--user-hive")

    try:
        report = build_policy_report(
            policy_context,
            strict_rules=strict_rules,
            include_observed=include_observed,
        )
    except PolicyContextException as exc:
        raise click.ClickException(str(exc)) from exc
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    rendered = render_report(report, output_format)
    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write(rendered)
                if not rendered.endswith("\n"):
                    handle.write("\n")
        except OSError as exc:
            raise click.ClickException(f"could not write {output_path}: {exc}") from exc
        click.echo(
            f"Wrote {summary_line(report)} to {output_path}",
            err=True,
        )
    else:
        click.echo(rendered)
        click.echo(summary_line(report), err=True)

    if fail_on_unbound and report.unbound_contexts:
        raise click.exceptions.Exit(3)


def summary_line(report) -> str:
    summary = report.summary
    return (
        f"{summary['explanations']} explanations, "
        f"{summary['unbound_contexts']} unbound contexts, "
        f"{summary['records']} policy records"
    )
