# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  reverification.py

<Purpose>
  Build a re-verification plan for a supply chain layout that has already been
  verified.

  A plan answers two questions for every step:

  * Can the existing, validly signed link metadata be reused as-is?
  * If not, why does the step have to be executed and recorded again?

  Reuse is decided on recorded evidence and on the layout's MATCH rules, not on
  file names. Two links are only treated as dependent if a MATCH rule actually
  connects the artifacts and their hash dictionaries are equal. A withdrawn
  artifact therefore invalidates the dependency edges that reference that
  artifact, while an unrelated branch that happens to use the same file name
  remains reusable.

  Only steps are planned. A delegated sublayout is represented by its verified
  summary link; call the planner recursively if its internal steps need their
  own plan.

<Classes>
  WithdrawnArtifact:
      An explicitly withdrawn artifact, optionally scoped to a producing step.

  DependencyEdge:
      A material of one step that really matches an artifact of another step.

  StepDecision:
      Reuse or re-execution decision, including the per-item basis.

  ReverificationPlan:
      All step decisions plus machine-readable evidence.

<Functions>
  build_reverification_plan:
      Build a plan from an already verified layout and verified links.

  verify_and_build_plan:
      Verify a layout/links from disk and build a plan in one call.

  render_plan:
      Render a plan as human-readable text.

"""

import fnmatch
import json
import os
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Optional

import securesystemslib.exceptions

import in_toto.models.layout
import in_toto.models.link
import in_toto.rulelib
import in_toto.settings
import in_toto.verifylib
from in_toto.exceptions import (
    LinkNotFoundError,
    ThresholdVerificationError,
)
from in_toto.models.metadata import Metadata

ACTION_REUSE = "reuse"
ACTION_REVERIFY = "reverify"

_WITHDRAWAL_META_KEYS = {"name", "path", "step", "producer", "hashes"}


@dataclass(frozen=True)
class WithdrawnArtifact:
    """An artifact that may no longer be used as evidence.

    Hash dictionaries are the identity of the artifact. ``name`` narrows the
    withdrawal to one recorded path, and ``step`` narrows it to an artifact
    produced by one step. Both are optional; a withdrawal without either
    applies to any artifact with the same content hashes.

    """

    hashes: Mapping[str, str]
    name: Optional[str] = None
    step: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.hashes, Mapping) or not self.hashes:
            raise securesystemslib.exceptions.FormatError(
                "A withdrawn artifact requires a non-empty hash dictionary."
            )

        if not all(
            isinstance(algorithm, str) and isinstance(digest, str)
            for algorithm, digest in self.hashes.items()
        ):
            raise securesystemslib.exceptions.FormatError(
                "Withdrawn artifact hashes must map strings to strings."
            )

        if self.name is not None and not isinstance(self.name, str):
            raise securesystemslib.exceptions.FormatError(
                "Withdrawn artifact name must be a string."
            )

        if self.step is not None and not isinstance(self.step, str):
            raise securesystemslib.exceptions.FormatError(
                "Withdrawn artifact step must be a string."
            )

    @classmethod
    def from_data(cls, data):
        """Create a withdrawn artifact from a wrapper or artifact dictionary.

        Accepted forms are ``WithdrawnArtifact`` instances, dictionaries with a
        ``hashes`` field, and flat dictionaries such as
        ``{"name": "foo", "sha256": "..."}``.

        """
        if isinstance(data, cls):
            return data

        if not isinstance(data, Mapping):
            raise securesystemslib.exceptions.FormatError(
                "Withdrawn artifacts must be dictionaries or "
                "WithdrawnArtifact instances."
            )

        hashes = data.get("hashes")
        if hashes is None:
            hashes = {
                key: value
                for key, value in data.items()
                if key not in _WITHDRAWAL_META_KEYS
            }

        return cls(
            hashes=dict(hashes),
            name=data.get("name", data.get("path")),
            step=data.get("step", data.get("producer")),
        )

    def matches(
        self,
        name: str,
        hashes: Mapping[str, str],
        step: Optional[str] = None,
    ) -> bool:
        """Return whether an artifact is covered by this withdrawal."""
        if self.name is not None and self.name != name:
            return False

        if self.step is not None and self.step != step:
            return False

        return all(
            hashes.get(algorithm) == digest
            for algorithm, digest in self.hashes.items()
        )

    def to_dict(self):
        """Return a JSON-serializable representation."""
        data = {"hashes": dict(self.hashes)}
        if self.name is not None:
            data["name"] = self.name
        if self.step is not None:
            data["step"] = self.step
        return data


@dataclass(frozen=True)
class DependencyEdge:
    """A material relationship that a layout MATCH rule really establishes."""

    consumer: str
    consumer_type: str
    consumer_path: str
    producer: str
    producer_type: str
    producer_path: str
    rule: tuple[str, ...]
    hashes: Mapping[str, str]

    def to_dict(self):
        """Return a JSON-serializable representation."""
        return {
            "consumer": self.consumer,
            "consumer_type": self.consumer_type,
            "consumer_path": self.consumer_path,
            "producer": self.producer,
            "producer_type": self.producer_type,
            "producer_path": self.producer_path,
            "rule": list(self.rule),
            "hashes": dict(self.hashes),
        }


@dataclass
class StepDecision:
    """Reuse decision and evidence for one supply chain step."""

    name: str
    action: str
    trusted_signers: list[str] = field(default_factory=list)
    dependencies: list[DependencyEdge] = field(default_factory=list)
    withdrawn_artifacts: list[dict[str, Any]] = field(default_factory=list)
    basis: list[str] = field(default_factory=list)
    findings: list[dict[str, str]] = field(default_factory=list)

    def add_finding(self, code, message):
        """Add an invalidating finding without duplicating it."""
        finding = {"code": code, "message": message}
        if finding not in self.findings:
            self.findings.append(finding)

    def to_dict(self):
        """Return a JSON-serializable representation."""
        return {
            "name": self.name,
            "action": self.action,
            "trusted_signers": list(self.trusted_signers),
            "basis": list(self.basis),
            "findings": list(self.findings),
            "dependencies": [
                dependency.to_dict() for dependency in self.dependencies
            ],
            "withdrawn_artifacts": list(self.withdrawn_artifacts),
        }


@dataclass
class ReverificationPlan:
    """Re-verification plan for all steps of a layout."""

    steps: list[StepDecision]
    withdrawn_artifacts: list[WithdrawnArtifact]
    unmatched_withdrawals: list[WithdrawnArtifact]
    rerun_order: list[str]
    layout_verified: bool = False
    layout_expires: Optional[str] = None
    layout_signers: list[str] = field(default_factory=list)

    @property
    def retained_steps(self):
        """Return names of steps whose existing links can be reused."""
        return [step.name for step in self.steps if step.action == ACTION_REUSE]

    @property
    def reverify_steps(self):
        """Return names of steps that have to be executed again."""
        return [
            step.name for step in self.steps if step.action == ACTION_REVERIFY
        ]

    def get_step(self, name):
        """Return the decision for a step name."""
        for step in self.steps:
            if step.name == name:
                return step
        raise KeyError(name)

    def to_dict(self):
        """Return a JSON-serializable representation of the plan."""
        return {
            "layout_verified": self.layout_verified,
            "layout_expires": self.layout_expires,
            "layout_signers": list(self.layout_signers),
            "summary": {
                "reuse": self.retained_steps,
                "reverify": self.reverify_steps,
                "rerun_order": list(self.rerun_order),
            },
            "withdrawn_artifacts": [
                artifact.to_dict() for artifact in self.withdrawn_artifacts
            ],
            "unmatched_withdrawals": [
                artifact.to_dict() for artifact in self.unmatched_withdrawals
            ],
            "steps": [step.to_dict() for step in self.steps],
        }

    def to_json(self, indent=2):
        """Return the plan as a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def render_plan(plan):
    """Render a :class:`ReverificationPlan` as human-readable text."""
    verification = "verified" if plan.layout_verified else "not verified"
    expires = plan.layout_expires or "unknown"
    lines = [
        f"Re-verification plan (layout {verification}, expires {expires})",
    ]
    if plan.layout_signers:
        lines.append("Layout signers: " + ", ".join(plan.layout_signers))

    for step in plan.steps:
        lines.append("")
        lines.append(f"[{step.action.upper()}] {step.name}")
        if step.trusted_signers:
            lines.append(
                "  trusted signers: " + ", ".join(step.trusted_signers)
            )
        else:
            lines.append("  trusted signers: none")

        lines.extend(f"  - {basis}" for basis in step.basis)
        lines.extend(f"  ! {finding['message']}" for finding in step.findings)

    lines.append("")
    if plan.rerun_order:
        lines.append("Rerun order: " + ", ".join(plan.rerun_order))
    else:
        lines.append("Rerun order: none, all existing links are reusable")

    if plan.unmatched_withdrawals:
        lines.append("Unmatched withdrawals:")
        lines.extend(
            "  - " + _format_artifact(artifact.to_dict())
            for artifact in plan.unmatched_withdrawals
        )

    return "\n".join(lines)


def _format_artifact(artifact):
    """Format a path/hash artifact for human-readable output."""
    name = artifact.get("name") or artifact.get("path") or "<any path>"
    hashes = artifact.get("hashes", artifact)
    digest = ", ".join(
        f"{algorithm}:{value}" for algorithm, value in hashes.items()
    )
    return f"{name} ({digest})"


def _get_payload_link(metadata):
    """Extract a Link and signature keyids from a metadata or link value."""
    if isinstance(metadata, Metadata):
        payload = metadata.get_payload()
        if not isinstance(payload, in_toto.models.link.Link):
            raise securesystemslib.exceptions.FormatError(
                "Re-verification plans require verified link metadata, got a "
                f"'{payload.type_}' payload."
            )
        if isinstance(metadata.signatures, Mapping):
            signers = list(metadata.signatures)
        else:
            signers = [
                signature.get("keyid") for signature in metadata.signatures
            ]
        return payload, signers

    if isinstance(metadata, in_toto.models.link.Link):
        return metadata, []

    raise securesystemslib.exceptions.FormatError(
        "Links must be Link or Metadata objects."
    )


def _normalize_links(layout, links, trusted_signers):  # noqa: C901
    """Return one link and signer evidence per step.

    ``links`` may map a step either to one Link/Metadata object or to a
    keyid-to-Link/Metadata dictionary as returned by
    ``verify_link_signature_thresholds``. In the latter case all links of a
    step must report identical materials and products.

    """
    if not isinstance(links, Mapping):
        raise securesystemslib.exceptions.FormatError(
            "Links must be passed as a dictionary."
        )

    normalized = {}
    for step in layout.steps:
        value = links.get(step.name)
        if value is None:
            raise LinkNotFoundError(
                f"No link metadata passed for step '{step.name}'."
            )

        signers = []
        if isinstance(value, Mapping) and not isinstance(value, Metadata):
            links_for_step = {}
            for keyid, metadata in value.items():
                link, _ = _get_payload_link(metadata)
                links_for_step[keyid] = link
                signers.append(keyid)

            if not links_for_step:
                raise LinkNotFoundError(
                    f"No link metadata passed for step '{step.name}'."
                )

            reference = next(iter(links_for_step.values()))
            for link in links_for_step.values():
                if (
                    link.materials != reference.materials
                    or link.products != reference.products
                ):
                    raise ThresholdVerificationError(
                        f"Links for step '{step.name}' report different "
                        "artifacts."
                    )
        else:
            reference, metadata_signers = _get_payload_link(value)
            signers.extend(metadata_signers)

        if trusted_signers is not None:
            explicit_signers = trusted_signers.get(step.name)
            if explicit_signers is not None:
                signers = list(explicit_signers)

        normalized[step.name] = (reference, list(dict.fromkeys(signers)))

    return normalized


def _match_paths(source_paths, pattern, source_prefix, dest_prefix):
    """Yield source/destination path pairs selected by one MATCH rule.

    This mirrors the prefix/glob handling of ``verify_match_rule`` so that a
    plan edge exists only if verification would consider the same artifact
    pair.

    """
    if source_prefix:
        normalized_source_prefix = os.path.join(source_prefix, "").replace(
            "\\", "/"
        )
        relative_paths = [
            path[len(normalized_source_prefix) :]
            for path in source_paths
            if path.startswith(normalized_source_prefix)
        ]
    else:
        relative_paths = list(source_paths)

    for relative_path in sorted(fnmatch.filter(relative_paths, pattern)):
        if source_prefix:
            source_path = os.path.join(source_prefix, relative_path).replace(
                "\\", "/"
            )
        else:
            source_path = relative_path

        if dest_prefix:
            dest_path = os.path.join(dest_prefix, relative_path).replace(
                "\\", "/"
            )
        else:
            dest_path = relative_path

        yield source_path, dest_path


def _collect_dependency_edges(layout, link_records):
    """Collect actual material dependencies established by MATCH rules."""
    edges = []

    for step in layout.steps:
        consumer_link = link_records[step.name][0]
        for rule in step.expected_materials:
            rule_data = in_toto.rulelib.unpack_rule(rule)
            if rule_data["rule_type"] != "match":
                continue

            producer = rule_data["dest_name"]
            if producer not in link_records:
                continue

            producer_link = link_records[producer][0]
            producer_artifacts = getattr(producer_link, rule_data["dest_type"])

            for source_path, dest_path in _match_paths(
                consumer_link.materials,
                rule_data["pattern"],
                rule_data["source_prefix"],
                rule_data["dest_prefix"],
            ):
                if dest_path not in producer_artifacts:
                    continue

                source_hashes = consumer_link.materials[source_path]
                dest_hashes = producer_artifacts[dest_path]
                if source_hashes != dest_hashes:
                    continue

                edges.append(
                    DependencyEdge(
                        consumer=step.name,
                        consumer_type="materials",
                        consumer_path=source_path,
                        producer=producer,
                        producer_type=rule_data["dest_type"],
                        producer_path=dest_path,
                        rule=tuple(rule),
                        hashes=dict(source_hashes),
                    )
                )

    return edges


def _incoming_edges(decision, artifact_path):
    """Return incoming material edges for one consumer artifact path."""
    return [
        edge
        for edge in decision.dependencies
        if edge.consumer_type == "materials"
        and edge.consumer_path == artifact_path
    ]


def _artifact_matches(  # noqa: PLR0913
    name,
    hashes,
    producer_step,
    incoming_edges,
    used,
    artifact_index,
):
    """Check one artifact against withdrawals and record usage.

    ``incoming_edges`` is ``None`` for products. For materials it contains the
    actual MATCH edges that led to this artifact. A withdrawal scoped to a
    producer step only applies to a product of that step or to a material that
    is really connected to that producer by a MATCH rule.

    """
    matched = False
    for index, withdrawal in enumerate(artifact_index):
        if withdrawal.step is not None:
            if incoming_edges is None:
                if producer_step != withdrawal.step:
                    continue
            elif not any(
                edge.producer == withdrawal.step for edge in incoming_edges
            ):
                continue

        if withdrawal.matches(
            name,
            hashes,
            step=withdrawal.step
            if withdrawal.step is not None
            else producer_step,
        ):
            used[index] = True
            matched = True

    return matched


def _topological_rerun_order(layout, affected, edges):
    """Order affected steps by their actual dependencies, layout order first."""
    layout_order = {step.name: index for index, step in enumerate(layout.steps)}
    successors = defaultdict(set)
    indegree = dict.fromkeys(affected, 0)

    for edge in edges:
        if edge.producer not in affected or edge.consumer not in affected:
            continue
        if edge.consumer in successors[edge.producer]:
            continue

        successors[edge.producer].add(edge.consumer)
        indegree[edge.consumer] += 1

    ready = sorted(
        (name for name in affected if indegree[name] == 0),
        key=layout_order.get,
    )
    ordered = []
    while ready:
        name = ready.pop(0)
        ordered.append(name)
        for successor in sorted(successors[name], key=layout_order.get):
            indegree[successor] -= 1
            if indegree[successor] == 0:
                ready.append(successor)
                ready.sort(key=layout_order.get)

    # A valid layout normally has no dependency cycle. Keep the plan useful
    # for malformed-but-verified data by falling back to layout order.
    ordered.extend(
        step.name
        for step in layout.steps
        if step.name in affected and step.name not in ordered
    )
    return ordered


def build_reverification_plan(  # noqa: C901, PLR0912, PLR0913, PLR0915
    layout,
    links,
    withdrawn_artifacts=None,
    trusted_signers=None,
    layout_verified=False,
    layout_signers=None,
):
    """Build a re-verification plan for a verified layout.

    Arguments:
      layout:
          A Layout object. Its signatures and expiration must already have been
          verified by the caller, or ``layout_verified`` must describe that
          precondition explicitly.

      links:
          Verified link metadata, either one Link/Metadata per step or the
          keyid-to-metadata dictionary returned by
          ``verify_link_signature_thresholds``.

      withdrawn_artifacts (optional):
          Iterable of :class:`WithdrawnArtifact` instances or dictionaries.
          A dictionary must contain content hashes, e.g. ``{"sha256": "..."}``
          or ``{"name": "foo", "hashes": {"sha256": "..."},
          "step": "build"}``.

      trusted_signers (optional):
          Dictionary mapping step names to the keyids whose signatures were
          verified. This overrides signer evidence inferred from nested links.

      layout_verified (optional):
          Whether layout signature and expiration checks passed. Defaults to
          False and is copied into the returned plan.

      layout_signers (optional):
          Keyids whose signatures verified the layout. Copied into the plan
          for auditability.

    Raises:
      securesystemslib.exceptions.FormatError:
          Arguments are malformed.

      LinkNotFoundError:
          Link metadata is missing for a layout step.

      ThresholdVerificationError:
          Multiple links for one step report different artifacts.

    Returns:
      A :class:`ReverificationPlan`.

    """
    if not isinstance(layout, in_toto.models.layout.Layout):
        raise securesystemslib.exceptions.FormatError(
            "A Layout object is required to build a re-verification plan."
        )

    withdrawals = [
        WithdrawnArtifact.from_data(artifact)
        for artifact in (withdrawn_artifacts or [])
    ]
    link_records = _normalize_links(layout, links, trusted_signers)
    edges = _collect_dependency_edges(layout, link_records)
    dependencies = defaultdict(list)
    for edge in edges:
        dependencies[edge.consumer].append(edge)

    used_withdrawals = [False] * len(withdrawals)
    decisions = {}

    for step in layout.steps:
        link, signers = link_records[step.name]
        decision = StepDecision(
            name=step.name,
            action=ACTION_REUSE,
            trusted_signers=signers,
            dependencies=sorted(
                dependencies[step.name],
                key=lambda edge: (
                    edge.producer,
                    edge.consumer_path,
                    edge.producer_path,
                ),
            ),
        )
        decisions[step.name] = decision

        for dependency in decision.dependencies:
            decision.basis.append(
                f"material '{dependency.consumer_path}' matched "
                f"{dependency.producer_type[:-1]} "
                f"'{dependency.producer_path}' from step "
                f"'{dependency.producer}' by rule "
                f"'{' '.join(dependency.rule)}' "
                f"({_format_hash(dependency.hashes)})"
            )

        unique_signers = set(signers)
        if not unique_signers:
            decision.add_finding(
                "untrusted_signature",
                "no trusted signature evidence is available for this link",
            )
        elif len(unique_signers) < step.threshold:
            decision.add_finding(
                "insufficient_trusted_signatures",
                f"{len(unique_signers)} trusted signature(s) do not meet "
                f"threshold {step.threshold}",
            )
        else:
            decision.basis.append(
                f"{len(unique_signers)} trusted signature(s) meet threshold "
                f"{step.threshold}"
            )

        for path, hashes in sorted(link.products.items()):
            matched = _artifact_matches(
                path,
                hashes,
                step.name,
                None,
                used_withdrawals,
                withdrawals,
            )
            if matched:
                decision.withdrawn_artifacts.append(
                    {
                        "role": "product",
                        "name": path,
                        "hashes": dict(hashes),
                    }
                )
                decision.add_finding(
                    "withdrawn_product",
                    f"product '{path}' ({_format_hash(hashes)}) is "
                    "explicitly withdrawn",
                )

        for path, hashes in sorted(link.materials.items()):
            matched = _artifact_matches(
                path,
                hashes,
                step.name,
                _incoming_edges(decision, path),
                used_withdrawals,
                withdrawals,
            )
            if matched:
                decision.withdrawn_artifacts.append(
                    {
                        "role": "material",
                        "name": path,
                        "hashes": dict(hashes),
                    }
                )
                decision.add_finding(
                    "withdrawn_material",
                    f"material '{path}' ({_format_hash(hashes)}) is "
                    "explicitly withdrawn",
                )

    # A withdrawn producer artifact invalidates the exact dependency edges that
    # consume it. This is where a branch is cut, without looking at same-named
    # artifacts in other branches.
    edge_findings = set()
    for edge in edges:
        for index, withdrawal in enumerate(withdrawals):
            if not withdrawal.matches(
                edge.producer_path,
                edge.hashes,
                step=edge.producer,
            ):
                continue

            used_withdrawals[index] = True
            decision = decisions[edge.consumer]
            finding_key = (edge.consumer, edge.producer, edge.producer_path)
            if finding_key not in edge_findings:
                decision.add_finding(
                    "withdrawn_dependency",
                    f"material '{edge.consumer_path}' "
                    f"({_format_hash(edge.hashes)}) matched withdrawn "
                    f"{edge.producer_type[:-1]} '{edge.producer_path}' from "
                    f"step '{edge.producer}'",
                )
                edge_findings.add(finding_key)
            break

    # Re-executing a step invalidates downstream consumers connected by an
    # actual MATCH edge. If only a specific product was withdrawn, only the
    # edges that consume that product are cut. If the step itself has to
    # regenerate all of its output (withdrawn input, untrusted signature or an
    # invalidated upstream input), all real downstream edges are cut. Unrelated
    # steps that merely share a file name are not reachable and stay reusable.
    affected = {
        name for name, decision in decisions.items() if decision.findings
    }
    invalidates_all_products = {}
    invalidated_products = defaultdict(set)
    for name, decision in decisions.items():
        codes = {finding["code"] for finding in decision.findings}
        invalidates_all_products[name] = any(
            code != "withdrawn_product" for code in codes
        )
        for artifact in decision.withdrawn_artifacts:
            if artifact["role"] == "product":
                invalidated_products[name].add(artifact["name"])

    successors = defaultdict(list)
    for edge in edges:
        successors[edge.producer].append(edge)

    queue = deque(step.name for step in layout.steps if step.name in affected)
    queued = set(queue)
    propagated_edges = set()
    while queue:
        producer = queue.popleft()
        for edge in successors[producer]:
            if not invalidates_all_products.get(
                producer, True
            ) and edge.producer_path not in invalidated_products.get(
                producer, set()
            ):
                continue

            consumer = edge.consumer
            edge_key = (
                edge.consumer,
                edge.consumer_path,
                edge.producer,
                edge.producer_path,
            )
            if edge_key not in propagated_edges:
                decisions[consumer].add_finding(
                    "upstream_reverification",
                    f"depends on step '{producer}' whose evidence will be "
                    f"regenerated through material '{edge.consumer_path}'",
                )
                propagated_edges.add(edge_key)

            # An invalidated input means the consumer's own products can no
            # longer be trusted as a whole.
            invalidates_all_products[consumer] = True
            if consumer not in affected:
                affected.add(consumer)
            if consumer not in queued:
                queued.add(consumer)
                queue.append(consumer)

    for step in layout.steps:
        decision = decisions[step.name]
        if decision.findings:
            decision.action = ACTION_REVERIFY
        else:
            decision.action = ACTION_REUSE
            if decision.dependencies:
                decision.basis.append(
                    "all "
                    f"{len(decision.dependencies)} matched upstream "
                    "artifact(s) come from retained steps with equal digests"
                )
            else:
                decision.basis.append(
                    "no MATCH rule connects this step to an upstream step"
                )
            decision.basis.append(
                "no explicitly withdrawn material or product intersects this "
                "step"
            )

    unmatched = []
    for index, withdrawal in enumerate(withdrawals):
        if not used_withdrawals[index]:
            unmatched.append(withdrawal)

    return ReverificationPlan(
        steps=[decisions[step.name] for step in layout.steps],
        withdrawn_artifacts=withdrawals,
        unmatched_withdrawals=unmatched,
        rerun_order=_topological_rerun_order(layout, affected, edges),
        layout_verified=layout_verified,
        layout_expires=getattr(layout, "expires", None),
        layout_signers=list(layout_signers or []),
    )


def _format_hash(hashes):
    """Format a hash dictionary compactly."""
    return ", ".join(
        f"{algorithm}:{digest}" for algorithm, digest in hashes.items()
    )


def verify_and_build_plan(  # noqa: PLR0913
    metadata,
    layout_key_dict,
    link_dir_path=".",
    withdrawn_artifacts=None,
    substitution_parameters=None,
    inspect_timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
    verify_inspections=False,
):
    """Verify layout/link metadata and build a re-verification plan.

    This performs the step-relevant part of ``in_toto_verify`` in the same
    order: layout signatures, layout expiration, optional parameter
    substitution, link loading, link signature thresholds, sublayouts, command
    alignment, threshold constraints, and step artifact rules.

    Inspection commands are not run by default because a planning tool must not
    execute unverified target files merely to decide which steps to rerun. Pass
    ``verify_inspections=True`` to run and verify inspections as well.

    Arguments are the same as for ``in_toto_verify``, plus
    ``withdrawn_artifacts`` and ``verify_inspections``.

    Returns:
      A :class:`ReverificationPlan`.

    """
    in_toto.verifylib.verify_metadata_signatures(metadata, layout_key_dict)
    layout = metadata.get_payload()

    in_toto.verifylib.verify_layout_expiration(layout)

    if substitution_parameters is not None:
        in_toto.verifylib.substitute_parameters(layout, substitution_parameters)

    steps_metadata = in_toto.verifylib.load_links_for_layout(
        layout, link_dir_path
    )
    steps_metadata = in_toto.verifylib.verify_link_signature_thresholds(
        layout, steps_metadata
    )
    chain_link_dict = in_toto.verifylib.verify_sublayouts(
        layout, steps_metadata, link_dir_path, inspect_timeout
    )
    in_toto.verifylib.verify_all_steps_command_alignment(
        layout, chain_link_dict
    )
    in_toto.verifylib.verify_threshold_constraints(layout, chain_link_dict)
    reduced_links = in_toto.verifylib.reduce_chain_links(chain_link_dict)
    in_toto.verifylib.verify_all_item_rules(layout.steps, reduced_links)

    if verify_inspections:
        inspection_links = in_toto.verifylib.run_all_inspections(
            layout, persist_inspection_links=False, timeout=inspect_timeout
        )
        links_with_inspections = dict(reduced_links)
        links_with_inspections.update(inspection_links)
        in_toto.verifylib.verify_all_item_rules(
            layout.inspect, links_with_inspections
        )

    return build_reverification_plan(
        layout,
        chain_link_dict,
        withdrawn_artifacts=withdrawn_artifacts,
        layout_verified=True,
        layout_signers=sorted(layout_key_dict),
    )
