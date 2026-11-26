"""Local disclosure receipts for already verified in-toto materials.

This module is intentionally adjacent to, rather than part of, signature and
rule verification.  Callers must first verify link signatures and applicable
in-toto rules.  The receipt builder only consumes explicit rule bases; equal
digests alone never connect two artifacts.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

import attr

from in_toto.models.link import Link
from in_toto.models.metadata import Metadata
from in_toto.rulelib import unpack_rule
from in_toto.verifylib import verify_match_rule

PUBLIC_RECEIPT_SCHEMA = "in-toto/disclosed-receipt/v1"
INTERNAL_RECEIPT_SCHEMA = "in-toto/internal-disclosure-receipt/v1"

STATUS_COMPLETE = "complete"
STATUS_GAP = "evidence_gap"
DEFAULT_GAP_NOTICE = "Provenance for this approved artifact cannot be disclosed."

_ARTIFACT_KINDS = ("materials", "products")


class DisclosureInputError(ValueError):
    """Raised when disclosure request data is malformed."""


@dataclass(frozen=True)
class ApprovedArtifact:
    """Artifact and purpose explicitly approved for disclosure.

    ``path`` and ``step`` are internal selectors.  They are used to choose the
    right node when the same digest occurs in multiple branches and are never
    copied to the public receipt.
    """

    purpose: str
    hashes: Mapping[str, str] = field(default_factory=dict)
    path: str | None = None
    step: str | None = None
    kind: str | None = None
    public_label: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.purpose, str) or not self.purpose.strip():
            raise DisclosureInputError("approval purpose must be a non-empty string")

        hashes = _normalise_hashes(self.hashes)
        if not hashes:
            raise DisclosureInputError("approval must include at least one digest")
        object.__setattr__(self, "hashes", hashes)

        if self.kind is not None and self.kind not in _ARTIFACT_KINDS:
            raise DisclosureInputError(f"kind must be one of {_ARTIFACT_KINDS}")

    @classmethod
    def from_digest(
        cls,
        *,
        purpose: str,
        digest: str,
        algorithm: str = "sha256",
        path: str | None = None,
        step: str | None = None,
        kind: str | None = None,
        public_label: str | None = None,
    ) -> "ApprovedArtifact":
        """Create an approval from one digest."""
        return cls(
            purpose=purpose,
            hashes={algorithm: digest},
            path=path,
            step=step,
            kind=kind,
            public_label=public_label,
        )

    def digest_values(self) -> set[str]:
        """Return lowercase digest values without algorithm names."""
        return {digest.lower() for digest in self.hashes.values()}


@dataclass(frozen=True)
class StepDisclosure:
    """Explicit public fields for one verified step.

    The ``fields`` mapping is an allow-list projection.  It is copied verbatim
    to the external receipt, so callers must put only approved values in it.
    """

    fields: Mapping[str, Any] = field(default_factory=dict)
    disclosed: bool = True
    notice: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "fields", dict(self.fields))
        json.dumps(self.fields, sort_keys=True)
        if self.notice is not None and not isinstance(self.notice, str):
            raise DisclosureInputError("step notice must be a string or None")


@dataclass(frozen=True)
class VerifiedStep:
    """Step materials whose signature and rules the caller has verified.

    The builder does not verify signatures.  ``authorized`` records whether the
    step is part of the approved functionary/layout chain.  A divergent step is
    retained in the internal receipt but produces only a generic public gap.
    """

    name: str
    link: Link | Mapping[str, Any] | str | Path
    authorized: bool = True
    source_divergent: bool = False
    key_id: str | None = None
    disclosure: StepDisclosure | Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise DisclosureInputError("step name must be a non-empty string")
        object.__setattr__(self, "link", _coerce_link(self.link))
        object.__setattr__(self, "disclosure", _coerce_disclosure(self.disclosure))


@dataclass(frozen=True)
class RuleBasis:
    """An explicit checked rule relation between two Link artifacts.

    Edges point forward in provenance: a matched prior artifact points to the
    current artifact, and a material points to the product it supports.
    """

    source_step: str
    source_path: str
    target_step: str
    target_path: str
    rule: Any
    source_kind: str = "materials"
    target_kind: str = "products"
    verified: bool = True

    def __post_init__(self) -> None:
        for value in (
            self.source_step,
            self.source_path,
            self.target_step,
            self.target_path,
        ):
            if not isinstance(value, str) or not value:
                raise DisclosureInputError("rule basis endpoints must be non-empty strings")
        if self.source_kind not in _ARTIFACT_KINDS:
            raise DisclosureInputError(f"source_kind must be one of {_ARTIFACT_KINDS}")
        if self.target_kind not in _ARTIFACT_KINDS:
            raise DisclosureInputError(f"target_kind must be one of {_ARTIFACT_KINDS}")
        if not self.rule:
            raise DisclosureInputError("rule basis must include the checked rule")
        json.dumps(self.rule, sort_keys=True)

    @classmethod
    def material_product(
        cls,
        *,
        step: str,
        material: str,
        product: str,
        rule: Any,
        verified: bool = True,
    ) -> "RuleBasis":
        """Create a material-to-product basis within one step."""
        return cls(
            source_step=step,
            source_path=material,
            source_kind="materials",
            target_step=step,
            target_path=product,
            target_kind="products",
            rule=rule,
            verified=verified,
        )

    @classmethod
    def artifact_match(
        cls,
        *,
        prior_step: str,
        prior_path: str,
        current_step: str,
        current_path: str,
        rule: Any,
        prior_kind: str = "products",
        current_kind: str = "materials",
        verified: bool = True,
    ) -> "RuleBasis":
        """Create a cross-step matched-artifact basis, including renames."""
        return cls(
            source_step=prior_step,
            source_path=prior_path,
            source_kind=prior_kind,
            target_step=current_step,
            target_path=current_path,
            target_kind=current_kind,
            rule=rule,
            verified=verified,
        )


@dataclass(frozen=True)
class DisclosureBundle:
    """Pair of internal and external receipts."""

    internal: dict[str, Any]
    public: dict[str, Any]

    def write(
        self,
        *,
        internal_path: str | Path,
        public_path: str | Path,
    ) -> None:
        """Write both receipts as sorted, indented JSON files."""
        _write_json(Path(internal_path), self.internal)
        _write_json(Path(public_path), self.public)

    def write_directory(self, directory: str | Path) -> tuple[Path, Path]:
        """Write receipts using their fixed local file names."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        internal_path = directory / "internal-disclosure-receipt.json"
        public_path = directory / "public-disclosure-receipt.json"
        self.write(internal_path=internal_path, public_path=public_path)
        return internal_path, public_path


def build_disclosure_receipt(
    *,
    approval: ApprovedArtifact | Mapping[str, Any],
    steps: Sequence[VerifiedStep | Mapping[str, Any]],
    rule_bases: Sequence[RuleBasis | Mapping[str, Any]] | None = None,
) -> DisclosureBundle:
    """Build the internal and privacy-minimised receipts.

    Malformed caller input raises :class:`DisclosureInputError`.  Missing,
    unauthorised, or divergent provenance does not raise; it becomes an
    internal diagnostic and the same generic public evidence gap.
    """
    approval = _coerce_approval(approval)
    verified_steps = [_coerce_step(step) for step in steps]
    bases = [_coerce_basis(basis) for basis in (rule_bases or [])]

    step_by_name: dict[str, VerifiedStep] = {}
    for step in verified_steps:
        if step.name in step_by_name:
            raise DisclosureInputError(f"duplicate verified step name: {step.name}")
        step_by_name[step.name] = step

    nodes = _build_nodes(verified_steps)
    edges = _build_edges(bases, nodes)
    diagnostics: list[dict[str, Any]] = []

    for edge in edges:
        if not edge["endpoint_valid"]:
            diagnostics.append(
                {
                    "code": "rule_endpoint_missing",
                    "rule_basis": edge["basis"],
                }
            )
        elif not edge["hash_compatible"]:
            diagnostics.append(
                {
                    "code": "rule_hash_mismatch",
                    "source": edge["source"],
                    "target": edge["target"],
                    "rule": edge["rule"],
                }
            )
        elif not edge["verified"]:
            diagnostics.append(
                {
                    "code": "rule_basis_unverified",
                    "source": edge["source"],
                    "target": edge["target"],
                    "rule": edge["rule"],
                }
            )

    for step in verified_steps:
        if step.source_divergent:
            diagnostics.append(
                {
                    "code": "source_divergence",
                    "step": step.name,
                    "detail": "caller reported conflicting source attestations",
                }
            )
        if not step.authorized:
            diagnostics.append(
                {
                    "code": "unauthorized_step",
                    "step": step.name,
                }
            )
        elif not step.disclosure.disclosed:
            diagnostics.append(
                {
                    "code": "step_disclosure_withheld",
                    "step": step.name,
                }
            )

    target, selection_diagnostic = _select_target(approval, nodes, step_by_name)
    if selection_diagnostic:
        diagnostics.append(selection_diagnostic)

    internal = _build_internal_receipt(
        approval=approval,
        steps=verified_steps,
        nodes=nodes,
        edges=edges,
        target=target,
        diagnostics=diagnostics,
    )

    public = _build_public_receipt(
        approval=approval,
        target=target,
        nodes=nodes,
        edges=edges,
        step_by_name=step_by_name,
    )

    return DisclosureBundle(internal=internal, public=public)


DisclosureReceipt = DisclosureBundle
build_local_disclosure_receipt = build_disclosure_receipt
create_disclosure_receipt = build_disclosure_receipt


def match_bases_from_rules(
    *,
    source_name: str,
    source_type: str,
    rules: Sequence[Sequence[str] | Mapping[str, Any] | str],
    links: Mapping[str, Link],
) -> list[RuleBasis]:
    """Return verified MATCH bases by reusing in-toto's rule implementation.

    ``links`` maps step names to :class:`~in_toto.models.link.Link` objects.
    The caller remains responsible for signature and layout verification.
    """
    if source_type not in _ARTIFACT_KINDS:
        raise DisclosureInputError(f"source_type must be one of {_ARTIFACT_KINDS}")
    if source_name not in links:
        raise DisclosureInputError(f"missing source link: {source_name}")

    source_link = links[source_name]
    source_artifacts = getattr(source_link, source_type)
    bases: list[RuleBasis] = []

    for packed_rule in rules:
        rule_data = unpack_rule(packed_rule)
        if rule_data["rule_type"] != "match":
            continue

        consumed = verify_match_rule(
            rule_data,
            set(source_artifacts.keys()),
            source_artifacts,
            links,
        )
        if not consumed:
            continue

        for full_source_path in sorted(consumed):
            relative_path = _relative_rule_path(
                full_source_path, rule_data["source_prefix"]
            )
            destination_path = _prefixed_rule_path(
                relative_path, rule_data["dest_prefix"]
            )
            bases.append(
                RuleBasis.artifact_match(
                    prior_step=rule_data["dest_name"],
                    prior_path=destination_path,
                    prior_kind=rule_data["dest_type"],
                    current_step=source_name,
                    current_path=full_source_path,
                    current_kind=source_type,
                    rule=list(packed_rule)
                    if not isinstance(packed_rule, str)
                    else packed_rule,
                )
            )

    return bases


def _coerce_approval(value: ApprovedArtifact | Mapping[str, Any]) -> ApprovedArtifact:
    if isinstance(value, ApprovedArtifact):
        return value
    if isinstance(value, Mapping):
        data = dict(value)
        if "hashes" not in data and "digest" in data:
            data["hashes"] = {
                data.pop("algorithm", "sha256"): data.pop("digest")
            }
        data.pop("digest", None)
        return ApprovedArtifact(**data)
    raise DisclosureInputError("approval must be an ApprovedArtifact or mapping")


def _coerce_disclosure(
    value: StepDisclosure | Mapping[str, Any] | None,
) -> StepDisclosure:
    if value is None:
        return StepDisclosure(fields={}, disclosed=False)
    if isinstance(value, StepDisclosure):
        return value
    if isinstance(value, Mapping):
        data = dict(value)
        if {"fields", "disclosed", "notice"}.intersection(data):
            return StepDisclosure(**data)
        return StepDisclosure(fields=data)
    raise DisclosureInputError("step disclosure must be a mapping or StepDisclosure")


def _coerce_step(value: VerifiedStep | Mapping[str, Any]) -> VerifiedStep:
    if isinstance(value, VerifiedStep):
        return value
    if isinstance(value, Mapping):
        return VerifiedStep(**dict(value))
    raise DisclosureInputError("step must be a VerifiedStep or mapping")


def _coerce_basis(value: RuleBasis | Mapping[str, Any]) -> RuleBasis:
    if isinstance(value, RuleBasis):
        return value
    if not isinstance(value, Mapping):
        raise DisclosureInputError("rule basis must be a RuleBasis or mapping")

    data = dict(value)
    if "source" in data or "target" in data:
        source = _endpoint_mapping(data.pop("source", {}))
        target = _endpoint_mapping(data.pop("target", {}))
        data.update(
            source_step=source["step"],
            source_path=source["path"],
            source_kind=source.get("kind", "materials"),
            target_step=target["step"],
            target_path=target["path"],
            target_kind=target.get("kind", "products"),
        )
    elif "material" in data:
        data.setdefault("source_step", data.get("step"))
        data.setdefault("target_step", data.get("step"))
        data.setdefault("source_path", data.pop("material"))
        data.setdefault("target_path", data.pop("product", None))
        data.setdefault("source_kind", "materials")
        data.setdefault("target_kind", "products")
        data.pop("step", None)
    return RuleBasis(**data)


def _endpoint_mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DisclosureInputError("rule endpoint must be a mapping")
    if "step" not in value or "path" not in value:
        raise DisclosureInputError("rule endpoint requires step and path")
    return value


def _coerce_link(value: Link | Mapping[str, Any] | str | Path) -> Link:
    if isinstance(value, Link):
        return value
    if isinstance(value, (str, Path)):
        path = Path(value)
        value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, Mapping):
        data = dict(value)
        if "signed" in data or "payload" in data:
            metadata = Metadata.from_dict(data)
            payload = metadata.get_payload()
            if not isinstance(payload, Link):
                raise DisclosureInputError("metadata payload is not a Link")
            return payload
        return Link.read(data)
    raise DisclosureInputError("link must be a Link, mapping, or metadata path")


def _normalise_hashes(value: Mapping[str, str] | None) -> dict[str, str]:
    if not value:
        return {}
    if not isinstance(value, Mapping):
        raise DisclosureInputError("hashes must be a mapping")
    return {str(algorithm): str(digest).lower() for algorithm, digest in sorted(value.items())}


def _node_key(step: str, kind: str, path: str) -> tuple[str, str, str]:
    return (step, kind, path)


def _build_nodes(
    steps: Sequence[VerifiedStep],
) -> dict[tuple[str, str, str], dict[str, Any]]:
    nodes: dict[tuple[str, str, str], dict[str, Any]] = {}
    for step in steps:
        for kind in _ARTIFACT_KINDS:
            artifacts = getattr(step.link, kind)
            for path, hashes in artifacts.items():
                key = _node_key(step.name, kind, path)
                nodes[key] = {
                    "step": step.name,
                    "kind": kind,
                    "path": path,
                    "hashes": _normalise_hashes(hashes),
                }
    return nodes


def _build_edges(
    bases: Sequence[RuleBasis],
    nodes: Mapping[tuple[str, str, str], Mapping[str, Any]],
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for basis in bases:
        source = _node_key(basis.source_step, basis.source_kind, basis.source_path)
        target = _node_key(basis.target_step, basis.target_kind, basis.target_path)
        endpoint_valid = source in nodes and target in nodes
        hash_compatible = True
        if endpoint_valid:
            if basis.source_kind == "products" and basis.target_kind == "materials":
                hash_compatible = nodes[source]["hashes"] == nodes[target]["hashes"]
        edges.append(
            {
                "source": source,
                "target": target,
                "rule": basis.rule,
                "verified": basis.verified,
                "endpoint_valid": endpoint_valid,
                "hash_compatible": hash_compatible,
                "trusted": endpoint_valid
                and hash_compatible
                and basis.verified,
                "basis": asdict(basis),
            }
        )
    return edges


def _select_target(
    approval: ApprovedArtifact,
    nodes: Mapping[tuple[str, str, str], Mapping[str, Any]],
    steps: Mapping[str, VerifiedStep],
) -> tuple[tuple[str, str, str] | None, dict[str, Any] | None]:
    candidates: list[tuple[str, str, str]] = []
    approved_digests = approval.digest_values()

    for key, node in nodes.items():
        if approval.step is not None and key[0] != approval.step:
            continue
        if approval.kind is not None and key[1] != approval.kind:
            continue
        if approval.path is not None and key[2] != approval.path:
            continue
        node_digests = {digest.lower() for digest in node["hashes"].values()}
        if approved_digests.isdisjoint(node_digests):
            continue
        candidates.append(key)

    if not candidates:
        return None, {
            "code": "approval_artifact_not_found",
            "purpose": approval.purpose,
        }

    if len(candidates) == 1:
        return candidates[0], None

    if approval.kind is None:
        products = [key for key in candidates if key[1] == "products"]
        if len(products) == 1:
            return products[0], None
        if products:
            candidates = products

    active = [key for key in candidates if _step_public(steps[key[0]])]
    if len(active) == 1:
        return active[0], None

    return None, {
        "code": "approval_artifact_ambiguous",
        "candidates": [_internal_node_ref(key, nodes[key]) for key in candidates],
    }


def _step_public(step: VerifiedStep) -> bool:
    return (
        step.authorized
        and not step.source_divergent
        and step.disclosure.disclosed
    )


def _trace_internal(
    target: tuple[str, str, str],
    edges: Sequence[Mapping[str, Any]],
) -> tuple[set[tuple[str, str, str]], set[int]]:
    seen = {target}
    used_edges: set[int] = set()
    stack = [target]

    while stack:
        current = stack.pop()
        for index, edge in enumerate(edges):
            if edge["target"] != current or not edge["trusted"]:
                continue
            used_edges.add(index)
            source = edge["source"]
            if source not in seen:
                seen.add(source)
                stack.append(source)

    return seen, used_edges


def _build_internal_receipt(
    *,
    approval: ApprovedArtifact,
    steps: Sequence[VerifiedStep],
    nodes: Mapping[tuple[str, str, str], Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    target: tuple[str, str, str] | None,
    diagnostics: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    reachable_nodes: set[tuple[str, str, str]] = set()
    used_edges: set[int] = set()
    if target is not None:
        reachable_nodes, used_edges = _trace_internal(target, edges)

    internal_edges = []
    for index, edge in enumerate(edges):
        if index in used_edges or target is None:
            internal_edges.append(_internal_edge(edge))

    receipt: dict[str, Any] = {
        "schema": INTERNAL_RECEIPT_SCHEMA,
        "approval": {
            "purpose": approval.purpose,
            "artifact": {
                "path": approval.path,
                "step": approval.step,
                "kind": approval.kind,
                "hashes": dict(approval.hashes),
                "public_label": approval.public_label,
            },
        },
        "status": STATUS_COMPLETE if target is not None else STATUS_GAP,
        "target": _internal_node_ref(target, nodes[target]) if target else None,
        "connected_provenance": {
            "nodes": [
                _internal_node_ref(key, nodes[key])
                for key in sorted(reachable_nodes)
            ],
            "rule_bases": internal_edges,
        },
        "all_rule_bases": [_internal_edge(edge) for edge in edges],
        "connected_rule_bases": internal_edges,
        "steps": {
            step.name: {
                "authorized": step.authorized,
                "source_divergent": step.source_divergent,
                "key_id": step.key_id,
                "disclosure": {
                    "disclosed": step.disclosure.disclosed,
                    "fields": dict(step.disclosure.fields),
                    "notice": step.disclosure.notice,
                },
                "link": attr.asdict(step.link),
            }
            for step in steps
        },
        "diagnostics": list(diagnostics),
    }
    return receipt


def _internal_node_ref(
    key: tuple[str, str, str] | None,
    node: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if key is None or node is None:
        return None
    return {
        "step": key[0],
        "artifact_type": key[1],
        "path": key[2],
        "hashes": dict(node["hashes"]),
    }


def _internal_edge(edge: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "source": list(edge["source"]),
        "target": list(edge["target"]),
        "rule": edge["rule"],
        "verified": edge["verified"],
        "trusted": edge["trusted"],
        "hash_compatible": edge["hash_compatible"],
    }


def _build_public_receipt(
    *,
    approval: ApprovedArtifact,
    target: tuple[str, str, str] | None,
    nodes: Mapping[tuple[str, str, str], Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    step_by_name: Mapping[str, VerifiedStep],
) -> dict[str, Any]:
    gap = target is None
    public_nodes: set[tuple[str, str, str]] = set()
    public_edges: list[Mapping[str, Any]] = []

    if target is not None:
        target_step = step_by_name[target[0]]
        if not _step_public(target_step):
            gap = True
        else:
            seen: set[tuple[str, str, str]] = set()
            stack = [target]
            while stack:
                current = stack.pop()
                if current in seen:
                    continue
                seen.add(current)

                current_step = step_by_name[current[0]]
                if not _step_public(current_step):
                    gap = True
                    continue

                public_nodes.add(current)
                incoming = [edge for edge in edges if edge["target"] == current]
                for edge in incoming:
                    if not edge["trusted"]:
                        gap = True
                        continue

                    source = edge["source"]
                    source_step = step_by_name[source[0]]
                    if not _step_public(source_step):
                        gap = True
                        continue

                    if edge not in public_edges:
                        public_edges.append(edge)
                    if source not in seen:
                        stack.append(source)

    ordered_steps, cycle = _public_step_order(
        public_nodes, public_edges, step_by_name
    )
    if cycle:
        gap = True

    steps_view = [
        dict(step_by_name[name].disclosure.fields)
        for name in ordered_steps
        if _step_public(step_by_name[name])
    ]

    provenance: dict[str, Any] = {"status": STATUS_GAP if gap else STATUS_COMPLETE}
    if gap:
        provenance["notice"] = DEFAULT_GAP_NOTICE

    artifact: dict[str, Any] = {}
    if approval.public_label is not None:
        artifact["label"] = approval.public_label

    return {
        "schema": PUBLIC_RECEIPT_SCHEMA,
        "approved_use": approval.purpose,
        "public_artifact": artifact,
        "provenance": provenance,
        "steps": steps_view,
    }


def _public_step_order(
    nodes: set[tuple[str, str, str]],
    edges: Sequence[Mapping[str, Any]],
    step_order: Mapping[str, VerifiedStep],
) -> tuple[list[str], bool]:
    node_step_names = {key[0] for key in nodes}
    step_names = [name for name in step_order if name in node_step_names]
    predecessors: dict[str, set[str]] = {name: set() for name in step_names}
    successors: dict[str, set[str]] = {name: set() for name in step_names}

    for edge in edges:
        source_name = edge["source"][0]
        target_name = edge["target"][0]
        if source_name not in predecessors or target_name not in predecessors:
            continue
        if source_name == target_name:
            continue
        predecessors[target_name].add(source_name)
        successors[source_name].add(target_name)

    ready = [name for name in step_names if not predecessors[name]]
    ordered: list[str] = []
    while ready:
        name = ready.pop(0)
        ordered.append(name)
        for successor in step_names:
            if successor not in successors[name]:
                continue
            predecessors[successor].discard(name)
            if not predecessors[successor] and successor not in ready:
                ready.append(successor)

    cycle = len(ordered) != len(step_names)
    if cycle:
        ordered.extend(name for name in step_names if name not in ordered)
    return ordered, cycle


def _relative_rule_path(path: str, source_prefix: str | None) -> str:
    if not source_prefix:
        return path
    normalized_prefix = Path(source_prefix).as_posix().rstrip("/") + "/"
    if path.startswith(normalized_prefix):
        return path[len(normalized_prefix) :]
    return path


def _prefixed_rule_path(path: str, destination_prefix: str | None) -> str:
    if not destination_prefix:
        return path
    return Path(destination_prefix).joinpath(path).as_posix()


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Command line entry point for building a receipt from request JSON."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Build local and partner-facing disclosure receipts."
    )
    parser.add_argument("request", type=Path, help="JSON disclosure request")
    parser.add_argument("--internal-out", type=Path, required=True)
    parser.add_argument("--public-out", type=Path, required=True)
    args = parser.parse_args(argv)

    request = json.loads(args.request.read_text(encoding="utf-8"))
    bundle = build_disclosure_receipt(
        approval=request["approval"],
        steps=request["steps"],
        rule_bases=request.get("rule_bases", []),
    )
    bundle.write(internal_path=args.internal_out, public_path=args.public_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
