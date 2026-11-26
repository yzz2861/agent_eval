# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Read-only helpers for planning in-toto link repairs."""

import fnmatch
import os
from dataclasses import asdict, dataclass, field, replace

import in_toto.models.link
from in_toto.models.layout import SUBLAYOUT_LINK_DIR_FORMAT
from in_toto.models.metadata import Metadata
from in_toto.rulelib import unpack_rule


ACTION_RECORD = "record"
ACTION_RESIGN = "resign"
ACTION_REUSE = "reuse"


@dataclass(frozen=True)
class EvidenceRequest:
    """One independently signed piece of evidence needed by a repair."""

    step_name: str
    keyid: str
    action: str
    location: str
    rationale: str
    threshold: int = 1
    artifacts: frozenset = frozenset()
    rule: tuple = ()
    children: tuple = ()


@dataclass(frozen=True)
class RepairOption:
    """A material chain that can be restored and its evidence cost."""

    candidate_keyid: str
    evidence: tuple
    reusable_evidence: tuple
    rules: tuple

    @property
    def cost(self):
        return len(self.evidence)

    def to_dict(self):
        return _jsonable(asdict(self))


def _jsonable(value):
    if isinstance(value, frozenset):
        return sorted(_jsonable(item) for item in value)
    if isinstance(value, set):
        return sorted(_jsonable(item) for item in value)
    if isinstance(value, dict):
        return {
            key: _jsonable(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


@dataclass
class _ScopeReview:
    layout_path: str
    candidates: dict = field(default_factory=dict)
    reusable: dict = field(default_factory=dict)
    rules: list = field(default_factory=list)
    rule_explained: set = field(default_factory=set)


def review_repairs(layout, steps_metadata, link_dir_path="."):
    """Return minimum-cost repair options for an in-toto layout.

    The function only reads the supplied metadata and link files. It does not
    verify signatures, run inspections, or modify metadata.
    """
    review = _review_scope(
        layout,
        steps_metadata,
        link_dir_path,
        "",
        (),
    )

    options = []
    for (_, keyid), evidence in sorted(review.candidates.items()):
        unique_evidence = _dedupe_evidence(evidence)
        reusable = tuple(
            sorted(
                (
                    item
                    for item in review.reusable.values()
                    if not _evidence_overlaps(item, unique_evidence)
                ),
                key=_evidence_identity,
            )
        )
        options.append(
            RepairOption(
                candidate_keyid=keyid,
                evidence=tuple(unique_evidence),
                reusable_evidence=reusable,
                rules=tuple(dict.fromkeys(review.rules)),
            )
        )

    minimum_cost = min((option.cost for option in options), default=0)
    return [option for option in options if option.cost == minimum_cost]


def _payloads_for_step(steps_metadata, step_name):
    metadata_dict = steps_metadata.get(step_name, {})
    return {
        keyid: metadata.get_payload()
        for keyid, metadata in metadata_dict.items()
    }


def _review_scope(layout, steps_metadata, link_dir_path, scope_path, ancestry):
    review = _ScopeReview(layout_path=scope_path or ".")

    for step in layout.steps:
        metadata_dict = steps_metadata.get(step.name, {})
        valid_keyids = [
            keyid for keyid in step.pubkeys if keyid in metadata_dict
        ]
        missing_keyids = [
            keyid for keyid in step.pubkeys if keyid not in metadata_dict
        ]
        candidate_keyids = valid_keyids or (
            [step.pubkeys[0]] if step.pubkeys else []
        )
        payloads = _payloads_for_step(steps_metadata, step.name)
        candidate_rule_requests = {}
        sub_metadata_by_candidate = {}
        review.rule_explained.clear()

        for candidate_keyid in candidate_keyids:
            candidate_payload = payloads.get(candidate_keyid)
            if _is_sublayout(candidate_payload):
                sub_path = _sublayout_path(
                    step, candidate_keyid, scope_path
                )
                sub_link_dir = os.path.join(link_dir_path, sub_path)
                try:
                    sub_metadata = _load_links_for_scope(
                        candidate_payload, sub_link_dir
                    )
                    source_artifacts = (
                        _summary_artifacts_from_metadata(
                            candidate_payload, sub_metadata
                        )
                    )
                except FileNotFoundError:
                    sub_metadata = None
                    source_artifacts = {
                        "materials": {},
                        "products": {},
                    }
            else:
                sub_metadata = None
                source_artifacts = _summary_artifacts(candidate_payload)
            summary_artifacts = source_artifacts
            sub_metadata_by_candidate[candidate_keyid] = sub_metadata

            rule_requests = []
            for artifact_type in ("materials", "products"):
                rule_requests.extend(
                    _rule_requests(
                        step,
                        artifact_type,
                        candidate_keyid,
                        source_artifacts[artifact_type],
                        summary_artifacts,
                        steps_metadata,
                        link_dir_path,
                        scope_path,
                        ancestry,
                        review,
                    )
                )
            candidate_rule_requests[candidate_keyid] = rule_requests

        for candidate_keyid in candidate_keyids:
            candidate_identity = (review.layout_path, candidate_keyid)
            evidence = review.candidates.setdefault(candidate_identity, [])
            candidate_payload = payloads.get(candidate_keyid)
            explained_identity = (
                review.layout_path,
                candidate_keyid,
            )

            for keyid in valid_keyids:
                if keyid == candidate_keyid:
                    _mark_reusable(
                        review,
                        step,
                        step.name,
                        keyid,
                        _evidence_location(
                            link_dir_path,
                            scope_path,
                            step.name,
                            keyid,
                        ),
                    )
                    continue

                if _is_sublayout(candidate_payload) or _is_sublayout(
                    payloads[keyid]
                ):
                    rationale = ""
                    differences = frozenset()
                elif not _artifacts_equal(
                    payloads[candidate_keyid], payloads[keyid]
                ):
                    if (
                        explained_identity,
                        step.name,
                        keyid,
                    ) in review.rule_explained:
                        rationale = ""
                        differences = frozenset()
                    else:
                        rationale = (
                            "threshold artifacts differ from candidate chain"
                        )
                        differences = _artifact_differences(
                            payloads[candidate_keyid],
                            payloads[keyid],
                        )
                else:
                    rationale = ""
                    differences = frozenset()

                if rationale:
                    evidence.append(
                        _request(
                            step,
                            keyid,
                            ACTION_RESIGN,
                            link_dir_path,
                            scope_path,
                            rationale,
                            step.threshold,
                            differences,
                        )
                    )
                else:
                    _mark_reusable(
                        review,
                        step,
                        step.name,
                        keyid,
                        _evidence_location(
                            link_dir_path,
                            scope_path,
                            step.name,
                            keyid,
                        ),
                    )

            for keyid in missing_keyids:
                evidence.append(
                    _request(
                        step,
                        keyid,
                        ACTION_RECORD,
                        link_dir_path,
                        scope_path,
                        f"threshold {step.threshold} requires"
                        " independent evidence",
                        step.threshold,
                    )
                )

            evidence.extend(candidate_rule_requests[candidate_keyid])

            if _is_sublayout(candidate_payload):
                evidence.extend(
                    _sublayout_requests(
                        step,
                        candidate_keyid,
                        candidate_payload,
                        sub_metadata_by_candidate[candidate_keyid],
                        link_dir_path,
                        scope_path,
                        ancestry,
                        review,
                    )
                )

    return review


def _rule_requests(
    step,
    artifact_type,
    candidate_keyid,
    source_artifacts,
    summary_artifacts,
    steps_metadata,
    link_dir_path,
    scope_path,
    ancestry,
    review,
):
    rules = getattr(step, f"expected_{artifact_type}")
    requests = []
    queue = set(source_artifacts)
    materials = set(summary_artifacts["materials"])
    products = set(summary_artifacts["products"])
    for rule in rules:
        rule_data = unpack_rule(rule)
        review.rules.append(
            (
                _scope_name(scope_path, step.name),
                artifact_type,
                step.threshold,
                tuple(rule),
            )
        )
        if rule_data["rule_type"] != "match":
            requests.extend(
                _generic_rule_request(
                    step,
                    candidate_keyid,
                    rule,
                    rule_data,
                    artifact_type,
                    queue,
                    materials,
                    products,
                    link_dir_path,
                    scope_path,
                    summary_artifacts,
                )
            )
            if requests:
                return requests
            continue

        dest_step = rule_data["dest_name"]
        dest_payloads = _payloads_for_step(steps_metadata, dest_step)
        dest_payload = dest_payloads.get(candidate_keyid)
        dest_keyid = candidate_keyid
        if dest_payload is None:
            dest_keyid, dest_payload = next(
                iter(dest_payloads.items()), ("", None)
            )
        if dest_payload is None:
            requests.append(
                _request(
                    step,
                    candidate_keyid,
                    ACTION_RECORD,
                    link_dir_path,
                    scope_path,
                    f"match destination '{dest_step}' has no evidence",
                    step.threshold,
                    _rule_artifacts(rule_data, source_artifacts),
                    tuple(rule),
                )
            )
            continue

        mismatches = _match_mismatches(
            rule_data,
            source_artifacts,
            getattr(dest_payload, rule_data["dest_type"]),
        )
        if mismatches:
            dest_metadata = steps_metadata.get(dest_step, {})
            requests.append(
                _request(
                    step,
                    dest_keyid,
                    ACTION_RESIGN,
                    link_dir_path,
                    scope_path,
                    "material/product reference has incompatible hash or path",
                    step.threshold,
                    mismatches,
                    tuple(rule),
                )
            )
        else:
            dest_metadata = steps_metadata.get(dest_step, {})
            review.rule_explained.add(
                (
                    (scope_path or ".", candidate_keyid),
                    dest_step,
                    dest_keyid,
                )
            )
            _mark_reusable(
                review,
                step,
                dest_step,
                dest_keyid,
                _evidence_location(
                    link_dir_path,
                    scope_path,
                    dest_step,
                    dest_keyid,
                ),
            )

    return requests


def _sublayout_requests(
    step,
    candidate_keyid,
    sublayout,
    sub_metadata,
    link_dir_path,
    scope_path,
    ancestry,
    review,
):
    sub_path = _sublayout_path(step, candidate_keyid, scope_path)
    try:
        if sub_metadata is None:
            raise FileNotFoundError(sub_path)
    except FileNotFoundError:
        return [
            _request(
                step,
                candidate_keyid,
                ACTION_RECORD,
                link_dir_path,
                scope_path,
                "sublayout evidence directory is unavailable",
                step.threshold,
                (),
                (),
            )
        ]

    identity = (*ancestry, (step.name, candidate_keyid, sub_path))
    sub_review = _review_scope(
        sublayout,
        sub_metadata,
        link_dir_path,
        sub_path,
        identity,
    )
    review.rules.extend(sub_review.rules)
    review.reusable.update(sub_review.reusable)

    minimum_cost = min(
        (len(evidence) for evidence in sub_review.candidates.values()),
        default=0,
    )
    minimum_options = [
        _dedupe_evidence(evidence)
        for evidence in sub_review.candidates.values()
        if len(evidence) == minimum_cost
    ]
    if not minimum_options:
        return []
    if len(minimum_options) == 1:
        return minimum_options[0]
    primary = minimum_options[0]
    primary[0] = replace(
        primary[0],
        children=tuple(minimum_options[1]),
    )
    return primary


def _load_links_for_scope(layout, link_dir_path):
    if not os.path.isdir(link_dir_path):
        raise FileNotFoundError(link_dir_path)

    metadata = {}
    for step in layout.steps:
        metadata[step.name] = {}
        for keyid in step.pubkeys:
            filename = in_toto.models.link.FILENAME_FORMAT.format(
                step_name=step.name,
                keyid=keyid,
            )
            path = os.path.join(link_dir_path, filename)
            if os.path.exists(path):
                metadata[step.name][keyid] = Metadata.load(path)
    return metadata


def _match_mismatches(rule_data, source_artifacts, dest_artifacts):
    mismatches = set()
    for path in _rule_artifacts(rule_data, source_artifacts):
        relative_path = _remove_prefix(path, rule_data["source_prefix"])
        dest_path = _add_prefix(relative_path, rule_data["dest_prefix"])
        if dest_path not in dest_artifacts:
            mismatches.add(path)
        elif source_artifacts[path] != dest_artifacts[dest_path]:
            mismatches.add(path)
    return frozenset(mismatches)


def _generic_rule_request(
    step,
    candidate_keyid,
    rule,
    rule_data,
    artifact_type,
    queue,
    materials,
    products,
    link_dir_path,
    scope_path,
    summary_artifacts,
):
    rule_type = rule_data["rule_type"]
    pattern = rule_data["pattern"]

    if rule_type == "create":
        consumed = set(fnmatch.filter(queue, pattern)) & (
            products - materials
        )
    elif rule_type == "delete":
        consumed = set(fnmatch.filter(queue, pattern)) & (
            materials - products
        )
    elif rule_type == "modify":
        opposite_artifacts = _opposite_artifacts(
            artifact_type, summary_artifacts
        )
        consumed = {
            path
            for path in fnmatch.filter(queue, pattern)
            if path in materials
            and path in products
            and source_artifacts.get(path) != opposite_artifacts.get(path)
        }
    elif rule_type == "allow":
        consumed = set(fnmatch.filter(queue, pattern))
    elif rule_type == "disallow":
        consumed = set()
        failed = frozenset(fnmatch.filter(queue, pattern))
    elif rule_type == "require":
        consumed = set()
        failed = frozenset() if pattern in queue else frozenset([pattern])
    else:
        consumed = set()
        failed = frozenset()

    if rule_type in {"create", "delete", "modify", "allow"}:
        failed = frozenset(
            set(fnmatch.filter(queue, pattern)) - consumed
        )
        queue -= consumed

    if not failed:
        return []

    return [
        _request(
            step,
            candidate_keyid,
            ACTION_RESIGN,
            link_dir_path,
            scope_path,
            f"{artifact_type} rule {' '.join(rule)} is not satisfied",
            step.threshold,
            frozenset(failed),
            tuple(rule),
        )
    ]


def _rule_artifacts(rule_data, artifacts):
    prefix = rule_data["source_prefix"]
    if prefix:
        normalized_prefix = _add_prefix(prefix, "")
        paths = [
            path[len(normalized_prefix):]
            for path in artifacts
            if path.startswith(normalized_prefix)
        ]
    else:
        paths = list(artifacts)
    return frozenset(
        _add_prefix(path, prefix)
        for path in fnmatch.filter(paths, rule_data["pattern"])
    )


def _opposite_artifacts(artifact_type, artifacts):
    opposite_type = (
        "products" if artifact_type == "materials" else "materials"
    )
    return artifacts[opposite_type]


def _artifact_differences(left, right):
    left_artifacts = _summary_artifacts(left)
    right_artifacts = _summary_artifacts(right)
    paths = set(left_artifacts["materials"]) | set(
        left_artifacts["products"]
    )
    paths |= set(right_artifacts["materials"]) | set(
        right_artifacts["products"]
    )
    return frozenset(
        path
        for path in paths
        if left_artifacts["materials"].get(path)
        != right_artifacts["materials"].get(path)
        or left_artifacts["products"].get(path)
        != right_artifacts["products"].get(path)
    )


def _artifacts_equal(left, right):
    return not _artifact_differences(left, right)


def _summary_artifacts(payload):
    return {
        "materials": getattr(payload, "materials", {}),
        "products": getattr(payload, "products", {}),
    }


def _is_sublayout(payload):
    return payload is not None and getattr(payload, "_type", None) == "layout"


def _sublayout_path(step, keyid, scope_path):
    sub_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
        name=step.name,
        keyid=keyid,
    )
    return os.path.join(scope_path, sub_dir) if scope_path else sub_dir


def _summary_artifacts_from_metadata(layout, steps_metadata):
    materials = {}
    products = {}
    if layout.steps:
        first_payload = next(
            iter(
                _payloads_for_step(
                    steps_metadata, layout.steps[0].name
                ).values()
            ),
            None,
        )
        last_payload = next(
            iter(
                _payloads_for_step(
                    steps_metadata, layout.steps[-1].name
                ).values()
            ),
            None,
        )
        if first_payload is not None:
            materials = first_payload.materials
        if last_payload is not None:
            products = last_payload.products
    return {"materials": materials, "products": products}


def _evidence_identity(item):
    return item.step_name, item.keyid, item.location


def _request(
    step,
    keyid,
    action,
    link_dir_path,
    scope_path,
    rationale,
    threshold,
    artifacts=frozenset(),
    rule=(),
    children=(),
):
    return EvidenceRequest(
        step_name=step.name,
        keyid=keyid,
        action=action,
        location=_evidence_location(
            link_dir_path,
            scope_path,
            step.name,
            keyid,
        ),
        rationale=rationale,
        threshold=threshold,
        artifacts=frozenset(artifacts),
        rule=tuple(rule),
        children=tuple(children),
    )


def _evidence_location(link_dir_path, scope_path, step_name, keyid):
    filename = in_toto.models.link.FILENAME_FORMAT.format(
        step_name=step_name,
        keyid=keyid,
    )
    path = os.path.join(scope_path, filename) if scope_path else filename
    return os.path.join(link_dir_path, path)


def _mark_reusable(review, step, step_name, keyid, location):
    review.reusable[(step_name, keyid, location)] = EvidenceRequest(
        step_name=step_name,
        keyid=keyid,
        action=ACTION_REUSE,
        location=location,
        rationale="existing signed evidence is compatible with this chain",
        threshold=step.threshold,
    )


def _keyid_for_payload(metadata_dict, step_name, payload):
    for keyid, metadata in metadata_dict.get(step_name, {}).items():
        if metadata.get_payload() is payload:
            return keyid
    return ""


def _dedupe_evidence(items):
    unique = {}
    for item in items:
        unique[_evidence_identity(item)] = item
    return sorted(unique.values(), key=_evidence_identity)


def _evidence_overlaps(evidence, requests):
    identities = {
        (item.step_name, item.keyid, item.location) for item in requests
    }
    return (evidence.step_name, evidence.keyid, evidence.location) in identities


def _remove_prefix(path, prefix):
    if not prefix:
        return path
    normalized = _add_prefix(prefix, "")
    return path[len(normalized):] if path.startswith(normalized) else path


def _add_prefix(path, prefix):
    if not prefix:
        return path
    return os.path.join(prefix, path).replace("\\", "/")


def _scope_name(scope_path, step_name):
    return f"{scope_path}/{step_name}" if scope_path else step_name
