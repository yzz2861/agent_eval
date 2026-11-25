from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable
from xml.etree import ElementTree

import Evtx.Evtx as evtx


EVENT_NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
POLICY_BOUNDARY_FORMAT = "%Y-%m-%dT%H:%M:%S%z"
PATH_PART = re.compile(r"(?P<name>[A-Za-z_][\w.-]*)(?:\[@(?P<attribute>[A-Za-z_][\w.-]*)='(?P<value>[^']*)'\])?")


@dataclass(frozen=True)
class FieldIdentity:
    path: str


@dataclass(frozen=True)
class TemplateScope:
    guid: str | None = None
    template_id: int | None = None

    def matches(self, observed: TemplateScope) -> bool:
        if self.guid is not None and self.guid.lower() != (observed.guid or "").lower():
            return False
        if self.template_id is not None and self.template_id != observed.template_id:
            return False
        return True


@dataclass(frozen=True)
class RetentionPolicy:
    name: str
    fields: tuple[FieldIdentity, ...]
    templates: tuple[TemplateScope, ...]
    effective_from: datetime | None = None
    effective_to: datetime | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RetentionPolicy":
        return cls(
            name=data["name"],
            fields=tuple(FieldIdentity(path=item) for item in data.get("fields", [])),
            templates=tuple(TemplateScope(**item) for item in data.get("templates", [])),
            effective_from=parse_policy_time(data.get("effective_from")),
            effective_to=parse_policy_time(data.get("effective_to")),
        )


@dataclass(frozen=True)
class ObservedRecord:
    source: str
    record_num: int | None
    offset: int | None
    timestamp: datetime | None
    xml: str
    template: TemplateScope

    def root(self) -> ElementTree.Element:
        return ElementTree.fromstring(self.xml)


@dataclass(frozen=True)
class Claim:
    statement_id: str
    source: str | None
    record_num: int | None
    policy: str | None = None
    event_time: datetime | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Claim":
        return cls(
            statement_id=data["statement_id"],
            source=data.get("source"),
            record_num=parse_optional_int(data.get("record_num")),
            policy=data.get("policy"),
            event_time=parse_event_time(data.get("event_time")),
        )


@dataclass
class AuditFinding:
    statement_id: str
    status: str
    record_num: int | None = None
    source: str | None = None
    offset: int | None = None
    policy: str | None = None
    missing_fields: list[str] = field(default_factory=list)
    possible_copy_offsets: list[dict[str, Any]] = field(default_factory=list)
    observed_template: dict[str, Any] | None = None
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "statement_id": self.statement_id,
            "status": self.status,
            "record_num": self.record_num,
            "source": self.source,
            "offset": self.offset,
            "policy": self.policy,
            "missing_fields": self.missing_fields,
            "possible_copy_offsets": self.possible_copy_offsets,
            "observed_template": self.observed_template,
            "reasons": self.reasons,
        }
        return {key: value for key, value in result.items() if value not in (None, [], {})}


def parse_optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def parse_policy_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.strptime(value, POLICY_BOUNDARY_FORMAT)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_event_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def child_by_name(element: ElementTree.Element, name: str) -> ElementTree.Element | None:
    for child in list(element):
        if local_name(child.tag) == name:
            return child
    return None


def find_path(root: ElementTree.Element, path: str) -> list[ElementTree.Element | tuple[ElementTree.Element, str]]:
    current: list[ElementTree.Element] = [root]
    for raw_part in path.split("/"):
        if not raw_part:
            continue
        match = PATH_PART.fullmatch(raw_part)
        if match is None:
            raise ValueError(f"invalid field path: {path}")
        name = match.group("name")
        attribute = match.group("attribute")
        value = match.group("value")
        next_nodes: list[ElementTree.Element] = []
        for node in current:
            for child in list(node):
                if local_name(child.tag) != name:
                    continue
                if attribute is None or child.attrib.get(attribute) == value:
                    next_nodes.append(child)
        current = next_nodes

    match = PATH_PART.fullmatch(path.rsplit("/", 1)[-1])
    attribute = match.group("attribute") if match else None
    if attribute:
        return [(node, attribute) for node in current if attribute in node.attrib]
    return [node for node in current if (node.text or "").strip() != ""]


def field_is_present(root: ElementTree.Element, identity: FieldIdentity) -> bool:
    return bool(find_path(root, identity.path))


def template_dict(template: TemplateScope) -> dict[str, Any]:
    return {"guid": template.guid, "template_id": template.template_id}


def policy_for_claim(claim: Claim, policies: Iterable[RetentionPolicy]) -> RetentionPolicy | None:
    if claim.policy:
        for policy in policies:
            if policy.name == claim.policy:
                return policy
        return None

    event_time = claim.event_time
    if event_time is None:
        return None
    for policy in policies:
        after_start = policy.effective_from is None or event_time >= policy.effective_from
        before_end = policy.effective_to is None or event_time < policy.effective_to
        if after_start and before_end:
            return policy
    return None


def reference_matches(claim: Claim, record: ObservedRecord) -> bool:
    if claim.source is not None and claim.source != record.source:
        return False
    if claim.record_num is not None and claim.record_num != record.record_num:
        return False
    return True


def could_be_collection_copy(claim: Claim, record: ObservedRecord) -> bool:
    if claim.source is not None and claim.source != record.source:
        return False
    if claim.record_num is None:
        return False
    return record.record_num != claim.record_num


def evaluate_record(record: ObservedRecord, policy: RetentionPolicy) -> tuple[str, list[str], bool]:
    root = record.root()
    missing = [identity.path for identity in policy.fields if not field_is_present(root, identity)]
    if missing:
        return "missing_fields", missing, False

    if policy.templates and not any(scope.matches(record.template) for scope in policy.templates):
        return "template_mismatch", [], False

    return "reviewable", [], True


def audit_claims(
    claims: Iterable[Claim | dict[str, Any]],
    records: Iterable[ObservedRecord],
    policies: Iterable[RetentionPolicy | dict[str, Any]],
) -> list[AuditFinding]:
    normalized_claims = [claim if isinstance(claim, Claim) else Claim.from_dict(claim) for claim in claims]
    normalized_policies = [
        policy if isinstance(policy, RetentionPolicy) else RetentionPolicy.from_dict(policy) for policy in policies
    ]
    record_list = list(records)
    findings: list[AuditFinding] = []

    for claim in normalized_claims:
        policy = policy_for_claim(claim, normalized_policies)
        if policy is None:
            findings.append(AuditFinding(claim.statement_id, "unknown_policy", reasons=["no retention policy matched the claim"]))
            continue

        exact_matches = [record for record in record_list if reference_matches(claim, record)]
        if not exact_matches:
            copy_candidates = [record for record in record_list if could_be_collection_copy(claim, record)]
            if copy_candidates:
                findings.append(
                    AuditFinding(
                        claim.statement_id,
                        "possible_collection_copy",
                        policy=policy.name,
                        possible_copy_offsets=[record_location(record) for record in copy_candidates],
                        reasons=["referenced record was not found, but another collected copy has a compatible reference"],
                    )
                )
            else:
                findings.append(AuditFinding(claim.statement_id, "record_not_found", policy=policy.name))
            continue

        evaluated = [(record, *evaluate_record(record, policy)) for record in exact_matches]
        reviewable = [item for item in evaluated if item[3]]
        if reviewable:
            record = reviewable[0][0]
            findings.append(
                AuditFinding(
                    claim.statement_id,
                    "reviewable",
                    record_num=record.record_num,
                    source=record.source,
                    offset=record.offset,
                    policy=policy.name,
                )
            )
            continue

        record, status, missing, _ = evaluated[0]
        reasons = {
            "missing_fields": ["one or more retained field identities are absent"],
            "template_mismatch": ["field exists, but the record template is outside the confirmed scope"],
        }.get(status, [status])
        findings.append(
            AuditFinding(
                claim.statement_id,
                status,
                record_num=record.record_num,
                source=record.source,
                offset=record.offset,
                policy=policy.name,
                missing_fields=missing,
                observed_template=template_dict(record.template),
                reasons=reasons,
            )
        )

    return findings


def record_location(record: ObservedRecord) -> dict[str, Any]:
    return {
        "source": record.source,
        "record_num": record.record_num,
        "offset": record.offset,
    }


def records_from_evtx(path: str, source: str | None = None) -> list[ObservedRecord]:
    observed: list[ObservedRecord] = []
    with evtx.Evtx(path) as log:
        for record in log.records():
            root_node = record.root()
            template_node = root_node.template()
            observed.append(
                ObservedRecord(
                    source=source or path,
                    record_num=record.record_num(),
                    offset=record.offset(),
                    timestamp=record.timestamp(),
                    xml=record.xml(),
                    template=TemplateScope(guid=template_node.guid(), template_id=template_node.template_id()),
                )
            )
    return observed


def load_input(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as stream:
        return json.load(stream)


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit which old EVTX claims remain publicly reviewable under retained fields.")
    parser.add_argument("input", help="JSON file containing claims, policies, and EVTX sources")
    parser.add_argument("-o", "--output", help="Write JSON findings to this path instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(argv)
    payload = load_input(args.input)

    records: list[ObservedRecord] = []
    for source in payload.get("sources", []):
        records.extend(records_from_evtx(source["path"], source.get("name")))

    findings = audit_claims(payload.get("claims", []), records, payload.get("policies", []))
    output = json.dumps([finding.to_dict() for finding in findings], indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as stream:
            stream.write(output + "\n")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
