from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal
from uuid import uuid4

import lxml.html

from .sanitizer import (
    bold_span_to_strong,
    italic_span_to_em,
    Sanitizer,
)


__all__ = (
    "ApprovalPolicy",
    "CentralPolicySanitizer",
    "EditorialSection",
    "PolicySanitizer",
    "RejectedFormat",
    "RetainedFormat",
    "ReviewedDocument",
    "SanitizedSection",
)


@dataclass(frozen=True)
class ApprovalPolicy:
    id: str
    source: str
    settings: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("Policy id must be a non-empty string")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("Policy source must be a non-empty string")


@dataclass(frozen=True)
class EditorialSection:
    id: str
    html: str
    policy_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("Section id must be a non-empty string")
        if not isinstance(self.html, str):
            raise TypeError("Section html must be a string")
        if not isinstance(self.policy_id, str) or not self.policy_id.strip():
            raise ValueError("Section policy id must be a non-empty string")


@dataclass(frozen=True)
class RetainedFormat:
    section_id: str
    tag: str
    attribute: str | None
    path: str
    policy_id: str
    policy_source: str


@dataclass(frozen=True)
class RejectedFormat:
    section_id: str
    tag: str
    attribute: str | None
    path: str
    reason: Literal["tag_not_allowed", "attribute_not_allowed"]
    policy_id: str
    policy_source: str


@dataclass(frozen=True)
class SanitizedSection:
    id: str
    html: str
    policy_id: str
    policy_source: str
    retained_formats: tuple[RetainedFormat, ...]
    rejected_formats: tuple[RejectedFormat, ...]


@dataclass(frozen=True)
class ReviewedDocument:
    html: str
    sections: tuple[SanitizedSection, ...]
    retained_formats: tuple[RetainedFormat, ...]
    rejected_formats: tuple[RejectedFormat, ...]

    def explanation(self) -> str:
        lines: list[str] = []
        for section in self.sections:
            lines.append(
                f"{section.id}: approved by {section.policy_id} "
                f"({section.policy_source})"
            )
            for retained in section.retained_formats:
                format_name = _format_name(retained.tag, retained.attribute)
                lines.append(f"  retained {format_name} at {retained.path}")
            for rejected in section.rejected_formats:
                format_name = _format_name(rejected.tag, rejected.attribute)
                lines.append(f"  rejected {format_name} at {rejected.path}")
        return "\n".join(lines)


class CentralPolicySanitizer:
    def __init__(self, policies: Iterable[ApprovalPolicy]):
        self._policies: dict[str, ApprovalPolicy] = {}
        self._sanitizers: dict[str, Sanitizer] = {}

        for policy in policies:
            if not isinstance(policy, ApprovalPolicy):
                raise TypeError("Policies must be ApprovalPolicy instances")
            if policy.id in self._policies:
                raise ValueError(f'Duplicate policy id "{policy.id}"')
            self._policies[policy.id] = policy
            self._sanitizers[policy.id] = Sanitizer(dict(policy.settings or {}))

    def sanitize_section(self, section: EditorialSection) -> SanitizedSection:
        if not isinstance(section, EditorialSection):
            raise TypeError("Sections must be EditorialSection instances")
        try:
            policy = self._policies[section.policy_id]
        except KeyError as exc:
            raise ValueError(f'Unknown policy id "{section.policy_id}"') from exc

        sanitizer = self._sanitizers[policy.id]
        sanitized_html = sanitizer.sanitize(section.html)
        retained_attributes = _probe_retained_attributes(section.html, sanitizer)

        return SanitizedSection(
            id=section.id,
            html=sanitized_html,
            policy_id=policy.id,
            policy_source=policy.source,
            retained_formats=tuple(
                _retained_formats(section.id, sanitized_html, policy)
            ),
            rejected_formats=tuple(
                _rejected_formats(
                    section.id,
                    section.html,
                    sanitizer,
                    policy,
                    retained_attributes,
                )
            ),
        )

    def sanitize_and_compose(
        self, sections: Iterable[EditorialSection]
    ) -> ReviewedDocument:
        section_list = list(sections)
        section_ids = [section.id for section in section_list]
        if len(section_ids) != len(set(section_ids)):
            raise ValueError("Section ids must be unique")

        sanitized_sections = tuple(
            self.sanitize_section(section) for section in section_list
        )
        return ReviewedDocument(
            html="".join(section.html for section in sanitized_sections),
            sections=sanitized_sections,
            retained_formats=tuple(
                item
                for section in sanitized_sections
                for item in section.retained_formats
            ),
            rejected_formats=tuple(
                item
                for section in sanitized_sections
                for item in section.rejected_formats
            ),
        )

    def compose(self, sections: Iterable[EditorialSection]) -> ReviewedDocument:
        return self.sanitize_and_compose(sections)


PolicySanitizer: type[CentralPolicySanitizer] = CentralPolicySanitizer


def _format_name(tag: str, attribute: str | None) -> str:
    return f"<{tag}>" if attribute is None else f"<{tag} {attribute}=...>"


def _parse_fragment(html: str):
    wrapped_html = f"<div>{html}</div>"
    try:
        doc = lxml.html.fromstring(wrapped_html)
        lxml.html.tostring(doc, encoding="utf-8")
        return doc
    except Exception:  # noqa: BLE001 -- mirror Sanitizer's parser fallback
        from lxml.html import soupparser  # noqa: PLC0415

        return soupparser.fromstring(wrapped_html)


def _element_path(element, root) -> str:
    parts: list[str] = []
    current = element
    while current is not None and current is not root:
        parent = current.getparent()
        position = list(parent).index(current) + 1
        parts.append(f"{current.tag}[{position}]")
        current = parent
    return "/div/" + "/".join(reversed(parts))


def _retained_formats(section_id: str, html: str, policy: ApprovalPolicy):
    root = _parse_fragment(html)
    for element in root.iterdescendants():
        path = _element_path(element, root)
        yield RetainedFormat(
            section_id=section_id,
            tag=element.tag,
            attribute=None,
            path=path,
            policy_id=policy.id,
            policy_source=policy.source,
        )
        for attribute in element.attrib:
            yield RetainedFormat(
                section_id=section_id,
                tag=element.tag,
                attribute=attribute,
                path=path,
                policy_id=policy.id,
                policy_source=policy.source,
            )


def _rejected_formats(
    section_id: str,
    html: str,
    sanitizer: Sanitizer,
    policy: ApprovalPolicy,
    retained_attributes: Mapping[int, set[str]],
):
    root = _parse_fragment(html)
    for index, element in enumerate(root.iterdescendants()):
        disallowed_ancestor = None
        current = element.getparent()
        while current is not None and current is not root:
            if _effective_tag(current, sanitizer) not in sanitizer.tags:
                disallowed_ancestor = current
                break
            current = current.getparent()
        if disallowed_ancestor is not None:
            if element is disallowed_ancestor:
                yield RejectedFormat(
                    section_id=section_id,
                    tag=element.tag,
                    attribute=None,
                    path=_element_path(element, root),
                    reason="tag_not_allowed",
                    policy_id=policy.id,
                    policy_source=policy.source,
                )
            continue

        effective_tag = _effective_tag(element, sanitizer)
        if effective_tag not in sanitizer.tags:
            yield RejectedFormat(
                section_id=section_id,
                tag=element.tag,
                attribute=None,
                path=_element_path(element, root),
                reason="tag_not_allowed",
                policy_id=policy.id,
                policy_source=policy.source,
            )
            continue

        allowed_attributes = sanitizer.attributes.get(effective_tag, set())
        path = _element_path(element, root)
        if index not in retained_attributes:
            return
        surviving_attributes = retained_attributes.get(index, set())
        for attribute in element.attrib:
            if (
                element.tag == "span"
                and attribute == "style"
                and effective_tag in {"strong", "em"}
            ):
                continue
            if (
                attribute not in allowed_attributes
                and attribute not in surviving_attributes
            ):
                yield RejectedFormat(
                    section_id=section_id,
                    tag=element.tag,
                    attribute=attribute,
                    path=path,
                    reason="attribute_not_allowed",
                    policy_id=policy.id,
                    policy_source=policy.source,
                )


def _probe_retained_attributes(
    html: str, sanitizer: Sanitizer
) -> dict[int, set[str]]:
    marker = f"data-html-sanitizer-policy-probe-{uuid4().hex}"
    source_root = _parse_fragment(html)
    elements = list(source_root.iterdescendants())
    for index, element in enumerate(elements):
        element.set(marker, str(index))

    probe_html = _serialize_children(source_root)
    probe_settings = vars(sanitizer).copy()
    probe_settings["attributes"] = {
        tag: set(attributes) | {marker}
        for tag, attributes in sanitizer.attributes.items()
    }
    for tag in sanitizer.tags:
        probe_settings["attributes"].setdefault(tag, {marker})

    probe_output = _parse_fragment(Sanitizer(probe_settings).sanitize(probe_html))
    return {
        int(element.get(marker)): set(element.attrib) - {marker}
        for element in probe_output.iterdescendants()
        if element.get(marker) is not None
    }


def _serialize_children(element) -> str:
    html = element.text or ""
    for child in element:
        html += lxml.html.tostring(child, encoding="unicode")
        if child.tail:
            html += child.tail
    return html


def _effective_tag(element, sanitizer: Sanitizer) -> str:
    if element.tag == "span":
        style = element.get("style", "")
        if bold_span_to_strong in sanitizer.element_preprocessors and "bold" in style:
            return "strong"
        if italic_span_to_em in sanitizer.element_preprocessors and "italic" in style:
            return "em"

    replacement = _configured_replacement(element.tag, sanitizer)
    return replacement or element.tag


def _configured_replacement(tag: str, sanitizer: Sanitizer) -> str | None:
    for processor in sanitizer.element_preprocessors:
        if getattr(processor, "__name__", "") != "replacer":
            continue
        closure = getattr(processor, "__closure__", ())
        if len(closure) >= 2 and closure[0].cell_contents == tag:
            replacement = closure[1].cell_contents
            return replacement if isinstance(replacement, str) else None
    return None
