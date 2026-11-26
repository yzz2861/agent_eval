"""Offline publication review built on top of Bleach sanitization."""

from dataclasses import dataclass

from bleach.sanitizer import (
    ALLOWED_ATTRIBUTES,
    ALLOWED_PROTOCOLS,
    ALLOWED_TAGS,
    Cleaner,
)


MISSING_REFERENCE = "missing_reference"
SANITIZED = "sanitized"
UNRESOLVED_REFERENCE = "unresolved_reference"
WITHDRAWN_APPROVAL = "withdrawn_approval"


def _as_frozenset(value, name):
    if isinstance(value, str):
        values = [value]
    else:
        try:
            values = tuple(value)
        except TypeError as error:
            raise TypeError(f"{name} must be a string or an iterable") from error

    if not values:
        raise ValueError(f"{name} must not be empty")
    if any(not isinstance(item, str) or not item for item in values):
        raise ValueError(f"{name} must contain only non-empty strings")
    return frozenset(values)


@dataclass(frozen=True)
class ContentFragment:
    """A source-owned HTML fragment and the references it depends on."""

    fragment_id: str
    source: str
    reader_domain: str
    html: str
    references: tuple[str, ...] = ()

    def __post_init__(self):
        if not isinstance(self.fragment_id, str) or not self.fragment_id:
            raise ValueError("fragment_id must be a non-empty string")
        if not isinstance(self.source, str) or not self.source:
            raise ValueError("source must be a non-empty string")
        if not isinstance(self.reader_domain, str) or not self.reader_domain:
            raise ValueError("reader_domain must be a non-empty string")
        if not isinstance(self.html, str):
            raise TypeError("html must be a string")
        if not isinstance(self.references, tuple):
            object.__setattr__(self, "references", tuple(self.references))
        if any(
            not isinstance(reference, str) or not reference
            for reference in self.references
        ):
            raise ValueError("references must contain only non-empty strings")


@dataclass(frozen=True)
class ApprovalScope:
    """Sources and reader domains covered by one reviewer approval."""

    approval_id: str
    reviewer: str
    sources: frozenset[str]
    reader_domains: frozenset[str]

    def contains(self, fragment):
        return (
            fragment.source in self.sources
            and fragment.reader_domain in self.reader_domains
        )


@dataclass(frozen=True)
class ApprovalChange:
    """An immutable record of an approval being granted or revoked."""

    sequence: int
    action: str
    approval_id: str
    reviewer: str
    sources: frozenset[str]
    reader_domains: frozenset[str]
    active: bool


@dataclass(frozen=True)
class PublishedFragment:
    """Minimal fragment data retained for an offline publication."""

    fragment_id: str
    source: str
    reader_domain: str
    sanitized_html: str
    references: tuple[str, ...]
    approval_ids: tuple[str, ...]
    reviewers: tuple[str, ...]
    changes: tuple[str, ...] = ()


@dataclass(frozen=True)
class WithdrawnFragment:
    """Fragment withheld from publication together with audit evidence."""

    fragment_id: str
    source: str
    reader_domain: str
    sanitized_html: str
    references: tuple[str, ...]
    reason: str
    missing_reviewers: tuple[str, ...] = ()
    unresolved_references: tuple[str, ...] = ()
    approval_ids: tuple[str, ...] = ()
    reviewers: tuple[str, ...] = ()
    changes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PublicationReviewResult:
    """Publication decision and approval history available at review time."""

    publishable: tuple[PublishedFragment, ...]
    withdrawn: tuple[WithdrawnFragment, ...]
    approval_history: tuple[ApprovalChange, ...]

    @property
    def published_map(self):
        return {fragment.fragment_id: fragment for fragment in self.publishable}

    @property
    def withdrawn_map(self):
        return {fragment.fragment_id: fragment for fragment in self.withdrawn}


class OfflinePublicationReview:
    """Review fragments against reviewer scopes and sanitized HTML."""

    def __init__(
        self,
        required_reviewers=("legal", "external_editor"),
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=False,
    ):
        self.required_reviewers = tuple(required_reviewers)
        if not self.required_reviewers:
            raise ValueError("required_reviewers must not be empty")
        if any(
            not isinstance(reviewer, str) or not reviewer
            for reviewer in self.required_reviewers
        ):
            raise ValueError("required_reviewers must contain non-empty strings")
        self.cleaner = Cleaner(
            tags=tags,
            attributes=attributes,
            protocols=protocols,
            strip=strip,
        )
        self._approvals = {}
        self._history = []
        self._next_sequence = 1

    def grant_approval(self, reviewer, sources, reader_domains, approval_id=None):
        """Grant an active, revocable approval and record its scope."""
        if not isinstance(reviewer, str) or not reviewer:
            raise ValueError("reviewer must be a non-empty string")
        if approval_id is None:
            approval_id = f"approval-{self._next_sequence}"
        if not isinstance(approval_id, str) or not approval_id:
            raise ValueError("approval_id must be a non-empty string")
        if approval_id in self._approvals:
            raise ValueError(f"approval {approval_id!r} already exists")

        scope = ApprovalScope(
            approval_id=approval_id,
            reviewer=reviewer,
            sources=_as_frozenset(sources, "sources"),
            reader_domains=_as_frozenset(reader_domains, "reader_domains"),
        )
        self._approvals[approval_id] = scope
        self._record_change("grant", scope, True)
        return scope

    def revoke_approval(self, approval_id, reviewer=None):
        """Revoke an active approval while retaining its history."""
        try:
            scope = self._approvals[approval_id]
        except KeyError as error:
            raise ValueError(f"approval {approval_id!r} is not active") from error
        if reviewer is not None and reviewer != scope.reviewer:
            raise PermissionError(
                f"approval {approval_id!r} belongs to {scope.reviewer!r}"
            )
        del self._approvals[approval_id]
        self._record_change("revoke", scope, False)

    def review(self, fragments):
        """Return publishable fragments and every fragment withdrawn."""
        fragments = tuple(fragments)
        if any(not isinstance(fragment, ContentFragment) for fragment in fragments):
            raise TypeError("fragments must contain ContentFragment instances")

        fragment_ids = [fragment.fragment_id for fragment in fragments]
        if len(set(fragment_ids)) != len(fragment_ids):
            raise ValueError("fragment ids must be unique")

        fragment_by_id = {fragment.fragment_id: fragment for fragment in fragments}
        sanitized = {
            fragment.fragment_id: self.cleaner.clean(fragment.html)
            for fragment in fragments
        }
        initial = {
            fragment.fragment_id: self._evaluate_fragment(fragment)
            for fragment in fragments
        }
        publishable_ids = {
            fragment_id
            for fragment_id, decision in initial.items()
            if decision["reason"] is None
        }
        withdrawn_ids = set()
        withdrawal_reasons = {}

        changed = True
        while changed:
            changed = False
            for fragment in fragments:
                fragment_id = fragment.fragment_id
                unresolved = tuple(
                    reference
                    for reference in fragment.references
                    if reference not in publishable_ids
                )
                if unresolved:
                    unique_unresolved = tuple(dict.fromkeys(unresolved))
                    publishable_ids.discard(fragment_id)
                    was_withdrawn = fragment_id in withdrawn_ids
                    withdrawn_ids.add(fragment_id)
                    reason = (
                        MISSING_REFERENCE
                        if any(
                            reference not in fragment_by_id
                            for reference in unresolved
                        )
                        else UNRESOLVED_REFERENCE
                    )
                    current = withdrawal_reasons.get(fragment_id)
                    if not was_withdrawn or current != (
                        reason,
                        unique_unresolved,
                    ):
                        withdrawal_reasons[fragment_id] = (
                            reason,
                            unique_unresolved,
                        )
                        changed = True

        published = []
        withdrawn = []
        for fragment in fragments:
            fragment_id = fragment.fragment_id
            decision = initial[fragment_id]
            if fragment_id in publishable_ids:
                published.append(
                    PublishedFragment(
                        fragment_id=fragment_id,
                        source=fragment.source,
                        reader_domain=fragment.reader_domain,
                        sanitized_html=sanitized[fragment_id],
                        references=fragment.references,
                        approval_ids=tuple(
                            scope.approval_id
                            for scope in decision["matched_approvals"]
                        ),
                        reviewers=tuple(
                            scope.reviewer
                            for scope in decision["matched_approvals"]
                        ),
                        changes=decision["changes"],
                    )
                )
                continue

            if fragment_id not in withdrawal_reasons:
                withdrawal_reasons[fragment_id] = (WITHDRAWN_APPROVAL, ())
            reason, unresolved = withdrawal_reasons[fragment_id]
            withdrawn.append(
                WithdrawnFragment(
                    fragment_id=fragment_id,
                    source=fragment.source,
                    reader_domain=fragment.reader_domain,
                    sanitized_html=sanitized[fragment_id],
                    references=fragment.references,
                    reason=reason,
                    missing_reviewers=decision["missing_reviewers"],
                    unresolved_references=unresolved,
                    approval_ids=tuple(
                        scope.approval_id
                        for scope in decision["matched_approvals"]
                    ),
                    reviewers=tuple(
                        scope.reviewer
                        for scope in decision["matched_approvals"]
                    ),
                    changes=decision["changes"],
                )
            )

        return PublicationReviewResult(
            publishable=tuple(published),
            withdrawn=tuple(withdrawn),
            approval_history=tuple(self._history),
        )

    def _evaluate_fragment(self, fragment):
        matched = [
            scope
            for scope in self._approvals.values()
            if scope.contains(fragment)
        ]
        matched_reviewers = {scope.reviewer for scope in matched}
        missing_reviewers = tuple(
            reviewer
            for reviewer in self.required_reviewers
            if reviewer not in matched_reviewers
        )
        changes = []
        sanitized_html = self.cleaner.clean(fragment.html)
        if sanitized_html != fragment.html:
            changes.append(SANITIZED)
        return {
            "reason": WITHDRAWN_APPROVAL if missing_reviewers else None,
            "matched_approvals": tuple(matched),
            "missing_reviewers": missing_reviewers,
            "changes": tuple(changes),
        }

    def _record_change(self, action, scope, active):
        self._history.append(
            ApprovalChange(
                sequence=self._next_sequence,
                action=action,
                approval_id=scope.approval_id,
                reviewer=scope.reviewer,
                sources=scope.sources,
                reader_domains=scope.reader_domains,
                active=active,
            )
        )
        self._next_sequence += 1
