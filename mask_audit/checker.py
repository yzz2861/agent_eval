"""Core offline consistency check between original and masked SQL."""

from __future__ import annotations

from dataclasses import dataclass, field

import sqlparse
from sqlparse import tokens as T
from sqlparse.sql import Identifier
from sqlparse.utils import remove_quotes

from mask_audit.models import (
    SEVERITY_ERROR,
    SEVERITY_INFO,
    SEVERITY_MANUAL,
    SEVERITY_VIOLATION,
    AuditFinding,
    AuditReport,
    NameResolution,
    SourceLocation,
)
from mask_audit.tokens import LeafToken, significant_tokens

SUPPORTED_STATEMENTS = frozenset({'CREATE', 'ALTER'})
MASK_CATEGORY_DATABASE = 'database'
MASK_CATEGORY_OTHER = 'other'


@dataclass
class MaskRange:
    """A permitted mask span inside the original document.

    Character offsets are 0-based and half-open, mirroring Python slicing.
    ``category`` explains what the span is allowed to hide; database spans
    are tracked separately because a changed target zone must never be
    swallowed by a generic mask permit.
    """

    start: int
    end: int
    category: str = MASK_CATEGORY_OTHER
    placeholder: str | None = None
    zone: str | None = None

    def covers(self, token: LeafToken) -> bool:
        return self.start <= token.start and token.end <= self.end


@dataclass
class SessionSchema:
    """Small caller-supplied schema for the review session.

    ``database_zones`` maps a concrete database/schema name to the controlled
    zone it belongs to. ``placeholder_zones`` pins a mask placeholder to the
    zone it is declared to stand for, so a placeholder cannot silently move a
    statement into a different zone.
    """

    database_zones: dict[str, str] = field(default_factory=dict)
    placeholder_zones: dict[str, str] = field(default_factory=dict)

    def zone_of_database(self, database: str | None) -> str | None:
        if database is None:
            return None
        return self.database_zones.get(database)


def _location(sql: str, token: LeafToken) -> SourceLocation:
    line = sql.count(chr(10), 0, token.start) + 1
    line_start = sql.rfind(chr(10), 0, token.start) + 1
    return SourceLocation(
        start=token.start,
        end=token.end,
        line=line,
        column=token.start - line_start + 1,
    )


def _overlaps_permit(token, permits):
    """True when a permit covers any interior character of *token*.

    Comment leaves include their --  prefix and trailing newline, while
    callers typically permit only the sensitive text inside the comment.
    """
    return any(
        permit.start < token.end and token.start < permit.end
        for permit in permits
    )


def _first_overlapping_permit(token, permits):
    for permit in permits:
        if permit.start < token.end and token.start < permit.end:
            return permit
    return None


def _permit_for(token, permits):
    for permit in permits:
        if permit.covers(token):
            return permit
    return None


def _values_equal(left: LeafToken, right: LeafToken) -> bool:
    if left.is_keyword and right.is_keyword:
        return left.value.upper() == right.value.upper()
    return left.value == right.value


def _compare_token_pair(
    index,
    original_token,
    review_token,
    original_sql,
    review_sql,
    permits,
    report,
):
    original_location = _location(original_sql, original_token)
    review_location = _location(review_sql, review_token)
    permit = _permit_for(original_token, permits)
    if permit is None and original_token.is_comment:
        permit = _first_overlapping_permit(original_token, permits)

    comment_overlap = (
        original_token.is_comment
        and _overlaps_permit(original_token, permits)
    )
    if review_token.is_placeholder or comment_overlap:
        if permit is None:
            report.add(AuditFinding(
                severity=SEVERITY_VIOLATION,
                code="mask_without_permit",
                message=(
                    "Review copy masks "
                    + repr(original_token.value)
                    + " but no permitted mask range covers it."
                ),
                statement_index=index,
                original_location=original_location,
                review_location=review_location,
                original_value=original_token.value,
                review_value=review_token.value,
            ))
            return

        if (
            not original_token.is_comment
            and permit.placeholder is not None
            and permit.placeholder != review_token.value
        ):
            report.add(AuditFinding(
                severity=SEVERITY_VIOLATION,
                code="mask_placeholder_mismatch",
                message=(
                    "Permit expects placeholder "
                    + str(permit.placeholder)
                    + " but review copy uses "
                    + review_token.value
                    + "."
                ),
                statement_index=index,
                original_location=original_location,
                review_location=review_location,
                original_value=original_token.value,
                review_value=review_token.value,
            ))
            return

        report.add(AuditFinding(
            severity=SEVERITY_INFO,
            code="masked_token",
            message=(
                repr(original_token.value)
                + " is masked by "
                + review_token.value
                + " within a permitted "
                + str(permit.category)
                + " range."
            ),
            statement_index=index,
            original_location=original_location,
            review_location=review_location,
            original_value=original_token.value,
            review_value=review_token.value,
        ))
        return

    if permit is not None:
        report.add(AuditFinding(
            severity=SEVERITY_INFO,
            code="permitted_range_kept_visible",
            message=(
                "Permitted mask range keeps "
                + repr(original_token.value)
                + " visible; no placeholder required."
            ),
            statement_index=index,
            original_location=original_location,
            review_location=review_location,
        ))

    if not _values_equal(original_token, review_token):
        report.add(AuditFinding(
            severity=SEVERITY_ERROR,
            code="token_mismatch",
            message=(
                "Concrete token changed outside a permitted mask: "
                + repr(original_token.value)
                + " -> "
                + repr(review_token.value)
                + "."
            ),
            statement_index=index,
            original_location=original_location,
            review_location=review_location,
            original_value=original_token.value,
            review_value=review_token.value,
        ))


def _target_identifier(statement):
    """Return the Identifier naming the object of CREATE/ALTER, if any."""
    saw_object_keyword = False
    for token in statement.tokens:
        if token.is_whitespace:
            continue
        if token.match(T.Keyword, ("TABLE", "SCHEMA", "DATABASE", "VIEW")):
            saw_object_keyword = True
            continue
        if token.ttype == T.Keyword and token.normalized == "IF NOT EXISTS":
            continue
        if saw_object_keyword and isinstance(token, Identifier):
            return token
        if saw_object_keyword and token.ttype in T.Name:
            return token
    return None


def _resolve_names(
    statement_index,
    statement,
    leaves,
    sql,
    schema,
    report,
    mask_ranges,
    permit_token=None,
):
    """Explain the target object and pin its controlled zone.

    A placeholder in the database position keeps the placeholder text as
    ``database`` and is flagged ``masked``; its zone is the zone declared
    on the mask permit covering the original database name, falling back to
    the session schema placeholder table.
    """
    target = _target_identifier(statement)
    database = None
    object_name = None
    location = None
    masked = False

    qualified = False
    if isinstance(target, Identifier):
        database = target.get_parent_name()
        object_name = target.get_real_name()
        qualified = database is not None
        if database is None:
            database = object_name
    elif target is not None:
        database = remove_quotes(target.value)
        object_name = database

    database_token = None
    if database is not None:
        for token in leaves:
            if token.is_placeholder:
                continue
            if remove_quotes(token.value) == database:
                database_token = token
                break

    placeholder_token = _database_placeholder(leaves)
    if placeholder_token is not None and database_token is None:
        database = placeholder_token.value
        database_token = placeholder_token
        masked = True

    if database_token is not None:
        location = _location(sql, database_token)

    if masked:
        permit = _permit_for(
            permit_token if permit_token is not None else database_token,
            mask_ranges,
        )
        zone = permit.zone if permit is not None else None
        if zone is None:
            zone = schema.placeholder_zones.get(database)
    else:
        zone = schema.zone_of_database(database)

    if qualified and database is not None and zone is None and not masked:
        report.add(AuditFinding(
            severity=SEVERITY_MANUAL,
            code="unknown_database_zone",
            message=(
                "Database "
                + repr(database)
                + " is not present in the session schema; "
                + "its controlled zone cannot be decided."
            ),
            statement_index=statement_index,
            original_location=location,
            original_value=database,
        ))

    resolution = NameResolution(
        statement_index=statement_index,
        statement_type=statement.get_type(),
        database=database,
        object_name=object_name,
        zone=zone,
        masked=masked,
        location=location,
    )
    report.resolutions.append(resolution)
    return resolution




def _database_placeholder(leaves):
    """Return a placeholder only when it sits in the database position."""
    for index, token in enumerate(leaves):
        if not token.is_placeholder:
            continue
        next_token = (
            leaves[index + 1] if index + 1 < len(leaves) else None
        )
        if next_token is not None and next_token.value == ".":
            return token
    return None


def _database_location(leaves, database):
    for token in leaves:
        if remove_quotes(token.value) == database:
            return token
    return None


def _check_zone_drift(
    statement_index,
    original_sql,
    review_sql,
    original_leaves,
    review_leaves,
    original_resolution,
    review_resolution,
    schema,
    report,
):
    """A changed target database/zone is an error, mask permit or not.

    When the review copy masks the database, the comparison uses the zone
    the placeholder is pinned to; masking the name does not hide a move.
    """
    original_zone = original_resolution.zone
    review_zone = review_resolution.zone
    if original_zone is None or review_zone is None:
        return
    if original_zone == review_zone:
        return

    original_token = _database_location(
        original_leaves, original_resolution.database,
    )
    review_token = _database_location(
        review_leaves, review_resolution.database,
    )
    report.add(AuditFinding(
        severity=SEVERITY_ERROR,
        code="target_zone_drift",
        message=(
            "Target zone changed from "
            + str(original_zone)
            + " to "
            + str(review_zone)
            + "; the review copy does not change the same controlled area."
        ),
        statement_index=statement_index,
        original_location=(
            _location(original_sql, original_token)
            if original_token is not None else None
        ),
        review_location=(
            _location(review_sql, review_token)
            if review_token is not None else None
        ),
        original_value=original_resolution.database,
        review_value=review_resolution.database,
        expected_zone=original_zone,
        actual_zone=review_zone,
    ))


def _slice_leaves(document_leaves, start, end):
    return [
        token
        for token in document_leaves
        if token.start >= start and token.end <= end
    ]


def _statement_span(statement, base_offset):
    text = statement.value
    return base_offset, base_offset + len(text)


def check_consistency(
    original_sql,
    review_sql,
    mask_ranges,
    schema=None,
):
    """Compare an original SQL document with its masked review copy.

    Returns an :class:`AuditReport` with per-token findings, name
    resolutions and source locations. ``mask_ranges`` lists the spans the
    caller is allowed to mask; ``schema`` is an optional SessionSchema with
    database-to-zone knowledge.
    """
    schema = schema or SessionSchema()
    report = AuditReport()
    original_statements = [
        item for item in sqlparse.parse(original_sql) if item.value.strip()
    ]
    review_statements = [
        item for item in sqlparse.parse(review_sql) if item.value.strip()
    ]
    original_docs = significant_tokens(original_sql)
    review_docs = significant_tokens(review_sql)

    if len(original_statements) != len(review_statements):
        report.add(AuditFinding(
            severity=SEVERITY_MANUAL,
            code="statement_count_mismatch",
            message=(
                "Original has "
                + str(len(original_statements))
                + " statements but review copy has "
                + str(len(review_statements))
                + "; pair them manually."
            ),
            statement_index=-1,
        ))

    pair_count = min(len(original_statements), len(review_statements))
    original_offset = 0
    review_offset = 0
    for pair_index in range(pair_count):
        original_stmt = original_statements[pair_index]
        review_stmt = review_statements[pair_index]
        original_span = _statement_span(original_stmt, original_offset)
        review_span = _statement_span(review_stmt, review_offset)
        original_offset = original_span[1]
        review_offset = review_span[1]
        original_leaves = _slice_leaves(original_docs, *original_span)
        review_leaves = _slice_leaves(review_docs, *review_span)

        _audit_statement(
            pair_index,
            original_stmt,
            review_stmt,
            original_sql,
            review_sql,
            original_leaves,
            review_leaves,
            mask_ranges,
            schema,
            report,
        )
    return report


def _audit_statement(
    index,
    original_stmt,
    review_stmt,
    original_sql,
    review_sql,
    original_leaves,
    review_leaves,
    mask_ranges,
    schema,
    report,
):
    statement_type = original_stmt.get_type()
    only_comments = all(
        token.is_comment or token.value == ";" for token in original_leaves
    )

    if statement_type not in SUPPORTED_STATEMENTS or only_comments:
        report.add(AuditFinding(
            severity=SEVERITY_MANUAL,
            code="unsupported_statement",
            message=(
                "Statement type "
                + repr(statement_type)
                + " is outside the supported CREATE/ALTER set; "
                + "route to a human reviewer."
            ),
            statement_index=index,
        ))
        return

    if len(original_leaves) != len(review_leaves):
        report.add(AuditFinding(
            severity=SEVERITY_ERROR,
            code="token_structure_mismatch",
            message=(
                "Significant token count differs ("
                + str(len(original_leaves))
                + " vs "
                + str(len(review_leaves))
                + "); a mask must replace a token one-for-one."
            ),
            statement_index=index,
        ))

    pair_total = min(len(original_leaves), len(review_leaves))
    for pair_index in range(pair_total):
        _compare_token_pair(
            index,
            original_leaves[pair_index],
            review_leaves[pair_index],
            original_sql,
            review_sql,
            mask_ranges,
            report,
        )

    original_resolution = _resolve_names(
        index,
        original_stmt,
        original_leaves,
        original_sql,
        schema,
        report,
        mask_ranges,
    )
    original_db_token = _database_location(
        original_leaves, original_resolution.database,
    )
    review_resolution = _resolve_names(
        index,
        review_stmt,
        review_leaves,
        review_sql,
        schema,
        report,
        mask_ranges,
        permit_token=original_db_token,
    )
    _check_zone_drift(
        index,
        original_sql,
        review_sql,
        original_leaves,
        review_leaves,
        original_resolution,
        review_resolution,
        schema,
        report,
    )
