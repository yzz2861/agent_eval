# mypy: allow-untyped-defs, allow-incomplete-defs, allow-untyped-calls
# mypy: no-warn-return-any, allow-any-generics

"""Optional integrity verification for applied revision scripts.

This module implements an opt-in mechanism that detects when revision
files that have already been applied to a database are changed
afterwards (for example when an old migration file is edited in place
without changing its revision id).

The mechanism records, for every revision that is successfully applied
to a database, a content digest of the revision script file as well as
a signature of the revision's position within the revision graph
(its ``down_revision`` and ``depends_on`` entries).  Before subsequent
upgrades are run, the recorded digests of all applied revisions are
checked against the current files.

Digest computation contract
---------------------------

The content digest of a revision is defined as::

    "sha256:" + hexdigest(SHA256(<raw bytes of the script file>))

The file is read in binary mode and hashed **byte for byte, exactly as
stored on disk**.  No newline translation is performed (so CRLF and LF
line endings produce different digests) and no text decoding or
encoding detection is applied (the bytes are hashed verbatim, never
decoded).  The digest therefore depends only on the file contents and
not on the platform, locale, or Python version of the machine that
computes it.

The graph signature of a revision is a canonical JSON document of the
form ``{"depends_on": [...], "down_revision": [...]}`` where both
lists are sorted revision identifiers, serialized with sorted keys and
compact separators.  This serialization is fully deterministic and
machine independent.

"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any
from typing import TYPE_CHECKING

from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import PrimaryKeyConstraint
from sqlalchemy import select
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import Text

from .. import util
from ..script.revision import RevisionError
from ..util import sqla_compat

if TYPE_CHECKING:
    from sqlalchemy.engine.base import Connection

    from ..script.base import Script
    from ..script.base import ScriptDirectory

log = logging.getLogger(__name__)

#: name of the digest algorithm used for revision content digests.
DIGEST_ALGORITHM = "sha256"

#: default name of the table that stores revision digests.
DEFAULT_DIGEST_TABLE = "alembic_revision_digests"

_CHUNK_SIZE = 65536


class RevisionIntegrityError(util.CommandError):
    """Raised when verification of applied revisions against their
    recorded digests fails.

    The individual problems are available as the
    :attr:`.RevisionIntegrityError.missing`,
    :attr:`.RevisionIntegrityError.changed` and
    :attr:`.RevisionIntegrityError.structure_changed` attributes.

    """

    def __init__(
        self,
        missing: list[str],
        changed: list[tuple[str, str, str]],
        structure_changed: list[tuple[str, str]],
    ) -> None:
        self.missing = missing
        self.changed = changed
        self.structure_changed = structure_changed
        super().__init__(self._render_message())

    def _render_message(self) -> str:
        total = (
            len(self.missing) + len(self.changed) + len(self.structure_changed)
        )
        lines = [
            "Revision integrity verification failed: "
            "%d problem(s) detected." % total,
            "",
        ]
        if self.missing:
            lines.append("Revision files missing (%d):" % len(self.missing))
            lines.extend("  %s" % rev for rev in self.missing)
            lines.append("")
        if self.changed:
            lines.append("Revision content changed (%d):" % len(self.changed))
            lines.extend(
                "  %s: recorded %s, current %s" % (rev, recorded, current)
                for rev, recorded, current in self.changed
            )
            lines.append("")
        if self.structure_changed:
            lines.append(
                "Revision graph structure changed (%d):"
                % len(self.structure_changed)
            )
            lines.extend(
                "  %s: %s" % (rev, detail)
                for rev, detail in self.structure_changed
            )
            lines.append("")
        lines.append(
            "The database was left unchanged.  If these changes are "
            "intentional, review them and re-establish the baseline "
            "with the 'alembic baseline' command."
        )
        return "\n".join(lines)


def revision_content_digest(path: str) -> str:
    """Return the content digest for the revision script at ``path``.

    The digest is computed over the exact bytes of the file, read in
    binary mode; no newline translation, decoding, or other
    normalization is applied, so the result is identical on any
    machine for the same file contents.

    """
    digest = hashlib.new(DIGEST_ALGORITHM)
    with open(path, "rb") as file_:
        for chunk in iter(lambda: file_.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return "%s:%s" % (DIGEST_ALGORITHM, digest.hexdigest())


def revision_graph_signature(script: Script) -> str:
    """Return a canonical, machine-independent signature of the
    revision's position within the revision graph.

    The signature covers the revision's ``down_revision`` identifier(s)
    as well as its resolved ``depends_on`` dependencies, serialized as
    canonical JSON (sorted keys, sorted lists, compact separators,
    ASCII output).

    """
    payload = {
        "depends_on": sorted(script._resolved_dependencies),
        "down_revision": sorted(script._versioned_down_revisions),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def revision_digest_table(table_name: str, schema: str | None) -> Table:
    """Return the :class:`_schema.Table` used to store revision digests."""
    return Table(
        table_name,
        MetaData(),
        Column("revision", String(250), nullable=False),
        Column("content_digest", String(128), nullable=False),
        Column("graph_signature", Text(), nullable=False),
        PrimaryKeyConstraint("revision", name="%s_pkc" % table_name),
        schema=schema,
    )


def create_digest_table(connection: Connection, table: Table) -> None:
    """Create the digest table if it does not exist yet."""
    with sqla_compat._ensure_scope_for_ddl(connection):
        table.create(connection, checkfirst=True)


def has_digest_table(connection: Connection, table: Table) -> bool:
    return sqla_compat._connectable_has_table(
        connection, table.name, table.schema
    )


def _resolve_dependency(
    scripts: dict[str, Script], dependency: str
) -> str | None:
    """Resolve a single ``depends_on`` entry to a revision id.

    Supports exact ids, branch labels, and unambiguous partial ids,
    mirroring the resolution the revision map would perform.

    """
    if dependency in scripts:
        return dependency
    labeled = [
        script.revision
        for script in scripts.values()
        if dependency in script.branch_labels
    ]
    if len(labeled) == 1:
        return labeled[0]
    matches = [rev_id for rev_id in scripts if rev_id.startswith(dependency)]
    if len(matches) == 1:
        return matches[0]
    return None


def _script_map(script_directory: ScriptDirectory) -> dict[str, Script]:
    """Return a mapping of revision id to :class:`.Script`.

    Normally this is the exact-id view of the revision map.  If the
    revision map cannot be built - which happens when a revision file
    was deleted while other revisions still reference it - a tolerant
    local map is constructed from the individual script files instead,
    so that verification can still report the missing files.

    """
    try:
        revision_map = script_directory.revision_map._revision_map
    except (KeyError, RevisionError):
        scripts = {}
        for script in script_directory._load_revisions():
            scripts[script.revision] = script
        for script in scripts.values():
            resolved = tuple(
                _resolve_dependency(scripts, dependency) or dependency
                for dependency in util.to_tuple(
                    script.dependencies, default=()
                )
            )
            script._resolved_dependencies = resolved
            script._normalized_resolved_dependencies = resolved
        return scripts
    else:
        return {
            rev_id: revision
            for rev_id, revision in revision_map.items()
            if revision is not None and revision.revision == rev_id
        }


def _exact_revision(scripts: dict[str, Script], rev_id: str) -> Script | None:
    """Return the :class:`.Script` for ``rev_id`` matched exactly.

    Returns ``None`` if the revision id is not present in the script
    directory.  Partial identifier resolution is explicitly avoided so
    that a recorded id is never matched against a different revision.

    """
    return scripts.get(rev_id)


def _ancestor_walk(
    scripts: dict[str, Script],
    head_ids: tuple[str, ...],
    stored_edges: dict[str, list[str]] | None = None,
) -> tuple[set[str], set[str]]:
    """Best-effort expansion of the ancestor graph of ``head_ids``.

    Traversal follows ``down_revision`` as well as ``depends_on``
    entries, across merges and branches.  Where a revision file is
    missing, the edges recorded in the digest table (``stored_edges``)
    are used to continue the traversal, so that the ancestors of a
    deleted revision are still accounted for.

    Returns a tuple ``(found, missing)`` of revision id sets: ``found``
    are revisions present in the current script directory, ``missing``
    are revisions for which no script exists.

    """
    found: set[str] = set()
    missing: set[str] = set()
    seen: set[str] = set()
    stack = list(head_ids)
    while stack:
        rev_id = stack.pop()
        if rev_id in seen:
            continue
        seen.add(rev_id)
        script = _exact_revision(scripts, rev_id)
        if script is not None:
            found.add(rev_id)
            stack.extend(script._all_down_revisions)
        else:
            missing.add(rev_id)
            if stored_edges and rev_id in stored_edges:
                stack.extend(stored_edges[rev_id])
    return found, missing


def _load_recorded(
    connection: Connection, table: Table
) -> dict[str, tuple[str, str]]:
    recorded: dict[str, tuple[str, str]] = {}
    for rev, content_digest, graph_signature in connection.execute(
        select(
            table.c.revision, table.c.content_digest, table.c.graph_signature
        )
    ):
        recorded[rev] = (content_digest, graph_signature)
    return recorded


def _baseline_missing_error(rev_ids: list[str]) -> util.CommandError:
    return util.CommandError(
        "Revision digest verification is enabled, but no digest "
        "baseline has been recorded for %d applied revision(s): %s. "
        "Record a baseline explicitly with the 'alembic baseline' "
        "command (this trusts the current revision files), or disable "
        "revision digest verification."
        % (len(rev_ids), ", ".join(sorted(rev_ids)))
    )


def verify_revision_digests(
    connection: Connection,
    script_directory: ScriptDirectory,
    table: Table,
    heads: tuple[str, ...],
) -> None:
    """Verify all applied revisions against their recorded digests.

    The verification scope is the full ancestor graph of the current
    database heads, expanded along ``down_revision`` and ``depends_on``
    edges, including merges.  Verification is purely static: no
    migration script is executed in order to determine whether a
    revision changed.

    Missing revision files, changed revision contents, and revision
    graph structure changes are collected and reported as separate
    categories by raising :class:`.RevisionIntegrityError`.

    Raises :class:`~alembic.util.CommandError` if no digest baseline
    has been recorded for the applied revisions.

    """
    if not heads:
        return

    if not has_digest_table(connection, table):
        raise _baseline_missing_error(list(heads))

    recorded = _load_recorded(connection, table)

    unrecorded_heads = [head for head in heads if head not in recorded]
    if unrecorded_heads:
        raise _baseline_missing_error(unrecorded_heads)

    stored_edges: dict[str, list[str]] = {}
    unparsable: list[str] = []
    for rev_id, (_, graph_signature) in recorded.items():
        try:
            payload = json.loads(graph_signature)
            edges = list(payload["down_revision"]) + list(
                payload["depends_on"]
            )
        except (ValueError, KeyError, TypeError):
            unparsable.append(rev_id)
        else:
            stored_edges[rev_id] = edges

    scripts = _script_map(script_directory)
    found, missing_ids = _ancestor_walk(
        scripts, heads, stored_edges=stored_edges
    )

    missing: list[str] = []
    changed: list[tuple[str, str, str]] = []
    structure_changed: list[tuple[str, str]] = []

    for rev_id in sorted(recorded):
        if rev_id in missing_ids:
            missing.append(rev_id)
        elif rev_id not in found:
            structure_changed.append(
                (rev_id, "no longer an ancestor of the database heads")
            )
        else:
            script = _exact_revision(scripts, rev_id)
            assert script is not None
            recorded_digest, recorded_signature = recorded[rev_id]
            try:
                current_digest = revision_content_digest(script.path)
            except OSError:
                missing.append(rev_id)
                continue
            if current_digest != recorded_digest:
                changed.append((rev_id, recorded_digest, current_digest))
            current_signature = revision_graph_signature(script)
            if current_signature != recorded_signature:
                structure_changed.append(
                    (
                        rev_id,
                        "down_revision/depends_on differ from the "
                        "recorded baseline",
                    )
                )

    for rev_id in sorted(unparsable):
        structure_changed.append(
            (rev_id, "recorded graph signature is not parsable")
        )

    for rev_id in sorted(found.difference(recorded)):
        structure_changed.append(
            (rev_id, "ancestor of the database heads with no recorded digest")
        )

    if missing or changed or structure_changed:
        raise RevisionIntegrityError(missing, changed, structure_changed)


def sync_revision_digests(
    connection: Connection,
    script_directory: ScriptDirectory,
    table: Table,
    heads: tuple[str, ...],
) -> int:
    """Synchronize the digest table with the given applied heads.

    Records content digests and graph signatures for every revision in
    the ancestor graph of ``heads`` and removes rows for revisions that
    are no longer applied.  Returns the number of applied revisions.

    """
    scripts = _script_map(script_directory)
    applied, _missing = _ancestor_walk(scripts, heads)

    existing = {row[0] for row in connection.execute(select(table.c.revision))}

    stale = existing.difference(applied)
    if stale:
        connection.execute(
            table.delete().where(table.c.revision.in_(sorted(stale)))
        )

    for rev_id in sorted(applied):
        script = _exact_revision(scripts, rev_id)
        if script is None:
            continue
        values: dict[str, Any] = {
            "content_digest": revision_content_digest(script.path),
            "graph_signature": revision_graph_signature(script),
        }
        if rev_id in existing:
            connection.execute(
                table.update()
                .where(table.c.revision == rev_id)
                .values(**values)
            )
        else:
            connection.execute(
                table.insert().values(revision=rev_id, **values)
            )
    return len(applied)
