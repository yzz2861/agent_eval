# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  revocationlib.py

<Purpose>
  Provides an optional, layout-authorized revocation workflow for final
  product verification.

  The workflow is fully offline and backwards compatible:

  * A ``Revocation`` invalidates one exact artifact version, identified by its
    path and content hashes, within an explicitly declared scope. A revocation
    never affects other versions that are recorded at the same path, so an
    un-revoked version of a same-path artifact keeps being accepted.
  * Revocation metadata must be signed with a key the layout lists in
    ``revocation_keys``, must not be expired, and must stay within its declared
    release binding and scope. These checks prevent a middleware from
    replaying stale revocation statements.
  * A revoked version may only be replaced offline by a ``ReplacementProof``
    that is signed with an authorized key, is bound to the same release order,
    and explicitly supersedes the matching revocation. Replaying a proof that
    was valid before the revocation cannot bring the revoked version back.
  * :func:`write_acceptance_records` emits three small, equally named files
    in separate directories, listing the revoked original, the accepted
    replacement and the still-missing approval side by side.
"""

import datetime
import json
import logging
import os

import iso8601
import securesystemslib.exceptions

from in_toto.exceptions import RevocationError
from in_toto.models.metadata import Metablock
from in_toto.models.revocation import ReplacementProof, Revocation

# Inherits from in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger(__name__)

ACCEPTANCE_REVOKED_DIR = "revoked"
ACCEPTANCE_REPLACED_DIR = "replaced"
ACCEPTANCE_PENDING_DIR = "pending"
ACCEPTANCE_FILENAME = "acceptance.json"


def _now():
    """Returns the current timezone-aware UTC time."""
    return datetime.datetime.now(datetime.timezone.utc)


def _check_expires(expires, what):
    """Raises if ``expires`` is malformed or already in the past."""
    try:
        expiration = iso8601.parse_date(expires)
    except iso8601.iso8601.ParseError as e:
        raise RevocationError(
            f"Malformed expiration date in {what}: {expires}"
        ) from e

    if expiration <= _now():
        raise RevocationError(f"Expired {what} (expired at {expires})")


def _verify_authorized_signature(metadata, layout, what):
    """Verifies that metadata carries a valid signature by a revocation key.

    The signing key must be listed in the layout's ``revocation_keys``.
    """
    authorized = layout.revocation_keys
    if not authorized:
        raise RevocationError(
            "The layout does not authorize any revocation or replacement"
            " key ('revocation_keys' is empty)."
        )

    for key in authorized.values():
        try:
            metadata.verify_signature(key)
            return
        except securesystemslib.exceptions.Error:
            continue

    raise RevocationError(
        f"{what} is not signed by a layout-authorized revocation key."
    )


def _check_release_binding(identifier, layout_release_id, what):
    """Checks that metadata's release order matches the layout's binding."""
    if not identifier:
        raise RevocationError(f"{what} is missing its release order binding.")

    if layout_release_id and identifier != layout_release_id:
        raise RevocationError(
            f"{what} is bound to release order '{identifier}', but the layout"
            f" is bound to release order '{layout_release_id}'."
        )


def _load_metadata(path, expected_type, what):
    """Loads metadata and asserts it carries the expected payload type."""
    metadata = Metablock.load(path)
    payload = metadata.get_payload()
    if not isinstance(payload, expected_type):
        raise RevocationError(f"File '{path}' does not contain {what}.")
    return metadata, payload


def load_revocations(revocation_dir_path, layout):
    """Loads and verifies revocation metadata from a directory.

    Every ``*.revoke`` file must be signed by a layout-authorized revocation
    key, must not be expired, and must match the layout's release order
    binding. Revocation ids must be unique to prevent ambiguous replacements.

    Arguments:
      revocation_dir_path: A directory containing ``*.revoke`` metadata.
      layout: The verified layout that authorizes the revocations.

    Raises:
      RevocationError: A revocation is malformed, expired, wrongly signed,
          bound to a different release, or has a duplicate id.

    Returns:
      A list of verified :class:`Revocation` objects.
    """
    revocations = []
    seen_ids = set()

    filenames = sorted(
        fn for fn in os.listdir(revocation_dir_path) if fn.endswith(".revoke")
    )

    for filename in filenames:
        path = os.path.join(revocation_dir_path, filename)
        metadata, revocation = _load_metadata(path, Revocation, "a revocation")

        _verify_authorized_signature(
            metadata, layout, f"Revocation '{filename}'"
        )
        _check_expires(revocation.expires, f"revocation '{filename}'")
        _check_release_binding(
            revocation.release_id,
            layout.release_id,
            f"Revocation '{filename}'",
        )

        if revocation.revocation_id in seen_ids:
            raise RevocationError(
                f"Duplicate revocation id '{revocation.revocation_id}' in"
                f" '{filename}'."
            )
        seen_ids.add(revocation.revocation_id)

        revocations.append(revocation)

    LOG.info("Loaded %d verified revocation statement(s).", len(revocations))
    return revocations


def load_replacement_proofs(revocation_dir_path, layout):
    """Loads and verifies offline replacement proofs from a directory.

    Every ``*.replace`` file must be signed by a layout-authorized revocation
    key, must not be expired, and must be bound to the layout's release order.

    Arguments:
      revocation_dir_path: A directory containing ``*.replace`` metadata.
      layout: The verified layout that authorizes the proofs.

    Raises:
      RevocationError: A proof is malformed, expired, wrongly signed, or
          bound to a different release.

    Returns:
      A dictionary mapping revocation ids to verified
      :class:`ReplacementProof` objects.
    """
    proofs = {}

    filenames = sorted(
        fn for fn in os.listdir(revocation_dir_path) if fn.endswith(".replace")
    )

    for filename in filenames:
        path = os.path.join(revocation_dir_path, filename)
        metadata, proof = _load_metadata(
            path, ReplacementProof, "a replacement proof"
        )

        _verify_authorized_signature(
            metadata, layout, f"Replacement '{filename}'"
        )
        _check_expires(proof.expires, f"replacement proof '{filename}'")
        _check_release_binding(
            proof.release_id,
            layout.release_id,
            f"Replacement proof '{filename}'",
        )

        proofs[proof.revocation_id] = proof

    LOG.info("Loaded %d verified replacement proof(s).", len(proofs))
    return proofs


def _hash_matches(artifact_hashes, target_hashes):
    """Returns True if all target hashes equal the artifact's hashes."""
    for algorithm, digest in target_hashes.items():
        if artifact_hashes.get(algorithm) != digest:
            return False
    return True


def _in_scope(revocation, item_name):
    """Returns True if a revocation applies to the given chain item."""
    if not revocation.scope:
        return True
    return item_name in revocation.scope


def _link_contains_version(link, revocation):
    """Returns True if a link carries the revoked artifact version."""
    for collection in (link.materials, link.products):
        hashes = collection.get(revocation.artifact_path)
        if hashes and _hash_matches(hashes, revocation.artifact_hashes):
            return True
    return False


def _find_affected_links(chain_link_dict, revocation):
    """Returns (item name, keyid) pairs carrying the revoked version."""
    affected = []
    for item_name, key_link_dict in chain_link_dict.items():
        if not _in_scope(revocation, item_name):
            continue
        for keyid, link in key_link_dict.items():
            if _link_contains_version(link, revocation):
                affected.append((item_name, keyid))
    return affected


def _report_entry(revocation):
    """Builds the serializable acceptance entry for a revocation."""
    return {
        "revocation_id": revocation.revocation_id,
        "artifact_path": revocation.artifact_path,
        "artifact_hashes": revocation.artifact_hashes,
        "scope": revocation.scope,
        "release_id": revocation.release_id,
    }


def _validate_proof(revocation, proof):
    """Checks that a proof supersedes the revoked version, not re-introduces it."""
    if proof.artifact_path != revocation.artifact_path:
        raise RevocationError(
            f"Replacement proof '{proof.proof_id}' targets path"
            f" '{proof.artifact_path}', but revocation"
            f" '{revocation.revocation_id}' revokes path"
            f" '{revocation.artifact_path}'."
        )

    if _hash_matches(proof.artifact_hashes, revocation.artifact_hashes):
        raise RevocationError(
            f"Replacement proof '{proof.proof_id}' re-introduces the"
            " revoked artifact version."
        )


def _replace_version(chain_link_dict, affected, revocation, proof):
    """Swaps the revoked hashes for the replacement hashes on affected links."""
    for item_name, keyid in affected:
        link = chain_link_dict[item_name][keyid]
        for collection in (link.materials, link.products):
            hashes = collection.get(revocation.artifact_path)
            if hashes and _hash_matches(hashes, revocation.artifact_hashes):
                collection[revocation.artifact_path] = dict(
                    proof.artifact_hashes
                )


def apply_revocations(chain_link_dict, layout, revocations, replacement_proofs):
    """Applies verified revocations to the artifacts of chain links.

    Artifacts are matched by the exact revoked version (path plus content
    hashes), so other versions recorded at the same path are preserved. A
    revoked version that is still present must be covered by a replacement
    proof bound to the same release order and the matching revocation;
    otherwise verification fails.

    Arguments:
      chain_link_dict: A dictionary of link metadata per functionary per step,
          as returned by verify_sublayouts. Modified in place.
      layout: The verified layout.
      revocations: Verified revocation statements.
      replacement_proofs: Verified replacement proofs keyed by revocation id.

    Raises:
      RevocationError: A revoked version is still in use without an acceptable
          replacement, or a replacement re-introduces the revoked version.

    Returns:
      An acceptance report dictionary with keys revoked, replaced and
      pending.
    """
    report = {"revoked": [], "replaced": [], "pending": []}
    handled = set()

    for revocation in revocations:
        entry = _report_entry(revocation)
        affected = _find_affected_links(chain_link_dict, revocation)

        if not affected:
            # The revoked version is not part of this delivery; the statement
            # is recorded but has no effect on un-revoked same-path versions.
            report["revoked"].append(entry)
            handled.add(revocation.revocation_id)
            continue

        proof = replacement_proofs.get(revocation.revocation_id)
        if proof is None:
            report["pending"].append(
                {
                    **entry,
                    "reason": (
                        "no replacement proof bound to release order"
                        f" '{layout.release_id}'"
                    ),
                }
            )
            raise RevocationError(
                f"Artifact '{revocation.artifact_path}' version"
                f" {revocation.artifact_hashes} is revoked, but no acceptable"
                " replacement proof was provided."
            )

        _validate_proof(revocation, proof)
        _replace_version(chain_link_dict, affected, revocation, proof)

        handled.add(revocation.revocation_id)
        report["revoked"].append(entry)
        report["replaced"].append(
            {
                **entry,
                "proof_id": proof.proof_id,
                "replacement_hashes": proof.artifact_hashes,
            }
        )

    _reject_orphan_proofs(replacement_proofs, handled)
    return report


def _reject_orphan_proofs(replacement_proofs, handled):
    """Rejects proofs that do not match an applicable revocation."""
    # A proof without a matching, applicable revocation cannot authorize
    # anything and must not be silently accepted.
    for proof in replacement_proofs.values():
        if proof.revocation_id not in handled:
            raise RevocationError(
                f"Replacement proof '{proof.proof_id}' references unknown or"
                f" inapplicable revocation '{proof.revocation_id}'."
            )


def write_acceptance_records(report, base_dir):
    """Writes the acceptance report as three equally named small files.

    The files are created in separate directories and share the same file
    name, so the revoked original, the accepted replacement and the still
    pending approval can be inspected side by side::

        <base_dir>/revoked/acceptance.json
        <base_dir>/replaced/acceptance.json
        <base_dir>/pending/acceptance.json

    Arguments:
      report: The acceptance report returned by :func:`apply_revocations`.
      base_dir: The directory under which the three record directories are
          created.

    Returns:
      A dictionary mapping each category to the written file path.
    """
    categories = {
        "revoked": ACCEPTANCE_REVOKED_DIR,
        "replaced": ACCEPTANCE_REPLACED_DIR,
        "pending": ACCEPTANCE_PENDING_DIR,
    }
    paths = {}

    for category, directory in categories.items():
        dir_path = os.path.join(base_dir, directory)
        os.makedirs(dir_path, exist_ok=True)
        file_path = os.path.join(dir_path, ACCEPTANCE_FILENAME)
        with open(file_path, "w", encoding="utf8") as fp:
            json.dump(report[category], fp, sort_keys=True, indent=2)
        paths[category] = file_path

    return paths
