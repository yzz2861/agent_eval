"""
Post-verification endorsement coverage analysis.

This module implements an optional, caller-driven layer that runs *after* a successful
:func:`signxml.XMLVerifier.verify` call. It computes how many independent sources have endorsed each
reference covered by an already-verified signature, deduplicating repeated deliveries (such as retries
of the same verification task) according to a caller-supplied independence rule. It never re-verifies,
alters, or replaces signature verification itself.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Iterable, Sequence
from dataclasses import dataclass

from .exceptions import InsufficientEndorsement, InvalidInput
from .util import namespaces
from .verifier import VerifyResult


@dataclass(frozen=True)
class Endorsement:
    """
    A single acknowledgment delivery from a service that approved (a subset of) the references covered by an
    already-verified signature.
    """

    source: str
    "Identifier of the acknowledging party or service that issued this delivery."

    task_id: str
    """
    Identifier of the verification task that produced this delivery. Retried deliveries of the same task
    share the same ``task_id`` and are therefore counted as a single independent endorsement by default.
    """

    references: frozenset[str] | None = None
    """
    URIs of the signature references approved by this delivery. If ``None``, the delivery approves every
    reference in the evaluated scope.
    """


@dataclass(frozen=True)
class ReferenceCoverage:
    """
    Endorsement coverage computed for a single verified signature reference.
    """

    uri: str
    "URI of the signature reference this coverage describes."

    required: int
    "Number of independent endorsements required for this reference to be considered sufficiently endorsed."

    deliveries: int
    "Total number of acknowledgment deliveries received for this reference, before deduplication."

    independent: int
    "Number of independent endorsements for this reference, after deduplicating repeated deliveries."

    sources: frozenset[str]
    "Sources of the independent endorsements counted for this reference."

    @property
    def sufficient(self) -> bool:
        "Whether this reference has at least ``required`` independent endorsements."
        return self.independent >= self.required


@dataclass(frozen=True)
class EndorsementCoverage:
    """
    Result of :func:`compute_endorsement_coverage`, describing per-reference independent endorsement coverage
    for an already-verified signature.
    """

    required: int
    "Number of independent endorsements required per reference."

    references: tuple[ReferenceCoverage, ...]
    "Coverage of each evaluated reference, in signature document order."

    @property
    def sufficient(self) -> bool:
        "Whether every evaluated reference has at least ``required`` independent endorsements."
        return all(reference.sufficient for reference in self.references)

    @property
    def insufficient(self) -> tuple[ReferenceCoverage, ...]:
        "The evaluated references that have fewer than ``required`` independent endorsements."
        return tuple(reference for reference in self.references if not reference.sufficient)

    def require(self) -> EndorsementCoverage:
        """
        Return this coverage if every evaluated reference is sufficiently endorsed, otherwise raise
        :class:`signxml.InsufficientEndorsement`. Note that this exception is distinct from
        :class:`signxml.InvalidSignature`: the signature itself already verified successfully.
        """
        if not self.sufficient:
            details = ", ".join(
                "{!r} ({} of {} independent endorsements)".format(
                    reference.uri, reference.independent, reference.required
                )
                for reference in self.insufficient
            )
            msg = "Insufficient independent endorsements for references: {}"
            raise InsufficientEndorsement(msg.format(details))
        return self


def _reference_uris(verify_results: Sequence[VerifyResult]) -> list[str]:
    uris: list[str] = []
    for result in verify_results:
        signed_info = result.signature_xml.find("ds:SignedInfo", namespaces)
        if signed_info is None:
            raise InvalidInput("VerifyResult does not contain a SignedInfo element")
        for reference in signed_info.findall("ds:Reference", namespaces):
            uri = reference.get("URI", "")
            if uri not in uris:
                uris.append(uri)
    return uris


def compute_endorsement_coverage(
    verify_results: VerifyResult | Sequence[VerifyResult],
    endorsements: Iterable[Endorsement],
    *,
    independence_key: Callable[[Endorsement], Hashable] | None = None,
    required: int = 2,
    scope: Iterable[str] | None = None,
) -> EndorsementCoverage:
    """
    Compute independent endorsement coverage for the references of an already-verified signature.

    This function must only be called with the result of a successful :func:`signxml.XMLVerifier.verify` call;
    it performs no signature verification itself. Whole-document authentication failures are still reported by
    ``XMLVerifier.verify()`` raising :class:`signxml.InvalidSignature`; this layer only reports insufficient
    endorsement quorum on individually verified references.

    :param verify_results:
        The :class:`signxml.VerifyResult` (or list of results, for multi-reference signatures) returned by a
        successful ``XMLVerifier.verify()`` call.
    :param endorsements:
        Acknowledgment deliveries collected for the verified document. Deliveries are deduplicated into
        independent endorsements using ``independence_key``.
    :param independence_key:
        Caller-supplied rule mapping a delivery to its independence group. Deliveries with equal keys (for
        example, retries of the same verification task) are counted as a single independent endorsement,
        represented by the first delivery in the group. Defaults to the delivery's ``task_id``.
    :param required:
        Number of independent endorsements required for each reference in scope.
    :param scope:
        URIs of the verified references to evaluate. If ``None``, all references covered by the signature
        are evaluated.
    :return: An :class:`EndorsementCoverage` describing per-reference coverage.
    """
    if isinstance(verify_results, VerifyResult):
        verify_results = [verify_results]
    verified_uris = _reference_uris(verify_results)

    if required < 1:
        raise InvalidInput("required must be at least 1")

    if scope is None:
        evaluated_uris = verified_uris
    else:
        evaluated_uris = list(scope)
        unknown = set(evaluated_uris) - set(verified_uris)
        if unknown:
            msg = "Scope contains URIs not covered by the verified signature: {}"
            raise InvalidInput(msg.format(sorted(unknown)))

    key_fn = independence_key if independence_key is not None else (lambda delivery: delivery.task_id)
    groups: dict[Hashable, Endorsement] = {}
    deliveries_per_uri = dict.fromkeys(evaluated_uris, 0)
    for delivery in endorsements:
        unknown = set(delivery.references) - set(verified_uris) if delivery.references is not None else set()
        if unknown:
            msg = "Endorsement from {!r} approves URIs not covered by the verified signature: {}"
            raise InvalidInput(msg.format(delivery.source, sorted(unknown)))
        if delivery.references is None:
            approved = evaluated_uris
        else:
            approved = [uri for uri in evaluated_uris if uri in delivery.references]
        for uri in approved:
            deliveries_per_uri[uri] += 1
        groups.setdefault(key_fn(delivery), delivery)

    independent_per_uri: dict[str, list[str]] = {uri: [] for uri in evaluated_uris}
    for group_delivery in groups.values():
        approved = evaluated_uris if group_delivery.references is None else [
            uri for uri in evaluated_uris if uri in group_delivery.references
        ]
        for uri in approved:
            independent_per_uri[uri].append(group_delivery.source)

    return EndorsementCoverage(
        required=required,
        references=tuple(
            ReferenceCoverage(
                uri=uri,
                required=required,
                deliveries=deliveries_per_uri[uri],
                independent=len(independent_per_uri[uri]),
                sources=frozenset(independent_per_uri[uri]),
            )
            for uri in evaluated_uris
        ),
    )
