""" pgpy.archive

Candidate reconciliation for archival evidence.

When a detached PGP signature is archived alongside several exported
representations of the same message (for example, a normalized text export
and an attachment that preserves the original line endings), the archiver
has to determine which candidate the signature actually covers.

This module provides an interface where the *caller* explicitly declares:

- which equivalence classes of representations are approved
  (e.g. newline normalization), via :py:class:`EquivalencePolicy`, and
- which part of each candidate holds the actual signed material, via the
  ``signed_part`` argument to :py:func:`verify_candidates`.

If more than one candidate verifies, no candidate is automatically promoted
to evidentiary original: the result is left in the ambiguous (pending)
state and it is up to the caller to resolve the attribution out of band.
"""

import enum
import re

from .errors import PGPError


__all__ = ['AttributionState',
           'CandidateVerification',
           'EquivalencePolicy',
           'EvidenceCandidate',
           'normalize_newlines',
           'verify_candidates']


class AttributionState(enum.Enum):
    """Outcome of reconciling a signature against a set of candidates."""
    VERIFIED_UNIQUE = 'verified-unique'  # exactly one candidate verified; attribution resolved
    AMBIGUOUS = 'ambiguous'              # multiple candidates verified; attribution left pending
    NO_MATCH = 'no-match'                # no candidate verified


def normalize_newlines(data):
    """Canonicalize line endings: CRLF and lone CR are folded to LF."""
    return re.sub(br'\r\n|\r', b'\n', data)


class EquivalencePolicy(object):
    """Caller-approved equivalence classes over candidate representations.

    Each normalizer is a callable ``bytes -> bytes`` mapping a
    representation to a canonical form of an equivalence class the caller
    has approved (e.g. :py:func:`normalize_newlines`). The exact bytes are
    always tried in addition to each approved normalizer.
    """
    def __init__(self, normalizers=()):
        self._normalizers = tuple(normalizers)

    @property
    def normalizers(self):
        return self._normalizers

    @classmethod
    def exact_only(cls):
        """A policy that approves no equivalences: only exact bytes verify."""
        return cls(())


class EvidenceCandidate(object):
    """One archived representation of a message, split into named parts.

    ``parts`` maps a part name (e.g. ``'exported_text'``, ``'attachment'``)
    to its ``bytes`` content. The caller declares which part holds the
    actual signed material when calling :py:func:`verify_candidates`.
    """
    def __init__(self, label, parts):
        self.label = label
        self.parts = dict(parts)

    def __repr__(self):
        return "EvidenceCandidate(label={!r}, parts={!r})".format(self.label, sorted(self.parts))


class CandidateVerification(object):
    """Result of reconciling one signature against a set of candidates."""
    def __init__(self, state, matches, details, signed_part):
        self._state = state
        self._matches = tuple(matches)
        self._details = dict(details)
        self._signed_part = signed_part

    @property
    def state(self):
        return self._state

    @property
    def signed_part(self):
        """The candidate part the caller declared as signed material."""
        return self._signed_part

    @property
    def matches(self):
        """All candidates that verified under the approved policy."""
        return self._matches

    @property
    def details(self):
        """Per-candidate tuple of representation forms that verified.

        Keys are candidate labels; values are tuples containing ``'exact'``
        and/or the names of approved normalizers under which the declared
        signed part verified.
        """
        return self._details

    @property
    def original(self):
        """The evidentiary original, if and only if attribution is resolved.

        This is ``None`` whenever the state is not
        ``AttributionState.VERIFIED_UNIQUE`` -- in particular, when multiple
        candidates verify the archiver must not auto-pick one.
        """
        if self._state is AttributionState.VERIFIED_UNIQUE:
            return self._matches[0]
        return None

    @property
    def pending(self):
        """True while the archiver cannot attribute the original."""
        return self._state is not AttributionState.VERIFIED_UNIQUE

    def __bool__(self):
        return self._state is AttributionState.VERIFIED_UNIQUE

    __nonzero__ = __bool__

    def __repr__(self):
        return "CandidateVerification(state={!r}, matches={!r})".format(
            self._state, [c.label for c in self._matches])


def verify_candidates(key, signature, candidates, signed_part, policy=None):
    """Verify a detached signature against a set of evidence candidates.

    :param key: The public :py:obj:`~pgpy.PGPKey` to verify with.
    :param signature: The detached :py:obj:`~pgpy.PGPSignature` under review.
    :param candidates: Iterable of :py:class:`EvidenceCandidate`.
    :param signed_part: Name of the candidate part the caller declares as
                        the actual signed material.
    :param policy: An :py:class:`EquivalencePolicy` declaring which
                   equivalence classes of representations the caller
                   approves. Defaults to :py:meth:`EquivalencePolicy.exact_only`.
    :returns: :py:class:`CandidateVerification`
    :raises: :py:exc:`~pgpy.errors.PGPError` if candidate labels are not
             unique, or a candidate lacks the declared signed part.
    """
    if policy is None:
        policy = EquivalencePolicy.exact_only()

    candidates = list(candidates)
    labels = [c.label for c in candidates]
    if len(set(labels)) != len(labels):
        raise PGPError("Candidate labels must be unique for attribution")

    forms = [('exact', None)]
    forms += [(getattr(n, '__name__', 'normalizer_{:d}'.format(i)), n)
              for i, n in enumerate(policy.normalizers)]

    matches = []
    details = {}
    for candidate in candidates:
        if signed_part not in candidate.parts:
            raise PGPError("Candidate {!r} has no part {!r} declared as signed material".format(
                candidate.label, signed_part))

        material = candidate.parts[signed_part]
        matched_forms = []
        for form_name, normalizer in forms:
            form = material if normalizer is None else normalizer(material)
            if bool(key.verify(form, signature)):
                matched_forms.append(form_name)

        details[candidate.label] = tuple(matched_forms)
        if matched_forms:
            matches.append(candidate)

    if len(matches) == 1:
        state = AttributionState.VERIFIED_UNIQUE
    elif len(matches) > 1:
        state = AttributionState.AMBIGUOUS
    else:
        state = AttributionState.NO_MATCH

    return CandidateVerification(state, matches, details, signed_part)
