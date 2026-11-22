# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime

from asn1crypto import pem
from asn1crypto.util import timezone
from asn1crypto.x509 import Certificate

from ._errors import pretty_message
from ._types import byte_cls, str_cls, type_name
from .context import ValidationContext
from .errors import (
    InvalidCertificateError,
    PathBuildingError,
    PathValidationError,
    RevokedError,
    ValidationError,
)

# The usage still validates under the post-removal trust configuration. When a
# replacement path exists, it is attached for independent verification.
STATUS_TRUSTED = "trusted"

# The only validating path chains to a trust root that is present in the
# current configuration but absent from the post-removal configuration.
STATUS_ROOT_REMOVED = "root_removed"

# A complete path was built and checked, but validation failed for a reason
# unrelated to the trust-root removal, such as expiry, a bad signature or a
# business constraint the certificate does not satisfy.
STATUS_DISTRUSTED = "distrusted"

# The frozen material is not enough to reach a definite answer at the
# validation moment, e.g. a missing intermediate or unavailable revocation
# information in hard-fail/require mode.
STATUS_INDETERMINATE = "indeterminate"

# Message fragments showing validation could not reach a definite revocation
# answer with the material that was provided.
_INDETERMINATE_FRAGMENTS = (
    "revocation checks failed",
    "no revocation information could be found",
)

_REVOKED_FRAGMENTS = (
    "revoked",
)

def _load_cert(cert, var_name):
    if isinstance(cert, Certificate):
        return cert
    if not isinstance(cert, byte_cls):
        raise TypeError(pretty_message(
            """
            %s must contain only byte strings or
            asn1crypto.x509.Certificate objects, not %s
            """,
            var_name,
            type_name(cert)
        ))
    if pem.detect(cert):
        _, _, cert = pem.unarmor(cert)
    return Certificate.load(cert)

def _load_certs(certs, var_name):
    if certs is None:
        return []
    if not isinstance(certs, (list, tuple)):
        raise TypeError(pretty_message(
            """
            %s must be a list of byte strings or
            asn1crypto.x509.Certificate objects, not %s
            """,
            var_name,
            type_name(certs)
        ))
    return [_load_cert(cert, var_name) for cert in certs]

class FailureRecord(object):
    """
    A structured record of one validation attempt that did not succeed.
    """

    def __init__(self, configuration, exception_type, message):
        self.configuration = configuration
        self.exception_type = exception_type
        self.message = message

    def __repr__(self):
        return "FailureRecord(%s, %s)" % (self.configuration, self.exception_type)

class PathRecord(object):
    """
    A checkable description of a certificate validation path, ordered from the
    trust anchor to the end-entity certificate.
    """

    def __init__(self, validation_path):
        self._certs = list(validation_path)
        self.anchor = self._certs[0]
        self.entries = list(self._certs)

    @property
    def subject_names(self):
        return [cert.subject.human_friendly for cert in self._certs]

    @property
    def anchor_sha256_fingerprint(self):
        return self.anchor.sha256_fingerprint

    @property
    def anchor_sha1_fingerprint(self):
        return self.anchor.sha1_fingerprint

    def __len__(self):
        return len(self._certs)

    def __iter__(self):
        return iter(self._certs)

    def __repr__(self):
        return "PathRecord(%s)" % " -> ".join(self.subject_names)

class BusinessConstraint(object):
    """
    A required usage of an end-entity certificate.

    key_usage contains required key usage bit names, extended_key_usage
    contains required extended key usage OIDs or friendly names, and
    extended_optional allows the extended key usage extension to be omitted.
    """

    def __init__(self, key_usage=None, extended_key_usage=None,
                 extended_optional=False, label=None):
        self.key_usage = set(key_usage) if key_usage is not None else set()
        self.extended_key_usage = set(extended_key_usage) if extended_key_usage is not None else set()
        self.extended_optional = bool(extended_optional)
        self.label = label or self._default_label()

    def _default_label(self):
        parts = sorted(self.key_usage) + sorted(self.extended_key_usage)
        return "+".join(parts) if parts else "any_usage"

    def __repr__(self):
        return "BusinessConstraint(%s)" % self.label

class UsageImpact(object):
    """
    The impact of the trust-root removal on a single business constraint.
    """

    def __init__(self, constraint, status, reason=None, current_path=None,
                 replacement_path=None, failures=None):
        self.constraint = constraint
        self.label = constraint.label
        self.status = status
        self.reason = reason
        self.current_path = current_path
        self.replacement_path = replacement_path
        self.failures = list(failures) if failures else []

    @property
    def is_affected(self):
        return self.status != STATUS_TRUSTED

    def __repr__(self):
        return "UsageImpact(%s, %s)" % (self.label, self.status)

class ImpactAssessment(object):
    """
    The full offline impact assessment for one end-entity certificate.
    """

    def __init__(self, certificate, usage_impacts):
        self.certificate = certificate
        self.usage_impacts = list(usage_impacts)

    @property
    def statuses(self):
        return set(impact.status for impact in self.usage_impacts)

    @property
    def affected_usages(self):
        return [impact for impact in self.usage_impacts if impact.is_affected]

    @property
    def is_fully_trusted(self):
        return all(not impact.is_affected for impact in self.usage_impacts)

    def usages_with_status(self, status):
        return [impact for impact in self.usage_impacts if impact.status == status]

    def __repr__(self):
        return "ImpactAssessment(%s, %s)" % (
            self.certificate.subject.human_friendly,
            sorted(self.statuses),
        )

class OfflineImpactAssessor(object):
    """
    Performs an offline impact assessment of removing one or more historical
    trust roots against a frozen set of certificate material.

    Two trust configurations are compared with independent validation
    contexts at a fixed validation moment:

     - current_trust_roots: the trust configuration before the removal
     - post_removal_trust_roots: the trust configuration after the removal

    No network access is ever performed: allow_fetching is hard-coded to
    False, and only the supplied certificates, CRLs and OCSP responses are
    used. Each configuration gets its own ValidationContext and
    CertificateRegistry, so validation caches can never leak between the two
    configurations.
    """

    def __init__(self, current_trust_roots, post_removal_trust_roots,
                 intermediate_certs=None, moment=None,
                 revocation_mode="soft-fail", crls=None, ocsps=None,
                 weak_hash_algos=None, whitelisted_certs=None):
        current_roots = _load_certs(current_trust_roots, "current_trust_roots")
        post_roots = _load_certs(post_removal_trust_roots, "post_removal_trust_roots")
        intermediates = _load_certs(intermediate_certs, "intermediate_certs")

        if not current_roots:
            raise ValueError(pretty_message(
                """
                current_trust_roots must contain at least one trust anchor
                """
            ))

        if moment is None:
            moment = datetime.now(timezone.utc)
        elif not isinstance(moment, datetime):
            raise TypeError(pretty_message(
                """
                moment must be a datetime object, not %s
                """,
                type_name(moment)
            ))
        elif moment.utcoffset() is None:
            raise ValueError(pretty_message(
                """
                moment is a naive datetime object, meaning the tzinfo
                attribute is not set to a valid timezone
                """
            ))

        if revocation_mode not in set(["soft-fail", "hard-fail", "require"]):
            raise ValueError(pretty_message(
                """
                revocation_mode must be one of "soft-fail", "hard-fail",
                "require", not %s
                """,
                repr(revocation_mode)
            ))

        self._current_roots = current_roots
        self._post_roots = post_roots
        self._intermediates = intermediates
        self._moment = moment
        self._revocation_mode = revocation_mode
        self._crls = crls
        self._ocsps = ocsps
        self._weak_hash_algos = weak_hash_algos
        self._whitelisted_certs = whitelisted_certs
        self._removed_roots = self._compute_removed_roots(current_roots, post_roots)

    @staticmethod
    def _compute_removed_roots(current_roots, post_roots):
        post_fingerprints = set(root.sha256 for root in post_roots)
        removed = []
        seen = set()
        for root in current_roots:
            if root.sha256 not in post_fingerprints and root.sha256 not in seen:
                removed.append(root)
                seen.add(root.sha256)
        return removed

    @property
    def removed_roots(self):
        """
        The trust anchors present in the current configuration but absent
        from the post-removal configuration, as Certificate objects.
        """
        return list(self._removed_roots)

    @property
    def moment(self):
        return self._moment

    def _new_context(self, trust_roots):
        # A fresh context (and thus a fresh CertificateRegistry and validation
        # caches) is built for every configuration and every end-entity
        # certificate, so no cached result is ever shared across
        # configurations.
        return ValidationContext(
            trust_roots=trust_roots,
            other_certs=list(self._intermediates),
            moment=self._moment,
            allow_fetching=False,
            crls=self._crls,
            ocsps=self._ocsps,
            revocation_mode=self._revocation_mode,
            weak_hash_algos=self._weak_hash_algos,
            whitelisted_certs=self._whitelisted_certs,
        )

    def _run_validation(self, trust_roots, end_entity_cert, constraint):
        # Imported lazily so that module import never pulls in the public API
        # in a circular fashion.
        from . import CertificateValidator

        context = self._new_context(trust_roots)
        validator = CertificateValidator(
            end_entity_cert,
            intermediate_certs=None,
            validation_context=context,
        )
        path = validator.validate_usage(
            constraint.key_usage,
            constraint.extended_key_usage,
            constraint.extended_optional,
        )
        return context, PathRecord(path)

    @staticmethod
    def _message_contains(message, fragments):
        lowered = message.lower()
        return any(fragment in lowered for fragment in fragments)

    def _classify_exception(self, exc):
        message = str_cls(exc)
        if isinstance(exc, PathBuildingError):
            return STATUS_INDETERMINATE, message
        if isinstance(exc, RevokedError) or self._message_contains(message, _REVOKED_FRAGMENTS):
            return STATUS_DISTRUSTED, message
        if self._message_contains(message, _INDETERMINATE_FRAGMENTS):
            return STATUS_INDETERMINATE, message
        if isinstance(exc, (PathValidationError, InvalidCertificateError, ValidationError)):
            return STATUS_DISTRUSTED, message
        return STATUS_DISTRUSTED, message

    def _root_removed_diagnostic(self, end_entity_cert, current_path_record, post_failure):
        # The post-removal configuration cannot build a path. Determine whether
        # the anchor used by the currently-validating path is one of the
        # removed roots; if so this is a definite removal impact, otherwise the
        # frozen material is simply insufficient.
        anchor = current_path_record.anchor
        removed_fingerprints = set(root.sha256 for root in self._removed_roots)
        if anchor.sha256 in removed_fingerprints:
            reason = pretty_message(
                """
                the only validating path chains to trust root "%s" (%s),
                which is removed from the post-removal trust configuration
                """,
                anchor.subject.human_friendly,
                anchor.sha256_fingerprint,
            )
            return STATUS_ROOT_REMOVED, reason
        return self._classify_exception(post_failure)

    def assess_usage(self, end_entity_cert, constraint):
        if not isinstance(constraint, BusinessConstraint):
            raise TypeError(pretty_message(
                """
                constraint must be an instance of
                certvalidator.impact.BusinessConstraint, not %s
                """,
                type_name(constraint)
            ))
        end_entity_cert = _load_cert(end_entity_cert, "end_entity_cert")

        current_path = None
        post_path = None
        current_exc = None
        post_exc = None
        current_status = None
        current_reason = None
        failures = []

        try:
            _, current_path = self._run_validation(
                self._current_roots, end_entity_cert, constraint
            )
        except Exception as exc:
            current_exc = exc
            current_status, current_reason = self._classify_exception(exc)
            failures.append(FailureRecord(
                "current", exc.__class__.__name__, current_reason
            ))

        try:
            _, post_path = self._run_validation(
                self._post_roots, end_entity_cert, constraint
            )
        except Exception as exc:
            post_exc = exc
            post_status, post_reason = self._classify_exception(exc)
            failures.append(FailureRecord(
                "post_removal", exc.__class__.__name__, post_reason
            ))

        if current_path is not None and post_path is not None:
            return UsageImpact(
                constraint,
                STATUS_TRUSTED,
                reason="a validating path exists under both trust configurations",
                current_path=current_path,
                replacement_path=post_path,
                failures=failures,
            )

        if current_path is not None and post_path is None:
            status, reason = self._root_removed_diagnostic(
                end_entity_cert, current_path, post_exc
            )
            return UsageImpact(
                constraint,
                status,
                reason=reason,
                current_path=current_path,
                replacement_path=None,
                failures=failures,
            )

        if current_path is None and post_path is not None:
            # The current configuration failing while the post-removal one
            # succeeds is only possible when material differs; report the
            # current failure honestly rather than claiming an impact.
            return UsageImpact(
                constraint,
                current_status,
                reason=current_reason,
                current_path=None,
                replacement_path=post_path,
                failures=failures,
            )

        # Neither configuration validates. A definite current failure is
        # reported as-is; an indeterminate current result stays indeterminate.
        return UsageImpact(
            constraint,
            current_status,
            reason=current_reason,
            current_path=None,
            replacement_path=None,
            failures=failures,
        )

    def assess(self, end_entity_cert, constraints):
        if not isinstance(constraints, (list, tuple)) or not constraints:
            raise ValueError(pretty_message(
                """
                constraints must be a non-empty list of BusinessConstraint
                objects
                """
            ))
        end_entity_cert = _load_cert(end_entity_cert, "end_entity_cert")
        impacts = [
            self.assess_usage(end_entity_cert, constraint)
            for constraint in constraints
        ]
        return ImpactAssessment(end_entity_cert, impacts)

    def assess_all(self, certificates, constraints):
        if not isinstance(certificates, (list, tuple)):
            raise TypeError(pretty_message(
                """
                certificates must be a list of byte strings or
                asn1crypto.x509.Certificate objects, not %s
                """,
                type_name(certificates)
            ))
        return [
            self.assess(_load_cert(cert, "certificates"), constraints)
            for cert in certificates
        ]
