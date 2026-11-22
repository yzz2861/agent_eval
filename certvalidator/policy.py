# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import binascii
import hashlib

from asn1crypto import pem, x509

from ._errors import pretty_message
from ._types import byte_cls, str_cls, type_name
from .context import ValidationContext
from .errors import PolicyValidationError, ValidationError
from .path import ValidationPath
from .validate import (
    _inhibit_any_policy,
    _policy_constraints,
    _policy_entries,
    _validate_path,
)


_ANY_POLICY = 'any_policy'

# These are the extensions the current path validation implementation knows
# how to evaluate. A critical extension outside this set is retained as
# "pending review" instead of being treated as absent.
_SUPPORTED_EXTENSIONS = set([
    'authority_information_access',
    'authority_key_identifier',
    'basic_constraints',
    'crl_distribution_points',
    'extended_key_usage',
    'freshest_crl',
    'key_identifier',
    'key_usage',
    'ocsp_no_check',
    'certificate_policies',
    'policy_mappings',
    'policy_constraints',
    'inhibit_any_policy',
])


def _normalize_initial_policy_set(initial_policy_set):
    """
    Normalizes the caller's policy domain to the names used in the internal
    policy tree

    :param initial_policy_set:
        None, or a set/list/tuple of unicode policy identifiers

    :return:
        A set of unicode strings
    """

    if initial_policy_set is None:
        return set([_ANY_POLICY])

    if not isinstance(initial_policy_set, (set, frozenset, list, tuple)):
        raise TypeError(pretty_message(
            '''
            initial_policy_set must be a set of unicode strings, not %s
            ''',
            type_name(initial_policy_set)
        ))

    output = set()
    for policy_identifier in initial_policy_set:
        if not isinstance(policy_identifier, str_cls):
            raise TypeError(pretty_message(
                '''
                initial_policy_set must contain only unicode strings, not %s
                ''',
                type_name(policy_identifier)
            ))
        if policy_identifier in set(['any_policy', 'any-policy', '2.5.29.32.0']):
            return set([_ANY_POLICY])
        output.add(policy_identifier)

    if not output:
        raise ValueError(pretty_message(
            '''
            initial_policy_set must contain at least one policy identifier
            '''
        ))

    return output


def _cert_identity(cert, index=None):
    """
    :return:
        A dict that uniquely identifies a certificate in a path
    """

    return {
        'index': index,
        'subject': cert.subject.human_friendly,
        'issuer': cert.issuer.human_friendly,
        'serial_number': cert.serial_number,
        'sha256': binascii.hexlify(cert.sha256).decode('ascii'),
    }


def _extension_pending(cert, index):
    """
    Finds extensions whose semantics can not be established by this
    implementation. They are reported, not silently discarded.

    :return:
        A list of dicts
    """

    pending = []
    extensions = cert['tbs_certificate']['extensions']
    if extensions is None:
        return pending

    for extension in extensions:
        extn_id = extension['extn_id']
        oid = extn_id.dotted
        name = extn_id.native
        critical = extension['critical'].native if extension['critical'] is not None else False

        try:
            parsed = extension['extn_value'].parsed
            if parsed is not None and hasattr(parsed, 'native'):
                parsed.native
            readable = True
        except (ValueError, TypeError, KeyError):
            readable = False

        if not readable:
            pending.append({
                'index': index,
                'oid': oid,
                'name': name,
                'critical': critical,
                'severity': 'critical' if critical else 'info',
                'reason': 'asn1crypto could not parse the extension value',
            })
            continue

        if critical and name not in _SUPPORTED_EXTENSIONS:
            pending.append({
                'index': index,
                'oid': oid,
                'name': name,
                'critical': True,
                'severity': 'critical',
                'reason': 'certvalidator can not evaluate this critical extension',
            })

    return pending


class PolicyPathResult(object):
    """
    Policy evidence for one validated path.

    The object doubles as the audit hook passed to
    certvalidator.validate._validate_path(). That keeps the evidence tied to
    the exact path validation run instead of re-implementing the RFC 5280
    algorithm outside of the validator.

    :ivar path:
        A certvalidator.path.ValidationPath object

    :ivar initial_policy_set:
        A set of unicode policy identifiers approved by the caller

    :ivar valid:
        A bool - if the underlying path validation completed

    :ivar final_policies:
        A list of unicode policy identifiers that survived at the leaf

    :ivar final_policy_trails:
        A list of dicts, one per surviving leaf node, containing the policy
        trail from the anyPolicy root to the leaf

    :ivar hops:
        A list of dicts of per-certificate policy evidence

    :ivar pending:
        A list of extension evidence that needs manual review

    :ivar error:
        None or the ValidationError raised by path validation
    """

    def __init__(self, initial_policy_set=None):
        self.path = None
        self.path_id = None
        self.chain = []
        self.initial_policy_set = _normalize_initial_policy_set(initial_policy_set)
        self.path_length = None
        self.valid = False
        self.final_policies = []
        self.final_policy_trails = []
        self.hops = []
        self.pending = []
        self.error = None
        self.final_state = None
        self.final_tree = None
        self.removed_policies = []
        self.expanded_any_policy = []

    @property
    def leaf_policies(self):
        """
        :return:
            A list of policy identifiers declared by the end-entity
            certificate, independently of whether the policy tree accepted
            them
        """

        for hop in reversed(self.hops):
            if not hop.get('is_end_entity'):
                continue
            policies = hop.get('certificate_policies') or []
            return [policy['policy_identifier'] for policy in policies]
        return []

    @property
    def declared_final_policies(self):
        """
        Alias for .leaf_policies - the policy OIDs declared by the leaf before
        the policy tree is taken into account
        """

        return self.leaf_policies

    @property
    def policies(self):
        """
        Alias for .final_policies
        """

        return self.final_policies

    @property
    def policy_trails(self):
        """
        Alias for .final_policy_trails
        """

        return self.final_policy_trails

    @property
    def chain_fingerprints(self):
        """
        :return:
            A list of SHA-256 fingerprints in path order
        """

        return [entry['sha256'] for entry in self.chain]

    @property
    def pending_critical(self):
        """
        :return:
            A list of pending extension records with critical severity
        """

        return [item for item in self.pending if item.get('severity') == 'critical']

    @property
    def accepted(self):
        """
        :return:
            A bool - if the path validated and at least one caller-approved
            policy remains. Critical unreadable extensions make the result
            indeterminate and therefore not accepted.
        """

        return bool(self.valid and self.final_policies and not self.pending_critical)

    @property
    def status(self):
        """
        :return:
            A unicode string: "accepted", "no_valid_policy", "pending" or
            "invalid_path"
        """

        if self.pending_critical:
            return "pending"
        if not self.valid:
            return "invalid_path"
        if not self.final_policies:
            return 'no_valid_policy'
        return 'accepted'

    def begin(self, path, path_length, initial_policy_set, state, tree, trust_anchor):
        """
        Audit hook called by _validate_path() during RFC 5280 initialization
        """

        self.path = path
        self.path_length = path_length
        self.initial_policy_set = set(initial_policy_set)
        self.chain = [_cert_identity(cert, index) for index, cert in enumerate(path)]
        digest = hashlib.sha256()
        for cert in path:
            digest.update(cert.sha256)
        self.path_id = digest.hexdigest()

        pending = _extension_pending(trust_anchor, 0)
        self.pending.extend(pending)
        hop = {
            'index': 0,
            'is_trust_anchor': True,
            'is_end_entity': len(path) == 1,
            'certificate_policies': _policy_entries(trust_anchor, 'certificate_policies'),
            'policy_mappings': _policy_entries(trust_anchor, 'policy_mappings'),
            'policy_constraints': _policy_constraints(trust_anchor),
            'inhibit_any_policy': _inhibit_any_policy(trust_anchor),
            'state_before': state,
            'state_after': state,
            'policy_mapping_counter_before': state['policy_mapping'],
            'mapping_status': 'not_processed',
            'policy_tree_before': tree,
            'policy_tree_after_policies': tree,
            'policy_tree_after_mappings': tree,
            'pending': pending,
        }
        hop.update(_cert_identity(trust_anchor, 0))
        self.hops.append(hop)

    def record_hop(self, index, cert, evidence):
        """
        Audit hook called by _validate_path() after each non-anchor
        certificate has been processed
        """

        pending = _extension_pending(cert, index)
        self.pending.extend(pending)
        hop = dict(evidence)
        hop.update(_cert_identity(cert, index))
        hop['pending'] = pending
        self.hops.append(hop)

    def finish(self, state, tree, final_nodes, final_policies, removed_policies,
               expanded_any_policy):
        """
        Audit hook called by _validate_path() during the RFC 5280 wrap-up
        """

        self.final_state = state
        self.final_tree = tree
        self.final_policy_trails = final_nodes
        self.final_policies = list(final_policies)
        self.removed_policies = list(removed_policies)
        self.expanded_any_policy = list(expanded_any_policy)

    def mark_error(self, error):
        """
        Records a path validation failure
        """

        self.error = error

    def to_dict(self):
        """
        :return:
            A JSON-serializable dict containing the complete evidence
        """

        return {
            'path_id': self.path_id,
            'path_length': self.path_length,
            'valid': self.valid,
            'accepted': self.accepted,
            'status': self.status,
            'initial_policy_set': sorted(self.initial_policy_set),
            'final_policies': list(self.final_policies),
            'final_policy_trails': self.final_policy_trails,
            'leaf_policies': self.leaf_policies,
            'declared_final_policies': self.leaf_policies,
            'removed_policies': list(self.removed_policies),
            'expanded_any_policy': list(self.expanded_any_policy),
            'final_state': self.final_state,
            'final_tree': self.final_tree,
            'chain': self.chain,
            'hops': self.hops,
            'pending': self.pending,
            'error': None if self.error is None else str_cls(self.error),
        }


class PolicyQuery(object):
    """
    The result of querying policy evidence for every candidate path to a
    certificate

    :ivar initial_policy_set:
        A set of unicode policy identifiers approved by the caller

    :ivar results:
        A list of PolicyPathResult objects, one per candidate path

    :ivar error:
        None or an error raised while building candidate paths
    """

    def __init__(self, initial_policy_set=None, results=None, error=None):
        self.initial_policy_set = _normalize_initial_policy_set(initial_policy_set)
        self.results = results or []
        self.error = error

    @property
    def paths(self):
        """
        Alias for .results
        """

        return self.results

    @property
    def accepted_paths(self):
        """
        Alias for .accepted_results
        """

        return self.accepted_results

    @property
    def accepted_results(self):
        """
        :return:
            A list of PolicyPathResult objects that satisfy the policy query
        """

        return [result for result in self.results if result.accepted]

    @property
    def accepted(self):
        """
        :return:
            A bool - if at least one path satisfies the policy query
        """

        return bool(self.accepted_results)

    @property
    def pending(self):
        """
        :return:
            A list of all pending extension evidence across paths
        """

        output = []
        for result in self.results:
            for item in result.pending:
                pending = dict(item)
                pending['path_id'] = result.path_id
                output.append(pending)
        return output

    def select(self):
        """
        :return:
            None, or the first accepted PolicyPathResult
        """

        accepted = self.accepted_results
        return accepted[0] if accepted else None

    def require_accepted(self):
        """
        :raises:
            certvalidator.errors.PolicyValidationError - when no path
            satisfies the policy query

        :return:
            The first accepted PolicyPathResult
        """

        result = self.select()
        if result is not None:
            return result

        descriptions = []
        for path_result in self.results:
            descriptions.append('%s (%s)' % (path_result.path_id, path_result.status))
        raise PolicyValidationError(pretty_message(
            '''
            No candidate certificate path satisfies the requested policy set
            %s: %s
            ''',
            ', '.join(sorted(self.initial_policy_set)),
            '; '.join(descriptions) if descriptions else 'no candidate paths'
        ))

    def to_dict(self):
        """
        :return:
            A JSON-serializable dict containing all path evidence
        """

        return {
            'initial_policy_set': sorted(self.initial_policy_set),
            'accepted': self.accepted,
            'results': [result.to_dict() for result in self.results],
            'pending': self.pending,
            'error': None if self.error is None else str_cls(self.error),
        }


def validate_policy_path(validation_context, path, initial_policy_set=None,
                         initial_explicit_policy=False,
                         initial_any_policy_inhibit=False,
                         initial_policy_mapping_inhibit=False):
    """
    Validates one offline path and records per-hop policy evidence.

    Structural path validation failures are captured in .error instead of
    being raised, so that every candidate path can be reported side by side.

    :param validation_context:
        A certvalidator.context.ValidationContext object

    :param path:
        A certvalidator.path.ValidationPath object

    :param initial_policy_set:
        None, or a set of unicode policy identifiers the caller accepts. None
        is equivalent to "any-policy".

    :param initial_explicit_policy:
        A bool - if the initial-explicit-policy input is set

    :param initial_any_policy_inhibit:
        A bool - if the initial-any-policy-inhibit input is set

    :param initial_policy_mapping_inhibit:
        A bool - if the initial-policy-mapping-inhibit input is set

    :return:
        A PolicyPathResult object
    """

    if not isinstance(path, ValidationPath):
        raise TypeError(pretty_message(
            '''
            path must be an instance of certvalidator.path.ValidationPath,
            not %s
            ''',
            type_name(path)
        ))

    if not isinstance(validation_context, ValidationContext):
        raise TypeError(pretty_message(
            '''
            validation_context must be an instance of
            certvalidator.context.ValidationContext, not %s
            ''',
            type_name(validation_context)
        ))

    result = PolicyPathResult(initial_policy_set)
    try:
        _validate_path(
            validation_context,
            path,
            initial_policy_set=result.initial_policy_set,
            policy_audit=result,
            initial_explicit_policy=initial_explicit_policy,
            initial_any_policy_inhibit=initial_any_policy_inhibit,
            initial_policy_mapping_inhibit=initial_policy_mapping_inhibit
        )
        result.valid = True
    except ValidationError as error:
        result.mark_error(error)

    return result


def query_policy_paths(validation_context, paths, initial_policy_set=None,
                       initial_explicit_policy=False,
                       initial_any_policy_inhibit=False,
                       initial_policy_mapping_inhibit=False):
    """
    Queries policy evidence for each candidate path

    :param validation_context:
        A certvalidator.context.ValidationContext object

    :param paths:
        A list of certvalidator.path.ValidationPath objects

    :return:
        A PolicyQuery object
    """

    results = []
    for path in paths:
        results.append(validate_policy_path(
            validation_context,
            path,
            initial_policy_set=initial_policy_set,
            initial_explicit_policy=initial_explicit_policy,
            initial_any_policy_inhibit=initial_any_policy_inhibit,
            initial_policy_mapping_inhibit=initial_policy_mapping_inhibit
        ))

    return PolicyQuery(initial_policy_set, results=results)


def query_certificate_policies(end_entity_cert, intermediate_certs=None,
                               validation_context=None, initial_policy_set=None,
                               initial_explicit_policy=False,
                               initial_any_policy_inhibit=False,
                               initial_policy_mapping_inhibit=False,
                               trust_roots=None, extra_trust_roots=None):
    """
    Builds every candidate path to an end-entity certificate and reports the
    policy evidence for each one. No network access is required; pass a
    ValidationContext configured for offline validation.

    :param end_entity_cert:
        An asn1crypto.x509.Certificate object, or a DER/PEM byte string

    :param intermediate_certs:
        None, or a list of intermediate certificates

    :param validation_context:
        None, or a certvalidator.context.ValidationContext object

    :param initial_policy_set:
        None, or the caller-approved initial policy domain

    :param trust_roots:
        None, or a list of trust roots used when validation_context is None

    :param extra_trust_roots:
        None, or extra trust roots used when validation_context is None

    :return:
        A PolicyQuery object
    """

    if not isinstance(end_entity_cert, x509.Certificate):
        if not isinstance(end_entity_cert, byte_cls):
            raise TypeError(pretty_message(
                '''
                end_entity_cert must be a byte string or an
                asn1crypto.x509.Certificate object, not %s
                ''',
                type_name(end_entity_cert)
            ))
        if pem.detect(end_entity_cert):
            _, _, end_entity_cert = pem.unarmor(end_entity_cert)
        end_entity_cert = x509.Certificate.load(end_entity_cert)

    if validation_context is None:
        validation_context = ValidationContext(
            trust_roots=trust_roots,
            extra_trust_roots=extra_trust_roots,
            other_certs=intermediate_certs,
            revocation_mode='soft-fail'
        )
    elif intermediate_certs:
        for intermediate_cert in intermediate_certs:
            validation_context.certificate_registry.add_other_cert(intermediate_cert)

    try:
        paths = validation_context.certificate_registry.build_paths(end_entity_cert)
    except Exception as error:
        return PolicyQuery(initial_policy_set, results=[], error=error)

    return query_policy_paths(
        validation_context,
        paths,
        initial_policy_set=initial_policy_set,
        initial_explicit_policy=initial_explicit_policy,
        initial_any_policy_inhibit=initial_any_policy_inhibit,
        initial_policy_mapping_inhibit=initial_policy_mapping_inhibit
    )


# Convenience aliases for callers that use audit/query terminology
query_policies = query_certificate_policies
audit_policy_path = validate_policy_path
