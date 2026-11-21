# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto import pem, x509

from ._errors import pretty_message
from ._types import byte_cls, str_cls, type_name
from .context import ValidationContext
from .errors import (
    IndependentResponsibilityError,
    InvalidCertificateError,
    PathBuildingError,
    PathValidationError,
    ValidationError,
)
from .validate import validate_path, validate_usage


_KEY_USAGE_NAMES = set([
    'digital_signature',
    'non_repudiation',
    'key_encipherment',
    'data_encipherment',
    'key_agreement',
    'key_cert_sign',
    'crl_sign',
    'encipher_only',
    'decipher_only',
])

_USAGE_DICT_KEYS = set([
    'key_usage',
    'key_usages',
    'keyUsage',
    'extended_key_usage',
    'extended_key_usages',
    'extendedKeyUsage',
    'extended_optional',
    'purpose',
    'purposes',
    'usage',
    'name',
    'end_entity_cert',
    'end_entity_certs',
    'certificate',
    'certificates',
])

_CERT_KEYS = set([
    'end_entity_cert',
    'end_entity_certs',
    'certificate',
    'certificates',
])

_PROPERTY_NAMES = {
    'key_usage': 'key usage',
    'extended_key_usage': 'extended key usage',
}


class UsageRequirement(object):
    """
    One purpose that must be validated as part of a joint admission decision.
    """

    def __init__(self, key_usage=None, extended_key_usage=None, extended_optional=False,
                 name=None, end_entity_certs=None):
        """
        :param key_usage:
            None, a unicode string, or an iterable of unicode strings of
            required key usage purposes

        :param extended_key_usage:
            None, a unicode string, or an iterable of unicode strings of
            required extended key usage purposes

        :param extended_optional:
            A bool - if the extended key usage extension may be omitted

        :param name:
            None or a unicode string used to identify the usage in results and
            error messages

        :param end_entity_certs:
            None, an asn1crypto.x509.Certificate object, a byte string, or a
            list of certificates/byte strings that may serve as the end-entity
            certificate for this usage
        """

        self.key_usage = _coerce_name_set(key_usage, 'key_usage')
        self.extended_key_usage = _coerce_name_set(extended_key_usage, 'extended_key_usage')
        self.extended_optional = _coerce_bool(extended_optional, 'extended_optional')
        self.name = _coerce_name(name, 'name')
        self.end_entity_certs = _coerce_cert_list(end_entity_certs, 'end_entity_certs')

    def __repr__(self):
        return 'UsageRequirement(name=%r, key_usage=%r, extended_key_usage=%r)' % (
            self.name,
            self.key_usage,
            self.extended_key_usage
        )


class JointValidationResult(object):
    """
    The path selected for each usage in a successful joint admission decision.

    The object is sequence-like: iterating over it yields
    certvalidator.path.ValidationPath objects in usage order.
    """

    def __init__(self, usages, paths):
        self.usages = tuple(usages)
        self.paths = tuple(paths)

    @property
    def selected_paths(self):
        return self.paths

    @property
    def paths_by_usage(self):
        output = {}
        for usage, path in zip(self.usages, self.paths):
            key = usage.name
            if key is None:
                key = self.usages.index(usage)
            output[key] = path
        return output

    def __iter__(self):
        return iter(self.paths)

    def __len__(self):
        return len(self.paths)

    def __getitem__(self, key):
        return self.paths[key]

    def __eq__(self, other):
        if isinstance(other, JointValidationResult):
            return self.paths == other.paths
        return self.paths == other

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return 'JointValidationResult(paths=%r)' % (self.paths,)


def validate_joint_usage(validation_context, end_entity_cert, usages,
                         end_entity_certs=None, require_offline=True,
                         include_trust_anchor=False, identity=None):
    """
    Validates a group of usages and checks that one complete path can be
    selected for each usage without sharing an intermediate authorization
    subject across usages.

    Each usage is first validated using the normal certvalidator path and usage
    validation functions. All paths that validate are kept, so the selection is
    not biased toward the first path built for a usage.

    :param validation_context:
        A certvalidator.context.ValidationContext object. When require_offline
        is True, the context must not have allow_fetching enabled.

    :param end_entity_cert:
        The default asn1crypto.x509.Certificate object or byte string for
        usages that do not specify their own end-entity certificates

    :param usages:
        A list/tuple of usage requirements. Each item may be a
        certvalidator.joint.UsageRequirement object, a dict, or a
        (key_usage, extended_key_usage, extended_optional) sequence. A dict
        may include "name", "key_usage", "extended_key_usage",
        "extended_optional" and "end_entity_cert"/"end_entity_certs" keys. A
        dict mapping usage names to requirement values is also accepted.

    :param end_entity_certs:
        None, or a certificate/byte string/list of certificates/certificate
        byte strings that may serve as the end-entity certificate for every
        usage without an explicit end_entity_certs value. When None, the
        end_entity_cert parameter is used.

    :param require_offline:
        A bool - if the validation_context must have fetching disabled

    :param include_trust_anchor:
        A bool - if trust anchors also count as intermediate authorization
        subjects. Defaults to False, matching the policy that intermediates,
        not roots, must be independent.

    :param identity:
        None or a callable that accepts an asn1crypto.x509.Certificate object
        and returns a hashable authorization-subject identifier. By default a
        certificate is identified by its subject and public key, so
        cross-signed copies of the same intermediate count as one subject.

    :raises:
        certvalidator.errors.PathValidationError - when one of the usages can
        not be validated at all, using the normal validator error

        certvalidator.errors.IndependentResponsibilityError - when every
        individual usage validates, but no path combination satisfies the
        independence constraint

    :return:
        A certvalidator.joint.JointValidationResult object
    """

    if not isinstance(validation_context, ValidationContext):
        raise TypeError(pretty_message(
            '''
            validation_context must be an instance of
            certvalidator.context.ValidationContext, not %s
            ''',
            type_name(validation_context)
        ))

    if require_offline and validation_context._allow_fetching:
        raise ValueError(pretty_message(
            '''
            validate_joint_usage() is an offline operation and requires a
            ValidationContext with allow_fetching set to False
            '''
        ))

    if identity is not None and not callable(identity):
        raise TypeError(pretty_message(
            '''
            identity must be callable, not %s
            ''',
            type_name(identity)
        ))

    if end_entity_certs is None:
        default_certs = _coerce_cert_list(end_entity_cert, 'end_entity_cert')
    else:
        default_certs = _coerce_cert_list(end_entity_certs, 'end_entity_certs')

    if not default_certs:
        raise ValueError('At least one end-entity certificate is required')

    requirements = _normalize_usages(usages)
    if not requirements:
        raise ValueError('At least one usage is required')

    identity = identity or _default_identity
    candidate_paths = []
    candidate_intermediates = []

    for requirement in requirements:
        certs = requirement.end_entity_certs or default_certs
        paths = _valid_paths_for_usage(
            validation_context,
            certs,
            requirement
        )
        if not paths:
            _raise_original_validation_error(validation_context, certs, requirement)

        intermediates = []
        for path in paths:
            intermediates.append(_intermediate_identities(
                path,
                identity,
                include_trust_anchor
            ))

        candidate_paths.append(paths)
        candidate_intermediates.append(intermediates)

    selected = _find_independent_combination(candidate_intermediates)
    if selected is None:
        shared = _shared_intermediate_descriptions(
            candidate_paths,
            identity,
            include_trust_anchor
        )
        usage_names = [_usage_label(index, requirement) for index, requirement in enumerate(requirements)]
        message = pretty_message(
            '''
            The requested usages validate independently, but no independent
            path combination exists. Every combination shares at least one
            intermediate authorization subject across usages %s.
            ''',
            ', '.join(usage_names)
        )
        if shared:
            message += pretty_message(
                '''
                Shared intermediate authorization subject candidates: %s
                ''',
                ', '.join(shared)
            )

        error = IndependentResponsibilityError(message)
        error.paths_by_usage = tuple(tuple(paths) for paths in candidate_paths)
        error.shared_intermediates = tuple(shared)
        raise error

    chosen_paths = [candidate_paths[index][path_index] for index, path_index in enumerate(selected)]
    return JointValidationResult(requirements, chosen_paths)


def _valid_paths_for_usage(validation_context, certs, requirement):
    """
    Returns every complete path that passes both normal path validation and
    the requested usage check.
    """

    valid_paths = []
    seen_paths = set()

    for cert in certs:
        try:
            paths = validation_context.certificate_registry.build_paths(cert)
        except (PathBuildingError):
            continue

        for path in paths:
            path_key = tuple(entry.sha256 for entry in path)
            if path_key in seen_paths:
                continue

            try:
                validate_path(validation_context, path)
            except (ValidationError):
                continue

            try:
                validate_usage(
                    validation_context,
                    path[-1],
                    requirement.key_usage,
                    requirement.extended_key_usage,
                    requirement.extended_optional
                )
            except (InvalidCertificateError):
                continue

            seen_paths.add(path_key)
            valid_paths.append(path)

    return valid_paths


def _raise_original_validation_error(validation_context, certs, requirement):
    """
    Re-runs the normal CertificateValidator entry point to produce the same
    error a caller would receive without joint validation.
    """

    from . import CertificateValidator

    exceptions = []
    for cert in certs:
        validator = CertificateValidator(cert, validation_context=validation_context)
        try:
            validator.validate_usage(
                requirement.key_usage,
                requirement.extended_key_usage,
                requirement.extended_optional
            )
        except (ValidationError) as e:
            exceptions.append(e)
            continue

        # A normal validation succeeded, so this should only be possible if
        # the registry changed while the joint decision was running.
        raise PathValidationError(pretty_message(
            '''
            The usage "%s" validated, but its path could not be used in the
            joint decision
            ''',
            _usage_label(0, requirement)
        ))

    if len(exceptions) == 1:
        raise exceptions[0]

    for exception in exceptions:
        if 'signature' not in str_cls(exception):
            raise exception

    raise exceptions[0]


def _find_independent_combination(candidate_intermediates):
    """
    Backtracks over every candidate path for every usage and returns a tuple of
    path indexes, or None when every combination has a conflict.
    """

    usage_count = len(candidate_intermediates)
    selected_indexes = []

    def search(usage_index, used_identities):
        if usage_index == usage_count:
            return True

        for path_index, identities in enumerate(candidate_intermediates[usage_index]):
            if used_identities & identities:
                continue

            selected_indexes.append(path_index)
            if search(usage_index + 1, used_identities | identities):
                return True
            selected_indexes.pop()

        return False

    if search(0, set()):
        return tuple(selected_indexes)
    return None


def _shared_intermediate_descriptions(candidate_paths, identity, include_trust_anchor):
    """
    Produces human-readable names for intermediate subjects that occur in
    candidates from more than one usage.
    """

    descriptions = {}
    usage_identities = []

    for paths in candidate_paths:
        seen = set()
        for path in paths:
            for cert in _intermediate_certs(path, include_trust_anchor):
                cert_identity = identity(cert)
                seen.add(cert_identity)
                descriptions[cert_identity] = cert.subject.human_friendly
        usage_identities.append(seen)

    shared = []
    for cert_identity, description in descriptions.items():
        occurrences = 0
        for identities in usage_identities:
            if cert_identity in identities:
                occurrences += 1
        if occurrences > 1:
            shared.append(description)

    return sorted(set(shared))


def _intermediate_certs(path, include_trust_anchor):
    start = 0 if include_trust_anchor else 1
    return list(path[start:-1])


def _intermediate_identities(path, identity, include_trust_anchor):
    return set(
        identity(cert)
        for cert in _intermediate_certs(path, include_trust_anchor)
    )


def _default_identity(cert):
    return (cert.subject.hashable, cert.public_key.sha256)


def _usage_label(index, requirement):
    if requirement.name:
        return '%s (%s)' % (requirement.name, index + 1)
    return 'usage %d' % (index + 1)


def _normalize_usages(usages):
    if isinstance(usages, UsageRequirement):
        return [usages]

    if isinstance(usages, dict):
        if _is_usage_dict(usages):
            return [_normalize_usage(usages)]

        output = []
        for name, value in usages.items():
            output.append(_normalize_usage(value, name=name))
        return output

    if isinstance(usages, (x509.Certificate, byte_cls, str_cls)):
        return [_normalize_usage(usages)]

    if not isinstance(usages, (list, tuple)):
        raise TypeError(pretty_message(
            '''
            usages must be a list or tuple of usage requirements, not %s
            ''',
            type_name(usages)
        ))

    output = []
    for usage in usages:
        output.append(_normalize_usage(usage))
    return output


def _normalize_usage(usage, name=None):
    if isinstance(usage, UsageRequirement):
        if name is None:
            return usage
        return UsageRequirement(
            usage.key_usage,
            usage.extended_key_usage,
            usage.extended_optional,
            name=name,
            end_entity_certs=usage.end_entity_certs
        )

    if isinstance(usage, dict):
        return _usage_from_dict(usage, name=name)

    if isinstance(usage, (tuple, list)):
        if len(usage) == 0:
            raise ValueError('A usage requirement may not be empty')
        if len(usage) > 4:
            raise TypeError(pretty_message(
                '''
                A usage sequence must contain at most key_usage,
                extended_key_usage, extended_optional and end_entity_certs
                '''
            ))

        key_usage = usage[0] if len(usage) > 0 else None
        extended_key_usage = usage[1] if len(usage) > 1 else None
        extended_optional = usage[2] if len(usage) > 2 else False
        end_entity_certs = usage[3] if len(usage) > 3 else None
        return UsageRequirement(
            key_usage,
            extended_key_usage,
            extended_optional,
            name=name,
            end_entity_certs=end_entity_certs
        )

    if isinstance(usage, str_cls):
        return UsageRequirement(extended_key_usage=usage, name=name)

    if isinstance(usage, (set, frozenset)):
        key_usage, extended_key_usage = _split_usage_names(usage)
        return UsageRequirement(
            key_usage,
            extended_key_usage,
            name=name
        )

    raise TypeError(pretty_message(
        '''
        Each usage must be a dict, UsageRequirement, sequence, set or unicode
        string, not %s
        ''',
        type_name(usage)
    ))


def _usage_from_dict(spec, name=None):
    key_usage = _first_present(spec, ['key_usage', 'key_usages', 'keyUsage'])
    extended_key_usage = _first_present(
        spec,
        ['extended_key_usage', 'extended_key_usages', 'extendedKeyUsage', 'purpose', 'purposes', 'usage']
    )
    extended_optional = _first_present(spec, ['extended_optional'])
    if extended_optional is None:
        extended_optional = False
    end_entity_certs = _first_present(
        spec,
        ['end_entity_certs', 'end_entity_cert', 'certificates', 'certificate']
    )

    usage_name = spec.get('name', name)

    if key_usage is None and extended_key_usage is None and end_entity_certs is None:
        unknown = set(spec.keys()) - _USAGE_DICT_KEYS
        if unknown:
            raise ValueError(pretty_message(
                '''
                Unrecognized usage key(s): %s
                ''',
                ', '.join(sorted(unknown))
            ))

    return UsageRequirement(
        key_usage,
        extended_key_usage,
        extended_optional,
        name=usage_name,
        end_entity_certs=end_entity_certs
    )


def _is_usage_dict(value):
    return bool(set(value.keys()) & _USAGE_DICT_KEYS)


def _first_present(mapping, keys):
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _split_usage_names(values):
    key_usage = set()
    extended_key_usage = set()

    for value in values:
        if not isinstance(value, str_cls):
            raise TypeError(pretty_message(
                '''
                Usage name sets may only contain unicode strings, not %s
                ''',
                type_name(value)
            ))
        if value in _KEY_USAGE_NAMES:
            key_usage.add(value)
        else:
            extended_key_usage.add(value)

    return key_usage, extended_key_usage


def _coerce_name_set(value, var_name):
    if value is None:
        return set()

    if isinstance(value, str_cls):
        return set([value])

    if isinstance(value, (set, frozenset)):
        output = set(value)
    elif isinstance(value, (list, tuple)):
        output = set(value)
    else:
        raise TypeError(pretty_message(
            '''
            %s must be a set of unicode strings, not %s
            ''',
            var_name,
            type_name(value)
        ))

    for entry in output:
        if not isinstance(entry, str_cls):
            raise TypeError(pretty_message(
                '''
                %s must contain only unicode strings, not %s
                ''',
                var_name,
                type_name(entry)
            ))

    return output


def _coerce_bool(value, var_name):
    if not isinstance(value, bool):
        raise TypeError(pretty_message(
            '''
            %s must be a boolean, not %s
            ''',
            var_name,
            type_name(value)
        ))
    return value


def _coerce_name(value, var_name):
    if value is None or isinstance(value, str_cls):
        return value
    raise TypeError(pretty_message(
        '''
        %s must be a unicode string, not %s
        ''',
        var_name,
        type_name(value)
    ))


def _coerce_cert_list(value, var_name):
    if value is None:
        return []

    if isinstance(value, (x509.Certificate, byte_cls)):
        values = [value]
    elif isinstance(value, (list, tuple)):
        values = list(value)
    else:
        raise TypeError(pretty_message(
            '''
            %s must be a certificate, a byte string or a list of certificates
            and byte strings, not %s
            ''',
            var_name,
            type_name(value)
        ))

    output = []
    for cert in values:
        if isinstance(cert, x509.Certificate):
            output.append(cert)
            continue

        if not isinstance(cert, byte_cls):
            raise TypeError(pretty_message(
                '''
                %s must contain only certificates and byte strings, not %s
                ''',
                var_name,
                type_name(cert)
            ))

        if pem.detect(cert):
            _, _, cert = pem.unarmor(cert)
        output.append(x509.Certificate.load(cert))

    return output


validate_joint_usages = validate_joint_usage

