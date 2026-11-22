# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import re

from ._ordereddict import OrderedDict
from ._types import byte_cls, int_types, str_cls
from . import pkcs12
from .x509 import Certificate


__all__ = [
    'DirectoryEntry',
    'ConflictGroup',
    'DirectoryReport',
    'reconcile',
    'directory',
    'inventory',
    'read_directory',
    'audit',
    'audit_directory',
    'inspect',
    'inspect_directory',
    'build_directory',
    'read_certificate_directory',
    'certificate_directory',
    'certificate_inventory',
    'inventory_certificates',
    'reconcile_certificates',
    'directory_report',
    'Pkcs12Directory',
    'CertificateDirectory',
]


_SECTION_ALIASES = {
    'resolved': 'resolved',
    'claimed': 'resolved',
    'identified': 'resolved',
    'matches': 'resolved',
    'conflicts': 'conflicts',
    'ambiguous': 'conflicts',
    'name_conflicts': 'conflicts',
    'not_visible': 'not_visible',
    'invisible': 'not_visible',
    'inaccessible': 'not_visible',
    'placeholders': 'not_visible',
    'unavailable': 'not_visible',
    'unmatched': 'unmatched',
    'unclaimed': 'unmatched',
    'catalog': 'catalog',
    'entries': 'catalog',
}


_REGISTRY_NAME_KEYS = (
    'friendly_name',
    'friendlyname',
    'friendly_name_bmp',
    'name',
    'label',
    'alias',
)

_REGISTRY_ID_KEYS = (
    'record_id',
    'registration_id',
    'id',
    'identifier',
)

_REGISTRY_SHA256_KEYS = (
    'sha256',
    'sha256_fingerprint',
    'sha256fingerprint',
    'sha256_thumbprint',
    'sha256thumbprint',
    'cert_sha256',
    'certsha256',
    'certificate_sha256',
    'fingerprint',
    'thumbprint',
    'certificate_id',
    'cert_id',
)

_REGISTRY_SHA1_KEYS = (
    'sha1',
    'sha1_fingerprint',
    'sha1fingerprint',
    'sha1_thumbprint',
    'sha1thumbprint',
    'cert_sha1',
    'certsha1',
    'certificate_sha1',
)

_SAFE_ATTRIBUTE_TYPES = set([
    'friendly_name',
    'local_key_id',
    'trusted_key_usage',
    'microsoft_csp_name',
])


def _to_unicode(value):
    if value is None:
        return None
    if isinstance(value, str_cls):
        return value
    if isinstance(value, byte_cls):
        return value.decode('utf-8', 'replace')
    return str_cls(value)


def _bytes_to_hex(value):
    if value is None:
        return None
    if isinstance(value, bytearray):
        value = bytes(value)
    if isinstance(value, byte_cls):
        if hasattr(value, 'hex'):
            return value.hex()
        return ''.join('%02x' % ord(c) for c in value)
    return _normalize_fingerprint(value)


def _normalize_fingerprint(value):
    if value is None:
        return None
    if isinstance(value, Certificate):
        return value.sha256.hex() if hasattr(value.sha256, 'hex') else _bytes_to_hex(value.sha256)
    if isinstance(value, bytearray):
        value = bytes(value)
    if isinstance(value, byte_cls):
        return _bytes_to_hex(value)
    text = _to_unicode(value)
    if text is None:
        return None
    text = text.strip().lower()
    for prefix in ('sha256:', 'sha-256:', 'sha1:', 'sha-1:', 'sha256=', 'sha1='):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    text = text.replace(':', '')
    text = text.replace(' ', '')
    text = text.replace('-', '')
    if re.match(r'^[0-9a-f]+$', text) is None:
        return text
    if len(text) % 2 == 0:
        return text
    return text


def _plain(value):
    if isinstance(value, DirectoryEntry):
        return value.to_dict()
    if isinstance(value, ConflictGroup):
        return value.to_dict()
    if isinstance(value, DirectoryReport):
        return value.to_dict()
    if isinstance(value, dict):
        out = OrderedDict()
        for key in value.keys():
            out[_to_unicode(key)] = _plain(value[key])
        return out
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, bytearray):
        return _bytes_to_hex(value)
    if isinstance(value, byte_cls):
        return _bytes_to_hex(value)
    if hasattr(value, 'isoformat'):
        return value.isoformat()
    return value


def _path_text(path):
    out = ''
    for part in path:
        if isinstance(part, int_types):
            out += '[%d]' % part
        else:
            if out != '':
                out += '.'
            out += _to_unicode(part)
    return out


def _container_info(path):
    info = OrderedDict()
    info['authenticated_safe_index'] = None
    info['safe_contents_depth'] = 0
    info['bag_index'] = None
    for index, part in enumerate(path):
        if part == 'authenticated_safe' and index + 1 < len(path):
            next_part = path[index + 1]
            if isinstance(next_part, int_types):
                info['authenticated_safe_index'] = next_part
        if part == 'safe_contents':
            info['safe_contents_depth'] += 1
            if index + 1 < len(path) and isinstance(path[index + 1], int_types):
                info['bag_index'] = path[index + 1]
    return info


def _name_summary(name):
    if name is None:
        return None
    out = OrderedDict()
    try:
        out['human_friendly'] = name.human_friendly
    except Exception:
        out['human_friendly'] = None
    try:
        out['sha256'] = _bytes_to_hex(name.sha256)
    except Exception:
        out['sha256'] = None
    try:
        native = name.native
        if isinstance(native, dict):
            normalized = OrderedDict()
            for key in native.keys():
                normalized[_to_unicode(key)] = _plain(native[key])
            out['native'] = normalized
        else:
            out['native'] = _plain(native)
    except Exception:
        out['native'] = None
    return out


def _certificate_summary(cert):
    if cert is None:
        return None
    if not isinstance(cert, Certificate):
        try:
            cert = Certificate.load(cert)
        except Exception:
            return None
    out = OrderedDict()
    try:
        out['sha256'] = _bytes_to_hex(cert.sha256)
    except Exception:
        out['sha256'] = None
    try:
        out['sha1'] = _bytes_to_hex(cert.sha1)
    except Exception:
        out['sha1'] = None
    try:
        out['sha256_fingerprint'] = cert.sha256_fingerprint
    except Exception:
        out['sha256_fingerprint'] = None
    try:
        out['serial_number'] = cert.serial_number
    except Exception:
        out['serial_number'] = None
    try:
        if out['serial_number'] is not None:
            out['serial_number_hex'] = '%x' % out['serial_number']
        else:
            out['serial_number_hex'] = None
    except Exception:
        out['serial_number_hex'] = None
    out['subject'] = _name_summary(cert.subject)
    out['issuer'] = _name_summary(cert.issuer)
    try:
        out['not_before'] = cert.not_valid_before.isoformat()
    except Exception:
        out['not_before'] = None
    try:
        out['not_after'] = cert.not_valid_after.isoformat()
    except Exception:
        out['not_after'] = None
    try:
        out['key_identifier'] = _bytes_to_hex(cert.key_identifier)
    except Exception:
        out['key_identifier'] = None
    return out


def _safe_attribute_value(attr_type, values):
    if attr_type == 'friendly_name':
        return [_to_unicode(value) for value in values]
    if attr_type == 'local_key_id':
        return [_bytes_to_hex(value) for value in values]
    if attr_type == 'trusted_key_usage':
        return [_to_unicode(value) for value in values]
    if attr_type == 'microsoft_csp_name':
        return [_to_unicode(value) for value in values]
    return None


def _read_bag_attributes(bag):
    friendly_names = []
    local_key_ids = []
    attributes = []
    try:
        bag_attributes = bag['bag_attributes']
    except Exception:
        bag_attributes = None
    if bag_attributes is None:
        return friendly_names, local_key_ids, attributes
    for attribute in bag_attributes:
        try:
            attr_type = attribute['type'].native
        except Exception:
            attr_type = 'unknown'
        attr_type = _to_unicode(attr_type)
        try:
            values = attribute['values'].native
        except Exception:
            values = []
        if not isinstance(values, (list, tuple)):
            values = [values]
        safe_values = _safe_attribute_value(attr_type, values)
        record = OrderedDict()
        record['type'] = attr_type
        if safe_values is None:
            record['values'] = None
            record['redacted'] = True
        else:
            record['values'] = safe_values
            record['redacted'] = False
            if attr_type == 'friendly_name':
                for value in safe_values:
                    if value not in friendly_names:
                        friendly_names.append(value)
            if attr_type == 'local_key_id':
                for value in safe_values:
                    if value is not None and value not in local_key_ids:
                        local_key_ids.append(value)
        attributes.append(record)
    return friendly_names, local_key_ids, attributes


def _bag_id(bag):
    try:
        return _to_unicode(bag['bag_id'].native)
    except Exception:
        try:
            return _to_unicode(bag['bag_id'].dotted)
        except Exception:
            return 'unknown'


def _parsed_bag_value(bag):
    try:
        value = bag['bag_value']
    except Exception:
        return None
    try:
        return value.parsed
    except Exception:
        return value


def _new_entry(path, bag_id):
    entry = DirectoryEntry()
    entry['path'] = tuple(path)
    entry['path_text'] = _path_text(path)
    entry['container'] = _container_info(path)
    entry['bag_id'] = bag_id
    entry['kind'] = None
    entry['placeholder'] = False
    entry['material_visible'] = False
    entry['material_status'] = 'unknown'
    entry['redacted'] = False
    entry['friendly_name'] = None
    entry['friendly_names'] = []
    entry['local_key_id'] = None
    entry['local_key_ids'] = []
    entry['certificate_id'] = None
    entry['certificate'] = None
    entry['bag_attributes'] = []
    entry['encryption_algorithm'] = None
    entry['encrypted_content_length'] = None
    entry['status'] = 'unmatched'
    entry['claim'] = None
    entry['reason'] = None
    entry['explanation'] = None
    entry['warnings'] = []
    return entry


def _finish_entry(entry, friendly_names, local_key_ids, attributes):
    entry['friendly_names'] = list(friendly_names)
    entry['friendly_name'] = friendly_names[0] if len(friendly_names) > 0 else None
    entry['local_key_ids'] = list(local_key_ids)
    entry['local_key_id'] = local_key_ids[0] if len(local_key_ids) > 0 else None
    entry['bag_attributes'] = attributes


def _entry_from_bag(bag, path, nested_entries):
    bag_id = _bag_id(bag)
    entry = _new_entry(path, bag_id)
    friendly_names, local_key_ids, attributes = _read_bag_attributes(bag)
    _finish_entry(entry, friendly_names, local_key_ids, attributes)
    value = _parsed_bag_value(bag)

    if bag_id == 'cert_bag':
        entry['kind'] = 'certificate'
        entry['material_visible'] = True
        entry['material_status'] = 'public_certificate'
        try:
            cert_id = _to_unicode(value['cert_id'].native)
        except Exception:
            cert_id = None
        entry['certificate_id'] = cert_id
        cert = None
        if cert_id == 'x509':
            try:
                cert = value['cert_value'].parsed
            except Exception:
                cert = None
        summary = _certificate_summary(cert) if cert is not None else None
        entry['certificate'] = summary
        if summary is None:
            entry['reason'] = 'certificate_material_unreadable'
            entry['material_visible'] = False
            entry['material_status'] = 'unreadable'
            entry['placeholder'] = True
            entry['status'] = 'not_visible'
            entry['explanation'] = 'Certificate bag is visible, but the certificate value could not be parsed.'
        return entry

    if bag_id in ('pkcs8_shrouded_key_bag', 'pkcs12_shrouded_key_bag'):
        entry['kind'] = 'private_key'
        entry['placeholder'] = True
        entry['material_visible'] = False
        entry['material_status'] = 'encrypted_private_key'
        entry['redacted'] = True
        entry['reason'] = 'encrypted_private_key'
        entry['status'] = 'not_visible'
        try:
            entry['encryption_algorithm'] = _to_unicode(value['encryption_algorithm']['algorithm'].native)
        except Exception:
            entry['encryption_algorithm'] = None
        entry['explanation'] = 'Encrypted private key material is not decoded or included in the report.'
        return entry

    if bag_id == 'key_bag':
        entry['kind'] = 'private_key'
        entry['placeholder'] = True
        entry['material_visible'] = False
        entry['material_status'] = 'private_key_redacted'
        entry['redacted'] = True
        entry['reason'] = 'private_key_redacted'
        entry['status'] = 'not_visible'
        entry['explanation'] = 'Private key material is deliberately redacted from the report.'
        return entry

    if bag_id == 'secret_bag':
        entry['kind'] = 'secret'
        entry['placeholder'] = True
        entry['material_visible'] = False
        entry['material_status'] = 'secret_redacted'
        entry['redacted'] = True
        entry['reason'] = 'secret_redacted'
        entry['status'] = 'not_visible'
        try:
            entry['certificate_id'] = _to_unicode(value['secret_type_id'].native)
        except Exception:
            entry['certificate_id'] = None
        entry['explanation'] = 'Secret bag material is deliberately redacted from the report.'
        return entry

    if bag_id == 'crl_bag':
        entry['kind'] = 'crl'
        entry['material_visible'] = True
        entry['material_status'] = 'public_crl'
        entry['reason'] = 'not_a_certificate'
        entry['status'] = 'unmatched'
        return entry

    if bag_id == 'safe_contents':
        entry['kind'] = 'safe_contents'
        entry['material_visible'] = True
        entry['material_status'] = 'public_container'
        entry['status'] = 'container'
        try:
            nested = value
            if nested is None:
                nested = bag['bag_value'].parsed
        except Exception:
            nested = None
        if nested is None:
            entry['placeholder'] = True
            entry['material_visible'] = False
            entry['reason'] = 'safe_contents_unreadable'
            entry['status'] = 'not_visible'
            entry['explanation'] = 'Nested safe contents could not be read.'
        else:
            _walk_safe_contents(nested, path, nested_entries)
        return entry

    entry['kind'] = 'unknown'
    entry['placeholder'] = True
    entry['material_visible'] = False
    entry['material_status'] = 'unsupported'
    entry['redacted'] = True
    entry['reason'] = 'unsupported_bag'
    entry['status'] = 'not_visible'
    entry['explanation'] = 'Unsupported bag type; bag material is not included in the report.'
    return entry


def _walk_safe_contents(safe_contents, path, entries):
    try:
        count = len(safe_contents)
    except Exception:
        return
    container_path = path + ('safe_contents',)
    for index in range(0, count):
        try:
            bag = safe_contents[index]
        except Exception:
            continue
        bag_path = container_path + (index,)
        entry = _entry_from_bag(bag, bag_path, entries)
        entries.append(entry)


def _content_type(content_info):
    try:
        return _to_unicode(content_info['content_type'].native)
    except Exception:
        return 'unknown'


def _encrypted_data_details(content_info):
    algorithm = None
    length = None
    try:
        encrypted_content_info = content_info['content']['encrypted_content_info']
        algorithm = _to_unicode(encrypted_content_info['content_encryption_algorithm']['algorithm'].native)
        encrypted_content = encrypted_content_info['encrypted_content']
        if encrypted_content.native is not None:
            length = len(encrypted_content.native)
    except Exception:
        pass
    return algorithm, length


def _walk_content_info(content_info, path, entries):
    ctype = _content_type(content_info)
    if ctype == 'data':
        try:
            data = content_info['content'].native
        except Exception:
            data = None
        if data is None:
            entry = _new_entry(path + ('safe_contents',), 'data')
            entry['kind'] = 'safe_contents'
            entry['placeholder'] = True
            entry['reason'] = 'empty_safe_contents'
            entry['status'] = 'not_visible'
            entry['explanation'] = 'Authenticated safe content is empty or unreadable.'
            entries.append(entry)
            return
        try:
            safe_contents = pkcs12.SafeContents.load(data)
        except Exception:
            entry = _new_entry(path + ('safe_contents',), 'data')
            entry['kind'] = 'safe_contents'
            entry['placeholder'] = True
            entry['material_status'] = 'unreadable'
            entry['reason'] = 'safe_contents_unreadable'
            entry['status'] = 'not_visible'
            entry['explanation'] = 'Authenticated safe content could not be parsed.'
            entries.append(entry)
            return
        _walk_safe_contents(safe_contents, path, entries)
        return

    if ctype == 'encrypted_data':
        entry = _new_entry(path + ('encrypted_data',), ctype)
        entry['kind'] = 'encrypted_safe_contents'
        entry['placeholder'] = True
        entry['material_visible'] = False
        entry['material_status'] = 'encrypted'
        entry['redacted'] = True
        entry['reason'] = 'encrypted_safe_contents'
        entry['status'] = 'not_visible'
        algorithm, length = _encrypted_data_details(content_info)
        entry['encryption_algorithm'] = algorithm
        entry['encrypted_content_length'] = length
        entry['explanation'] = 'Authenticated safe contents are encrypted; no bag or certificate material is visible.'
        entries.append(entry)
        return

    if ctype == 'signed_data':
        try:
            signed = content_info['content']
            nested = signed['content_info']
            _walk_content_info(nested, path + ('signed_data', 'content_info'), entries)
            return
        except Exception:
            pass

    entry = _new_entry(path + (ctype,), ctype)
    entry['kind'] = ctype
    entry['placeholder'] = True
    entry['material_visible'] = False
    entry['material_status'] = 'encrypted_or_unsupported'
    entry['redacted'] = True
    entry['reason'] = 'unsupported_content_type'
    entry['status'] = 'not_visible'
    entry['explanation'] = 'Content type %s is not readable by the public-material viewer.' % ctype
    entries.append(entry)


def _load_pfx(source):
    source_types = (pkcs12.Pfx, pkcs12.AuthenticatedSafe, pkcs12.SafeContents, pkcs12.SafeBag)
    if isinstance(source, source_types):
        return source
    if isinstance(source, bytearray):
        source = bytes(source)
    if isinstance(source, byte_cls):
        return pkcs12.Pfx.load(source)
    if hasattr(source, 'read'):
        return pkcs12.Pfx.load(source.read())
    if isinstance(source, str_cls):
        with open(source, 'rb') as handle:
            return pkcs12.Pfx.load(handle.read())
    raise TypeError('pfx must be a Pfx object, DER byte string or readable file object')


def _walk_source(source):
    if isinstance(source, pkcs12.AuthenticatedSafe):
        entries = []
        for index in range(0, len(source)):
            _walk_content_info(source[index], ('authenticated_safe', index), entries)
        return entries
    if isinstance(source, pkcs12.SafeContents):
        entries = []
        _walk_safe_contents(source, (), entries)
        return entries
    if isinstance(source, pkcs12.SafeBag):
        entries = []
        entries.append(_entry_from_bag(source, ('safe_bag',), entries))
        return entries
    return _walk_pfx(source)


def _walk_pfx(pfx):
    entries = []
    try:
        auth_safe = pfx['auth_safe']
    except Exception:
        entry = _new_entry(('auth_safe',), 'unknown')
        entry['kind'] = 'authenticated_safe'
        entry['placeholder'] = True
        entry['reason'] = 'auth_safe_unreadable'
        entry['status'] = 'not_visible'
        entry['explanation'] = 'The top-level authenticated safe could not be read.'
        entries.append(entry)
        return entries

    ctype = _content_type(auth_safe)
    prefix = ('auth_safe',)
    if ctype == 'signed_data':
        try:
            signed = auth_safe['content']
            content_info = signed['content_info']
            data = content_info['content'].native
            authenticated_safe = pkcs12.AuthenticatedSafe.load(data)
            prefix = ('auth_safe', 'signed_data', 'content_info')
        except Exception:
            authenticated_safe = None
    else:
        try:
            authenticated_safe = pfx.authenticated_safe
        except Exception:
            authenticated_safe = None

    if authenticated_safe is None:
        entry = _new_entry(prefix, ctype)
        entry['kind'] = 'authenticated_safe'
        entry['placeholder'] = True
        entry['reason'] = 'authenticated_safe_unreadable'
        entry['status'] = 'not_visible'
        entry['explanation'] = 'The authenticated safe could not be parsed without decryption.'
        entries.append(entry)
        return entries

    for index in range(0, len(authenticated_safe)):
        content_info = authenticated_safe[index]
        _walk_content_info(content_info, prefix + ('authenticated_safe', index), entries)
    return entries


def _first(record, keys):
    for key in keys:
        if key in record:
            value = record[key]
            if value is not None:
                return value
    return None


def _record_to_dict(record):
    if isinstance(record, dict):
        return record
    out = OrderedDict()
    for key in dir(record):
        if key.startswith('_'):
            continue
        try:
            value = getattr(record, key)
        except Exception:
            continue
        if callable(value):
            continue
        out[key] = value
    return out


def _serial_int(value):
    if value is None:
        return None
    if isinstance(value, int_types):
        return value
    if isinstance(value, byte_cls):
        return int(_bytes_to_hex(value), 16)
    text = _to_unicode(value).strip().lower()
    if text.startswith('0x'):
        try:
            return int(text[2:], 16)
        except Exception:
            return None
    if re.match(r'^[0-9]+$', text) is not None:
        try:
            return int(text, 10)
        except Exception:
            return None
    try:
        return int(text, 16)
    except Exception:
        return None


def _name_key(value):
    if value is None:
        return None
    if isinstance(value, dict):
        human = value.get('human_friendly')
        if human:
            return _to_unicode(human).strip().lower()
        native = value.get('native')
        if native is not None:
            value = native
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys()):
            item = value[key]
            if isinstance(item, (list, tuple)):
                item = ','.join([_to_unicode(part) for part in item])
            parts.append('%s=%s' % (_to_unicode(key), _to_unicode(item)))
        return ';'.join(parts).lower()
    return _to_unicode(value).strip().lower()


def _name_values(summary):
    if summary is None:
        return []
    native = summary.get('native')
    values = []
    if isinstance(native, dict):
        for key in native.keys():
            values.append(_to_unicode(key))
            value = native[key]
            if isinstance(value, (list, tuple)):
                for item in value:
                    values.append(_to_unicode(item))
            else:
                values.append(_to_unicode(value))
    else:
        human = summary.get('human_friendly')
        if human:
            values.append(_to_unicode(human))
    out = []
    for value in values:
        value = value.strip().lower()
        if value != '' and value not in out:
            out.append(value)
    return out


def _name_value_match(record_name, summary):
    if record_name is None or summary is None:
        return False
    if record_name == _name_key(summary):
        return True
    text = _to_unicode(record_name).lower()
    values = _name_values(summary)
    if len(values) == 0:
        return False
    for value in values:
        if value not in text:
            return False
    return True


def _normalize_record(record, fallback_id):
    record = _record_to_dict(record)
    lowered = OrderedDict()
    for key in record.keys():
        lowered[_to_unicode(key).lower().replace('-', '_')] = record[key]

    out = OrderedDict()
    out['record_id'] = _to_unicode(_first(lowered, _REGISTRY_ID_KEYS))
    if out['record_id'] is None:
        out['record_id'] = fallback_id
    out['friendly_name'] = _to_unicode(_first(lowered, _REGISTRY_NAME_KEYS))
    out['sha256'] = _normalize_fingerprint(_first(lowered, _REGISTRY_SHA256_KEYS))
    out['sha1'] = _normalize_fingerprint(_first(lowered, _REGISTRY_SHA1_KEYS))
    if out['sha256'] is not None and len(out['sha256']) == 40 and out['sha1'] is None:
        out['sha1'] = out['sha256']
        out['sha256'] = None
    elif out['sha1'] is not None and len(out['sha1']) == 64 and out['sha256'] is None:
        out['sha256'] = out['sha1']
        out['sha1'] = None
    local_key_id = _first(lowered, ('local_key_id', 'local_keyid', 'localkeyid', 'local_key_identifier'))
    out['local_key_id'] = _normalize_fingerprint(local_key_id)
    out['serial_number'] = _serial_int(_first(lowered, ('serial_number', 'serial', 'serialnumber')))
    out['issuer'] = _name_key(_first(lowered, ('issuer', 'issuer_name', 'issuername')))
    out['subject'] = _name_key(_first(lowered, ('subject', 'subject_name', 'subjectname')))

    cert = _first(lowered, ('certificate', 'cert', 'cert_object', 'certificateid', 'cert_id'))
    if cert is not None:
        summary = _certificate_summary(cert)
        if summary is not None:
            if out['sha256'] is None:
                out['sha256'] = summary['sha256']
            if out['sha1'] is None:
                out['sha1'] = summary['sha1']
            if out['serial_number'] is None:
                out['serial_number'] = summary['serial_number']
            if out['issuer'] is None and summary['issuer'] is not None:
                out['issuer'] = _name_key(summary['issuer'])
            if out['subject'] is None and summary['subject'] is not None:
                out['subject'] = _name_key(summary['subject'])

    return out


def _normalize_registry(registry):
    if registry is None:
        return []
    if isinstance(registry, dict):
        record_keys = set([
            'friendly_name', 'friendlyname', 'name', 'label', 'alias',
            'record_id', 'registration_id', 'id', 'identifier',
            'sha256', 'sha256_fingerprint', 'sha256fingerprint',
            'sha256_thumbprint', 'sha256thumbprint', 'thumbprint', 'fingerprint',
            'cert_sha256', 'certsha256', 'certificate_sha256',
            'sha1', 'sha1_fingerprint', 'sha1fingerprint',
            'sha1_thumbprint', 'sha1thumbprint',
            'cert_sha1', 'certsha1', 'certificate_sha1',
            'serial_number', 'serial', 'serialnumber',
            'issuer', 'issuer_name', 'issuername',
            'subject', 'subject_name', 'subjectname',
            'certificate', 'cert', 'cert_object', 'certificateid', 'cert_id',
            'local_key_id', 'localkeyid',
        ])
        lowered_keys = set([_to_unicode(key).lower().replace('-', '_') for key in registry.keys()])
        if len(lowered_keys.intersection(record_keys)) > 0:
            items = [registry]
        else:
            items = []
            for name in registry.keys():
                value = registry[name]
                if isinstance(value, (list, tuple)):
                    for item in value:
                        if isinstance(item, dict):
                            copy = OrderedDict(item)
                            if _first(copy, _REGISTRY_NAME_KEYS) is None:
                                copy['friendly_name'] = name
                            items.append(copy)
                        else:
                            items.append({'friendly_name': name, 'certificate': item})
                elif isinstance(value, dict):
                    copy = OrderedDict(value)
                    if _first(copy, _REGISTRY_NAME_KEYS) is None:
                        copy['friendly_name'] = name
                    items.append(copy)
                else:
                    items.append({'friendly_name': name, 'sha256': value})
    elif isinstance(registry, (list, tuple)):
        items = list(registry)
    else:
        items = [registry]

    out = []
    for index, item in enumerate(items):
        if isinstance(item, Certificate):
            item = {'certificate': item}
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            item = {'friendly_name': item[0], 'sha256': item[1]}
        out.append(_normalize_record(item, 'registration[%d]' % index))
    return out


def _record_match(record, entry):
    certificate = entry.get('certificate')
    if certificate is not None:
        if record['sha256'] is not None and certificate.get('sha256') == record['sha256']:
            return 'sha256', 100
        if record['sha1'] is not None and certificate.get('sha1') == record['sha1']:
            return 'sha1', 90
    if record['local_key_id'] is not None and record['local_key_id'] in entry['local_key_ids']:
        return 'local_key_id', 80

    serial_matches = False
    if record['serial_number'] is not None and certificate is not None:
        serial_matches = record['serial_number'] == certificate.get('serial_number')
    if serial_matches:
        issuer = certificate.get('issuer')
        subject = certificate.get('subject')
        if record['issuer'] is not None and _name_value_match(record['issuer'], issuer):
            return 'issuer_serial', 70
        if record['subject'] is not None and _name_value_match(record['subject'], subject):
            return 'subject_serial', 65
        if record['issuer'] is None and record['subject'] is None:
            return 'serial_number', 50
    return None, 0


def _claim(entry, record, basis, score, explanation):
    entry['claim'] = DirectoryEntry()
    entry['claim']['record_id'] = record['record_id']
    entry['claim']['basis'] = basis
    entry['claim']['strength'] = score
    entry['claim']['record'] = DirectoryEntry()
    for key in ('record_id', 'friendly_name', 'sha256', 'sha1', 'local_key_id', 'serial_number'):
        entry['claim']['record'][key] = record[key]
    entry['status'] = 'resolved'
    entry['reason'] = 'identified'
    if record['friendly_name'] is not None and record['friendly_name'] not in entry['friendly_names']:
        entry['warnings'].append('registration_name_mismatch')
        explanation += ' The registration friendly name differs from the bag friendly name.'
    entry['explanation'] = explanation


def _same_certificate(first, second):
    first_cert = first.get('certificate')
    second_cert = second.get('certificate')
    if first_cert is None or second_cert is None:
        return False
    return first_cert.get('sha256') is not None and first_cert.get('sha256') == second_cert.get('sha256')


def _resolve(entries, records):
    cert_entries = []
    for entry in entries:
        if entry.get('kind') == 'certificate' and entry.get('status') == 'unmatched':
            cert_entries.append(entry)

    entry_matches = {}
    record_matches = {}
    for entry_index in range(0, len(cert_entries)):
        entry = cert_entries[entry_index]
        entry_matches[entry_index] = []
        for record_index in range(0, len(records)):
            basis, score = _record_match(records[record_index], entry)
            if basis is not None:
                entry_matches[entry_index].append((score, record_index, basis))
                if record_index not in record_matches:
                    record_matches[record_index] = []
                record_matches[record_index].append(entry_index)

    claimed_records = set()
    claimed_entries = set()

    for record_index in record_matches.keys():
        matched_entries = record_matches[record_index]
        if len(matched_entries) == 1:
            entry_index = matched_entries[0]
            candidates = entry_matches[entry_index]
            if len(candidates) != 1:
                continue
            score, candidate_index, basis = candidates[0]
            if candidate_index != record_index:
                continue
            entry = cert_entries[entry_index]
            record = records[record_index]
            _claim(
                entry,
                record,
                basis,
                score,
                'Certificate identifier %s matches registration %s.' % (basis, record['record_id'])
            )
            claimed_records.add(record_index)
            claimed_entries.add(entry_index)
            continue

        all_same = True
        first_entry = cert_entries[matched_entries[0]]
        for entry_index in matched_entries[1:]:
            if not _same_certificate(first_entry, cert_entries[entry_index]):
                all_same = False
                break
        if all_same:
            first_index = matched_entries[0]
            first_entry = cert_entries[first_index]
            candidates = entry_matches[first_index]
            if len(candidates) == 1:
                score, candidate_index, basis = candidates[0]
                if candidate_index == record_index:
                    record = records[record_index]
                    _claim(
                        first_entry,
                        record,
                        basis,
                        score,
                        'Certificate identifier %s matches registration %s; duplicate copies use the first path.'
                        % (basis, record['record_id'])
                    )
                    claimed_records.add(record_index)
                    claimed_entries.add(first_index)
                    for entry_index in matched_entries[1:]:
                        cert_entries[entry_index]['warnings'].append('duplicate_certificate_material')
                    continue

    for record_index in record_matches.keys():
        if record_index in claimed_records:
            continue
        matched_entries = record_matches[record_index]
        if len(matched_entries) > 1:
            for entry_index in matched_entries:
                cert_entries[entry_index]['warnings'].append(
                    'registration_shared_by_multiple_entries'
                )

    for entry_index in range(0, len(cert_entries)):
        entry = cert_entries[entry_index]
        if entry_index in claimed_entries or entry['status'] == 'resolved':
            continue
        if len(entry_matches[entry_index]) > 1:
            entry['status'] = 'conflict'
            entry['reason'] = 'multiple_registration_matches'
            entry['explanation'] = 'More than one registration matches this certificate identifier.'
            continue
        if len(entry_matches[entry_index]) == 1:
            score, record_index, basis = entry_matches[entry_index][0]
            if record_index in claimed_records:
                entry['status'] = 'conflict'
                entry['reason'] = 'duplicate_registration_claim'
                entry['explanation'] = (
                    'Registration %s is already claimed by another entry; only one entry may claim a registration.'
                    % records[record_index]['record_id']
                )
            else:
                entry['status'] = 'conflict'
                entry['reason'] = 'registration_shared_by_multiple_entries'
                entry['explanation'] = (
                    'Registration %s matches more than one entry, so no single entry can be selected.'
                    % records[record_index]['record_id']
                )
            continue

        name = entry['friendly_name']
        if name is None:
            entry['status'] = 'unmatched'
            entry['reason'] = 'no_friendly_name'
            entry['explanation'] = 'The certificate has no friendly name and no registration identifier match.'
            continue
        named_records = []
        for record_index in range(0, len(records)):
            if records[record_index]['friendly_name'] == name:
                named_records.append(record_index)
        named_entries = []
        for other_index in range(0, len(cert_entries)):
            if cert_entries[other_index]['friendly_name'] == name:
                named_entries.append(other_index)
        available_records = [index for index in named_records if index not in claimed_records]
        if len(named_records) > 1:
            entry['status'] = 'conflict'
            entry['reason'] = 'duplicate_registration_name'
            entry['explanation'] = (
                'Friendly name %s occurs in more than one registration; the name alone cannot select one.' % name
            )
        elif len(named_entries) > 1:
            entry['status'] = 'conflict'
            entry['reason'] = 'duplicate_friendly_name'
            entry['explanation'] = (
                'Friendly name %s is shared by more than one entry; the name alone cannot select one.' % name
            )
        elif len(available_records) == 1:
            record_index = available_records[0]
            record = records[record_index]
            _claim(
                entry,
                record,
                'friendly_name',
                30,
                'Friendly name %s is unique in both the archive and the registration table.' % name
            )
            claimed_records.add(record_index)
            claimed_entries.add(entry_index)
        elif len(available_records) == 0 and len(named_records) == 1:
            entry['status'] = 'conflict'
            entry['reason'] = 'duplicate_registration_claim'
            entry['explanation'] = (
                'The only registration with friendly name %s is already claimed by another entry.' % name
            )
        else:
            entry['status'] = 'unmatched'
            entry['reason'] = 'not_registered'
            entry['explanation'] = 'No registration with this friendly name exists.'

    for entry in cert_entries:
        if entry['status'] == 'unmatched' and entry['reason'] is None:
            entry['reason'] = 'not_registered'
            entry['explanation'] = 'The certificate could not be matched to a registration.'


def _build_conflicts(entries, records, cert_entries):
    all_names = []
    for entry in entries:
        name = entry.get('friendly_name')
        if name is not None and name not in all_names:
            all_names.append(name)
    for record in records:
        name = record.get('friendly_name')
        if name is not None and name not in all_names:
            all_names.append(name)

    groups = []
    for name in sorted(all_names):
        group_entries = []
        for entry in entries:
            if entry.get('friendly_name') == name:
                group_entries.append(entry)
        group_records = []
        for record in records:
            if record.get('friendly_name') == name:
                group_records.append(record)
        if len(group_entries) <= 1 and len(group_records) <= 1:
            continue
        if len(group_entries) == 0:
            continue

        claimable = []
        unclaimed = []
        for entry in group_entries:
            if entry.get('claim') is not None:
                claimable.append(entry)
            else:
                unclaimed.append(entry)

        group = ConflictGroup()
        group['name'] = name
        group['entries'] = group_entries
        group['claimable_paths'] = [entry['path'] for entry in claimable]
        group['unclaimed_paths'] = [entry['path'] for entry in unclaimed]
        group['claimable'] = claimable
        group['unclaimed'] = unclaimed
        group['entry_count'] = len(group_entries)
        group['registration_count'] = len(group_records)
        group['reason'] = 'duplicate_friendly_name'

        if len(claimable) == 1 and len(unclaimed) > 0:
            claimed_entry = claimable[0]
            basis = claimed_entry['claim']['basis']
            unreadable_only = True
            for item in unclaimed:
                if not item.get('placeholder') and not item.get('redacted'):
                    unreadable_only = False
                    break
            if basis == 'friendly_name' and unreadable_only:
                explanation = (
                    'Friendly name %s is shared by %d entries, but only %s can be claimed: it is '
                    'the only visible certificate bag with that name. Placeholder entries have no '
                    'readable certificate material and cannot be claimed.'
                    % (name, len(group_entries), claimed_entry['path_text'])
                )
            else:
                explanation = (
                    'Friendly name %s is shared by %d entries, but only %s can be claimed: its %s '
                    'matches registration %s. Friendly-name-only evidence is not unique, so the other '
                    'entries remain unclaimed.'
                    % (name, len(group_entries), claimed_entry['path_text'], basis, claimed_entry['claim']['record_id'])
                )
        elif len(claimable) > 1:
            explanation = (
                'Friendly name %s is shared by %d entries; %d entries have distinct certificate '
                'identifier matches, so each of those may be claimed independently.'
                % (name, len(group_entries), len(claimable))
            )
        elif len(group_records) > 1:
            explanation = (
                'Friendly name %s occurs in %d registrations and %d archive entries; the name alone '
                'cannot select a single owner.'
                % (name, len(group_records), len(group_entries))
            )
        else:
            explanation = (
                'Friendly name %s is shared by %d entries and no entry has a unique certificate '
                'identifier match, so none can be claimed from the name alone.'
                % (name, len(group_entries))
            )
        group['explanation'] = explanation
        groups.append(group)
    return groups


class DirectoryEntry(dict):
    def __getattr__(self, name):
        if name in self:
            return self[name]
        raise AttributeError(name)

    def to_dict(self):
        return _plain(dict(self))


class ConflictGroup(dict):
    def __getattr__(self, name):
        if name in self:
            return self[name]
        raise AttributeError(name)

    def to_dict(self):
        out = OrderedDict()
        for key in self.keys():
            if key in ('entries', 'claimable', 'unclaimed'):
                out[key] = [_plain(item) for item in self[key]]
            else:
                out[key] = _plain(self[key])
        return out


class DirectoryReport(dict):
    def __init__(self, resolved=None, conflicts=None, not_visible=None, unmatched=None, catalog=None):
        dict.__init__(self)
        if resolved is None:
            resolved = []
        if conflicts is None:
            conflicts = []
        if not_visible is None:
            not_visible = []
        if unmatched is None:
            unmatched = []
        if catalog is None:
            catalog = []
        self['resolved'] = resolved
        self['conflicts'] = conflicts
        self['not_visible'] = not_visible
        self['unmatched'] = unmatched
        self['catalog'] = catalog

    def conflict_entries(self):
        out = []
        for group in self['conflicts']:
            for entry in group['entries']:
                if entry not in out:
                    out.append(entry)
        return out

    def __getitem__(self, key):
        if key in ('conflict_entries', 'conflicting_entries'):
            return self.conflict_entries()
        if key in ('review_table', 'review_rows'):
            return self.review_table()
        if key in ('review_text', 'table'):
            return self.format_review_table()
        canonical = _SECTION_ALIASES.get(key, key)
        return dict.__getitem__(self, canonical)

    def __contains__(self, key):
        if key in ('conflict_entries', 'conflicting_entries'):
            return True
        if key in ('review_table', 'review_rows', 'review_text', 'table'):
            return True
        canonical = _SECTION_ALIASES.get(key, key)
        return dict.__contains__(self, canonical)

    def get(self, key, default=None):
        canonical = _SECTION_ALIASES.get(key, key)
        return dict.get(self, canonical, default)

    def __getattr__(self, name):
        canonical = _SECTION_ALIASES.get(name, name)
        if canonical in self:
            return dict.__getitem__(self, canonical)
        raise AttributeError(name)

    def to_dict(self):
        out = OrderedDict()
        for key in self.keys():
            out[key] = _plain(self[key])
        return out

    def review_table(self):
        rows = []
        for entry in self['resolved']:
            rows.append(_review_row('resolved', entry, entry.get('explanation')))
        for group in self['conflicts']:
            for entry in group['entries']:
                if entry.get('claim') is not None:
                    continue
                rows.append(_review_row('conflict', entry, group.get('explanation')))
        for entry in self['not_visible']:
            rows.append(_review_row('not_visible', entry, entry.get('explanation')))
        for entry in self['unmatched']:
            if entry.get('kind') != 'certificate':
                continue
            rows.append(_review_row('unmatched', entry, entry.get('explanation')))
        return rows

    def summary(self):
        out = OrderedDict()
        out['resolved'] = len(self['resolved'])
        out['conflicts'] = len(self['conflicts'])
        out['conflict_entries'] = 0
        for group in self['conflicts']:
            out['conflict_entries'] += len(group['entries'])
        out['not_visible'] = len(self['not_visible'])
        out['unmatched'] = len(self['unmatched'])
        out['catalog'] = len(self['catalog'])
        return out

    def review_rows(self):
        return self.review_table()

    def to_table(self):
        return self.format_review_table()

    def table(self):
        return self.format_review_table()

    def review_text(self):
        return self.format_review_table()

    def format_review_table(self):
        rows = self.review_table()
        headers = ['Section', 'Path', 'Friendly Name', 'Placeholder', 'Claim', 'Explanation']
        widths = []
        for header in headers:
            widths.append(len(header))
        for row in rows:
            values = [
                row['section'],
                row['path'],
                row.get('friendly_name') or '',
                'yes' if row['placeholder'] else 'no',
                row.get('claim') or '',
                row.get('explanation') or '',
            ]
            for index in range(0, len(values)):
                widths[index] = max(widths[index], len(_to_unicode(values[index])))
        lines = []
        line = []
        for index in range(0, len(headers)):
            line.append(headers[index].ljust(widths[index]))
        lines.append(' | '.join(line))
        lines.append('-+-'.join(['-' * width for width in widths]))
        for row in rows:
            values = [
                row['section'],
                row['path'],
                row.get('friendly_name') or '',
                'yes' if row['placeholder'] else 'no',
                row.get('claim') or '',
                row.get('explanation') or '',
            ]
            line = []
            for index in range(0, len(values)):
                line.append(_to_unicode(values[index]).ljust(widths[index]))
            lines.append(' | '.join(line))
        return '\n'.join(lines)


Pkcs12Directory = DirectoryReport
CertificateDirectory = DirectoryReport


def _review_row(section, entry, explanation):
    certificate = entry.get('certificate') or {}
    claim = entry.get('claim')
    return {
        'section': section,
        'path': entry.get('path_text'),
        'kind': entry.get('kind'),
        'friendly_name': entry.get('friendly_name'),
        'placeholder': entry.get('placeholder', False),
        'certificate_sha256': certificate.get('sha256'),
        'certificate_serial': certificate.get('serial_number'),
        'claim': claim.get('record_id') if claim is not None else None,
        'status': entry.get('status'),
        'explanation': explanation,
    }


def reconcile(pfx, registry=None, **kwargs):
    if registry is None:
        for key in ('registration', 'registrations', 'records', 'register', 'manifest'):
            if key in kwargs:
                registry = kwargs[key]
                break
    pfx_obj = _load_pfx(pfx)
    entries = _walk_source(pfx_obj)
    records = _normalize_registry(registry)
    for entry in entries:
        entry['path_parts'] = list(entry['path'])
        entry['hierarchy'] = list(entry['path'])
        entry['index_path'] = [part for part in entry['path'] if isinstance(part, int_types)]
        entry['container_path'] = entry['path_text']
        entry['is_placeholder'] = entry['placeholder']
        entry['visible'] = entry['material_visible']
        entry['invisible'] = not entry['material_visible']
        entry['private'] = entry['kind'] == 'private_key'
        certificate = entry.get('certificate')
        if certificate is not None:
            entry['certificate_sha256'] = certificate.get('sha256')
            entry['certificate_sha1'] = certificate.get('sha1')
            entry['certificate_serial'] = certificate.get('serial_number')
            entry['subject'] = certificate.get('subject')
            entry['issuer'] = certificate.get('issuer')
        else:
            entry['certificate_sha256'] = None
            entry['certificate_sha1'] = None
            entry['certificate_serial'] = None
            entry['subject'] = None
            entry['issuer'] = None
    _resolve(entries, records)
    for entry in entries:
        claim = entry.get('claim')
        entry['claim_basis'] = claim.get('basis') if claim is not None else None
        entry['claimed_by'] = claim.get('record_id') if claim is not None else None
        binding = DirectoryEntry()
        binding['path'] = entry['path']
        binding['path_text'] = entry['path_text']
        binding['container'] = entry['container']
        binding['placeholder'] = entry['placeholder']
        binding['material_visible'] = entry['material_visible']
        binding['record_id'] = entry['claimed_by']
        binding['basis'] = entry['claim_basis']
        entry['binding'] = binding

    cert_entries = [entry for entry in entries if entry.get('kind') == 'certificate']
    resolved = [entry for entry in entries if entry.get('status') == 'resolved']
    not_visible = [entry for entry in entries if entry.get('status') == 'not_visible']
    conflicts = _build_conflicts(entries, records, cert_entries)
    unmatched = []
    for entry in cert_entries:
        if entry.get('status') == 'conflict':
            continue
        if entry.get('status') == 'resolved':
            continue
        if entry.get('status') == 'unmatched':
            unmatched.append(entry)

    return DirectoryReport(resolved, conflicts, not_visible, unmatched, entries)


directory = reconcile
inventory = reconcile
read_directory = reconcile
build_directory = reconcile
audit = reconcile
audit_directory = reconcile
inspect = reconcile
inspect_directory = reconcile
read_certificate_directory = reconcile
certificate_directory = reconcile
certificate_inventory = reconcile
inventory_certificates = reconcile
reconcile_certificates = reconcile
directory_report = reconcile
