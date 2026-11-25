"""Parse-only extraction of synthetic CMS records and time-stamp receipts.

Only asn1crypto is used to decode the caller-provided bytes. Nothing here
checks a signature, evaluates a certificate chain, or decides whether a
time-stamp authority is trusted. Those verdicts arrive from the caller via
:class:`evidence_timeline.model.TrustInputs`.
"""

from __future__ import unicode_literals

import hashlib

from asn1crypto import cms, tsp

from .model import NestedRecord, ParsedRecord, TokenInfo


# Any unsigned attribute that structurally carries a ContentInfo is treated
# as a receipt slot; its OID is reported verbatim on the resulting token.


def parse_record(record_id, blob, envelope_path=None):
    """Parse one outer CMS blob, recursively collecting embedded receipts."""

    root = cms.ContentInfo.load(blob)
    tokens = []
    nested = []
    signers = []
    path = list(envelope_path or [root['content_type'].native])
    _collect(root, path, tokens, nested, signers)
    record_digest = hashlib.sha256(blob).digest()
    return ParsedRecord(
        record_id=record_id,
        content_type=root['content_type'].native,
        record_digest=record_digest,
        envelope_path=path,
        tokens=tokens,
        nested_records=nested,
        signers=signers,
    )


def _collect(content_info, path, tokens, nested, signers):
    content = content_info['content']
    if isinstance(content, cms.ContentInfo):
        child_path = path + ['content.' + content['content_type'].native]
        nested.append(NestedRecord(
            path=child_path,
            bytes=content.dump(),
            content_type=content['content_type'].native,
        ))
        _collect(content, child_path, tokens, nested, signers)
        return
    if not isinstance(content, cms.SignedData):
        return
    # The first SignedData on each branch owns its direct SignerInfo list.
    # SignedData reached through an unsigned attribute is a receipt token and
    # must not contribute its internal TST signer to the outer record.
    inside_unsigned = any('unsigned_attrs' in segment for segment in path)
    for signer_index, signer_info in enumerate(content['signer_infos']):
        if not inside_unsigned:
            signers.append(signer_info)
        _collect_unsigned(
            signer_info, signer_index, path, tokens, nested, signers,
        )
    # Encapsulated content is recorded as a nested object so commitment
    # ranges can be located, but receipts inside an embedded predecessor are
    # receipts of that predecessor, not of the current outer record.
    for content_info, child_path in _iter_embedded_content_infos(
        content['encap_content_info'], path,
    ):
        nested.append(NestedRecord(
            path=child_path,
            bytes=content_info.dump(),
            content_type=content_info['content_type'].native,
        ))


def _collect_unsigned(signer_info, signer_index, path, tokens, nested, signers):
    unsigned = signer_info['unsigned_attrs']
    if unsigned is None:
        return
    for attribute in unsigned:
        attribute_oid = attribute['type'].native
        for value in _iter_content_infos(attribute):
            token_path = path + [
                'signer_infos[%d].unsigned_attrs[%s]' % (
                    signer_index, attribute_oid,
                ),
            ]
            nested.append(NestedRecord(
                path=token_path,
                bytes=value.dump(),
                content_type=value['content_type'].native,
            ))
            token_info = _read_token(
                value, token_path, attribute_oid, signer_index,
            )
            if token_info is not None:
                tokens.append(token_info)
            _collect(value, token_path, tokens, nested, signers)


def _iter_content_infos(attribute):
    values = attribute['values']
    for index in range(len(values)):
        value = values[index]
        if isinstance(value, cms.ContentInfo):
            yield value
            continue
        try:
            yield cms.ContentInfo.load(value.dump())
        except (ValueError, TypeError):
            continue


def _iter_embedded_content_infos(node, path):
    if isinstance(node, cms.EncapsulatedContentInfo):
        octets = node['content']
        if octets is None:
            return
        try:
            raw_bytes = octets.native
        except (ValueError, TypeError):
            return
        try:
            embedded = cms.ContentInfo.load(raw_bytes)
        except (ValueError, TypeError):
            return
        yield embedded, path + ['encap_content_info.content']
    elif isinstance(node, cms.ContentInfo):
        content = node['content']
        if isinstance(content, cms.ContentInfo):
            yield content, path + ['content']


def _read_token(content_info, path, attribute_oid, signer_index):
    if content_info['content_type'].native != 'signed_data':
        return None
    signed_data = content_info['content']
    encap = signed_data['encap_content_info']
    try:
        tst_info = encap['content'].parsed
    except (ValueError, TypeError):
        return None
    if not isinstance(tst_info, tsp.TSTInfo):
        return None
    imprint = tst_info['message_imprint']
    signer_info = signed_data['signer_infos'][0]
    tsa_key_id = _signer_key_id(signer_info)
    serial = tst_info['serial_number'].native
    return TokenInfo(
        token_id='tst-serial-%s' % serial,
        token_der=content_info.dump(),
        generation_time=tst_info['gen_time'].native,
        serial_number=serial,
        tsa_key_id=tsa_key_id,
        hash_algorithm=imprint['hash_algorithm']['algorithm'].native,
        message_imprint=imprint['hashed_message'].native,
        located_in=list(path),
        attribute_oid=attribute_oid,
        signer_index=signer_index,
    )


def _signer_key_id(signer_info):
    sid = signer_info['sid']
    if sid.name == 'subject_key_identifier':
        return sid.chosen.native.hex()
    issuer_serial = sid.chosen
    return '%s#%s' % (
        issuer_serial['issuer'].human_friendly,
        issuer_serial['serial_number'].native,
    )
