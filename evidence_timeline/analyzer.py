"""
Time-line reconstruction for synthetic CMS evidence records.

The analyzer never validates signatures. Trust verdicts are supplied by the
caller through a :class:`TrustInputs` instance; this layer only recomputes
digests (structural hash comparison, not signature verification), locates the
exact byte ranges each time-stamp token committed to, and reconstructs which
earlier receipt each later receipt builds on.
"""

from __future__ import unicode_literals

import hashlib
from collections import OrderedDict

from asn1crypto import cms

from .model import (
    Commitment,
    Gap,
    RecordEntry,
    Timeline,
    TimelineEntry,
    TrustInput,
    TrustInputs,
)
from .offsets import ByteOffsetIndex
from .parser import parse_record


SIGNATURE_TST_ATTR = 'signature_time_stamp_token'
SIGNATURE_TST_ATTR_OID = '1.2.840.113549.1.9.16.2.14'
# Private-enterprise number reserved for the synthetic archive chain in this
# package. The attribute carries the whole previous record DER inside a
# counter-signed CMS structure, mirroring archive-time-stamp renewal semantics.
ARCHIVE_CHAIN_ATTR = '1.2.840.113549.1.9.16.6.100.1'


class _RecordContext(object):
    def __init__(self, record_id, blob, parsed, index):
        self.record_id = record_id
        self.blob = blob
        self.parsed = parsed
        self.index = index
        self.token_by_id = {}
        for token in parsed.tokens:
            self.token_by_id[token.token_id] = token

    def range_of(self, needle):
        return self.index.locate(needle, record_id=self.record_id)


class TimelineAnalyzer(object):
    """Reconstructs receipt history from caller-provided synthetic records."""

    def __init__(self, trust_inputs=None):
        self.trust_inputs = trust_inputs or TrustInputs()
        self._records = OrderedDict()

    def add_record(self, record_id, blob):
        parsed = parse_record(record_id, blob)
        index = ByteOffsetIndex(blob)
        self._records[record_id] = _RecordContext(record_id, blob, parsed, index)
        return parsed

    def build(self):
        record_entries = OrderedDict()
        token_entries = []
        for record_id, context in self._records.items():
            record_entry = self._build_record(context)
            record_entries[record_id] = record_entry
            token_entries.extend(record_entry.tokens)

        token_entries.sort(key=lambda entry: entry.generation_time)
        self._mark_repackaging(token_entries)
        gaps = self._build_gaps(token_entries)
        provable = self._provable_window(token_entries)
        return Timeline(
            records=list(record_entries.values()),
            timeline=token_entries,
            gaps=gaps,
            provable_window=provable,
        )

    def _build_record(self, context):
        entry = RecordEntry(
            record_id=context.record_id,
            content_type=context.parsed.content_type,
            record_digest=context.parsed.record_digest,
            blob_length=len(context.blob),
            envelope_path=list(context.parsed.envelope_path),
            tokens=[],
        )
        for token in context.parsed.tokens:
            entry.tokens.append(self._build_token(context, token))
        return entry

    def _build_token(self, context, token):
        commitment = self._resolve_commitment(context, token)
        predecessor = self._resolve_predecessor(context, token)
        return TimelineEntry(
            token_id=token.token_id,
            record_id=context.record_id,
            generation_time=token.generation_time,
            serial_number=token.serial_number,
            tsa_key_id=token.tsa_key_id,
            hash_algorithm=token.hash_algorithm,
            message_imprint=token.message_imprint,
            located_in=token.located_in,
            attribute_oid=token.attribute_oid,
            commitment=commitment,
            predecessor=predecessor,
            trust=self._trust_for(token),
        )

    def _resolve_commitment(self, context, token):
        for candidate in self._commitment_candidates(context, token):
            digest = hashlib.new(token.hash_algorithm, candidate.bytes).digest()
            if digest != token.message_imprint:
                continue
            located = context.range_of(candidate.bytes)
            if not located:
                continue
            return Commitment(
                status='matched',
                kind=candidate.kind,
                description=candidate.description,
                byte_ranges=located,
                matched_bytes=len(candidate.bytes),
            )
        return Commitment(
            status='unmatched',
            kind='unknown',
            description='no reachable bytes hash to the message imprint',
            byte_ranges=[],
            matched_bytes=0,
        )

    def _commitment_candidates(self, context, token):
        candidates = []
        signer_info = self._find_signer_info(context, token)
        if signer_info is not None:
            # RFC 3161 hashes the signature OCTET STRING content (the raw
            # signature bytes), not its tag/length header.
            candidates.append(_Candidate(
                signer_info['signature'].native,
                'signature_value',
                'content bytes of the signer signature OCTET STRING '
                '(RFC 3161 signature time-stamp)',
            ))
            candidates.append(_Candidate(
                signer_info.dump(),
                'signer_info',
                'DER of the SignerInfo carrying the receipt',
            ))
        for nested in self._nested_record_bytes(context, token):
            candidates.append(nested)
        candidates.append(_Candidate(
            context.blob,
            'whole_record',
            'DER of the whole outer CMS record (archive-style renewal)',
        ))
        candidates.sort(key=lambda candidate: -len(candidate.bytes))
        return candidates

    def _nested_record_bytes(self, context, token):
        result = []
        for nested in context.parsed.nested_records:
            if nested.bytes == token.token_der:
                continue
            result.append(_Candidate(
                nested.bytes,
                'nested_record',
                'DER of a nested ContentInfo at ' + '/'.join(nested.path),
            ))
        return result

    def _find_signer_info(self, context, token):
        for signer_info in context.parsed.signers:
            unsigned = signer_info['unsigned_attrs']
            if unsigned is None:
                continue
            for attribute in unsigned:
                for value in self._attribute_content_infos(attribute):
                    if value.dump() == token.token_der:
                        return signer_info
        return None

    def _attribute_content_infos(self, attribute):
        values = attribute['values']
        result = []
        for index in range(len(values)):
            value = values[index]
            if isinstance(value, cms.ContentInfo):
                result.append(value)
                continue
            try:
                result.append(cms.ContentInfo.load(value.dump()))
            except (ValueError, TypeError):
                continue
        return result

    def _resolve_predecessor(self, context, token):
        if token.attribute_oid == SIGNATURE_TST_ATTR:
            return None
        for record in self._records.values():
            if record.record_id == context.record_id:
                continue
            digest = hashlib.new(token.hash_algorithm, record.blob).digest()
            if digest == token.message_imprint:
                return record.record_id
            for nested in record.parsed.nested_records:
                for candidate in _nested_encodings(record.blob, nested):
                    nested_digest = hashlib.new(
                        token.hash_algorithm, candidate,
                    ).digest()
                    if nested_digest == token.message_imprint:
                        return record.record_id + ' (inner record, repackaged)'
        own_digest = hashlib.new(
            token.hash_algorithm, context.blob,
        ).digest()
        if own_digest == token.message_imprint:
            return None
        return 'unresolved'

    def _trust_for(self, token):
        return self.trust_inputs.token_verdicts.get(
            token.token_id,
            self.trust_inputs.default_verdict,
        )

    def _mark_repackaging(self, token_entries):
        imprint_groups = OrderedDict()
        for entry in token_entries:
            imprint_groups.setdefault(entry.message_imprint, []).append(entry)
        for entries in imprint_groups.values():
            if len(entries) < 2:
                continue
            records = set(entry.record_id for entry in entries)
            if len(records) > 1:
                for entry in entries:
                    entry.repackaged = True

    def _build_gaps(self, token_entries):
        gaps = []
        matched = [
            entry for entry in token_entries
            if entry.commitment.status == 'matched'
        ]
        for index, entry in enumerate(matched):
            predecessor = entry.predecessor
            if predecessor is None:
                continue
            if predecessor == 'unresolved':
                gaps.append(self._gap(
                    entry,
                    entry.message_imprint.hex(),
                    'receipt %s (%s) still imprints the immediately prior '
                    'record, but that predecessor segment is absent from the '
                    'supplied materials (expected sha256=%s). Only the '
                    'segment this receipt itself covers stays provable; the '
                    'missing original is not reverse-inferred.' % (
                        entry.token_id,
                        entry.generation_time.strftime('%Y-%m-%d'),
                        entry.message_imprint.hex(),
                    ),
                ))
                continue
            if predecessor not in self._records:
                if predecessor.endswith(' (inner record, repackaged)'):
                    continue
                gaps.append(self._gap(
                    entry,
                    entry.message_imprint.hex(),
                    'predecessor record %s is absent from the supplied '
                    'materials' % predecessor,
                ))
        return gaps

    def _gap(self, entry, missing_digest, reason):
        return Gap(
            after_token_id=entry.token_id,
            missing_record_digest=missing_digest,
            reason=reason,
            still_provable_from=entry.token_id,
        )

    def _provable_window(self, token_entries):
        window = []
        for entry in token_entries:
            if entry.commitment.status != 'matched':
                continue
            if entry.trust == TrustInput.REJECTED:
                continue
            window.append(entry.token_id)
        return window


class _Candidate(object):
    def __init__(self, data, kind, description):
        self.bytes = data
        self.kind = kind
        self.description = description


def _nested_encodings(blob, nested):
    """Yield candidate DER encodings for a nested object.

    A nested ContentInfo reached through an explicit-tagged field dumps with
    the surrounding context tag, while an imprint was calculated over the
    inner DER. The context header is either two bytes (short form) or more
    when the length is encoded in long form, so the header size is derived
    from the tag/length octets instead of being assumed constant.
    """

    seen = set()
    tagged = nested.bytes
    if tagged in seen:
        return
    seen.add(tagged)
    yield tagged
    if not tagged or tagged[0] != 0xA0:
        return
    header_length = 2
    if len(tagged) > 1 and tagged[1] & 0x80:
        header_length = 2 + (tagged[1] & 0x7F)
    inner = tagged[header_length:]
    if inner and inner not in seen:
        seen.add(inner)
        yield inner
