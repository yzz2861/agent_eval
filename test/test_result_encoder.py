import csv
import io
import json

import pytest

from ssh_audit.result_encoder import ResultEncoder


# pylint: disable=attribute-defined-outside-init
class TestResultEncoder:
    @pytest.fixture(autouse=True)
    def init(self):
        self.ResultEncoder = ResultEncoder

    @staticmethod
    def _sample_struct():
        '''A structured result resembling ssh_audit.build_struct() output, with hostile content mixed in.'''
        return {
            'banner': {
                'raw': 'SSH-2.0-OpenSSH_7.3\nspoofed second line',
                'protocol': '2.0',
                'software': 'OpenSSH_7.3‮dpa',
                'comments': None,
            },
            'target': 'localhost:22',
            'compression': ['none'],
            'kex': [
                {'algorithm': 'curve25519-sha256', 'notes': {'info': ['available since OpenSSH 7.4']}},
                {'algorithm': '=cmd|/c calc!A0', 'notes': {'fail': ['unknown algorithm']}},
            ],
            'key': [],
            'enc': [],
            'mac': [],
            'fingerprints': [],
            'cves': [],
            'recommendations': {},
            'additional_notes': [],
        }

    # JSON encoding.

    def test_json_roundtrip_preserves_raw_unicode(self):
        res = self._sample_struct()
        text = self.ResultEncoder.to_json(res)
        # Raw Unicode (including the U+202E bidi override) is preserved, not escaped.
        assert '‮' in text
        assert '\\u202e' not in text
        # Newlines inside strings remain JSON-escaped, so records are never split.
        assert '\\nspoofed' in json.dumps(json.loads(text))
        assert json.loads(text) == res

    def test_json_roundtrip_with_indent(self):
        res = self._sample_struct()
        assert json.loads(self.ResultEncoder.to_json(res, indent=4)) == res

    def test_json_preserves_existing_keys_and_order(self):
        res = self._sample_struct()
        parsed = json.loads(self.ResultEncoder.to_json(res))
        assert set(parsed.keys()) == set(res.keys())
        assert set(parsed['banner'].keys()) == {'raw', 'protocol', 'software', 'comments'}

    def test_json_rejects_nul(self):
        res = self._sample_struct()
        res['banner']['software'] = 'OpenSSH_7.3\x00evil'
        with pytest.raises(ValueError) as excinfo:
            self.ResultEncoder.to_json(res)
        excinfo.match(r'.*NUL.*')

    def test_json_rejects_unpaired_surrogates(self):
        for bad in ['\ud800', '\udfff', '\ud800\ud800']:
            res = self._sample_struct()
            res['banner']['software'] = 'OpenSSH' + bad
            with pytest.raises(ValueError) as excinfo:
                self.ResultEncoder.to_json(res)
            excinfo.match(r'.*surrogate.*')

    def test_json_missing_fields(self):
        # Minimal/degenerate structures must still encode.
        assert json.loads(self.ResultEncoder.to_json({})) == {}
        assert json.loads(self.ResultEncoder.to_json({'banner': {'raw': '', 'protocol': None, 'software': None, 'comments': None}}))['banner']['software'] is None

    # CSV encoding.

    def _parse_csv(self, text):
        return list(csv.reader(io.StringIO(text)))

    def test_csv_rfc4180_quoting(self):
        res = self._sample_struct()
        res['banner']['comments'] = 'has, comma and "quote" and\nnewline'
        rows = self._parse_csv(self.ResultEncoder.to_csv(res))
        values = {row[0]: row[1] for row in rows[1:]}
        # The csv module must be able to recover the exact original value.
        assert values['banner.comments'] == 'has, comma and "quote" and\nnewline'

    def test_csv_uses_crlf_line_endings(self):
        text = self.ResultEncoder.to_csv({'a': 'b'})
        assert '\r\n' in text

    def test_csv_formula_injection_guard(self):
        res = self._sample_struct()
        res['banner']['software'] = '=HYPERLINK("http://evil")'
        res['target'] = '+1-555-1234'
        res['kex'][0]['algorithm'] = '-2+3+cmd'
        res['kex'][1]['algorithm'] = '@SUM(A1:A9)'
        rows = self._parse_csv(self.ResultEncoder.to_csv(res))
        values = {row[0]: row[1] for row in rows[1:]}
        assert values['banner.software'] == "'=HYPERLINK(\"http://evil\")"
        assert values['target'] == "'+1-555-1234"
        assert values['kex[0].algorithm'] == "'-2+3+cmd"
        assert values['kex[1].algorithm'] == "'@SUM(A1:A9)"
        # No unguarded formula prefix may remain in any cell.
        for row in rows:
            for cell in row:
                assert not cell.startswith(('=', '+', '-', '@'))

    def test_csv_formula_guard_is_reversible(self):
        for original in ['=1+1', '+x', '-x', '@x']:
            guarded = self.ResultEncoder.csv_safe_field(original)
            assert guarded == "'" + original
            # Documented recovery: strip one leading apostrophe before a formula prefix.
            assert guarded[1:] == original
        # Ordinary values (including leading apostrophes in data) pass through unchanged.
        assert self.ResultEncoder.csv_safe_field('plain') == 'plain'
        assert self.ResultEncoder.csv_safe_field('') == ''

    def test_csv_roundtrip_from_same_struct(self):
        res = self._sample_struct()
        rows = self._parse_csv(self.ResultEncoder.to_csv(res))
        assert rows[0] == ['field', 'value']
        values = {row[0]: row[1] for row in rows[1:]}
        assert values['target'] == 'localhost:22'
        assert values['banner.raw'] == 'SSH-2.0-OpenSSH_7.3\nspoofed second line'
        assert values['banner.software'] == 'OpenSSH_7.3‮dpa'
        assert values['banner.comments'] == ''  # None flattens to an empty field.
        assert values['kex[0].algorithm'] == 'curve25519-sha256'
        assert values['kex[0].notes.info[0]'] == 'available since OpenSSH 7.4'

    def test_csv_empty_and_missing_fields(self):
        res = self._sample_struct()
        rows = self._parse_csv(self.ResultEncoder.to_csv(res))
        fields = [row[0] for row in rows[1:]]
        # Empty containers are present as rows with empty values, so downstream can tell them apart from missing fields.
        assert 'key' in fields
        assert 'cves' in fields
        assert 'additional_notes' in fields
        # Degenerate structures still produce a valid document.
        assert self._parse_csv(self.ResultEncoder.to_csv({}))[0] == ['field', 'value']

    def test_csv_field_order_matches_struct(self):
        res = self._sample_struct()
        rows = self._parse_csv(self.ResultEncoder.to_csv(res))
        fields = [row[0] for row in rows[1:]]
        assert fields[0].startswith('banner.')
        assert fields.index('target') < fields.index('compression[0]') < fields.index('kex[0].algorithm')

    # Terminal encoding.

    def test_escape_terminal_control_characters(self):
        esc = self.ResultEncoder.escape_terminal
        assert esc('a\x1b[2Jb') == 'a\\x1b[2Jb'
        assert esc('a\tb') == 'a\\tb'
        assert esc('a\rb') == 'a\\rb'
        assert esc('a\x00b') == 'a\\x00b'
        assert esc('a\x7fb') == 'a\\x7fb'
        assert esc('a\x85b') == 'a\\x85b'
        # Newlines carry the line structure and are preserved.
        assert esc('line1\nline2') == 'line1\nline2'
        # Printable text is untouched.
        assert esc('SSH-2.0-OpenSSH_7.3 comment') == 'SSH-2.0-OpenSSH_7.3 comment'

    def test_escape_terminal_bidi_and_format_characters(self):
        esc = self.ResultEncoder.escape_terminal
        assert esc('OpenSSH‮dpa') == 'OpenSSH\\u202edpa'
        assert esc('a‎b') == 'a\\u200eb'
        assert esc('a﻿b') == 'a\\ufeffb'

    def test_escape_terminal_unpaired_surrogates(self):
        assert self.ResultEncoder.escape_terminal('a\ud800b') == 'a\\ud800b'

    def test_escape_terminal_is_explainable_and_reversible(self):
        # The escapes follow Python-style syntax, so they decode back to the original.
        original = 'tab\t cr\r esc\x1b bidi‮ end'
        escaped = self.ResultEncoder.escape_terminal(original)
        assert escaped.encode().decode('unicode_escape') == original

    # Sanitization: redaction & truncation.

    def test_sensitive_fields_are_redacted(self):
        res = {
            'private_key': '-----BEGIN OPENSSH PRIVATE KEY-----',
            'password': 'hunter2',
            'Handshake_Data': 'raw handshake bytes',
            'kexinit_payload': 'full packet',
            'banner': {'raw': 'SSH-2.0-OpenSSH_7.3'},
        }
        sanitized = self.ResultEncoder.sanitize_struct(res)
        assert sanitized['private_key'] == '[REDACTED]'
        assert sanitized['password'] == '[REDACTED]'
        assert sanitized['Handshake_Data'] == '[REDACTED]'
        assert sanitized['kexinit_payload'] == '[REDACTED]'
        # The banner's raw identification string is not sensitive and must survive.
        assert sanitized['banner']['raw'] == 'SSH-2.0-OpenSSH_7.3'
        # Redaction is applied in every output format.
        assert 'hunter2' not in self.ResultEncoder.to_json(res)
        assert 'hunter2' not in self.ResultEncoder.to_csv(res)

    def test_overlong_fields_are_truncated_and_marked(self):
        res = self._sample_struct()
        res['banner']['comments'] = 'A' * 5000
        sanitized = self.ResultEncoder.sanitize_struct(res)
        assert len(sanitized['banner']['comments']) == ResultEncoder.MAX_FIELD_LENGTH + len(ResultEncoder.TRUNCATION_MARKER)
        assert sanitized['banner']['comments'].endswith('...[truncated]')
        # Truncation is visible in every output format.
        assert '...[truncated]' in self.ResultEncoder.to_json(res)
        assert '...[truncated]' in self.ResultEncoder.to_csv(res)

    def test_sanitize_does_not_modify_caller_struct(self):
        res = self._sample_struct()
        res['banner']['comments'] = 'A' * 5000
        self.ResultEncoder.to_json(res)
        assert len(res['banner']['comments']) == 5000

    # All formats are generated from the same structured result.

    def test_all_formats_from_same_struct(self):
        res = self._sample_struct()
        json_text = self.ResultEncoder.to_json(res)
        csv_text = self.ResultEncoder.to_csv(res)
        terminal_text = self.ResultEncoder.escape_terminal(res['banner']['raw'])
        # JSON round-trips back to the original structure.
        assert json.loads(json_text)['banner']['software'] == 'OpenSSH_7.3‮dpa'
        # CSV carries the same values (with formula guarding where needed).
        assert 'OpenSSH_7.3‮dpa' in csv_text
        # Terminal output shows the newline as structure and would escape control characters.
        assert terminal_text == 'SSH-2.0-OpenSSH_7.3\nspoofed second line'
