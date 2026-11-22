import base64
import hashlib
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import TestCase

from .__main__ import main
from .archive import (
    ArchiveConflictError,
    render_review,
    review_archives,
    sanitize_archive,
)
from .sanitizer import Sanitizer


FIXTURES = Path(__file__).with_name("tests_data")


def fixture(name):
    return base64.b64decode((FIXTURES / name).read_bytes())


class ArchiveTestCase(TestCase):
    def test_legacy_gb18030_can_sign_off(self):
        data = fixture("legacy_gb18030.html.b64")
        result = sanitize_archive(data, "gb18030", source="archive/legacy.html")

        self.assertTrue(result.ok)
        self.assertTrue(result.can_sign_off)
        self.assertEqual(result.status, "accepted")
        self.assertEqual(result.declared_encoding, "gb18030")
        self.assertEqual(result.encoding, "gb18030")
        self.assertIsInstance(result.html, str)
        self.assertIn("旧档:一九九八年十月,经费已核。", result.html)
        self.assertEqual(result.input_range.start, 0)
        self.assertEqual(result.input_range.end, len(data))
        self.assertEqual(result.input_range.source, "archive/legacy.html")
        self.assertEqual(result.digest, hashlib.sha256(data).hexdigest())
        self.assertEqual([item.kind for item in result.metadata], ["html-meta"])
        self.assertEqual(result.metadata[0].encoding, "gb18030")
        self.assertIsNone(result.error)

    def test_ambiguous_material_cannot_sign_off(self):
        data = fixture("ambiguous_utf8.html.b64")
        result = sanitize_archive(data, "utf-8", source="archive/ambiguous.html")

        self.assertFalse(result.ok)
        self.assertFalse(result.can_sign_off)
        self.assertEqual(result.status, "conflict")
        self.assertIsNone(result.html)
        self.assertIsNone(result.text)
        self.assertEqual(result.digest, hashlib.sha256(data).hexdigest())

        conflict = result.error
        self.assertEqual(conflict.code, "metadata_mismatch")
        self.assertEqual(conflict.source, "archive/ambiguous.html")
        self.assertEqual(conflict.metadata_kind, "html-meta")
        self.assertEqual(conflict.metadata_encoding, "cp1252")
        self.assertEqual(conflict.position.byte_offset, 27)
        self.assertEqual(conflict.position.line, 1)
        self.assertGreater(conflict.position.column, 0)
        self.assertIn("windows-1252", conflict.message)
        self.assertIn("utf-8", conflict.message)

    def test_undecodable_bytes_report_exact_position(self):
        data = b"<p>ok " + b"\xff" + b"</p>"
        result = sanitize_archive(data, "utf-8", source="archive/broken.html")

        conflict = result.error
        self.assertEqual(conflict.code, "undecodable_bytes")
        self.assertEqual(conflict.source, "archive/broken.html")
        self.assertEqual(conflict.position.byte_offset, 6)
        self.assertEqual(conflict.position.line, 1)
        self.assertEqual(conflict.position.column, 7)
        self.assertEqual(conflict.byte_range.start, 6)

    def test_bom_mismatch_is_conflict(self):
        data = "\ufeff<p>hello</p>".encode()
        result = sanitize_archive(data, "cp1252", source="archive/bom.html")

        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "bom_mismatch")
        self.assertEqual(result.error.position.byte_offset, 0)
        self.assertEqual(result.metadata[0].kind, "bom")

    def test_body_metadata_can_supply_missing_declaration(self):
        data = fixture("legacy_gb18030.html.b64")
        result = sanitize_archive(data, None, source="archive/meta-only.html")

        self.assertTrue(result.ok)
        self.assertEqual(result.declared_encoding, "gb18030")
        self.assertIn("旧档:一九九八年十月,经费已核。", result.html)

    def test_mime_evidence_supports_old_encoding(self):
        body = "<p>旧档</p>".encode("gb18030")
        data = (
            b"Content-Type: text/html; charset=gb18030\r\n"
            b"MIME-Version: 1.0\r\n\r\n" + body
        )
        result = sanitize_archive(data, "gb18030", source="archive/mail.eml")

        self.assertTrue(result.ok)
        self.assertEqual(result.input_range.start, data.index(body))
        self.assertEqual(result.metadata[0].kind, "mime")
        self.assertEqual(result.metadata[0].encoding, "gb18030")

    def test_mime_header_mismatch_is_reported_at_the_header(self):
        body = "<p>Résumé</p>".encode()
        data = (
            b"Content-Type: text/html; charset=windows-1252\r\n"
            b"MIME-Version: 1.0\r\n\r\n" + body
        )
        result = sanitize_archive(data, "utf-8", source="archive/mail.eml")

        self.assertFalse(result.ok)
        self.assertEqual(result.error.metadata_kind, "mime")
        self.assertIn(result.error.code, {"metadata_mismatch", "metadata_undecodable"})
        self.assertEqual(result.error.source, "archive/mail.eml")
        self.assertGreater(result.error.position.byte_offset, 0)

    def test_meta_http_equiv_is_checked(self):
        data = (
            '<meta http-equiv="Content-Type" content="text/html; charset=gb18030">'
            "<p>旧档</p>"
        ).encode("gb18030")
        result = sanitize_archive(data, "gb18030", source="archive/http-equiv.html")

        self.assertTrue(result.ok)
        self.assertEqual(result.metadata[0].kind, "html-meta")
        self.assertEqual(result.metadata[0].encoding, "gb18030")

    def test_require_metadata_rejects_uncorroborated_declaration(self):
        data = "<p>café</p>".encode("cp1252")
        lenient = sanitize_archive(data, "cp1252", source="archive/legacy.html")
        self.assertTrue(lenient.ok)

        strict = sanitize_archive(
            data,
            "cp1252",
            source="archive/legacy.html",
            require_metadata=True,
        )
        self.assertFalse(strict.ok)
        self.assertEqual(strict.error.code, "missing_metadata")

    def test_unlabelled_legacy_bytes_with_two_interpretations(self):
        data = "<p>Résumé</p>".encode()
        result = sanitize_archive(data, "cp1252", source="archive/two-readings.html")

        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "ambiguous_interpretation")

    def test_review_interface_distinguishes_signable_material(self):
        legacy = fixture("legacy_gb18030.html.b64")
        ambiguous = fixture("ambiguous_utf8.html.b64")
        report = review_archives(
            [
                ("archive/legacy.html", legacy, "gb18030"),
                ("archive/ambiguous.html", ambiguous, "utf-8"),
            ]
        )
        lines = report.splitlines()
        self.assertTrue(lines[0].startswith("ACCEPTED archive/legacy.html"))
        self.assertTrue(lines[1].startswith("CONFLICT archive/ambiguous.html"))
        self.assertIn("metadata_mismatch", lines[1])
        self.assertIn("sha256=", lines[0])

    def test_conflict_exception_retains_source_and_position(self):
        data = fixture("ambiguous_utf8.html.b64")
        with self.assertRaises(ArchiveConflictError) as context:
            sanitize_archive(
                data,
                "utf-8",
                source="archive/ambiguous.html",
                on_conflict="raise",
            )
        exc = context.exception
        self.assertEqual(exc.source, "archive/ambiguous.html")
        self.assertEqual(exc.position.byte_offset, 27)
        self.assertEqual(exc.conflicts[0].code, "metadata_mismatch")
        self.assertEqual(exc.result.error.code, "metadata_mismatch")

    def test_existing_string_entry_still_works(self):
        self.assertEqual(Sanitizer().sanitize("<b>x</b>"), "<strong>x</strong>")
        data = fixture("legacy_gb18030.html.b64")
        result = Sanitizer().sanitize_archive(data, "gb18030")
        self.assertTrue(result.ok)

        with self.assertRaises(TypeError):
            sanitize_archive("<p>x</p>", "utf-8")

    def test_render_review_includes_range_and_encoding(self):
        data = fixture("legacy_gb18030.html.b64")
        result = sanitize_archive(data, "gb18030", source="archive/legacy.html")
        line = render_review(result)

        self.assertIn("ACCEPTED archive/legacy.html", line)
        self.assertIn("encoding=gb18030", line)
        self.assertIn("bytes=0:", line)

    def test_accepted_output_is_stable_across_source_encodings(self):
        template = (
            '<html><head><meta charset="{}"></head>'
            "<body><p>旧档：经费已核。</p></body></html>"
        )
        outputs = []
        for encoding in ("gb18030", "utf-8"):
            data = template.format(encoding).encode(encoding)
            result = sanitize_archive(data, encoding, source="archive/" + encoding)
            self.assertTrue(result.ok)
            outputs.append(result.html)

        self.assertEqual(outputs[0], outputs[1])
        self.assertIn("旧档:经费已核。", outputs[0])

    def test_utf16_endianness_mismatch_is_conflict(self):
        data = (
            '﻿<html><head><meta charset="utf-16-be"></head><body><p>hi</p></body></html>'
        ).encode("utf-16-le")
        result = sanitize_archive(data, "utf-16", source="archive/u16.html")

        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "metadata_mismatch")
        self.assertEqual(result.error.metadata_encoding, "utf-16-be")

    def test_raw_fixtures_match_base64(self):
        for name in ("legacy_gb18030.html", "ambiguous_utf8.html"):
            self.assertEqual((FIXTURES / name).read_bytes(), fixture(name + ".b64"))

    def test_result_is_json_serializable_for_review_pages(self):
        data = fixture("ambiguous_utf8.html.b64")
        result = sanitize_archive(data, "utf-8", source="archive/ambiguous.html")
        payload = result.as_dict()
        json.dumps(payload, ensure_ascii=False)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["conflicts"][0]["code"], "metadata_mismatch")
        self.assertEqual(payload["document_range"], {"start": 0, "end": len(data)})

    def test_bom_can_supply_missing_declaration(self):
        data = "\ufeff<p>hello</p>".encode()
        result = sanitize_archive(data, None, source="archive/bom-only.html")

        self.assertTrue(result.ok)
        self.assertEqual(result.declared_encoding, "utf-8")
        self.assertEqual(result.input_range.start, 3)
        self.assertEqual(result.metadata[0].kind, "bom")

    def test_cli_reviews_two_archives(self):
        output = StringIO()
        with redirect_stdout(output):
            status = main(
                [
                    "--archive-pair",
                    "gb18030",
                    str(FIXTURES / "legacy_gb18030.html"),
                    "--archive-pair",
                    "utf-8",
                    str(FIXTURES / "ambiguous_utf8.html"),
                ]
            )

        lines = output.getvalue().splitlines()
        self.assertEqual(status, 1)
        self.assertTrue(lines[0].startswith("ACCEPTED"))
        self.assertTrue(lines[1].startswith("CONFLICT"))
        self.assertIn("code=metadata_mismatch", lines[1])

    def test_strict_labels_can_be_relaxed(self):
        body = b'<meta charset="utf-8"><p>hello</p>'
        data = (
            b"Content-Type: text/html; charset=gb18030\r\n"
            b"MIME-Version: 1.0\r\n\r\n" + body
        )
        strict = sanitize_archive(data, "gb18030", source="archive/labels.html")
        self.assertFalse(strict.ok)
        self.assertEqual(strict.error.code, "metadata_mismatch")

        relaxed = sanitize_archive(
            data,
            "gb18030",
            source="archive/labels.html",
            strict_labels=False,
        )
        self.assertTrue(relaxed.ok)
        self.assertEqual(len(relaxed.warnings), 1)
