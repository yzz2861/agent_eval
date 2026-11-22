Archive fixtures
================

The .html files are the raw archive bytes; the matching .b64 files contain
the same bytes in base64 so that the legacy sequences survive editors and
patches unchanged.  The test suite decodes the .b64 fixtures.

legacy_gb18030.html.b64
    123-byte HTML document encoded as GB18030.  The body contains a
    <meta charset="gb18030"> declaration and Chinese text, giving clear
    old-encoding evidence.  It can be signed off when the independent
    declaration is also gb18030.

ambiguous_utf8.html.b64
    125-byte UTF-8 HTML document whose <meta> claims windows-1252.  The
    bytes are valid under both readings: UTF-8 gives "Résumé 2024 —
    archive", windows-1252 gives mojibake.  A reviewer must not sign it
    off with declared encoding utf-8 until the metadata is corrected.
