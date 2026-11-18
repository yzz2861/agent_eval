import shutil
import zlib
from pathlib import Path

import pytest

from pykeepass import PyKeePass
from pykeepass.exceptions import PayloadLimitError, XMLSecurityError
from pykeepass.kdbx_parsing import common
from pykeepass.kdbx_parsing.common import (
    parse_safe_xml,
    safe_decompress,
)

BASE_DIR = Path(__file__).resolve().parent
KDBX3 = BASE_DIR / "test3.kdbx"
KDBX4 = BASE_DIR / "test4.kdbx"
KEYFILE = BASE_DIR / "test4.key"
PASSWORD = "password"

class TestSafeXMLParsing:
    """Hardening of the lxml-based payload/keyfile XML parser."""

    def test_normal_xml_parses(self):
        tree = parse_safe_xml(b"<root><a>text</a></root>")
        assert tree.getroot().tag == "root"
        assert tree.find(".//a").text == "text"

    def test_external_entity_is_blocked(self):
        xxe = (
            b"<?xml version=\"1.0\"?>"
            b"<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
            b"<r>&x;</r>"
        )
        with pytest.raises(XMLSecurityError):
            parse_safe_xml(xxe)

    def test_doctype_with_internal_entity_is_blocked(self):
        billion_laughs = (
            b"<!DOCTYPE lolz ["
            b"<!ENTITY lol \"lol\">"
            b"<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;\">"
            b"]><lolz>&lol2;</lolz>"
        )
        with pytest.raises(XMLSecurityError):
            parse_safe_xml(billion_laughs)

    def test_empty_doctype_is_blocked(self):
        with pytest.raises(XMLSecurityError):
            parse_safe_xml(b"<!DOCTYPE root><root/>")

    def test_external_dtd_is_not_loaded(self):
        external_dtd = (
            b"<!DOCTYPE r SYSTEM \"file:///nonexistent/evil.dtd\">"
            b"<r/>"
        )
        with pytest.raises(XMLSecurityError):
            parse_safe_xml(external_dtd)

    def test_node_count_limit(self):
        document = b"<root>" + b"<child/>" * 100 + b"</root>"
        with pytest.raises(PayloadLimitError, match="element count"):
            parse_safe_xml(document, max_nodes=50)

    def test_depth_limit(self):
        document = b"<root>" + b"<n>" * 60 + b"</n>" * 60 + b"</root>"
        with pytest.raises(PayloadLimitError, match="depth"):
            parse_safe_xml(document, max_depth=20)

    def test_malformed_xml_raises_syntax_error(self):
        from lxml import etree
        with pytest.raises(etree.XMLSyntaxError):
            parse_safe_xml(b"<root><unclosed>")

    def test_default_limits_allow_realistic_documents(self):
        document = b"<root>" + b"<item>v</item>" * 1000 + b"</root>"
        tree = parse_safe_xml(document)
        assert len(tree.findall(".//item")) == 1000

def _zlib_stream(data):
    compressor = zlib.compressobj(
        6, zlib.DEFLATED, zlib.MAX_WBITS | 16
    )
    return compressor.compress(data) + compressor.flush()


class TestSafeDecompression:
    """Decompression bomb protection."""

    def test_decompress_within_limit(self):
        payload = b"hello world" * 100
        assert safe_decompress(_zlib_stream(payload), zlib.MAX_WBITS | 32) == payload

    def test_decompression_bomb_is_stopped(self):
        bomb = _zlib_stream(b"x" * 100_000)
        with pytest.raises(PayloadLimitError, match="Decompressed data"):
            safe_decompress(bomb, zlib.MAX_WBITS | 32, max_size=1024)

    def test_decompress_cap_does_not_allocate_full_output(self):
        # a highly compressible blob that would expand far past the cap
        bomb = _zlib_stream(b"y" * (5 * 1024 * 1024))
        with pytest.raises(PayloadLimitError):
            safe_decompress(bomb, zlib.MAX_WBITS | 32, max_size=64 * 1024)

@pytest.fixture
def tmp_kdbx4(tmp_path):
    target = tmp_path / "test4.kdbx"
    shutil.copy(KDBX4, target)
    return target


@pytest.fixture
def tmp_kdbx3(tmp_path):
    target = tmp_path / "test3.kdbx"
    shutil.copy(KDBX3, target)
    return target


class TestNormalDatabases:
    """Legitimate databases must still parse with hardening enabled."""

    def test_kdbx4_opens_and_reads_attachments(self):
        kp = PyKeePass(KDBX4, password=PASSWORD, keyfile=KEYFILE)
        assert len(kp.entries) > 0
        assert isinstance(kp.binaries, list)
        for attachment in kp.attachments:
            assert isinstance(attachment.data, bytes)

    def test_kdbx3_opens_and_reads_binaries(self):
        kp = PyKeePass(KDBX3, password=PASSWORD, keyfile=BASE_DIR / "test3.key")
        assert len(kp.entries) > 0
        assert isinstance(kp.binaries, list)

    def test_roundtrip_preserves_binary(self, tmp_kdbx4):
        kp = PyKeePass(tmp_kdbx4, password=PASSWORD, keyfile=KEYFILE)
        binary_id = kp.add_binary(b"round trip payload")
        kp.entries[0].add_attachment(binary_id, "roundtrip.txt")
        kp.save()

        reloaded = PyKeePass(tmp_kdbx4, password=PASSWORD, keyfile=KEYFILE)
        assert b"round trip payload" in reloaded.binaries

class TestOversizedAttachments:
    """Binary/attachment size and count limits."""

    def test_kdbx4_oversized_binary_rejected_at_parse(
        self, tmp_kdbx4, monkeypatch
    ):
        kp = PyKeePass(tmp_kdbx4, password=PASSWORD, keyfile=KEYFILE)
        binary_id = kp.add_binary(b"A" * 5000)
        kp.entries[0].add_attachment(binary_id, "big.bin")
        kp.save()

        monkeypatch.setattr(common, "MAX_BINARY_SIZE", 1000)
        with pytest.raises(PayloadLimitError, match="Binary of"):
            PyKeePass(tmp_kdbx4, password=PASSWORD, keyfile=KEYFILE)

    def test_kdbx4_binary_count_limit(self, tmp_kdbx4, monkeypatch):
        kp = PyKeePass(tmp_kdbx4, password=PASSWORD, keyfile=KEYFILE)
        for index in range(5):
            kp.add_binary(b"data-" + str(index).encode())
        kp.save()

        monkeypatch.setattr(common, "MAX_BINARY_COUNT", 2)
        with pytest.raises(PayloadLimitError, match="Binary count"):
            PyKeePass(tmp_kdbx4, password=PASSWORD, keyfile=KEYFILE)

    def test_kdbx3_compressed_binary_size_limit(
        self, tmp_kdbx3, monkeypatch
    ):
        kp = PyKeePass(tmp_kdbx3, password=PASSWORD, keyfile=BASE_DIR / "test3.key")
        binary_id = kp.add_binary(b"B" * 5000)
        kp.entries[0].add_attachment(binary_id, "big3.bin")
        kp.save()

        monkeypatch.setattr(common, "MAX_BINARY_SIZE", 1000)
        import pykeepass.pykeepass as pykeepass_module
        monkeypatch.setattr(pykeepass_module, "MAX_BINARY_SIZE", 1000)

        reloaded = PyKeePass(
            tmp_kdbx3, password=PASSWORD, keyfile=BASE_DIR / "test3.key"
        )
        with pytest.raises(PayloadLimitError, match="Decompressed data"):
            reloaded.binaries

    def test_kdbx3_binary_count_limit(self, tmp_kdbx3, monkeypatch):
        kp = PyKeePass(tmp_kdbx3, password=PASSWORD, keyfile=BASE_DIR / "test3.key")
        for index in range(5):
            kp.add_binary(b"data-" + str(index).encode())
        kp.save()

        import pykeepass.pykeepass as pykeepass_module
        monkeypatch.setattr(pykeepass_module, "MAX_BINARY_COUNT", 2)

        reloaded = PyKeePass(
            tmp_kdbx3, password=PASSWORD, keyfile=BASE_DIR / "test3.key"
        )
        with pytest.raises(PayloadLimitError, match="Binary count"):
            reloaded.binaries

class TestMaliciousKeyfile:
    """XXE inside an XML keyfile must be rejected."""

    def test_keyfile_xml_parser_blocks_xxe(self, tmp_path):
        # compute_key_composite parses XML keyfiles through parse_safe_xml
        malicious = (
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            b"<!DOCTYPE KeyFile [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
            b"<KeyFile><Meta><Version>2.0</Version></Meta>"
            b"<Key><Data>&x;</Data></Key></KeyFile>"
        )
        keyfile = tmp_path / "evil.key"
        keyfile.write_bytes(malicious)
        with pytest.raises(XMLSecurityError):
            parse_safe_xml(malicious)

    def test_malicious_keyfile_does_not_open_database(self, tmp_path):
        malicious = (
            b"<!DOCTYPE KeyFile [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
            b"<KeyFile><Meta><Version>2.0</Version></Meta>"
            b"<Key><Data>&x;</Data></Key></KeyFile>"
        )
        keyfile = tmp_path / "evil.key"
        keyfile.write_bytes(malicious)
        from pykeepass.exceptions import CredentialsError
        # the untrusted keyfile never authenticates the database
        with pytest.raises((XMLSecurityError, CredentialsError)):
            PyKeePass(KDBX4, password=PASSWORD, keyfile=keyfile)

