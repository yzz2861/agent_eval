"""Agile encryption with a hash shorter than the AES block-padded values (SHA1)."""

import base64
import io
import unittest
from os.path import dirname, join

import olefile

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.method.ecma376_agile import ECMA376Agile, _get_hash_func

#: directory with input
DATA_DIR = join(dirname(__file__), "inputs")

#: directory with expected output
OUTPUT_DIR = join(dirname(__file__), "outputs")

PASSWORD = "Password1234_"

#: pairs of input/output files: agile SHA1/AES-128 and agile SHA512/AES-256
EXAMPLE_FILES = (
    ("ecma376agile_sha1_password.xlsx", "example.xlsx"),
    ("example_password.xlsx", "example.xlsx"),
)


def _read_input(name):
    with open(join(DATA_DIR, name), "rb") as f:
        return f.read()


def _rewrite_stream(data, stream_name, replacement):
    """Return a copy of an OLE file with one same-sized stream replaced."""
    buffer = io.BytesIO(data)
    ole = olefile.OleFileIO(buffer, write_mode=True)
    try:
        ole.write_stream(stream_name, replacement)
    finally:
        ole.close()
    return buffer.getvalue()


def _tamper_encryption_info(data, tamper):
    """Return a copy of an OLE file with the EncryptionInfo XML transformed."""
    buffer = io.BytesIO(data)
    ole = olefile.OleFileIO(buffer)
    try:
        stream = ole.openstream("EncryptionInfo").read()
    finally:
        ole.close()

    header, xml = stream[:8], stream[8:].decode("UTF-8")
    tampered_xml = tamper(xml)
    # olefile can only replace streams with the same size, and XML attribute
    # values are kept verbatim, so the transformations below preserve length.
    if len(tampered_xml) != len(xml):
        raise AssertionError("Tampered XML must have the same length")
    return _rewrite_stream(data, "EncryptionInfo", header + tampered_xml.encode("UTF-8"))


def _replace_first_hash_algorithm(xml):
    """Change keyData's hashAlgorithm to an unknown algorithm."""
    old = 'hashAlgorithm="SHA512"'
    return xml.replace(old, 'hashAlgorithm="SHA999"', 1)


def _replace_second_hash_algorithm(xml):
    """Change the password key encryptor's hashAlgorithm to an unknown algorithm."""
    old = 'hashAlgorithm="SHA512"'
    head, tail = xml.rsplit(old, 1)
    return head + 'hashAlgorithm="SHA999"' + tail


def _tamper_hmac_value(tamper):
    def transform(xml):
        marker = 'encryptedHmacValue="'
        start = xml.index(marker) + len(marker)
        end = xml.index('"', start)
        value = xml[start:end]
        replacement = tamper(value)
        if len(replacement) != len(value):
            raise AssertionError("Tampered HMAC value must have the same length")
        return xml[:start] + replacement + xml[end:]

    return transform


def _flip_first_hmac_byte(value):
    raw = bytearray(base64.b64decode(value))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ASCII")


def _shorten_hmac_value(value):
    # Remove one cipher block. Trailing spaces keep the XML attribute the same
    # length; base64.b64decode ignores them.
    raw = base64.b64decode(value)
    shorter = base64.b64encode(raw[:-16]).decode("ASCII")
    return shorter + " " * (len(value) - len(shorter))


def _integrity_args(ofile):
    info = ofile.info
    return (
        ofile.secret_key,
        info["keyDataSalt"],
        info["keyDataHashAlgorithm"],
        info["keyDataBlockSize"],
        info["encryptedHmacKey"],
        info["encryptedHmacValue"],
    )


def _encrypted_package(ofile):
    with ofile.file.openstream("EncryptedPackage") as stream:
        return stream.read()


class ECMA376AgileTest(unittest.TestCase):
    """See module doc."""

    def test_verify_password_and_integrity(self):
        for in_name, out_name in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                ofile.load_key(password=PASSWORD, verify_password=True)
                outfile = io.BytesIO()
                ofile.decrypt(outfile, verify_integrity=True)

            with open(join(OUTPUT_DIR, out_name), "rb") as f:
                self.assertEqual(outfile.getvalue(), f.read())

    def test_wrong_password(self):
        for in_name, _ in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                with self.assertRaises(exceptions.InvalidKeyError):
                    ofile.load_key(password="Password1234", verify_password=True)

    def test_tampered_package(self):
        for in_name, _ in EXAMPLE_FILES:
            with self.subTest(in_name), open(join(DATA_DIR, in_name), "rb") as f:
                ofile = OfficeFile(f)
                ofile.load_key(password=PASSWORD)
                with ofile.file.openstream("EncryptedPackage") as stream:
                    package = bytearray(stream.read())

            info = ofile.info
            args = (
                ofile.secret_key,
                info["keyDataSalt"],
                info["keyDataHashAlgorithm"],
                info["keyDataBlockSize"],
                info["encryptedHmacKey"],
                info["encryptedHmacValue"],
            )
            self.assertTrue(ECMA376Agile.verify_integrity(*args, io.BytesIO(bytes(package))))

            package[100] ^= 0x01
            self.assertFalse(ECMA376Agile.verify_integrity(*args, io.BytesIO(bytes(package))))

    def test_unsupported_hash_algorithm_raises(self):
        for algorithm in ("SHA999", "SHA3-256", "", None):
            with self.subTest(algorithm=algorithm):
                with self.assertRaises(exceptions.UnsupportedAlgorithmError):
                    _get_hash_func(algorithm)

    def test_unsupported_key_data_hash_fails_decrypt(self):
        sample = _tamper_encryption_info(
            _read_input("example_password.xlsx"), _replace_first_hash_algorithm
        )
        ofile = OfficeFile(io.BytesIO(sample))
        self.assertEqual(ofile.info["keyDataHashAlgorithm"], "SHA999")
        # The password hash is still supported, so key loading succeeds.
        ofile.load_key(password=PASSWORD, verify_password=True)

        for verify_integrity in (False, True):
            with self.subTest(verify_integrity=verify_integrity):
                outfile = io.BytesIO()
                with self.assertRaises(exceptions.UnsupportedAlgorithmError):
                    ofile.decrypt(outfile, verify_integrity=verify_integrity)
                self.assertEqual(outfile.getvalue(), b"")

    def test_unsupported_password_hash_fails_key_derivation(self):
        sample = _tamper_encryption_info(
            _read_input("example_password.xlsx"), _replace_second_hash_algorithm
        )
        ofile = OfficeFile(io.BytesIO(sample))
        self.assertEqual(ofile.info["passwordHashAlgorithm"], "SHA999")
        with self.assertRaises(exceptions.UnsupportedAlgorithmError):
            ofile.load_key(password=PASSWORD, verify_password=True)

    def test_tampered_hmac_value_fails_integrity_check(self):
        for tamper in (_flip_first_hmac_byte, _shorten_hmac_value):
            with self.subTest(tamper=tamper.__name__):
                sample = _tamper_encryption_info(
                    _read_input("example_password.xlsx"), _tamper_hmac_value(tamper)
                )
                ofile = OfficeFile(io.BytesIO(sample))
                ofile.load_key(password=PASSWORD, verify_password=True)

                args = _integrity_args(ofile)
                package = _encrypted_package(ofile)
                self.assertFalse(
                    ECMA376Agile.verify_integrity(*args, io.BytesIO(package))
                )
                # Appending a cipher block must not be ignored by truncating to
                # the hash size before comparison.
                self.assertFalse(
                    ECMA376Agile.verify_integrity(
                        *args[:5], args[5] + b"\x00" * 16, io.BytesIO(package)
                    )
                )

                outfile = io.BytesIO()
                with self.assertRaises(exceptions.InvalidKeyError):
                    ofile.decrypt(outfile, verify_integrity=True)
                self.assertEqual(outfile.getvalue(), b"")

    def test_tampered_package_fails_decrypt(self):
        data = _read_input("example_password.xlsx")
        ofile = OfficeFile(io.BytesIO(data))
        ofile.load_key(password=PASSWORD, verify_password=True)
        package = bytearray(_encrypted_package(ofile))
        package[100] ^= 0x01

        sample = _rewrite_stream(data, "EncryptedPackage", bytes(package))
        ofile = OfficeFile(io.BytesIO(sample))
        ofile.load_key(password=PASSWORD, verify_password=True)

        outfile = io.BytesIO()
        with self.assertRaises(exceptions.InvalidKeyError):
            ofile.decrypt(outfile, verify_integrity=True)
        self.assertEqual(outfile.getvalue(), b"")


if __name__ == "__main__":
    unittest.main()
