# Copyright (C) 2015 JWCrypto Project Contributors - see LICENSE file

import zlib

from jwcrypto import common
from jwcrypto.common import InvalidJWSEHeader
from jwcrypto.common import JWKeyNotFound
from jwcrypto.common import JWSEHeaderParameter, JWSEHeaderRegistry
from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import check_crit, merge_headers, validate_headers
from jwcrypto.common import json_decode_strict, json_encode
from jwcrypto.jwa import JWA
from jwcrypto.jwk import JWK, JWKSet

# Limit the amount of data we are willing to decompress by default.
default_max_compressed_size = 256 * 1024
# Limit the maximum plaintext size to 100MB by default.
default_max_plaintext_size = 100 * 1024 * 1024
# Limit the number of recipients accepted in one decrypt() call.
default_max_recipients = 10

# RFC 7518 Section 6.4 / RFC 8037: curves allowed for the ECDH-ES "epk".
allowed_ecdh_epk_curves = {
    'EC': ('P-256', 'P-384', 'P-521', 'secp256k1'),
    'OKP': ('X25519', 'X448'),
}
"""Curves permitted for an ECDH-ES ephemeral public key per key type"""

# Key types accepted by each key management algorithm family.
_keymgmt_key_types = {
    'RSA1_5': ('RSA',),
    'RSA-OAEP': ('RSA',),
    'RSA-OAEP-256': ('RSA',),
    'A128KW': ('oct',),
    'A192KW': ('oct',),
    'A256KW': ('oct',),
    'dir': ('oct',),
    'ECDH-ES': ('EC', 'OKP'),
    'ECDH-ES+A128KW': ('EC', 'OKP'),
    'ECDH-ES+A192KW': ('EC', 'OKP'),
    'ECDH-ES+A256KW': ('EC', 'OKP'),
    'A128GCMKW': ('oct',),
    'A192GCMKW': ('oct',),
    'A256GCMKW': ('oct',),
    'PBES2-HS256+A128KW': ('oct',),
    'PBES2-HS384+A192KW': ('oct',),
    'PBES2-HS512+A256KW': ('oct',),
}

# RFC 7516 - 4.1
# name: (description, supported?)
JWEHeaderRegistry = {
    'alg': JWSEHeaderParameter('Algorithm', False, True, None),
    'enc': JWSEHeaderParameter('Encryption Algorithm', False, True, None),
    'zip': JWSEHeaderParameter('Compression Algorithm', True, True, None),
    'jku': JWSEHeaderParameter('JWK Set URL', False, False, None),
    'jwk': JWSEHeaderParameter('JSON Web Key', False, False, None),
    'kid': JWSEHeaderParameter('Key ID', False, True, None),
    'x5u': JWSEHeaderParameter('X.509 URL', False, False, None),
    'x5c': JWSEHeaderParameter('X.509 Certificate Chain', False, False, None),
    'x5t': JWSEHeaderParameter('X.509 Certificate SHA-1 Thumbprint', False,
                               False, None),
    'x5t#S256': JWSEHeaderParameter('X.509 Certificate SHA-256 Thumbprint',
                                    False, False, None),
    'typ': JWSEHeaderParameter('Type', False, True, None),
    'cty': JWSEHeaderParameter('Content Type', False, True, None),
    'crit': JWSEHeaderParameter('Critical', True, True, None),
}
"""Registry of valid header parameters"""

default_allowed_algs = [
    # Key Management Algorithms
    'RSA-OAEP', 'RSA-OAEP-256',
    'A128KW', 'A192KW', 'A256KW',
    'dir',
    'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
    'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
    'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
    # Content Encryption Algorithms
    'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
    'A128GCM', 'A192GCM', 'A256GCM']
"""Default allowed algorithms"""


# These have been moved to jwcrypto.common, maintain here for backwards compat
InvalidCEKeyLength = common.InvalidCEKeyLength
InvalidJWEData = common.InvalidJWEData
InvalidJWEKeyLength = common.InvalidJWEKeyLength
InvalidJWEKeyType = common.InvalidJWEKeyType
InvalidJWEOperation = common.InvalidJWEOperation


class JWE:
    """JSON Web Encryption object

    This object represent a JWE token.
    """

    def __init__(self, plaintext=None, protected=None, unprotected=None,
                 aad=None, algs=None, recipient=None, header=None,
                 header_registry=None, flattened=True):
        """Creates a JWE token.

        :param plaintext(bytes): An arbitrary plaintext to be encrypted.
        :param protected: A JSON string with the protected header.
        :param unprotected: A JSON string with the shared unprotected header.
        :param aad(bytes): Arbitrary additional authenticated data
        :param algs: An optional list of allowed algorithms
        :param recipient: An optional, default recipient key
        :param header: An optional header for the default recipient
        :param header_registry: Optional additions to the header registry
        :param flattened: Use flattened serialization syntax (default True)
        """
        self._allowed_algs = None
        self.objects = {}
        self.plaintext = None
        self.header_registry = JWSEHeaderRegistry(JWEHeaderRegistry)
        self.flattened = flattened
        if header_registry:
            self.header_registry.update(header_registry)
        if plaintext is not None:
            if isinstance(plaintext, bytes):
                self.plaintext = plaintext
            else:
                self.plaintext = plaintext.encode('utf-8')
        self.cek = None
        self.decryptlog = None
        self.decrypted_recipient = None
        self.key_attempts = 0
        if aad:
            self.objects['aad'] = aad
        if protected:
            if isinstance(protected, dict):
                protected = json_encode(protected)
            else:
                json_decode_strict(protected)  # check header encoding
            self.objects['protected'] = protected
        if unprotected:
            if isinstance(unprotected, dict):
                unprotected = json_encode(unprotected)
            else:
                json_decode_strict(unprotected)  # check header encoding
            self.objects['unprotected'] = unprotected
        if algs:
            self._allowed_algs = algs

        if recipient:
            self.add_recipient(recipient, header=header)
        elif header:
            raise ValueError('Header is allowed only with default recipient')

    def _jwa_keymgmt(self, name):
        allowed = self._allowed_algs or default_allowed_algs
        if name not in allowed:
            raise InvalidJWEOperation('Algorithm not allowed')
        return JWA.keymgmt_alg(name)

    def _jwa_enc(self, name):
        allowed = self._allowed_algs or default_allowed_algs
        if name not in allowed:
            raise InvalidJWEOperation('Algorithm not allowed')
        return JWA.encryption_alg(name)

    @property
    def allowed_algs(self):
        """Allowed algorithms.

        The list of allowed algorithms.
        Can be changed by setting a list of algorithm names.
        """

        if self._allowed_algs:
            return self._allowed_algs
        else:
            return default_allowed_algs

    @allowed_algs.setter
    def allowed_algs(self, algs):
        if not isinstance(algs, list):
            raise TypeError('Allowed Algs must be a list')
        self._allowed_algs = algs

    def _merge_headers(self, h1, h2):
        try:
            return merge_headers(h1, h2)
        except InvalidJWSEHeader as e:
            raise InvalidJWEData(str(e)) from e

    @staticmethod
    def _encode_header(header):
        # Headers may arrive as dicts or as raw JSON strings; strings are
        # parsed strictly so duplicate members are rejected, then encoded
        # back into the canonical internal representation.
        if isinstance(header, str):
            header = json_decode_strict(header)
        return json_encode(header)

    def _get_jose_header(self, header=None):
        ph = json_decode_strict(self.objects.get('protected', '{}'))
        uh = json_decode_strict(self.objects.get('unprotected', '{}'))
        rh = None
        if header:
            if isinstance(header, dict):
                rh = header
            else:
                rh = json_decode_strict(header)
        try:
            jh = merge_headers(ph, uh, rh, registry=self.header_registry)
            check_crit(jh, ph, registry=self.header_registry)
            return jh
        except InvalidJWSEHeader as e:
            raise InvalidJWEData(str(e)) from e

    def _get_alg_enc_from_headers(self, jh):
        algname = jh.get('alg', None)
        if algname is None:
            raise InvalidJWEData('Missing "alg" from headers')
        alg = self._jwa_keymgmt(algname)
        encname = jh.get('enc', None)
        if encname is None:
            raise InvalidJWEData('Missing "enc" from headers')
        enc = self._jwa_enc(encname)
        return alg, enc

    def _encrypt(self, alg, enc, jh):
        aad = base64url_encode(self.objects.get('protected', ''))
        if 'aad' in self.objects:
            aad += '.' + base64url_encode(self.objects['aad'])
        aad = aad.encode('utf-8')

        compress = jh.get('zip', None)
        if compress == 'DEF':
            data = zlib.compress(self.plaintext)[2:-4]
        elif compress is None:
            data = self.plaintext
        else:
            raise ValueError('Unknown compression')

        iv, ciphertext, tag = enc.encrypt(self.cek, aad, data)
        self.objects['iv'] = iv
        self.objects['ciphertext'] = ciphertext
        self.objects['tag'] = tag

    def add_recipient(self, key, header=None):
        """Encrypt the plaintext with the given key.

        :param key: A JWK key or password of appropriate type for the 'alg'
         provided in the JOSE Headers.
        :param header: A JSON string representing the per-recipient header.

        :raises ValueError: if the plaintext is missing or not of type bytes.
        :raises ValueError: if the compression type is unknown.
        :raises InvalidJWAAlgorithm: if the 'alg' provided in the JOSE
         headers is missing or unknown, or otherwise not implemented.
        """
        if self.plaintext is None:
            raise ValueError('Missing plaintext')
        if not isinstance(self.plaintext, bytes):
            raise ValueError("Plaintext must be 'bytes'")

        if isinstance(header, dict):
            header = json_encode(header)

        jh = self._get_jose_header(header)
        alg, enc = self._get_alg_enc_from_headers(jh)

        rec = {}
        if header:
            rec['header'] = header

        wrapped = alg.wrap(key, enc.wrap_key_size, self.cek, jh)
        self.cek = wrapped['cek']

        if 'ek' in wrapped:
            rec['encrypted_key'] = wrapped['ek']

        if 'header' in wrapped:
            h = json_decode_strict(rec.get('header', '{}'))
            nh = self._merge_headers(h, wrapped['header'])
            rec['header'] = json_encode(nh)

        if 'ciphertext' not in self.objects:
            self._encrypt(alg, enc, jh)

        if 'recipients' in self.objects:
            self.objects['recipients'].append(rec)
        elif self.flattened:
            if 'encrypted_key' in self.objects or 'header' in self.objects:
                self.objects['recipients'] = []
                n = {}
                if 'encrypted_key' in self.objects:
                    n['encrypted_key'] = self.objects.pop('encrypted_key')
                if 'header' in self.objects:
                    n['header'] = self.objects.pop('header')
                self.objects['recipients'].append(n)
                self.objects['recipients'].append(rec)
            else:
                self.objects.update(rec)
        else:
            self.objects['recipients'] = [rec]

    def serialize(self, compact=False):
        """Serializes the object into a JWE token.

        :param compact(boolean): if True generates the compact
         representation, otherwise generates a standard JSON format.

        :raises InvalidJWEOperation: if the object cannot be serialized
         with the compact representation and `compact` is True.
        :raises InvalidJWEOperation: if no recipients have been added
         to the object.

        :return: A json formatted string or a compact representation string
        :rtype: `str`
        """

        if 'ciphertext' not in self.objects:
            raise InvalidJWEOperation("No available ciphertext")

        if compact:
            for invalid in 'aad', 'unprotected':
                if invalid in self.objects:
                    raise InvalidJWEOperation(
                        "Can't use compact encoding when the '%s' parameter "
                        "is set" % invalid)
            if 'protected' not in self.objects:
                raise InvalidJWEOperation(
                    "Can't use compact encoding without protected headers")
            else:
                ph = json_decode_strict(self.objects['protected'])
                for required in 'alg', 'enc':
                    if required not in ph:
                        raise InvalidJWEOperation(
                            "Can't use compact encoding, '%s' must be in the "
                            "protected header" % required)
            if 'recipients' in self.objects:
                if len(self.objects['recipients']) != 1:
                    raise InvalidJWEOperation("Invalid number of recipients")
                rec = self.objects['recipients'][0]
            else:
                rec = self.objects
            if 'header' in rec:
                # The AESGCMKW algorithm generates data (iv, tag) we put in the
                # per-recipient unprotected header by default. Move it to the
                # protected header and re-encrypt the payload, as the protected
                # header is used as additional authenticated data.
                h = json_decode_strict(rec['header'])
                ph = json_decode_strict(self.objects['protected'])
                nph = self._merge_headers(h, ph)
                self.objects['protected'] = json_encode(nph)
                jh = self._get_jose_header()
                alg, enc = self._get_alg_enc_from_headers(jh)
                self._encrypt(alg, enc, jh)
                del rec['header']

            return '.'.join([base64url_encode(self.objects['protected']),
                             base64url_encode(rec.get('encrypted_key', '')),
                             base64url_encode(self.objects['iv']),
                             base64url_encode(self.objects['ciphertext']),
                             base64url_encode(self.objects['tag'])])
        else:
            obj = self.objects
            enc = {'ciphertext': base64url_encode(obj['ciphertext']),
                   'iv': base64url_encode(obj['iv']),
                   'tag': base64url_encode(self.objects['tag'])}
            if 'protected' in obj:
                enc['protected'] = base64url_encode(obj['protected'])
            if 'unprotected' in obj:
                enc['unprotected'] = json_decode_strict(obj['unprotected'])
            if 'aad' in obj:
                enc['aad'] = base64url_encode(obj['aad'])
            if 'recipients' in obj:
                enc['recipients'] = []
                for rec in obj['recipients']:
                    e = {}
                    if 'encrypted_key' in rec:
                        e['encrypted_key'] = \
                            base64url_encode(rec['encrypted_key'])
                    if 'header' in rec:
                        e['header'] = json_decode_strict(rec['header'])
                    enc['recipients'].append(e)
            else:
                if 'encrypted_key' in obj:
                    enc['encrypted_key'] = \
                        base64url_encode(obj['encrypted_key'])
                if 'header' in obj:
                    enc['header'] = json_decode_strict(obj['header'])
            return json_encode(enc)

    def _unwrap_decrypt(self, alg, enc, key, enckey, header,
                        aad, iv, ciphertext, tag):
        cek = alg.unwrap(key, enc.wrap_key_size, enckey, header)
        data = enc.decrypt(cek, aad, iv, ciphertext, tag)
        self.cek = cek
        return data

    def _validate_ecdh_epk(self, jh):
        epk_data = jh.get('epk')
        if not isinstance(epk_data, dict):
            raise InvalidJWEData(
                'Invalid ECDH-ES epk: must be a JWK object')
        try:
            epk = JWK(**epk_data)
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidJWEData(
                'Invalid ECDH-ES epk' + repr(e)) from e

        kty = epk.get('kty')
        if kty not in allowed_ecdh_epk_curves:
            raise InvalidJWEData(
                'Invalid ECDH-ES epk key type: ' + repr(kty))
        crv = epk.get('crv')
        if crv not in allowed_ecdh_epk_curves[kty]:
            raise InvalidJWEData(
                'Disallowed ECDH-ES epk curve: ' + repr(crv))
        if kty == 'EC':
            if not epk.get('x') or not epk.get('y') or epk.get('d'):
                raise InvalidJWEData(
                    'Invalid ECDH-ES epk: not a valid EC public key')
        else:
            if not epk.get('x') or epk.get('d'):
                raise InvalidJWEData(
                    'Invalid ECDH-ES epk: not a valid OKP public key')
        try:
            epk.get_op_key('wrapKey')
        except Exception as e:  # pylint: disable=broad-except
            raise InvalidJWEData(
                'Invalid ECDH-ES epk' + repr(e)) from e
        return epk

    def _prepare_recipient(self, ppe):
        jh = self._get_jose_header(ppe.get('header', None))
        try:
            validate_headers(jh, registry=self.header_registry, target=self)
        except InvalidJWSEHeader as e:
            raise InvalidJWEData(str(e)) from e

        # The algorithm allow list is enforced before key selection.
        alg = self._jwa_keymgmt(jh.get('alg', None))
        enc = self._jwa_enc(jh.get('enc', None))

        if jh.get('alg', '').startswith('ECDH-ES'):
            self._validate_ecdh_epk(jh)

        return jh, alg, enc

    @staticmethod
    def _key_is_compatible(key, algname, jh):
        # Backwards compatibility: PBES2 algorithms accept a raw
        # string/bytes password instead of a JWK.
        if isinstance(key, (str, bytes)):
            return algname.startswith('PBES2')
        if not isinstance(key, JWK):
            return False
        expected_kty = _keymgmt_key_types.get(algname)
        if expected_kty is None or key.get('kty') not in expected_kty:
            return False
        if algname.startswith('ECDH-ES'):
            epk = jh.get('epk') or {}
            if key.get('crv') != epk.get('crv'):
                return False
        return True

    def _select_key(self, keyset, jh, selector):
        algname = jh.get('alg')
        candidates = [k for k in keyset['keys']
                      if self._key_is_compatible(k, algname, jh)]

        if 'kid' in jh:
            kid = jh['kid']
            kid_matches = [k for k in candidates if k.get('kid') == kid]
            if not kid_matches:
                raise JWKeyNotFound(
                    'Key ID ' + repr(kid) +
                    ' not found among compatible keys')
            candidates = kid_matches

        if not candidates:
            raise JWKeyNotFound('No compatible key found in key set')

        for thumb_header in ('x5t#S256', 'x5t'):
            if thumb_header in jh and len(candidates) > 1:
                thumb = jh[thumb_header]
                narrowed = [k for k in candidates
                            if k.thumbprint() == thumb or
                            k.get(thumb_header) == thumb]
                if narrowed:
                    candidates = narrowed

        if len(candidates) == 1:
            return candidates[0]

        if selector is not None:
            chosen = selector(list(candidates), dict(jh))
            if not isinstance(chosen, JWK) or chosen not in candidates:
                raise InvalidJWEData(
                    'Recipient selector did not return a matching key')
            return chosen

        raise InvalidJWEData(
            'Ambiguous recipient: %d keys match kid/alg/curve; provide an '
            'explicit selector' % len(candidates))

    def _recipient_identity(self, index, jh, key):
        if isinstance(key, JWK):
            thumbprint = key.thumbprint()
            key_kid = key.get('kid')
            key_kty = key.get('kty')
            key_crv = key.get('crv')
        else:
            # Deprecated raw password interface: no stable JWK identity.
            thumbprint = None
            key_kid = None
            key_kty = type(key).__name__
            key_crv = None
        return {
            'recipient_index': index,
            'kid': jh.get('kid'),
            'alg': jh.get('alg'),
            'enc': jh.get('enc'),
            'key_kid': key_kid,
            'key_thumbprint': thumbprint,
            'key_kty': key_kty,
            'key_crv': key_crv,
            'header': jh,
        }

    def _attempt_key(self, alg, enc, key, enckey, jh, aad,
                     log_prefix=None):
        self.key_attempts += 1
        try:
            data = self._unwrap_decrypt(alg, enc, key, enckey, jh, aad,
                                        self.objects['iv'],
                                        self.objects['ciphertext'],
                                        self.objects['tag'])
        except Exception as e:  # pylint: disable=broad-except
            if log_prefix is None:
                if isinstance(key, JWK):
                    keyid = key.get('kid', key.thumbprint())
                else:
                    keyid = type(key).__name__
                self.decryptlog.append('Key [%s] failed: [%s]' %
                                       (keyid, repr(e)))
            else:
                self.decryptlog.append('%s[%s]' % (log_prefix, repr(e)))
            raise
        self.decryptlog.append('Success')
        return data

    # FIXME: allow to specify which algorithms to accept as valid
    def _decrypt(self, key, ppe, max_plaintext=default_max_plaintext_size,
                 selector=None, recipient_index=None):

        jh, alg, enc = self._prepare_recipient(ppe)

        aad = base64url_encode(self.objects.get('protected', ''))
        if 'aad' in self.objects:
            aad += '.' + base64url_encode(self.objects['aad'])
        aad = aad.encode('utf-8')

        if isinstance(key, JWKSet):
            selected = self._select_key(key, jh, selector)
            data = self._attempt_key(alg, enc, selected,
                                     ppe.get('encrypted_key', b''),
                                     jh, aad)
        else:
            if not self._key_is_compatible(key, jh.get('alg'), jh):
                raise InvalidJWEData(
                    'Provided key is not compatible with recipient alg ' +
                    repr(jh.get('alg')))
            selected = key
            data = self._attempt_key(alg, enc, key,
                                     ppe.get('encrypted_key', b''),
                                     jh, aad, log_prefix='Failed: ')

        self.decrypted_recipient = self._recipient_identity(
            recipient_index, jh, selected)

        compress = jh.get('zip', None)
        if compress == 'DEF':
            if len(data) > default_max_compressed_size:
                raise InvalidJWEData(
                    'Compressed data exceeds maximum allowed'
                    'size' + f' ({default_max_compressed_size})')
            do = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
            self.plaintext = do.decompress(data, max_plaintext)
            if do.unconsumed_tail or not do.eof:
                self.plaintext = None
                raise InvalidJWEData(
                    'Compressed data exceeds maximum allowed'
                    'output size' + f' ({max_plaintext})')
        elif compress is None:
            self.plaintext = data
        else:
            raise ValueError('Unknown compression')

    def decrypt(self, key, max_plaintext=0, selector=None):
        """Decrypt a JWE token.

        :param key: A (:class:`jwcrypto.jwk.JWK`) decryption key, or a
         (:class:`jwcrypto.jwk.JWKSet`) containing candidate keys.
        :param max_plaintext: Maximum plaintext size allowed, 0 means
         the library default applies. Application writers are recommended
         to set a limit here if they know what is the max plaintext size
         for their application.
        :param selector: An optional callable used to disambiguate a
         recipient for which several keys still match after 'kid',
         algorithm and curve filtering. It is called as
         ``selector(candidate_keys, merged_header)`` and must return the
         single :class:`jwcrypto.jwk.JWK` to use. When several keys match
         and no selector is provided decryption fails instead of guessing.

        :raises InvalidJWEOperation: if no ciphertext is available.
        :raises InvalidJWEData: if a recipient header is self-inconsistent,
         the algorithm is not allowed, an ECDH-ES 'epk' is invalid, the
         recipient is ambiguous, or the ciphertext can't be decrypted.
        :raises JWKeyNotFound: if no provided key matches a recipient.

        :return: A dict describing the recipient and key actually used,
         also available as :attr:`decrypted_recipient`.
        """

        self.plaintext = None
        self.cek = None
        self.decrypted_recipient = None
        self.key_attempts = 0
        if max_plaintext == 0:
            max_plaintext = default_max_plaintext_size

        if 'ciphertext' not in self.objects:
            raise InvalidJWEOperation("No available ciphertext")
        self.decryptlog = []
        missingkey = False

        if 'recipients' in self.objects:
            if len(self.objects['recipients']) > default_max_recipients:
                raise InvalidJWEData(
                    'Too many recipients (%d)' %
                    len(self.objects['recipients']))
            for idx, rec in enumerate(self.objects['recipients']):
                log_start = len(self.decryptlog)
                try:
                    self._decrypt(key, rec, max_plaintext=max_plaintext,
                                  selector=selector, recipient_index=idx)
                    # Stop after the first successful recipient so that no
                    # other recipient key is ever attempted.
                    if self.plaintext is not None:
                        break
                except Exception as e:  # pylint: disable=broad-except
                    if isinstance(e, JWKeyNotFound):
                        missingkey = True
                    if len(self.decryptlog) == log_start:
                        self.decryptlog.append('Failed: [%s]' % repr(e))
        else:
            log_start = len(self.decryptlog)
            try:
                self._decrypt(key, self.objects,
                              max_plaintext=max_plaintext,
                              selector=selector, recipient_index=0)
            except Exception as e:  # pylint: disable=broad-except
                if isinstance(e, JWKeyNotFound):
                    missingkey = True
                if len(self.decryptlog) == log_start:
                    self.decryptlog.append('Failed: [%s]' % repr(e))

        if not self.plaintext:
            if missingkey:
                raise JWKeyNotFound("Key Not found in JWKSet")
            raise InvalidJWEData('No recipient matched the provided '
                                 'key' + repr(self.decryptlog))

        return self.decrypted_recipient

    def deserialize(self, raw_jwe, key=None, selector=None):
        """Deserialize a JWE token.

        NOTE: Destroys any current status and tries to import the raw
        JWE provided.

        If a key is provided a decryption step will be attempted after
        the object is successfully deserialized.

        :param raw_jwe: a 'raw' JWE token (JSON Encoded or Compact
         notation) string.
        :param key: A (:class:`jwcrypto.jwk.JWK`) decryption key,
         or a (:class:`jwcrypto.jwk.JWKSet`) that contains a key indexed
         by the 'kid' header or (deprecated) a string containing a password
         (optional).

        :raises InvalidJWEData: if the raw object is an invalid JWE token,
         including JSON headers with duplicate member names.
        :raises InvalidJWEOperation: if the decryption fails.
        """

        self.objects = {}
        self.plaintext = None
        self.cek = None
        self.decrypted_recipient = None
        self.key_attempts = 0

        o = {}
        try:
            try:
                djwe = json_decode_strict(raw_jwe)
                o['iv'] = base64url_decode(djwe['iv'])
                o['ciphertext'] = base64url_decode(djwe['ciphertext'])
                o['tag'] = base64url_decode(djwe['tag'])
                if 'protected' in djwe:
                    p = base64url_decode(djwe['protected'])
                    protected = p.decode('utf-8')
                    json_decode_strict(protected)
                    o['protected'] = protected
                if 'unprotected' in djwe:
                    o['unprotected'] = json_encode(djwe['unprotected'])
                if 'aad' in djwe:
                    o['aad'] = base64url_decode(djwe['aad'])
                if 'recipients' in djwe:
                    o['recipients'] = []
                    for rec in djwe['recipients']:
                        e = {}
                        if 'encrypted_key' in rec:
                            e['encrypted_key'] = \
                                base64url_decode(rec['encrypted_key'])
                        if 'header' in rec:
                            e['header'] = self._encode_header(rec['header'])
                        o['recipients'].append(e)
                else:
                    if 'encrypted_key' in djwe:
                        o['encrypted_key'] = \
                            base64url_decode(djwe['encrypted_key'])
                    if 'header' in djwe:
                        o['header'] = self._encode_header(djwe['header'])

            except ValueError as e:
                # process up to 5 dots, if we have 5+ dots we get more than 5
                # chunks and that means we have a malformed JWE
                data = raw_jwe.split('.', 5)
                if len(data) != 5:
                    raise InvalidJWEData() from e
                p = base64url_decode(data[0])
                protected = p.decode('utf-8')
                json_decode_strict(protected)
                o['protected'] = protected
                ekey = base64url_decode(data[1])
                if ekey != b'':
                    o['encrypted_key'] = base64url_decode(data[1])
                o['iv'] = base64url_decode(data[2])
                o['ciphertext'] = base64url_decode(data[3])
                o['tag'] = base64url_decode(data[4])

            self.objects = o

        except Exception as e:  # pylint: disable=broad-except
            raise InvalidJWEData('Invalid format', repr(e)) from e

        if key:
            return self.decrypt(key, selector=selector)
        return None

    @property
    def payload(self):
        if not self.plaintext:
            raise InvalidJWEOperation("Plaintext not available")
        return self.plaintext

    @property
    def jose_header(self):
        if 'recipients' in self.objects:
            jhl = []
            for rec in self.objects['recipients']:
                jhl.append(self._get_jose_header(rec.get('header')))
            return jhl
        jh = self._get_jose_header(self.objects.get('header'))
        if len(jh) == 0:
            raise InvalidJWEOperation("JOSE Header not available")
        return jh

    @classmethod
    def from_jose_token(cls, token):
        """Creates a JWE object from a serialized JWE token.

        :param token: A string with the json or compat representation
         of the token.

        :raises InvalidJWEData: if the raw object is an invalid JWE token.

        :return: A JWE token
        :rtype: JWE
        """

        obj = cls()
        obj.deserialize(token)
        return obj

    def __eq__(self, other):
        if not isinstance(other, JWE):
            return False
        try:
            return self.serialize() == other.serialize()
        except Exception:  # pylint: disable=broad-except
            data1 = {'plaintext': self.plaintext}
            data1.update(self.objects)
            data2 = {'plaintext': other.plaintext}
            data2.update(other.objects)
            return data1 == data2

    def __str__(self):
        try:
            return self.serialize()
        except Exception:  # pylint: disable=broad-except
            return self.__repr__()

    def __repr__(self):
        try:
            return f'JWE.from_json_token("{self.serialize()}")'
        except Exception:  # pylint: disable=broad-except
            plaintext = repr(self.plaintext)
            protected = self.objects.get('protected')
            unprotected = self.objects.get('unprotected')
            aad = self.objects.get('aad')
            algs = self._allowed_algs
            return f'JWE(plaintext={plaintext}, ' + \
                   f'protected={protected}, ' + \
                   f'unprotected={unprotected}, ' + \
                   f'aad={aad}, algs={algs})'
