"""JSON Web Signature."""

import argparse
import base64
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Tuple,
    Type,
    cast,
)

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

import josepy
from josepy import b64, errors, json_util, jwa
from josepy import jwk as jwk_mod
from josepy.util import frozendict

#: Key used for verification was supplied by the caller.
KEY_SOURCE_EXTERNAL = "external"
#: Key used for verification was taken from the ``jwk`` header parameter.
KEY_SOURCE_JWK = "jwk"
#: Key used for verification was selected through the ``kid`` header parameter.
KEY_SOURCE_KID = "kid"

#: Header parameters that RFC 8555 (section 6.2) requires to be carried in
#: the JWS Protected Header rather than the JWS Unprotected Header.
ACME_PROTECTED_PARAMETERS: FrozenSet[str] = frozenset(("alg", "kid", "jwk", "crit", "nonce", "url"))


class MediaType:
    """MediaType field encoder/decoder."""

    PREFIX = "application/"
    """MIME Media Type and Content Type prefix."""

    @classmethod
    def decode(cls, value: str) -> str:
        """Decoder."""
        # 4.1.10
        if "/" not in value:
            if ";" in value:
                raise errors.DeserializationError("Unexpected semi-colon")
            return cls.PREFIX + value
        return value

    @classmethod
    def encode(cls, value: str) -> str:
        """Encoder."""
        # 4.1.10
        if ";" not in value:
            assert value.startswith(cls.PREFIX)
            return value[len(cls.PREFIX) :]
        return value


class Header(json_util.JSONObjectWithFields):
    """JOSE Header.

    .. warning:: This class supports **only** Registered Header
        Parameter Names (as defined in section 4.1 of the
        protocol). If you need Public Header Parameter Names (4.2)
        or Private Header Parameter Names (4.3), you must subclass
        and override :meth:`from_json` and :meth:`to_partial_json`
        appropriately.

    .. warning:: This class does not support any extensions through
        the "crit" (Critical) Header Parameter (4.1.11) by default and as a
        conforming implementation, :meth:`from_json` treats the occurrence of
        an unregistered "crit" entry as an error. Subclasses may extend
        :attr:`supported_crit` to opt into additional critical extensions.

    :ivar x5tS256: "x5t#S256"
    :ivar str typ: MIME Media Type, inc. :const:`MediaType.PREFIX`.
    :ivar str cty: Content-Type, inc. :const:`MediaType.PREFIX`.

    """

    alg: Optional[jwa.JWASignature] = json_util.field(
        "alg", decoder=lambda value: Header._decode_alg(value), omitempty=True
    )
    jku: Optional[bytes] = json_util.field("jku", omitempty=True)
    jwk: Optional[jwk_mod.JWK] = json_util.field(
        "jwk", decoder=jwk_mod.JWK.from_json, omitempty=True
    )
    kid: Optional[str] = json_util.field("kid", omitempty=True)
    nonce: Optional[str] = json_util.field("nonce", omitempty=True)
    url: Optional[str] = json_util.field("url", omitempty=True)
    x5u: Optional[bytes] = json_util.field("x5u", omitempty=True)
    x5c: Tuple[x509.Certificate, ...] = json_util.field("x5c", omitempty=True, default=())
    x5t: Optional[bytes] = json_util.field("x5t", decoder=json_util.decode_b64jose, omitempty=True)
    x5tS256: Optional[bytes] = json_util.field(
        "x5t#S256", decoder=json_util.decode_b64jose, omitempty=True
    )
    typ: Optional[MediaType] = json_util.field(
        "typ", encoder=MediaType.encode, decoder=MediaType.decode, omitempty=True
    )
    cty: Optional[MediaType] = json_util.field(
        "cty", encoder=MediaType.encode, decoder=MediaType.decode, omitempty=True
    )
    crit: Tuple[Any, ...] = json_util.field("crit", omitempty=True, default=())
    _fields: Dict[str, json_util.Field]

    #: Names listed in "crit" that this implementation understands. Empty by
    #: default, which means every "crit" occurrence fails deserialization
    #: until a subclass registers the extension it actually implements.
    supported_crit: FrozenSet[str] = frozenset()

    @classmethod
    def from_json(cls, jobj: Mapping[str, Any]) -> "Header":
        if not isinstance(jobj, Mapping):
            raise errors.DeserializationError("JWS header must be a JSON object")
        header = cast("Header", super().from_json(jobj))
        header.validate_crit()
        return header

    def not_omitted(self) -> Dict[str, json_util.Field]:
        """Fields that would not be omitted in the JSON object."""
        return {
            name: getattr(self, name)
            for name, field in self._fields.items()
            if not field.omit(getattr(self, name))
        }

    def __add__(self, other: Any) -> "Header":
        if not isinstance(other, type(self)):
            raise TypeError("Header cannot be added to: {0}".format(type(other)))

        not_omitted_self = self.not_omitted()
        not_omitted_other = other.not_omitted()

        overlapping = set(not_omitted_self).intersection(not_omitted_other)
        if overlapping:
            # Reject even identical values: merging would hide which layer
            # provided the parameter and enable cross-layer header injection.
            raise errors.HeaderConflictError(
                "Header parameters appear in both the protected and the"
                " unprotected header: {0}".format(",".join(sorted(overlapping)))
            )

        not_omitted_self.update(not_omitted_other)
        return type(self)(**not_omitted_self)

    @classmethod
    def merge(
        cls, protected: Optional["Header"], unprotected: Optional["Header"]
    ) -> Tuple["Header", Dict[str, str]]:
        """Merge the protected and unprotected header layers deterministically.

        Each Header Parameter Name may occur in at most one of the two
        layers; a duplicate (including a duplicate carrying the same value)
        raises :class:`~josepy.errors.HeaderConflictError`.

        :returns: The combined header and a mapping of every present
            parameter name to ``"protected"`` or ``"unprotected"``, making
            the origin of every merged parameter explicit.

        """
        protected = cls() if protected is None else protected
        unprotected = cls() if unprotected is None else unprotected

        protected_names = set(protected.not_omitted())
        unprotected_names = set(unprotected.not_omitted())
        duplicates = protected_names.intersection(unprotected_names)
        if duplicates:
            raise errors.HeaderConflictError(
                "Header parameters appear in both the protected and the"
                " unprotected header: {0}".format(",".join(sorted(duplicates)))
            )

        origins = {name: "protected" for name in protected_names}
        origins.update({name: "unprotected" for name in unprotected_names})
        return protected + unprotected, origins

    def validate_crit(self) -> None:
        """Validate the "crit" header parameter against the registry.

        Per RFC 7515 section 4.1.11, "crit" must be a non-empty array of
        unique header parameter names, every listed parameter must be present
        in the JOSE header, and every listed extension must be understood by
        the recipient. This runs before signature verification.

        """
        if not self.crit:
            return

        names = list(self.crit)
        if not all(isinstance(name, str) for name in names):
            raise errors.CriticalHeaderError('"crit" must contain header parameter names only')
        if len(set(names)) != len(names):
            raise errors.CriticalHeaderError('"crit" contains duplicate entries')

        present = set(self.not_omitted())
        missing = [name for name in names if name not in present]
        if missing:
            raise errors.CriticalHeaderError(
                '"crit" lists header parameters that are not present: {0}'.format(
                    ",".join(sorted(missing))
                )
            )

        unsupported = [name for name in names if name not in type(self).supported_crit]
        if unsupported:
            raise errors.CriticalHeaderError(
                "Unsupported critical header parameter(s): {0}".format(
                    ",".join(sorted(unsupported))
                )
            )

    def validate_key_selection(self) -> None:
        """Enforce that "jwk" and "kid" are mutually exclusive."""
        if self.jwk is not None and self.kid is not None:
            raise errors.KeySelectorError(
                'The "jwk" and "kid" header parameters are mutually exclusive'
            )

    def validate_acme_sources(self, origins: Mapping[str, str]) -> None:
        """Validate the ACME (RFC 8555 section 6.2) header source constraints.

        The "alg", "kid", "jwk", "crit", "nonce" and "url" parameters must
        be carried by the JWS Protected Header, and exactly one of "jwk" and
        "kid" identifies the account key.

        """
        misplaced = sorted(
            name for name in ACME_PROTECTED_PARAMETERS if origins.get(name) == "unprotected"
        )
        if misplaced:
            raise errors.HeaderSourceError(
                "ACME header parameters must be protected, found in the"
                " unprotected header: {0}".format(",".join(misplaced))
            )

        self.validate_key_selection()
        if self.jwk is None and self.kid is None:
            raise errors.KeySelectorError(
                'Exactly one of the "jwk" and "kid" header parameters is required'
            )
        self.validate_crit()

    def find_key(self) -> josepy.JWK:
        """Find key based on header.

        .. todo:: Supports only "jwk" header parameter lookup.

        :returns: (Public) key found in the header.
        :rtype: .JWK

        :raises josepy.errors.Error: if key could not be found

        """
        if self.jwk is None:
            raise errors.Error("No key found")
        return self.jwk

    @staticmethod
    def _decode_alg(value: Any) -> jwa.JWASignature:
        if not isinstance(value, str) or not value:
            # Do not echo the value: header material must not leak through
            # error messages.
            raise errors.AlgorithmError('The "alg" header parameter must be a non-empty string')
        try:
            return jwa.JWASignature.from_json(value)
        except KeyError:
            # The JWA registry is matched case-sensitively, so casing
            # variants never silently select a different algorithm.
            raise errors.AlgorithmError("Unsupported signature algorithm")

    @crit.decoder  # type: ignore
    def crit(value: Any) -> Tuple[Any, ...]:
        if not isinstance(value, list) or not value:
            raise errors.CriticalHeaderError(
                '"crit" must be a non-empty array of header parameter names'
            )
        decoded = tuple(json_util.Field.default_decoder(value))
        if not all(isinstance(name, str) for name in decoded):
            raise errors.CriticalHeaderError('"crit" must contain header parameter names only')
        if len(set(decoded)) != len(decoded):
            raise errors.CriticalHeaderError('"crit" contains duplicate entries')
        return decoded

    # x5c does NOT use JOSE Base64 (4.1.6)

    @x5c.encoder  # type: ignore
    def x5c(value: Sequence[x509.Certificate]) -> list[bytes]:
        """
        .. versionchanged:: 2.0.0
           The values are now `cryptography.x509.Certificate` objects.
           Previously these were `josepy.util.ComparableX509` objects, which wrapped
           `OpenSSL.crypto.X509` objects.
        """
        return [base64.b64encode(cert.public_bytes(Encoding.DER)) for cert in value]

    @x5c.decoder  # type: ignore
    def x5c(value: Sequence[str]) -> tuple[x509.Certificate, ...]:
        """
        .. versionchanged:: 2.0.0
           The values are now `cryptography.x509.Certificate` objects.
           Previously these were `josepy.util.ComparableX509` objects, which wrapped
           `OpenSSL.crypto.X509` objects.
        """
        try:
            return tuple(x509.load_der_x509_certificate(base64.b64decode(cert)) for cert in value)
        except ValueError as error:
            raise errors.DeserializationError(error)


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of a signature verification.

    Instances are truthy when the signature is valid, so they remain a drop-in
    replacement for the boolean returned by :meth:`Signature.verify`.

    :ivar bool valid: Whether the signature verified successfully.
    :ivar JWASignature alg: The algorithm actually used for verification,
        taken from the merged header rather than any unprotected input.
    :ivar str key_source: One of :data:`KEY_SOURCE_EXTERNAL`,
        :data:`KEY_SOURCE_JWK` and :data:`KEY_SOURCE_KID`.

    """

    valid: bool
    alg: jwa.JWASignature
    key_source: str

    def __bool__(self) -> bool:
        return self.valid


class Signature(json_util.JSONObjectWithFields):
    """JWS Signature.

    :ivar combined: Combined Header (protected and unprotected,
        :class:`Header`).
    :ivar unicode protected: JWS protected header (Jose Base-64 decoded).
    :ivar header: JWS Unprotected Header (:class:`Header`).
    :ivar str signature: The signature.

    """

    header_cls = Header
    combined: Header
    header_origins: frozendict

    __slots__ = ("combined", "header_origins")
    protected: str = json_util.field("protected", omitempty=True, default="")
    header: Header = json_util.field(
        "header", omitempty=True, default=header_cls(), decoder=header_cls.from_json
    )
    signature: bytes = json_util.field(
        "signature", decoder=json_util.decode_b64jose, encoder=json_util.encode_b64jose
    )

    @protected.encoder  # type: ignore
    def protected(value: str) -> str:
        # wrong type guess (Signature, not bytes) | pylint: disable=no-member
        return json_util.encode_b64jose(value.encode("utf-8"))

    @protected.decoder  # type: ignore
    def protected(value: str) -> str:
        return json_util.decode_b64jose(value).decode("utf-8")

    def __init__(self, **kwargs: Any) -> None:
        if "combined" not in kwargs:
            kwargs = self._with_combined(kwargs)
        elif "header_origins" not in kwargs:
            kwargs["header_origins"] = frozendict()
        super().__init__(**kwargs)
        if self.combined.alg is None:
            raise errors.AlgorithmError('The "alg" header parameter is required')
        self.combined.validate_crit()
        self.combined.validate_key_selection()

    @classmethod
    def _with_combined(cls, kwargs: Any) -> Dict[str, Any]:
        assert "combined" not in kwargs
        header = kwargs.get("header", cls._fields["header"].default)
        protected = kwargs.get("protected", cls._fields["protected"].default)

        if protected:
            protected_header = cls.header_cls.json_loads(protected)
            combined, origins = cls.header_cls.merge(protected_header, header)
        else:
            combined = header
            origins = {name: "unprotected" for name in header.not_omitted()}

        kwargs["combined"] = combined
        kwargs["header_origins"] = frozendict(origins)
        return kwargs

    @classmethod
    def _msg(cls, protected: str, payload: bytes) -> bytes:
        return b64.b64encode(protected.encode("utf-8")) + b"." + b64.b64encode(payload)

    def verify(self, payload: bytes, key: Optional[josepy.JWK] = None) -> bool:
        """Verify.

        :param bytes payload: Payload to verify.
        :param JWK key: Key used for verification.

        """
        return bool(self.verify_detailed(payload, key).valid)

    def verify_detailed(
        self,
        payload: bytes,
        key: Optional[josepy.JWK] = None,
        acme: bool = False,
    ) -> VerificationResult:
        """Verify and report the algorithm and key source that were used.

        :param bytes payload: Payload to verify.
        :param JWK key: Optional externally supplied key. When omitted the key
            is taken from the ``jwk`` header parameter; a ``kid`` based key
            lookup is not implemented and must be supplied by the caller.
        :param bool acme: When True, enforce the RFC 8555 header source
            constraints before touching any signature primitive.

        """
        if acme:
            self.combined.validate_acme_sources(self.header_origins)
        self.combined.validate_crit()

        alg = self.combined.alg
        if alg is None:
            raise errors.AlgorithmError('The "alg" header parameter is required')

        if key is not None:
            actual_key = key
            key_source = KEY_SOURCE_KID if self.combined.kid is not None else KEY_SOURCE_EXTERNAL
        elif self.combined.jwk is not None:
            actual_key = self.combined.find_key()
            key_source = KEY_SOURCE_JWK
        elif self.combined.kid is not None:
            raise errors.KeySelectorError(
                'A "kid" header parameter requires an externally supplied key'
            )
        else:
            raise errors.KeySelectorError(
                'No key available: supply a key or include a "jwk" header parameter'
            )

        valid = alg.verify(
            key=actual_key.key, sig=self.signature, msg=self._msg(self.protected, payload)
        )
        return VerificationResult(valid=valid, alg=alg, key_source=key_source)

    @classmethod
    def sign(
        cls,
        payload: bytes,
        key: josepy.JWK,
        alg: josepy.JWASignature,
        include_jwk: bool = True,
        protect: FrozenSet = frozenset(),
        **kwargs: Any,
    ) -> "Signature":
        """Sign.

        :param bytes payload: Payload to sign.
        :param JWK key: Key for signature.
        :param JWASignature alg: Signature algorithm to use to sign.
        :param bool include_jwk: If True, insert the JWK inside the signature headers.
        :param FrozenSet protect: List of headers to protect.

        """
        assert isinstance(key, alg.kty)

        header_params = kwargs
        header_params["alg"] = alg
        if include_jwk:
            header_params["jwk"] = key.public_key()

        assert set(header_params).issubset(cls.header_cls._fields)
        assert protect.issubset(cls.header_cls._fields)

        protected_params = {}
        for header in protect:
            if header in header_params:
                protected_params[header] = header_params.pop(header)
        if protected_params:
            protected = cls.header_cls(**protected_params).json_dumps()
        else:
            protected = ""

        header = cls.header_cls(**header_params)
        signature = alg.sign(key.key, cls._msg(protected, payload))

        return cls(protected=protected, header=header, signature=signature)

    def fields_to_partial_json(self) -> Dict[str, Any]:
        fields = super().fields_to_partial_json()
        if not fields["header"].not_omitted():
            del fields["header"]
        return fields

    @classmethod
    def fields_from_json(cls, jobj: Mapping[str, Any]) -> Dict[str, Any]:
        fields = super().fields_from_json(jobj)
        fields_with_combined = cls._with_combined(fields)
        if "alg" not in fields_with_combined["combined"].not_omitted():
            raise errors.AlgorithmError('The "alg" header parameter is required')
        return fields_with_combined


class JWS(json_util.JSONObjectWithFields):
    """JSON Web Signature.

    :ivar str payload: JWS Payload.
    :ivar str signature: JWS Signatures.

    """

    __slots__ = ("payload", "signatures")
    payload: bytes
    signatures: List[Signature]

    signature_cls = Signature

    def verify(self, key: Optional[josepy.JWK] = None) -> bool:
        """Verify."""
        return all(sig.verify(self.payload, key) for sig in self.signatures)

    def verify_detailed(
        self,
        key: Optional[josepy.JWK] = None,
        acme: bool = False,
    ) -> Tuple[VerificationResult, ...]:
        """Verify every signature and return the per-signature results.

        Each result reports the algorithm actually used (from the merged
        header) and the key source (``external``, ``jwk`` or ``kid``).

        """
        return tuple(sig.verify_detailed(self.payload, key, acme=acme) for sig in self.signatures)

    @classmethod
    def sign(cls, payload: bytes, **kwargs: Any) -> "JWS":
        """Sign."""
        return cls(payload=payload, signatures=(cls.signature_cls.sign(payload=payload, **kwargs),))

    @property
    def signature(self) -> Signature:
        """Get a singleton signature.

        :rtype: :class:`JWS.signature_cls`

        """
        assert len(self.signatures) == 1
        return self.signatures[0]

    def to_compact(self) -> bytes:
        """Compact serialization.

        :rtype: bytes

        """
        assert len(self.signatures) == 1

        assert "alg" not in self.signature.header.not_omitted()
        # ... it must be in protected

        return (
            b64.b64encode(self.signature.protected.encode("utf-8"))
            + b"."
            + b64.b64encode(self.payload)
            + b"."
            + b64.b64encode(self.signature.signature)
        )

    @classmethod
    def from_compact(cls, compact: bytes) -> "JWS":
        """Compact deserialization.

        :param bytes compact:

        """
        try:
            protected, payload, signature = compact.split(b".")
        except ValueError:
            raise errors.DeserializationError(
                "Compact JWS serialization should comprise of exactly" " 3 dot-separated components"
            )

        sig = cls.signature_cls(
            protected=b64.b64decode(protected).decode("utf-8"), signature=b64.b64decode(signature)
        )
        return cls(payload=b64.b64decode(payload), signatures=(sig,))

    def to_partial_json(self, flat: bool = True) -> Dict[str, Any]:
        assert self.signatures
        payload = json_util.encode_b64jose(self.payload)

        if flat and len(self.signatures) == 1:
            ret = self.signatures[0].to_partial_json()
            ret["payload"] = payload
            return ret
        else:
            return {
                "payload": payload,
                "signatures": self.signatures,
            }

    @classmethod
    def from_json(cls, jobj: Mapping[str, Any]) -> "JWS":
        if "signature" in jobj and "signatures" in jobj:
            raise errors.DeserializationError("Flat mixed with non-flat")
        elif "signature" in jobj:  # flat
            filtered = {key: value for key, value in jobj.items() if key != "payload"}
            return cls(
                payload=json_util.decode_b64jose(jobj["payload"]),
                signatures=(cls.signature_cls.from_json(filtered),),
            )
        else:
            return cls(
                payload=json_util.decode_b64jose(jobj["payload"]),
                signatures=tuple(cls.signature_cls.from_json(sig) for sig in jobj["signatures"]),
            )


class CLI:
    """JWS CLI."""

    @classmethod
    def sign(cls, args: argparse.Namespace) -> None:
        """Sign."""
        with open(args.key, "rb") as fp:
            key = args.alg.kty.load(fp.read())
        if args.protect is None:
            args.protect = []
        if args.compact:
            args.protect.append("alg")

        sig = JWS.sign(
            payload=sys.stdin.read().encode(), key=key, alg=args.alg, protect=set(args.protect)
        )

        if args.compact:
            print(sig.to_compact().decode("utf-8"))
        else:  # JSON
            print(sig.json_dumps_pretty())

    @classmethod
    def verify(cls, args: argparse.Namespace) -> bool:
        """Verify."""
        if args.compact:
            sig = JWS.from_compact(sys.stdin.read().encode())
        else:  # JSON
            try:
                sig = cast(JWS, JWS.json_loads(sys.stdin.read()))
            except errors.Error as error:
                print(error)
                return False

        if args.key is not None:
            assert args.kty is not None
            with open(args.key, "rb") as fp:
                key = args.kty.load(fp.read()).public_key()
        else:
            key = None

        sys.stdout.write(sig.payload.decode())
        return not sig.verify(key=key)

    @classmethod
    def _alg_type(cls, arg: Any) -> jwa.JWASignature:
        return jwa.JWASignature.from_json(arg)

    @classmethod
    def _header_type(cls, arg: Any) -> Any:
        assert arg in Signature.header_cls._fields
        return arg

    @classmethod
    def _kty_type(cls, arg: Any) -> Type[jwk_mod.JWK]:
        assert arg in jwk_mod.JWK.TYPES
        return jwk_mod.JWK.TYPES[arg]

    @classmethod
    def run(cls, args: Optional[List[str]] = None) -> Optional[bool]:
        """Parse arguments and sign/verify."""
        if args is None:
            args = sys.argv[1:]
        parser = argparse.ArgumentParser()
        parser.add_argument("--compact", action="store_true")

        subparsers = parser.add_subparsers()
        parser_sign = subparsers.add_parser("sign")
        parser_sign.set_defaults(func=cls.sign)
        parser_sign.add_argument("-k", "--key", required=True)
        parser_sign.add_argument("-a", "--alg", type=cls._alg_type, default=jwa.RS256)
        parser_sign.add_argument("-p", "--protect", action="append", type=cls._header_type)

        parser_verify = subparsers.add_parser("verify")
        parser_verify.set_defaults(func=cls.verify)
        parser_verify.add_argument("-k", "--key", required=False)
        parser_verify.add_argument("--kty", type=cls._kty_type, required=False)

        parsed = parser.parse_args(args)
        return parsed.func(parsed)


if __name__ == "__main__":
    exit(CLI.run())  # pragma: no cover
