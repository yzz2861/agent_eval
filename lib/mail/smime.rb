# frozen_string_literal: true

require 'openssl'

module Mail
  # Verify multipart/signed (RFC 2311 / RFC 5751) S/MIME messages.
  #
  # Only detached signatures carried by multipart/signed messages are
  # supported. The signed bytes are extracted verbatim from the raw MIME
  # source; the parsed first part is never re-encoded, since re-encoding
  # would fold headers, normalize line endings and otherwise produce bytes
  # that differ from the ones the signer signed.
  #
  # Trust anchors must be supplied by the caller as an OpenSSL::X509::Store
  # (or certificates that are added to one). No certificates are fetched
  # from the network: only certificates embedded in the signature and the
  # caller-provided trust store are used.
  module SMIME
    class Error < StandardError; end

    # The message is not a multipart/signed S/MIME message, or its structure
    # is not suitable for verification.
    class NotSignedError < Error; end

    # The signature blob is missing, cannot be parsed or is malformed.
    class SignatureCorruptError < Error; end

    # The signature uses a digest/signature algorithm the underlying OpenSSL
    # cannot process.
    class UnsupportedAlgorithmError < Error; end

    # The signature matched, but the signer certificate does not chain to a
    # trusted certificate in the provided store.
    class CertificateUntrustedError < Error; end

    # The signature was made over different bytes than the message carries.
    class ContentTamperedError < Error; end

    # Build a verifier. +trust+ may be an existing OpenSSL::X509::Store, a
    # single OpenSSL::X509::Certificate, or an array of certificates to use
    # as trust anchors.
    def self.verifier(trust)
      Verifier.new(trust)
    end

    class Verifier
      def initialize(trust)
        @store = self.class.store_from(trust)
      end

      # Verify a multipart/signed message.
      #
      # Returns a new Mail::Message parsed from the signed MIME entity. The
      # passed-in message is left untouched.
      def verify(message)
        signed_bytes, signature_bytes = extract(message)
        pkcs7 = parse_signature(signature_bytes)
        run_verification(pkcs7, signed_bytes)
        Mail.new(signed_bytes)
      end

      def self.store_from(trust)
        case trust
        when OpenSSL::X509::Store
          trust
        when Array
          trust.each_with_object(OpenSSL::X509::Store.new) { |cert, store| store.add_cert(cert) }
        when OpenSSL::X509::Certificate
          OpenSSL::X509::Store.new.tap { |store| store.add_cert(trust) }
        else
          raise ArgumentError,
                'expected an OpenSSL::X509::Store, an OpenSSL::X509::Certificate, or an array of certificates'
        end
      end

      private

      SIGNATURE_CONTENT_TYPES = %w[
        application/pkcs7-signature
        application/x-pkcs7-signature
      ].freeze

      def extract(message)
        unless message.respond_to?(:mime_type) && message.mime_type == 'multipart/signed'
          raise NotSignedError, 'message is not multipart/signed'
        end

        parts = message.parts
        unless parts.length == 2
          raise NotSignedError,
                "multipart/signed message must contain exactly two parts (found #{parts.length})"
        end

        boundary = message.boundary
        source = message.body.raw_source
        if boundary.nil? || boundary.empty?
          raise NotSignedError, 'multipart/signed message has no boundary parameter'
        end
        if source.nil? || source.empty?
          raise NotSignedError, 'multipart/signed message has no raw body source'
        end

        signature_part = parts.last
        unless SIGNATURE_CONTENT_TYPES.include?(signature_part.mime_type)
          raise NotSignedError,
                "signature part has unexpected content type #{signature_part.mime_type.inspect}"
        end

        [extract_signed_bytes(source, boundary), decode_signature(signature_part)]
      end

      # Pull the exact bytes of the first body part out of the raw message.
      # The result starts at the first byte after the opening boundary line
      # and ends at, but does not include, the CRLF that precedes the next
      # boundary (see RFC 2046, the delimiter is CRLF dash-boundary).
      def extract_signed_bytes(source, boundary)
        dash = Regexp.escape("--#{boundary}")
        line_end = /(?:[ \t]*\r?\n)/
        opening = /(?:\A|\r?\n)#{dash}#{line_end}/m
        match = opening.match(source)
        raise NotSignedError, 'could not locate multipart boundary in raw source' unless match

        start = match.end(0)
        closing = /\r?\n#{dash}(?:--)?#{line_end}/m
        closing_match = closing.match(source, start)
        raise NotSignedError, 'could not locate closing multipart boundary in raw source' unless closing_match

        source[start...closing_match.begin(0)]
      end

      def decode_signature(part)
        bytes = part.body.decoded
        if bytes.nil? || bytes.empty?
          raise SignatureCorruptError, 'signature part is empty'
        end
        bytes
      end

      def parse_signature(bytes)
        OpenSSL::PKCS7.new(bytes)
      rescue ArgumentError
        # Some CMS producers emit BER-encoded structures that the strict
        # DER/BER parser still accepts when fed through ASN1 first.
        reparse(bytes) || raise(SignatureCorruptError, 'signature is not a valid PKCS#7/CMS structure')
      end

      def reparse(bytes)
        OpenSSL::PKCS7.new(OpenSSL::ASN1.decode(bytes).to_der)
      rescue ArgumentError, OpenSSL::ASN1::ASN1Error, TypeError
        nil
      end

      def run_verification(pkcs7, signed_bytes)
        raise SignatureCorruptError, "unexpected PKCS#7 content type: #{pkcs7.type}" unless pkcs7.type == :signed

        unless pkcs7.verify(nil, @store, signed_bytes, 0)
          raise_for_error(pkcs7.error_string.to_s)
        end
      rescue SignatureCorruptError, UnsupportedAlgorithmError, CertificateUntrustedError, ContentTamperedError
        raise
      rescue => e
        raise SignatureCorruptError, "signature could not be verified: #{e.message}"
      end

      def raise_for_error(error)
        case error
        when /unsupported/i
          raise UnsupportedAlgorithmError, "unsupported signature or digest algorithm (#{error})"
        when /certificate/i
          raise CertificateUntrustedError, "signer certificate is not trusted (#{error})"
        when /digest/i
          raise ContentTamperedError, "signed content does not match the signature (#{error})"
        when /signature|padding|bad decrypt/i
          raise SignatureCorruptError, "signature is corrupt (#{error})"
        else
          raise SignatureCorruptError, "signature verification failed (#{error})"
        end
      end
    end
  end
end
