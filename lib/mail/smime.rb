# frozen_string_literal: true
require 'openssl'

module Mail
  module SMIME
    class VerificationError < StandardError; end
    class UnsupportedAlgorithmError < VerificationError; end
    class SignatureError < VerificationError; end
    class CertificateNotTrustedError < VerificationError; end
    class ContentTamperedError < VerificationError; end

    SIGNATURE_CONTENT_TYPE = 'application/pkcs7-signature'
    SIGNED_DATA_CONTENT_TYPE = '1.2.840.113549.1.7.2'
    DATA_CONTENT_TYPE = '1.2.840.113549.1.7.1'
    MESSAGE_DIGEST_CONTENT_TYPE = '1.2.840.113549.1.9.4'
    SUPPORTED_SIGNATURE_ALGORITHM_OIDS = %w[
      1.2.840.113549.1.1.2
      1.2.840.113549.1.1.1
      1.2.840.113549.1.1.4
      1.2.840.113549.1.1.5
      1.2.840.113549.1.1.10
      1.2.840.113549.1.1.11
      1.2.840.113549.1.1.12
      1.2.840.113549.1.1.13
      1.2.840.113549.1.1.14
      1.2.840.113549.1.1.15
      1.2.840.113549.1.1.16
      1.2.840.10040.4.3
      1.2.840.10045.4.1
      1.2.840.10045.4.3.1
      1.2.840.10045.4.3.2
      1.2.840.10045.4.3.3
      1.2.840.10045.4.3.4
      1.3.101.112
      1.3.101.113
      2.16.840.1.101.3.4.3.1
      2.16.840.1.101.3.4.3.2
      2.16.840.1.101.3.4.3.3
      2.16.840.1.101.3.4.3.4
      2.16.840.1.101.3.4.3.5
    ].freeze

    def self.verify(message, trust_store)
      Verifier.new(trust_store).verify(message)
    end

    private

    class Verifier
      def initialize(trust_store)
        unless trust_store.is_a?(OpenSSL::X509::Store)
          raise ArgumentError, 'expected an OpenSSL::X509::Store trust store'
        end

        @trust_store = trust_store
      end

      def verify(message)
        signed_data, signature_data = detached_parts(message)
        pkcs7 = parse_signature(signature_data)

        asn1_signed_data = ensure_supported_algorithms(pkcs7)

        unless run_verification(pkcs7, signed_data, OpenSSL::PKCS7::NOSIGS | OpenSSL::PKCS7::BINARY)
          raise CertificateNotTrustedError, 'S/MIME certificate is not trusted by the supplied store'
        end

        unless content_digest_matches?(asn1_signed_data, signed_data)
          raise ContentTamperedError, 'S/MIME content does not match the signature'
        end

        unless run_verification(pkcs7, signed_data, OpenSSL::PKCS7::BINARY)
          raise SignatureError, 'S/MIME signature is invalid or malformed'
        end

        signed_data
      end

      private

      def detached_parts(message)
        unless message.mime_type.to_s.downcase == 'multipart/signed'
          raise SignatureError, 'message is not multipart/signed'
        end

        protocol = message.content_type_parameters && message.content_type_parameters['protocol'].to_s.downcase.delete('"')
        unless protocol == SIGNATURE_CONTENT_TYPE
          raise SignatureError, "expected protocol #{SIGNATURE_CONTENT_TYPE}"
        end

        if message.parts.length != 2
          raise SignatureError, 'multipart/signed message must contain signed content and a signature'
        end

        signed_part = message.parts.first
        signature_part = message.parts[1]
        unless signature_part.mime_type.to_s.downcase == SIGNATURE_CONTENT_TYPE
          raise SignatureError, "expected #{SIGNATURE_CONTENT_TYPE} signature part"
        end

        signed_data = mime_entity_bytes(signed_part)
        signature_data = decode_signature(signature_part)
        [signed_data, signature_data]
      end

      def mime_entity_bytes(part)
        source = part.raw_source.to_s.dup.force_encoding(Encoding::BINARY)
        source.sub!(/\A(?:\r\n|\n)/, '')
        source
      end

      def decode_signature(part)
        encoding = part.content_transfer_encoding.to_s.downcase
        source = part.body.raw_source.to_s.dup.force_encoding(Encoding::BINARY)

        case encoding
        when '', '7bit', '8bit', 'binary'
          source
        when 'base64'
          Utilities.decode_base64(source)
        when 'quoted-printable'
          Encodings::QuotedPrintable.decode(source)
        else
          raise SignatureError, "unsupported signature transfer encoding: #{encoding}"
        end
      end

      def parse_signature(data)
        OpenSSL::PKCS7.new(data)
      rescue ArgumentError
        begin
          OpenSSL::PKCS7.new(OpenSSL::ASN1.decode(data).to_der)
        rescue StandardError
          raise SignatureError, 'S/MIME signature is malformed'
        end
      rescue OpenSSL::ASN1::ASN1Error, OpenSSL::PKCS7::PKCS7Error
        raise SignatureError, 'S/MIME signature is malformed'
      end

      def run_verification(pkcs7, signed_data, flags)
        clear_openssl_errors
        pkcs7.verify([], @trust_store, signed_data, flags)
      rescue ArgumentError, OpenSSL::PKCS7::PKCS7Error
        false
      ensure
        clear_openssl_errors
      end

      def clear_openssl_errors
        OpenSSL.errors.clear
      end

      def ensure_supported_algorithms(pkcs7)
        signed_data = signed_data_structure(pkcs7)
        digest_algorithms = asn1_sequence_value(signed_data, 1)
        signer_infos = asn1_sequence_value(signed_data, 4)
        raise SignatureError, 'S/MIME signature has no signer information' if signer_infos.empty?

        algorithm_identifiers = digest_algorithms.map do |digest_algorithm|
          [object_identifier(digest_algorithm, 0), :digest]
        end

        signer_infos.each do |signer_info|
          signer_values = signer_info.value
          algorithm_identifiers << [object_identifier(signer_values[2], 0), :digest]
          algorithm_identifiers << [algorithm_object_identifier(signer_values[4]), :signature]
        end

        algorithm_identifiers.each do |oid, kind|
          raise SignatureError, 'S/MIME signature algorithm information is malformed' unless oid

          unless supported_algorithm?(oid, kind)
            raise UnsupportedAlgorithmError, "unsupported S/MIME #{kind} algorithm: #{oid}"
          end
        end

        signed_data
      rescue OpenSSL::ASN1::ASN1Error, NoMethodError
        raise SignatureError, 'S/MIME signature is malformed'
      end

      def content_digest_matches?(signed_data, content)
        signer_infos = asn1_sequence_value(signed_data, 4)

        signer_infos.all? do |signer_info|
          digest_oid = object_identifier(signer_info.value[2], 0)
          expected_digest = message_digest(signer_info)
          next false unless expected_digest

          object_id = OpenSSL::ASN1::ObjectId.new(digest_oid)
          digest_name = object_id.short_name || object_id.long_name
          OpenSSL::Digest.digest(digest_name, content) == expected_digest
        end
      rescue OpenSSL::ASN1::ASN1Error, NoMethodError
        raise SignatureError, 'S/MIME signature is malformed'
      end

      def message_digest(signer_info)
        signed_attributes = signer_info.value[3]
        raise SignatureError, 'S/MIME signature is missing authenticated attributes' unless signed_attributes

        attribute = Array(signed_attributes.value).detect do |signed_attribute|
          object_identifier(signed_attribute, 0) == MESSAGE_DIGEST_CONTENT_TYPE
        end
        raise SignatureError, 'S/MIME signature is missing the message digest attribute' unless attribute

        attribute.value[1].value[0].value
      rescue NoMethodError
        raise SignatureError, 'S/MIME message digest attribute is malformed'
      end

      def signed_data_structure(pkcs7)
        root = OpenSSL::ASN1.decode(pkcs7.to_der)
        content_type = object_identifier(root, 0)
        unless content_type == SIGNED_DATA_CONTENT_TYPE
          raise SignatureError, 'S/MIME signature does not contain signedData'
        end

        signed_data = root.value[1].value[0]
        unless object_identifier(signed_data, 2) == DATA_CONTENT_TYPE
          raise SignatureError, 'S/MIME signature does not contain data content'
        end

        signed_data
      rescue OpenSSL::ASN1::ASN1Error, NoMethodError
        raise SignatureError, 'S/MIME signature is malformed'
      end

      def asn1_sequence_value(value, index)
        Array(value.value[index].value)
      end

      def object_identifier(value, index)
        identifier = value.value[index]
        identifier.respond_to?(:oid) ? identifier.oid : identifier.value[0].oid
      end

      def algorithm_object_identifier(algorithm)
        identifier = algorithm.value[0]
        identifier.respond_to?(:oid) ? identifier.oid : identifier.value[0].oid
      end

      def supported_algorithm?(oid, kind)
        case kind
        when :digest
          supported_digest_algorithm?(oid)
        when :signature
          supported_signature_algorithm?(oid)
        end
      end

      def supported_digest_algorithm?(oid)
        object_id = OpenSSL::ASN1::ObjectId.new(oid)
        name = object_id.short_name || object_id.long_name
        return false unless name

        OpenSSL::Digest.new(name)
        true
      rescue ArgumentError, TypeError, RuntimeError, OpenSSL::ASN1::ASN1Error
        false
      end

      def supported_signature_algorithm?(oid)
        SUPPORTED_SIGNATURE_ALGORITHM_OIDS.include?(oid)
      end
    end
  end
end
