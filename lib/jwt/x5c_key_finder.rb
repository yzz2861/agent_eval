# frozen_string_literal: true

module JWT
  # If the x5c header certificate chain can be validated by trusted root
  # certificates, and none of the certificates are revoked, returns the public
  # key from the first certificate.
  # See https://tools.ietf.org/html/rfc7515#section-4.1.6
  class X5cKeyFinder
    KEY_USAGE_OID = '2.5.29.15'
    EXTENDED_KEY_USAGE_OID = '2.5.29.37'
    DIGITAL_SIGNATURE_BIT = 0x80

    def initialize(root_certificates, crls = nil, policy = {}, **policy_overrides)
      raise ArgumentError, 'Root certificates must be specified' unless root_certificates

      policy = (policy || {}).merge(policy_overrides)
      @root_certificates = root_certificates
      @required_ekus = Array(policy.fetch(:eku, nil)).map { |required_eku| normalize_oid(required_eku) }
      @allow_missing_eku = policy.fetch(:allow_missing_eku, false)
      @require_digital_signature = policy.fetch(:require_digital_signature, false)
      @allow_missing_digital_signature = policy.fetch(:allow_missing_digital_signature, false)
      @max_chain_depth = policy.fetch(:max_chain_depth, nil)
      @verification_time = policy.fetch(:verification_time, nil)

      validate_configuration!
      @store = build_store(root_certificates, crls)
    end

    def from(x5c_header_or_certificates)
      signing_certificate, *certificate_chain = parse_certificates(x5c_header_or_certificates)
      certificates = [signing_certificate, *certificate_chain]
      validate_chain_structure!(certificates)

      store_context = OpenSSL::X509::StoreContext.new(@store, signing_certificate, certificate_chain)
      store_context.time = @verification_time unless @verification_time.nil?

      if store_context.verify
        validate_chain_depth!(store_context.chain)
        validate_leaf_key_usage!(signing_certificate)
        validate_leaf_extended_key_usage!(signing_certificate)
        signing_certificate.public_key
      else
        raise_verification_error(store_context)
      end
    end

    private

    def build_store(root_certificates, crls)
      store = OpenSSL::X509::Store.new
      store.purpose = OpenSSL::X509::PURPOSE_ANY
      store.flags = OpenSSL::X509::V_FLAG_CRL_CHECK | OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
      root_certificates.each { |certificate| store.add_cert(certificate) }
      crls&.each { |crl| store.add_crl(crl) }
      store
    end

    def parse_certificates(x5c_header_or_certificates)
      unless x5c_header_or_certificates.is_a?(Array) && !x5c_header_or_certificates.empty?
        raise JWT::CertificateChainOrderError, 'Certificate chain must be a non-empty array'
      end

      if x5c_header_or_certificates.all?(OpenSSL::X509::Certificate)
        x5c_header_or_certificates.dup
      else
        x5c_header_or_certificates.map do |encoded|
          OpenSSL::X509::Certificate.new(::JWT::Base64.url_decode(encoded))
        end
      end
    end

    def validate_configuration!
      if !@max_chain_depth.nil? && (!@max_chain_depth.is_a?(Integer) || @max_chain_depth.negative?)
        raise ArgumentError, 'Maximum chain depth must be a non-negative integer'
      end

      return if @verification_time.nil? || @verification_time.is_a?(Time) || @verification_time.is_a?(Integer)

      raise ArgumentError, 'Verification time must be a Time or an integer number of seconds since the Epoch'
    end

    def validate_chain_structure!(certificates)
      validate_no_duplicates!(certificates)
      validate_certificate_order!(certificates)
      validate_trusted_self_signed_certificates!(certificates)
    end

    def validate_no_duplicates!(certificates)
      encoded_certificates = certificates.map(&:to_der)
      return if encoded_certificates.uniq.length == encoded_certificates.length

      raise JWT::DuplicateCertificateError, 'Certificate chain contains duplicate certificates'
    end

    def validate_certificate_order!(certificates)
      certificates.each_cons(2) do |certificate, issuer_certificate|
        next if certificate.issuer == issuer_certificate.subject &&
                certificate.verify(issuer_certificate.public_key)

        raise JWT::CertificateChainOrderError,
              'Certificate chain must be ordered from the signing certificate toward its issuer'
      end
    end

    def validate_trusted_self_signed_certificates!(certificates)
      certificates.each do |certificate|
        next unless certificate.subject == certificate.issuer && certificate.verify(certificate.public_key)
        next if trusted_root?(certificate)

        raise JWT::CertificateChainError,
              'Self-signed certificates in the x5c chain must also be supplied as trusted roots'
      end
    end

    def validate_chain_depth!(verified_chain)
      return if @max_chain_depth.nil?

      intermediate_count = verified_chain.count { |certificate| !trusted_root?(certificate) } - 1
      return if intermediate_count <= @max_chain_depth

      raise JWT::CertificateChainDepthError,
            "Certificate chain depth #{intermediate_count} exceeds maximum #{@max_chain_depth}"
    end

    def validate_leaf_key_usage!(certificate)
      return unless @require_digital_signature

      extension = extension_by_oid(certificate, KEY_USAGE_OID)
      if extension.nil?
        return if @allow_missing_digital_signature

        raise JWT::MissingKeyUsageError, 'Signing certificate is missing the key usage extension'
      end

      return if digital_signature_allowed?(extension)

      raise JWT::InvalidKeyUsageError, 'Signing certificate does not permit digitalSignature'
    end

    def validate_leaf_extended_key_usage!(certificate)
      return if @required_ekus.empty?

      extension = extension_by_oid(certificate, EXTENDED_KEY_USAGE_OID)
      if extension.nil?
        return if @allow_missing_eku

        raise JWT::MissingExtendedKeyUsageError,
              'Signing certificate is missing the extended key usage extension'
      end

      extended_key_usages = decode_extended_key_usages(extension)
      return if @required_ekus.all? { |required_eku| extended_key_usages.include?(required_eku) }

      raise JWT::InvalidExtendedKeyUsageError,
            "Signing certificate does not include required extended key usage: #{@required_ekus.join(', ')}"
    end

    def digital_signature_allowed?(extension)
      der_bytes = extension.value_der.bytes
      return false if der_bytes.length < 4

      der_bytes[3] & DIGITAL_SIGNATURE_BIT != 0
    rescue OpenSSL::ASN1::ASN1Error, NoMethodError
      false
    end

    def decode_extended_key_usages(extension)
      decoded_extension = OpenSSL::ASN1.decode(extension.value_der)
      raise OpenSSL::ASN1::ASN1Error unless decoded_extension.is_a?(OpenSSL::ASN1::Sequence)

      decoded_extension.value.map do |object_identifier|
        raise OpenSSL::ASN1::ASN1Error unless object_identifier.is_a?(OpenSSL::ASN1::ObjectId)

        object_identifier.oid
      end
    rescue OpenSSL::ASN1::ASN1Error
      raise JWT::InvalidExtendedKeyUsageError,
            'Signing certificate has an invalid extended key usage extension'
    end

    def trusted_root?(certificate)
      @root_certificates.any? { |root_certificate| root_certificate.to_der == certificate.to_der }
    end

    def extension_by_oid(certificate, oid)
      certificate.extensions.find { |extension| OpenSSL::ASN1::ObjectId.new(extension.oid).oid == oid }
    rescue OpenSSL::ASN1::ASN1Error
      nil
    end

    def normalize_oid(oid)
      OpenSSL::ASN1::ObjectId.new(oid.to_s).oid
    rescue OpenSSL::ASN1::ASN1Error, TypeError
      raise ArgumentError, "Invalid extended key usage OID: #{oid}"
    end

    def raise_verification_error(store_context)
      error_class = verification_error_class(store_context.error)
      message = "Certificate verification failed: #{store_context.error_string}."
      if (current_cert = store_context.current_cert)
        message = "#{message} Certificate subject: #{current_cert.subject}."
      end

      raise error_class, message
    end

    def verification_error_class(error)
      case error
      when OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED
        JWT::CertificateExpiredError
      when OpenSSL::X509::V_ERR_CERT_NOT_YET_VALID
        JWT::CertificateNotYetValidError
      when OpenSSL::X509::V_ERR_UNHANDLED_CRITICAL_EXTENSION,
           OpenSSL::X509::V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION
        JWT::UnsupportedCriticalExtensionError
      when OpenSSL::X509::V_ERR_PATH_LENGTH_EXCEEDED, OpenSSL::X509::V_ERR_CERT_CHAIN_TOO_LONG
        JWT::CertificateChainDepthError
      when OpenSSL::X509::V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
           OpenSSL::X509::V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
           OpenSSL::X509::V_ERR_CERT_UNTRUSTED,
           OpenSSL::X509::V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
           OpenSSL::X509::V_ERR_UNABLE_TO_GET_ISSUER_CERT,
           OpenSSL::X509::V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
        JWT::CertificateChainError
      when OpenSSL::X509::V_ERR_SUBJECT_ISSUER_MISMATCH, OpenSSL::X509::V_ERR_PATH_LOOP
        JWT::CertificateChainOrderError
      else
        JWT::VerificationError
      end
    end
  end
end
