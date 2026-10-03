# frozen_string_literal: true

module JWT
  # Validates an x5c certificate chain and returns the public key of the leaf.
  # See https://tools.ietf.org/html/rfc7515#section-4.1.6
  class X5cKeyFinder
    ANY_EXTENDED_KEY_USAGE_OID = '2.5.29.37.0'
    DIGITAL_SIGNATURE_BIT = 0x80

    def initialize(root_certificates,
                   crls = nil,
                   eku: nil,
                   allow_missing_eku: false,
                   allow_mismatched_eku: false,
                   digital_signature: false,
                   allow_missing_key_usage: false,
                   allow_mismatched_key_usage: false,
                   max_chain_depth: nil,
                   time: nil,
                   verification_time: nil)
      raise ArgumentError, 'Root certificates must be specified' unless root_certificates

      @root_certificates = root_certificates
      configure_policy(eku, allow_missing_eku, allow_mismatched_eku, digital_signature,
                       allow_missing_key_usage, allow_mismatched_key_usage, max_chain_depth,
                       time, verification_time)

      validate_configuration!
      @store = build_store(root_certificates, crls)
    end

    def from(x5c_header_or_certificates)
      certificates = parse_certificates(x5c_header_or_certificates)
      signing_certificate = certificates.first
      certificate_chain = certificates[1..] || []

      validate_chain_structure!(certificates)

      store_context = OpenSSL::X509::StoreContext.new(@store, signing_certificate, certificate_chain)
      store_context.purpose = OpenSSL::X509::PURPOSE_ANY
      store_context.time = verification_time if verification_time

      if store_context.verify
        validate_leaf_policies!(signing_certificate)
        signing_certificate.public_key
      else
        raise_store_error(store_context)
      end
    end

    private

    attr_reader :ekus, :max_chain_depth, :root_certificates

    def configure_policy(eku, allow_missing_eku, allow_mismatched_eku, digital_signature,
                         allow_missing_key_usage, allow_mismatched_key_usage,
                         max_chain_depth, time, verification_time)
      @ekus = Array(eku).map { |value| normalize_oid(value) }
      @allow_missing_eku = allow_missing_eku
      @allow_mismatched_eku = allow_mismatched_eku
      @digital_signature = digital_signature
      @allow_missing_key_usage = allow_missing_key_usage
      @allow_mismatched_key_usage = allow_mismatched_key_usage
      @max_chain_depth = max_chain_depth
      @time_argument = verification_time.nil? ? time : verification_time
    end

    def validate_configuration!
      if max_chain_depth && (!max_chain_depth.is_a?(Integer) || max_chain_depth.negative?)
        raise ArgumentError, 'Maximum chain depth must be a non-negative integer'
      end

      return unless @time_argument
      return if @time_argument.is_a?(Time) || @time_argument.is_a?(Numeric)

      raise ArgumentError, 'Verification time must be a Time or numeric timestamp'
    end

    def verification_time
      @verification_time ||= if @time_argument.nil?
                                nil
                              elsif @time_argument.is_a?(Time)
                                @time_argument
                              else
                                Time.at(@time_argument)
                              end
    end

    def normalize_oid(oid)
      OpenSSL::ASN1::ObjectId.new(oid.to_s).oid
    rescue ArgumentError
      raise ArgumentError, "Invalid EKU OID: #{oid}"
    end

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
        raise JWT::InvalidCertificateChainError, 'Certificate chain must be a non-empty array'
      end

      x5c_header_or_certificates.map do |certificate|
        next certificate if certificate.is_a?(OpenSSL::X509::Certificate)
        unless certificate.is_a?(String)
          raise JWT::CertificateError, 'Invalid certificate in x5c header: value must be a string'
        end

        begin
          OpenSSL::X509::Certificate.new(::JWT::Base64.url_decode(certificate))
        rescue JWT::Base64DecodeError => e
          raise JWT::CertificateError, "Invalid certificate in x5c header: #{e.message}"
        end
      end
    rescue OpenSSL::X509::CertificateError, ArgumentError, TypeError => e
      raise JWT::CertificateError, "Invalid certificate in x5c header: #{e.message}"
    end

    def validate_chain_structure!(certificates)
      detect_duplicates!(certificates)
      validate_certificate_order!(certificates)
      validate_chain_depth!(certificates)
    end

    def detect_duplicates!(certificates)
      seen = {}
      certificates.each do |certificate|
        encoded = certificate.to_der
        raise JWT::DuplicateCertificateError, duplicate_message(certificate) if seen.key?(encoded)

        seen[encoded] = true
      end
    end

    def validate_certificate_order!(certificates)
      certificates.each_cons(2) do |certificate, issuer|
        next if certificate.issuer == issuer.subject && certificate.verify(issuer.public_key)

        raise JWT::CertificateChainOrderError, order_message(certificate, issuer)
      end
    end

    def validate_chain_depth!(certificates)
      return unless max_chain_depth

      intermediates = certificates[1..] || []
      intermediates = intermediates[0...-1] if intermediates.any? && trusted_root?(intermediates.last)

      return if intermediates.size <= max_chain_depth

      raise JWT::InvalidCertificateChainError,
            "Certificate chain depth #{intermediates.size} exceeds maximum #{max_chain_depth}"
    end

    def trusted_root?(certificate)
      root_certificates.any? { |root| root.to_der == certificate.to_der }
    end

    def validate_leaf_policies!(certificate)
      validate_eku!(certificate) unless ekus.empty?
      validate_digital_signature!(certificate) if @digital_signature
    end

    def validate_eku!(certificate)
      extension = certificate.find_extension('extendedKeyUsage')
      if extension.nil?
        raise JWT::MissingEkuError, missing_extension_message('Extended key usage') unless @allow_missing_eku
        return
      end

      certificate_ekus = decode_ekus(extension)
      return if certificate_ekus.include?(ANY_EXTENDED_KEY_USAGE_OID) || (certificate_ekus & ekus).any?
      return if @allow_mismatched_eku

      raise JWT::InvalidEkuError,
            "Leaf certificate extended key usage #{certificate_ekus.join(', ')} does not match #{ekus.join(', ')}"
    end

    def decode_ekus(extension)
      OpenSSL::ASN1.decode(extension.value_der).value.map(&:oid)
    end

    def validate_digital_signature!(certificate)
      extension = certificate.find_extension('keyUsage')
      if extension.nil?
        unless @allow_missing_key_usage
          raise JWT::MissingKeyUsageError, missing_extension_message('Key usage')
        end

        return
      end

      return if digital_signature_allowed?(extension)
      return if @allow_mismatched_key_usage

      raise JWT::InvalidKeyUsageError, 'Leaf certificate key usage does not allow digital signature'
    end

    def digital_signature_allowed?(extension)
      key_usage = OpenSSL::ASN1.decode(extension.value_der)
      key_usage.value.bytes.first & DIGITAL_SIGNATURE_BIT != 0
    end

    def raise_store_error(store_context)
      error = store_context.error
      if error == OpenSSL::X509::V_ERR_UNHANDLED_CRITICAL_EXTENSION
        raise JWT::UnsupportedCriticalExtensionError, store_failure_message(store_context)
      elsif error == OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED && store_context.error_depth.positive?
        raise JWT::ExpiredIntermediateCertificateError, store_failure_message(store_context)
      end

      raise JWT::VerificationError, store_failure_message(store_context)
    end

    def store_failure_message(store_context)
      error = "Certificate verification failed: #{store_context.error_string}."
      current_cert = store_context.current_cert
      return error unless current_cert

      "#{error} Certificate subject: #{current_cert.subject}."
    end

    def duplicate_message(certificate)
      "Duplicate certificate in chain: #{certificate.subject}"
    end

    def order_message(certificate, issuer)
      "Certificate chain is not in leaf-to-root order: #{certificate.subject} is not issued by #{issuer.subject}"
    end

    def missing_extension_message(extension_name)
      "Leaf certificate is missing the required #{extension_name} extension"
    end
  end
end
