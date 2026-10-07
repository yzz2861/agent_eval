require "cgi"

require "onelogin/ruby-saml/utils"
require "onelogin/ruby-saml/validation_error"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # Entry point for receiving SAML messages sent via the HTTP-Redirect binding.
    #
    # Web frameworks URL-decode the query string before handing it to the
    # application, and re-encoding the decoded values does not necessarily
    # reproduce the bytes the IdP actually signed (percent-encoding case,
    # '+' vs '%20', and so on). This class instead consumes the raw,
    # still-encoded query string, reconstructs the signature input
    # byte-for-byte as required by the SAML HTTP-Redirect binding, verifies
    # the signature against the IdP certificate(s) from the settings, and
    # returns a VerifiedParams object that only exposes the trusted,
    # signature-covered fields.
    #
    class RedirectBinding
      # Parameters defined by the HTTP-Redirect binding. Any other parameter
      # in the query string is tolerated but never exposed as trusted data.
      KNOWN_PARAMS = %w[SAMLRequest SAMLResponse RelayState SigAlg Signature].freeze

      # Trusted result of a successfully verified raw query string.
      # Only exposes fields covered by the verified signature; unrelated
      # query parameters are deliberately not accessible here.
      class VerifiedParams
        # @return [String|nil] The URL-decoded SAMLRequest parameter, if present
        attr_reader :saml_request
        # @return [String|nil] The URL-decoded SAMLResponse parameter, if present
        attr_reader :saml_response
        # @return [String|nil] The URL-decoded RelayState parameter (nil if absent, "" if empty)
        attr_reader :relay_state
        # @return [String] The URL-decoded SigAlg parameter
        attr_reader :sig_alg
        # @return [String] The URL-decoded Signature parameter
        attr_reader :signature

        def initialize(saml_request:, saml_response:, relay_state:, sig_alg:, signature:)
          @saml_request = saml_request
          @saml_response = saml_response
          @relay_state = relay_state
          @sig_alg = sig_alg
          @signature = signature
          freeze
        end

        # @return [Symbol] :request or :response
        def type
          saml_request.nil? ? :response : :request
        end

        def request?
          type == :request
        end

        def response?
          type == :response
        end
      end

      class << self
        # Parse and verify a raw query string received via the HTTP-Redirect binding.
        # @param raw_query_string [String] The raw, still URL-encoded query string
        # @param settings [OneLogin::RubySaml::Settings] Toolkit settings
        # @param options [Hash] :relax_signature_validation to accept the message
        #                       if no IdP certificate is registered on settings
        # @return [VerifiedParams] The verified binding parameters
        # @raise [ValidationError] if the query string is malformed or the signature is invalid
        #
        def verify(raw_query_string, settings, options = {})
          new(raw_query_string, settings, options).verify
        end

        # Parse a raw query string into raw (still URL-encoded) parameters,
        # enforcing the structural rules of the HTTP-Redirect binding.
        # @param raw_query_string [String] The raw, still URL-encoded query string
        # @return [Hash] Parameter name => raw (still URL-encoded) value
        # @raise [ValidationError] if the query string violates the binding rules
        #
        def parse(raw_query_string)
          new(raw_query_string).parse
        end
      end

      # @param raw_query_string [String] The raw, still URL-encoded query string
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @param options [Hash] Extra parameters
      # @raise [ArgumentError] if raw_query_string is nil
      #
      def initialize(raw_query_string, settings = nil, options = {})
        raise ArgumentError.new("raw_query_string cannot be nil") if raw_query_string.nil?

        @raw_query_string = raw_query_string
        @settings = settings
        @options = options || {}
      end

      # Parse the raw query string into raw (still URL-encoded) parameters.
      # Duplicate parameters are rejected instead of letting the last value
      # silently override the previous one.
      # @return [Hash] Parameter name => raw (still URL-encoded) value
      # @raise [ValidationError] if the query string violates the binding rules
      #
      def parse
        @raw_params ||= begin
          raw_params = {}
          @raw_query_string.split('&', -1).each do |pair|
            next if pair.empty?

            raw_name, raw_value = pair.split('=', 2)
            name = CGI.unescape(raw_name)
            if raw_params.key?(name)
              raise ValidationError.new("Duplicate parameter in query string: " + name)
            end
            raw_params[name] = raw_value || ""
          end

          has_request = raw_params.key?('SAMLRequest')
          has_response = raw_params.key?('SAMLResponse')
          if has_request && has_response
            raise ValidationError.new("Query string contains both SAMLRequest and SAMLResponse")
          end
          unless has_request || has_response
            raise ValidationError.new("Query string contains neither SAMLRequest nor SAMLResponse")
          end

          if raw_params.key?('Signature') && !raw_params.key?('SigAlg')
            raise ValidationError.new("SigAlg parameter is missing from signed query string")
          end
          if raw_params.key?('SigAlg') && !raw_params.key?('Signature')
            raise ValidationError.new("Signature parameter is missing from signed query string")
          end

          raw_params
        end
      end

      # Verify the signature of the raw query string against the IdP
      # certificate(s) from the settings.
      # @return [VerifiedParams] The verified binding parameters
      # @raise [ValidationError] if the message is unsigned, no IdP certificate
      #   is available, or the signature is invalid
      #
      def verify
        raw_params = parse

        unless raw_params.key?('Signature') && raw_params.key?('SigAlg')
          raise ValidationError.new("Signature and SigAlg parameters are required")
        end

        raise ValidationError.new("No settings on redirect binding verification") if @settings.nil?

        idp_cert = @settings.get_idp_cert
        idp_certs = @settings.get_idp_cert_multi

        if idp_cert.nil? && (idp_certs.nil? || idp_certs[:signing].empty?)
          unless @options[:relax_signature_validation]
            raise ValidationError.new("No fingerprint or certificate on settings of the redirect binding message")
          end
          return verified_params(raw_params)
        end

        query_string = OneLogin::RubySaml::Utils.build_query_from_raw_parts(
          :type            => raw_params.key?('SAMLRequest') ? 'SAMLRequest' : 'SAMLResponse',
          :raw_data        => raw_params['SAMLRequest'] || raw_params['SAMLResponse'],
          :raw_relay_state => raw_params['RelayState'],
          :raw_sig_alg     => raw_params['SigAlg']
        )

        sig_alg = CGI.unescape(raw_params['SigAlg'])
        signature = CGI.unescape(raw_params['Signature'])

        signing_certs = if idp_certs.nil? || idp_certs[:signing].empty?
          [idp_cert]
        else
          idp_certs[:signing]
        end

        valid = false
        expired = false
        signing_certs.each do |cert|
          valid = OneLogin::RubySaml::Utils.verify_signature(
            :cert         => cert,
            :sig_alg      => sig_alg,
            :signature    => signature,
            :query_string => query_string
          )
          next unless valid

          if @settings.security[:check_idp_cert_expiration] && OneLogin::RubySaml::Utils.is_cert_expired(cert)
            expired = true
          end
          break
        end

        raise ValidationError.new("IdP x509 certificate expired") if expired
        raise ValidationError.new("Invalid Signature on SAML Redirect binding message") unless valid

        verified_params(raw_params)
      end

      private

      # Build the trusted result object from the raw parameters. Only the
      # fields covered by the verified signature are exposed; any other
      # query parameters are dropped here.
      # @param raw_params [Hash] Parameter name => raw (still URL-encoded) value
      # @return [VerifiedParams]
      #
      def verified_params(raw_params)
        VerifiedParams.new(
          :saml_request  => raw_params['SAMLRequest'] && CGI.unescape(raw_params['SAMLRequest']),
          :saml_response => raw_params['SAMLResponse'] && CGI.unescape(raw_params['SAMLResponse']),
          :relay_state   => raw_params['RelayState'] && CGI.unescape(raw_params['RelayState']),
          :sig_alg       => CGI.unescape(raw_params['SigAlg']),
          :signature     => CGI.unescape(raw_params['Signature'])
        )
      end
    end
  end
end
