require 'cgi'

require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/utils"
require "onelogin/ruby-saml/validation_error"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 HTTP-Redirect binding parameters, as verified against the IdP
    # signature. Only the well-known binding parameters that were part of the
    # signed query string are exposed here; unknown extra query parameters are
    # deliberately not carried over so they can never inherit that trust.
    #
    class VerifiedBindingParams

      # @return [String] 'SAMLRequest' or 'SAMLResponse'
      attr_reader :type

      # @return [String] The decoded (but still Base64/deflated) SAML message
      attr_reader :saml

      # @return [String|nil] The decoded RelayState, nil when absent
      attr_reader :relay_state

      # @return [String] The decoded signature algorithm URI
      attr_reader :sig_alg

      # @return [String|nil] 'request' or 'response' convenience accessor
      def message_type
        type == 'SAMLRequest' ? 'request' : 'response'
      end

      # @return [Boolean] True when the binding carried a SAMLRequest
      def request?
        type == 'SAMLRequest'
      end

      # @return [Boolean] True when the binding carried a SAMLResponse
      def response?
        type == 'SAMLResponse'
      end

      # Hash suitable to be passed as :get_params to the receiving message
      # classes. Never includes the Signature and never includes parameters
      # that were not part of the signed, well-known binding set.
      #
      # @return [Hash]
      def to_h
        params = { type => saml, 'SigAlg' => sig_alg }
        params['RelayState'] = relay_state unless relay_state.nil?
        params
      end

      # @private
      def initialize(type:, saml:, relay_state:, sig_alg:)
        @type = type
        @saml = saml
        @relay_state = relay_state
        @sig_alg = sig_alg
        freeze
      end
    end

    # Verifies a SAML 2.0 HTTP-Redirect binding message directly from the raw,
    # still percent-encoded query string, exactly as received from the IdP.
    #
    # Web frameworks usually decode the query string before handing it to the
    # application. Re-encoding those values while rebuilding the signature
    # input can silently change it (percent case, '+', ordering, ...) and make
    # a valid signature fail, or an attacker-controlled value be mixed in.
    # This class parses the raw query itself and keeps the original octets
    # when constructing the canonical string to be signed.
    #
    class RedirectBinding < SamlMessage

      # Verifies the raw query string, raising when validation fails.
      #
      # @param (see #initialize)
      # @return [VerifiedBindingParams] The trusted binding parameters
      # @raise [ValidationError] if the query string is malformed or the signature does not verify
      #
      def self.verify!(raw_query_string, settings: nil, cert: nil)
        new(raw_query_string, settings: settings, cert: cert, soft: false).verify!
      end

      # Verifies the raw query string, returning nil when validation fails.
      # Errors are available through #errors.
      #
      # @param (see #initialize)
      # @return [VerifiedBindingParams|nil] The trusted binding parameters, or nil
      #
      def self.verify(raw_query_string, settings: nil, cert: nil)
        new(raw_query_string, settings: settings, cert: cert, soft: true).verified_params
      end

      # @return [Array<String>] Validation errors collected on the last verification run
      attr_reader :errors

      # @param raw_query_string [String] The raw query string (without leading '?') exactly as received
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings, used to obtain the IdP cert(s)
      # @param cert [OpenSSL::X509::Certificate|String|nil] Explicit IdP certificate, takes precedence over settings
      # @param soft [Boolean|nil] When false, #verify! raises on failure; defaults to settings.soft or true
      #
      def initialize(raw_query_string, settings: nil, cert: nil, soft: nil)
        @raw_query_string = raw_query_string
        @settings = settings
        @cert = cert
        @soft = soft.nil? ? (settings.nil? || settings.soft.nil? ? true : settings.soft) : soft
        @errors = []
        @verified_params = nil
      end

      # Performs the verification, raising in non-soft mode on failure.
      #
      # @return [VerifiedBindingParams] The trusted binding parameters
      # @raise [ValidationError] when soft is false and validation fails
      #
      def verify!
        @errors = []
        @verified_params = nil

        raw_parts = parse
        return fail unless raw_parts

        query_string = build_signed_query(raw_parts)
        return fail unless query_string

        sig_alg = CGI.unescape(raw_parts['SigAlg'])
        signature = raw_parts['Signature']

        certs = verification_certs
        return fail if certs.nil?

        valid, expired = verify_against_certs(certs, sig_alg, signature, query_string)
        return fail("IdP x509 certificate expired") if expired
        return fail("Invalid Signature on HTTP-Redirect binding") unless valid

        @verified_params = VerifiedBindingParams.new(
          :type        => raw_parts[:type],
          :saml        => CGI.unescape(raw_parts[raw_parts[:type]]),
          :relay_state => raw_parts.key?('RelayState') ? CGI.unescape(raw_parts['RelayState']) : nil,
          :sig_alg     => sig_alg
        )
      end

      # @return [VerifiedBindingParams|nil] The trusted binding parameters after a successful verification
      #
      def verified_params
        verify! unless attempted?
        @verified_params
      end

      # @return [Boolean] True when the signature verified
      #
      def valid?
        verify! unless attempted?
        !@verified_params.nil?
      end

      private

      def attempted?
        @attempted == true
      end

      def fail(message = nil)
        append_error(message) if message
        raise ValidationError.new(@errors.join(', ')) unless @soft
        nil
      end

      def append_error(message)
        @errors << message
        message
      end

      # Splits the raw query string on '&' only, keeping each value exactly as
      # encoded. Rejects duplicate parameters instead of letting one override
      # another.
      #
      def parse
        @attempted = true

        query = @raw_query_string
        if query.nil? || !query.is_a?(String) || query.empty?
          return fail("Blank query string")
        end

        query = query[1..-1] if query.start_with?('?')
        if query.empty?
          return fail("Blank query string")
        end
        if query.start_with?('&') || query.end_with?('&') || query.include?('&&')
          return fail("Malformed query string: empty parameter")
        end

        parts = {}
        query.split('&').each do |pair|
          key, separator, raw_value = pair.partition('=')
          return fail("Malformed query string: parameter missing value") if separator.empty?
          return fail("Malformed query string: empty parameter name") if key.empty?
          return fail("Duplicate parameter '#{key}' in query string") if parts.key?(key)

          parts[key] = raw_value
        end

        has_request = parts.key?('SAMLRequest')
        has_response = parts.key?('SAMLResponse')
        if has_request && has_response
          return fail("Query string cannot contain both SAMLRequest and SAMLResponse")
        elsif !has_request && !has_response
          return fail("Query string must contain a SAMLRequest or SAMLResponse parameter")
        end

        parts[:type] = has_request ? 'SAMLRequest' : 'SAMLResponse'

        return fail("SAML message parameter is empty") if parts[parts[:type]].empty?
        return fail("Query string is missing the SigAlg parameter") unless parts.key?('SigAlg') && !parts['SigAlg'].empty?
        return fail("Query string is missing the Signature parameter") unless parts.key?('Signature') && !parts['Signature'].empty?

        parts
      end

      # Rebuilds the canonical signed string in the fixed order mandated by the
      # SAML 2.0 binding specification, reusing the exact encodings received.
      #
      def build_signed_query(parts)
        type = parts[:type]
        query = "#{type}=#{parts[type]}"
        # An empty RelayState present in the query string carries no value and
        # is not part of the signed input, matching the builder behavior.
        query << "&RelayState=#{parts['RelayState']}" if parts.key?('RelayState') && !parts['RelayState'].empty?
        query << "&SigAlg=#{parts['SigAlg']}"
        query
      end

      def verification_certs
        unless @cert.nil?
          cert = @cert.is_a?(OpenSSL::X509::Certificate) ? @cert : OneLogin::RubySaml::Utils.build_cert_object(@cert)
          return cert.nil? ? nil : [cert]
        end

        unless @settings.nil?
          multi = @settings.get_idp_cert_multi
          return multi[:signing] unless multi.nil? || multi[:signing].empty?

          cert = @settings.get_idp_cert
          return [cert] unless cert.nil?
        end

        append_error("No IdP certificate configured to verify the signature")
        nil
      end

      def verify_against_certs(certs, sig_alg, raw_signature, query_string)
        signature = CGI.unescape(raw_signature)
        expired = false
        valid = certs.any? do |cert|
          if OneLogin::RubySaml::Utils.verify_signature(
            :cert         => cert,
            :sig_alg      => sig_alg,
            :signature    => signature,
            :query_string => query_string
          )
            if @settings && @settings.security[:check_idp_cert_expiration] && OneLogin::RubySaml::Utils.is_cert_expired(cert)
              expired = true
            end
            true
          else
            false
          end
        end
        [valid, expired]
      end
    end
  end
end
