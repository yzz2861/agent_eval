require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class RedirectBindingTest < Minitest::Test

  SAML_REQUEST  = "fVJtT8IwEP0rmfYcQ1NtYqFkEWlSFKhS2YIFiRcwYpZEpDlQvHdrBmJb0qH33t27u7N9g/"
  SAML_RESPONSE = "fVLBbtwwEPwVq/1i2A6EtMh1U5agWKiV2mBqB6ZslCWlSJCI322FpEfr2na7"
  SIG_ALG       = XMLSecurity::Document::RSA_SHA256

  describe OneLogin::RubySaml::RedirectBinding do
    before do
      @settings = OneLogin::RubySaml::Settings.new
      @settings.idp_cert = ruby_saml_cert_text
      @signing_key = OpenSSL::PKey::RSA.new(ruby_saml_key_text)
    end

    def sign_query(query)
      digest = XMLSecurity::BaseDocument.new.algorithm(SIG_ALG).new
      Base64.strict_encode64(@signing_key.sign(digest, query))
    end

    # Builds a raw, percent-encoded query string signed with the (same) SP key,
    # allowing raw pieces to be supplied so encoding edge cases can be tested.
    def build_raw_query(type: 'SAMLRequest', saml: SAML_REQUEST, relay_state: nil,
                        sig_alg: SIG_ALG, extra: {}, include_relay: true)
      pieces = ["#{type}=#{CGI.escape(saml)}"]

      signed_relay_state = relay_state
      if include_relay && !relay_state.nil?
        pieces << "RelayState=#{CGI.escape(relay_state)}"
        signed_relay_state = relay_state.empty? ? nil : relay_state
      end

      pieces << "SigAlg=#{CGI.escape(sig_alg)}"

      signed_query = OneLogin::RubySaml::Utils.build_query(
        :type => type,
        :data => saml,
        :relay_state => signed_relay_state,
        :sig_alg => sig_alg
      )
      pieces << "Signature=#{CGI.escape(sign_query(signed_query))}"

      extra.each { |key, value| pieces.insert(-2, "#{key}=#{value}") }
      pieces.join('&')
    end

    describe "successful verification" do
      it "verifies a SAMLRequest and exposes trusted fields" do
        query = build_raw_query(relay_state: 'https://sp.example.com/relay')

        result = OneLogin::RubySaml::RedirectBinding.verify!(query, settings: @settings)

        assert_instance_of OneLogin::RubySaml::VerifiedBindingParams, result
        assert result.request?
        refute result.response?
        assert_equal 'SAMLRequest', result.type
        assert_equal 'request', result.message_type
        assert_equal SAML_REQUEST, result.saml
        assert_equal 'https://sp.example.com/relay', result.relay_state
        assert_equal SIG_ALG, result.sig_alg
        assert_equal(
          {
            'SAMLRequest' => SAML_REQUEST,
            'RelayState'  => 'https://sp.example.com/relay',
            'SigAlg'      => SIG_ALG
          },
          result.to_h
        )
        assert result.frozen?
      end

      it "verifies a SAMLResponse" do
        query = build_raw_query(type: 'SAMLResponse', saml: SAML_RESPONSE, include_relay: false)

        result = OneLogin::RubySaml::RedirectBinding.verify!(query, settings: @settings)

        assert result.response?
        assert_equal 'response', result.message_type
        assert_equal SAML_RESPONSE, result.saml
        assert_nil result.relay_state
        refute result.to_h.key?('RelayState')
      end

      it "accepts a query string with a leading '?'" do
        query = '?' + build_raw_query(include_relay: false)
        assert OneLogin::RubySaml::RedirectBinding.verify!(query, settings: @settings)
      end

      it "verifies when parameters arrive in a non canonical order" do
        raw_saml = CGI.escape(SAML_REQUEST)
        relay = 'https://sp.example.com/relay'
        signed_query = OneLogin::RubySaml::Utils.build_query(
          :type => 'SAMLRequest', :data => SAML_REQUEST,
          :relay_state => relay, :sig_alg => SIG_ALG
        )
        signature = CGI.escape(sign_query(signed_query))

        # Signature interleaved between signed parameters, RelayState first
        query = "RelayState=#{CGI.escape(relay)}&SAMLRequest=#{raw_saml}" \
                "&Signature=#{signature}&SigAlg=#{CGI.escape(SIG_ALG)}"

        result = OneLogin::RubySaml::RedirectBinding.verify!(query, settings: @settings)
        assert_equal relay, result.relay_state
      end

      it "verifies an empty RelayState present in the query string" do
        query = build_raw_query(relay_state: '')

        result = OneLogin::RubySaml::RedirectBinding.verify!(query, settings: @settings)

        assert_equal '', result.relay_state
        assert_equal '', result.to_h['RelayState']
      end

      it "verifies a query without RelayState" do
        query = build_raw_query(include_relay: false)

        result = OneLogin::RubySaml::RedirectBinding.verify!(query, settings: @settings)
        assert_nil result.relay_state
      end

      it "preserves percent-encoding case when rebuilding the signed input" do
        relay_encoded = "https%3a%2f%2fsp.example.com%2frelay"
        raw_saml = CGI.escape(SAML_REQUEST).gsub(/%[A-F0-9]{2}/) { |match| match.downcase }
        raw_sig_alg = downcased_escape(SIG_ALG)

        signed_query = "SAMLRequest=#{raw_saml}&RelayState=#{relay_encoded}&SigAlg=#{raw_sig_alg}"
        signature = CGI.escape(sign_query(signed_query))
        query = "#{signed_query}&Signature=#{signature}"

        result = OneLogin::RubySaml::RedirectBinding.verify!(query, settings: @settings)
        assert_equal 'https://sp.example.com/relay', result.relay_state
        assert_equal SAML_REQUEST, result.saml
        assert_equal SIG_ALG, result.sig_alg
      end

      it "keeps '+' in values literal instead of treating it as a space" do
        # The '+' is an encoded plus sent by the IdP; the signature covers the
        # raw representation, so decoding it later must not invalidate verification.
        relay_encoded = "a%2Bb+c"
        signed_query = "SAMLRequest=#{CGI.escape(SAML_REQUEST)}&RelayState=#{relay_encoded}&SigAlg=#{CGI.escape(SIG_ALG)}"
        signature = CGI.escape(sign_query(signed_query))
        query = "#{signed_query}&Signature=#{signature}"

        result = OneLogin::RubySaml::RedirectBinding.verify!(query, settings: @settings)
        assert_equal 'a+b c', result.relay_state
      end

      it "does not trust extra unknown query parameters" do
        query = build_raw_query(
          relay_state: 'https://sp.example.com/relay',
          extra: { 'Evil' => 'inject', 'foo' => 'bar' }
        )

        result = OneLogin::RubySaml::RedirectBinding.verify!(query, settings: @settings)

        assert_equal %w[SAMLRequest SigAlg RelayState], result.to_h.keys
        refute result.to_h.key?('Evil')
        refute result.respond_to?(:extra)
      end

      it "verifies with an explicit certificate object or PEM string" do
        query = build_raw_query(include_relay: false)

        assert OneLogin::RubySaml::RedirectBinding.verify!(query, cert: ruby_saml_cert)
        assert OneLogin::RubySaml::RedirectBinding.verify!(query, cert: ruby_saml_cert_text)
      end

      it "verifies when at least one of multiple idp certs matches" do
        @settings.idp_cert = nil
        @settings.idp_cert_multi = {
          signing: [ruby_saml_cert_text2, ruby_saml_cert_text],
          encryption: []
        }
        query = build_raw_query(include_relay: false)

        assert OneLogin::RubySaml::RedirectBinding.verify!(query, settings: @settings)
      end

      it "is idempotent on valid data" do
        binding = OneLogin::RubySaml::RedirectBinding.new(build_raw_query(include_relay: false), settings: @settings)
        assert binding.valid?
        assert_empty binding.errors
        assert binding.verified_params
        assert binding.valid?
      end
    end

    describe "rejected queries" do
      def assert_rejects(raw_query, message_part = nil, settings: @settings)
        assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.verify!(raw_query, settings: settings)
        end

        assert_nil OneLogin::RubySaml::RedirectBinding.verify(raw_query, settings: settings)

        if message_part
          binding = OneLogin::RubySaml::RedirectBinding.new(raw_query, settings: settings)
          refute binding.valid?
          assert(binding.errors.any? { |error| error.include?(message_part) },
                 "expected errors #{binding.errors.inspect} to include #{message_part.inspect}")
        end
      end

      it "rejects a nil or empty query string" do
        assert_rejects nil, "Blank query string"
        assert_rejects '', "Blank query string"
        assert_rejects '?', "Blank query string"
      end

      it "rejects duplicate parameters instead of last-value-wins" do
        query = build_raw_query(relay_state: 'https://sp.example.com/relay')
        assert_rejects query + '&RelayState=other', "Duplicate parameter"
      end

      it "rejects a duplicated SigAlg even if the values match" do
        query = build_raw_query(include_relay: false)
        assert_rejects query.sub('SigAlg=', "SigAlg=x&SigAlg="), "Duplicate parameter"
      end

      it "rejects when both SAMLRequest and SAMLResponse are present" do
        query = build_raw_query + "&SAMLResponse=#{CGI.escape(SAML_RESPONSE)}"
        assert_rejects query, "both SAMLRequest and SAMLResponse"
      end

      it "rejects when neither SAMLRequest nor SAMLResponse is present" do
        query = "RelayState=x&SigAlg=#{CGI.escape(SIG_ALG)}&Signature=#{CGI.escape('abc')}"
        assert_rejects query, "SAMLRequest or SAMLResponse"
      end

      it "rejects a missing SigAlg" do
        query = build_raw_query(include_relay: false).sub(/&SigAlg=[^&]+/, '')
        assert_rejects query, "missing the SigAlg"
      end

      it "rejects a missing Signature" do
        query = build_raw_query(include_relay: false).sub(/&Signature=[^&]+/, '')
        assert_rejects query, "missing the Signature"
      end

      it "rejects an empty SigAlg or Signature" do
        query = build_raw_query(include_relay: false).sub(
          'SigAlg=' + CGI.escape(SIG_ALG), 'SigAlg='
        )
        assert_rejects query, "missing the SigAlg"

        query = build_raw_query(include_relay: false).sub(/Signature=[^&]+/, 'Signature=')
        assert_rejects query, "missing the Signature"
      end

      it "rejects malformed pairs" do
        base = 'SAMLRequest=' + CGI.escape(SAML_REQUEST)
        assert_rejects base + '&&RelayState=x', "empty parameter"
        assert_rejects '&' + base, "empty parameter"
        assert_rejects base + '&', "empty parameter"
        assert_rejects base + '&novalue', "missing value"
      end

      it "rejects a signature signed by a different key" do
        _other_cert, other_key = CertificateHelper.generate_pair
        signed_query = OneLogin::RubySaml::Utils.build_query(
          :type => 'SAMLRequest', :data => SAML_REQUEST,
          :relay_state => 'https://sp.example.com/relay', :sig_alg => SIG_ALG
        )
        forged = Base64.strict_encode64(other_key.sign(XMLSecurity::BaseDocument.new.algorithm(SIG_ALG).new, signed_query))
        query = build_raw_query(relay_state: 'https://sp.example.com/relay')
        query = query.sub(/Signature=[^&]+/, 'Signature=' + CGI.escape(forged))

        assert_rejects query, "Invalid Signature"
      end

      it "rejects a tampered SAML message" do
        query = build_raw_query(include_relay: false)
        tampered = query.sub(SAML_REQUEST[0, 4], 'AAAA')
        assert_rejects tampered, "Invalid Signature"
      end

      it "rejects a tampered relay state" do
        query = build_raw_query(relay_state: 'https://sp.example.com/relay')
        tampered = query.sub('RelayState=https', 'RelayState=http_')
        assert_rejects tampered, "Invalid Signature"
      end

      it "fails soft when no idp certificate is configured" do
        assert_rejects build_raw_query(include_relay: false), "No IdP certificate", settings: OneLogin::RubySaml::Settings.new
      end

      it "rejects an expired idp certificate when expiration is enforced" do
        expired_cert, expired_key = CertificateHelper.generate_pair(
          not_before: Time.now - (3600 * 24 * 730),
          not_after: Time.now - (3600 * 24)
        )
        settings = OneLogin::RubySaml::Settings.new
        settings.idp_cert = expired_cert.to_pem
        settings.security[:check_idp_cert_expiration] = true

        signed_query = OneLogin::RubySaml::Utils.build_query(
          :type => 'SAMLRequest', :data => SAML_REQUEST, :sig_alg => SIG_ALG
        )
        signature = Base64.strict_encode64(
          expired_key.sign(XMLSecurity::BaseDocument.new.algorithm(SIG_ALG).new, signed_query)
        )
        query = "SAMLRequest=#{CGI.escape(SAML_REQUEST)}&SigAlg=#{CGI.escape(SIG_ALG)}&Signature=#{CGI.escape(signature)}"

        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.verify!(query, settings: settings)
        end
        assert_match(/certificate expired/, error.message)
      end
    end
  end
end
