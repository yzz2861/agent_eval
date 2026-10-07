require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/redirect_binding'

class RedirectBindingTest < Minitest::Test

  describe "RedirectBinding" do
    let(:settings) do
      OneLogin::RubySaml::Settings.new.tap { |s| s.idp_cert = ruby_saml_cert_text }
    end

    let(:rsa_sha256) { XMLSecurity::Document::RSA_SHA256 }

    def deflate(xml)
      Zlib::Deflate.deflate(xml, 9)[2..-5]
    end

    def saml_request_value
      @saml_request_value ||= Base64.strict_encode64(deflate('<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>'))
    end

    def saml_response_value
      @saml_response_value ||= Base64.strict_encode64(deflate('<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>'))
    end

    # Sign the given signed portion and return a full query string with
    # the Signature parameter appended.
    def append_signature(signed_portion, key = ruby_saml_key, sig_alg = XMLSecurity::Document::RSA_SHA256)
      algorithm = XMLSecurity::BaseDocument.new.algorithm(sig_alg)
      signature = key.sign(algorithm.new, signed_portion)
      signed_portion + "&Signature=" + CGI.escape(Base64.strict_encode64(signature))
    end

    # Build a signed query string. raw_relay_state must already be URL-encoded,
    # so tests can control the exact bytes that go into the signature.
    def signed_query(raw_relay_state: nil, type: 'SAMLRequest', value: nil, key: ruby_saml_key, sig_alg: XMLSecurity::Document::RSA_SHA256)
      value ||= type == 'SAMLRequest' ? saml_request_value : saml_response_value
      signed_portion = "#{type}=#{CGI.escape(value)}"
      signed_portion << "&RelayState=#{raw_relay_state}" unless raw_relay_state.nil?
      signed_portion << "&SigAlg=#{CGI.escape(sig_alg)}"
      append_signature(signed_portion, key, sig_alg)
    end

    describe "structural rules" do
      it "rejects duplicate parameters instead of letting the last value win" do
        query = "SAMLRequest=a&SAMLRequest=b&SigAlg=c&Signature=d"
        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.parse(query)
        end
        assert_includes error.message, "Duplicate parameter"
      end

      it "rejects duplicates even when the parameter name is percent-encoded" do
        query = "SAMLRequest=a&%53AMLRequest=b&SigAlg=c&Signature=d"
        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.parse(query)
        end
        assert_includes error.message, "Duplicate parameter"
      end

      it "rejects duplicated unknown parameters" do
        query = "SAMLRequest=a&SigAlg=c&Signature=d&foo=1&foo=2"
        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.parse(query)
        end
        assert_includes error.message, "Duplicate parameter"
      end

      it "rejects a query string with both SAMLRequest and SAMLResponse" do
        query = "SAMLRequest=a&SAMLResponse=b&SigAlg=c&Signature=d"
        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.parse(query)
        end
        assert_includes error.message, "both SAMLRequest and SAMLResponse"
      end

      it "rejects a query string without SAMLRequest or SAMLResponse" do
        query = "SigAlg=c&Signature=d"
        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.parse(query)
        end
        assert_includes error.message, "neither SAMLRequest nor SAMLResponse"
      end

      it "rejects a Signature without SigAlg" do
        query = "SAMLRequest=a&Signature=d"
        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.parse(query)
        end
        assert_includes error.message, "SigAlg parameter is missing"
      end

      it "rejects a SigAlg without Signature" do
        query = "SAMLRequest=a&SigAlg=c"
        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.parse(query)
        end
        assert_includes error.message, "Signature parameter is missing"
      end

      it "rejects an unsigned message on verify" do
        query = "SAMLRequest=a"
        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.verify(query, settings)
        end
        assert_includes error.message, "Signature and SigAlg parameters are required"
      end

      it "raises ArgumentError when the raw query string is nil" do
        assert_raises(ArgumentError) { OneLogin::RubySaml::RedirectBinding.new(nil) }
      end
    end

    describe ".parse" do
      it "returns the raw, still URL-encoded values" do
        query = signed_query(raw_relay_state: "a+b")
        raw_params = OneLogin::RubySaml::RedirectBinding.parse(query)
        assert_equal "a+b", raw_params['RelayState']
        assert_equal CGI.escape(saml_request_value), raw_params['SAMLRequest']
        assert_equal CGI.escape(rsa_sha256), raw_params['SigAlg']
      end
    end

    describe "signature verification" do
      it "verifies a signed SAMLRequest query string and exposes trusted fields" do
        query = signed_query(raw_relay_state: CGI.escape("http://example.com"))
        verified = OneLogin::RubySaml::RedirectBinding.verify(query, settings)

        assert verified.request?
        refute verified.response?
        assert_equal :request, verified.type
        assert_equal saml_request_value, verified.saml_request
        assert_nil verified.saml_response
        assert_equal "http://example.com", verified.relay_state
        assert_equal rsa_sha256, verified.sig_alg
        refute_nil verified.signature
      end

      it "verifies a signed SAMLResponse query string" do
        query = signed_query(type: 'SAMLResponse')
        verified = OneLogin::RubySaml::RedirectBinding.verify(query, settings)

        assert verified.response?
        refute verified.request?
        assert_equal saml_response_value, verified.saml_response
        assert_nil verified.saml_request
        assert_nil verified.relay_state
      end

      it "rejects a tampered RelayState" do
        query = signed_query(raw_relay_state: CGI.escape("http://example.com"))
        tampered = query.sub(CGI.escape("http://example.com"), CGI.escape("http://evil.example.com"))
        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.verify(tampered, settings)
        end
        assert_includes error.message, "Invalid Signature"
      end

      it "rejects when the IdP certificate does not match the signature" do
        settings.idp_cert = ruby_saml_cert_text2
        query = signed_query
        assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.verify(query, settings)
        end
      end

      it "rejects when no IdP certificate is configured" do
        settings.idp_cert = nil
        query = signed_query
        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.verify(query, settings)
        end
        assert_includes error.message, "No fingerprint or certificate"
      end

      it "accepts an unverifiable message with :relax_signature_validation" do
        settings.idp_cert = nil
        query = signed_query
        verified = OneLogin::RubySaml::RedirectBinding.verify(query, settings, :relax_signature_validation => true)
        assert_equal saml_request_value, verified.saml_request
      end

      it "verifies against idp_cert_multi signing certificates" do
        settings.idp_cert = nil
        settings.idp_cert_multi = { :signing => [ruby_saml_cert_text], :encryption => [] }
        query = signed_query
        verified = OneLogin::RubySaml::RedirectBinding.verify(query, settings)
        assert verified.request?
      end

      it "rejects an expired IdP certificate when expiration checking is enabled" do
        cert, key = CertificateHelper.generate_pair(not_after: Time.now - 3600)
        settings.idp_cert = cert.to_pem
        settings.security[:check_idp_cert_expiration] = true
        query = signed_query(key: key)
        error = assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.verify(query, settings)
        end
        assert_includes error.message, "IdP x509 certificate expired"
      end
    end

    describe "raw encoding preservation" do
      it "verifies a signature computed over lowercase percent-encoding" do
        query = signed_query(raw_relay_state: "http%3a%2f%2fexample.com%2fsso")
        verified = OneLogin::RubySaml::RedirectBinding.verify(query, settings)
        assert_equal "http://example.com/sso", verified.relay_state
      end

      it "rejects when the percent-encoding case differs from what was signed" do
        query = signed_query(raw_relay_state: "http%3a%2f%2fexample.com%2fsso")
        uppercased = query.gsub("%2f", "%2F")
        refute_equal query, uppercased
        assert_equal CGI.unescape(query), CGI.unescape(uppercased)
        assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.verify(uppercased, settings)
        end
      end

      it "verifies a RelayState containing a plus sign and decodes it as a space" do
        query = signed_query(raw_relay_state: "hello+world")
        verified = OneLogin::RubySaml::RedirectBinding.verify(query, settings)
        assert_equal "hello world", verified.relay_state
      end

      it "distinguishes a plus sign from a percent-encoded space" do
        query = signed_query(raw_relay_state: "hello%20world")
        swapped = query.sub("hello%20world", "hello+world")
        assert_equal CGI.unescape(query), CGI.unescape(swapped)
        assert_raises(OneLogin::RubySaml::ValidationError) do
          OneLogin::RubySaml::RedirectBinding.verify(swapped, settings)
        end
      end

      it "verifies a query string with an empty RelayState" do
        query = signed_query(raw_relay_state: "")
        verified = OneLogin::RubySaml::RedirectBinding.verify(query, settings)
        assert_equal "", verified.relay_state
      end

      it "verifies a query string without RelayState" do
        query = signed_query
        verified = OneLogin::RubySaml::RedirectBinding.verify(query, settings)
        assert_nil verified.relay_state
      end

      it "verifies regardless of the parameter order in the query string" do
        query = signed_query(raw_relay_state: CGI.escape("http://example.com"))
        parts = query.split('&')
        reordered = ([parts.last] + parts[0..-2].reverse).join('&')
        verified = OneLogin::RubySaml::RedirectBinding.verify(reordered, settings)
        assert_equal "http://example.com", verified.relay_state
        assert_equal saml_request_value, verified.saml_request
      end
    end

    describe "trusted fields" do
      it "ignores extra query parameters and does not expose them" do
        query = "foo=bar&admin=true&" + signed_query(raw_relay_state: CGI.escape("http://example.com"))
        verified = OneLogin::RubySaml::RedirectBinding.verify(query, settings)

        assert verified.request?
        refute_respond_to verified, :foo
        refute_respond_to verified, :admin
      end

      it "returns a frozen object" do
        query = signed_query
        verified = OneLogin::RubySaml::RedirectBinding.verify(query, settings)
        assert verified.frozen?
      end
    end
  end
end
