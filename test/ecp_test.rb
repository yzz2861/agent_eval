require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/ecp_request'
require 'onelogin/ruby-saml/ecp_response'

class EcpTest < Minitest::Test

  SOAP_ENV = OneLogin::RubySaml::SamlMessage::SOAP_ENV_NAMESPACE
  PAOS = OneLogin::RubySaml::SamlMessage::PAOS_NAMESPACE
  ECP = OneLogin::RubySaml::SamlMessage::ECP_NAMESPACE
  SOAP_ACTOR_NEXT = OneLogin::RubySaml::SamlMessage::SOAP_ACTOR_NEXT
  PAOS_BINDING = OneLogin::RubySaml::SamlMessage::PAOS_BINDING

  describe "EcpRequest" do
    let(:request_settings) do
      s = OneLogin::RubySaml::Settings.new
      s.sp_entity_id = "http://sp.example.com/metadata"
      s.assertion_consumer_service_url = "http://sp.example.com/acs"
      s.idp_sso_service_url = "http://idp.example.com/sso"
      s
    end

    it "raise when the assertion consumer service url is not declared" do
      request_settings.assertion_consumer_service_url = nil
      assert_raises(OneLogin::RubySaml::SettingError) do
        OneLogin::RubySaml::EcpRequest.new.create(request_settings)
      end
    end

    it "embed the AuthnRequest built by the Authrequest builder in the SOAP body" do
      ecp_request = OneLogin::RubySaml::EcpRequest.new
      envelope = REXML::Document.new(ecp_request.create(request_settings))

      authn_request = REXML::XPath.first(
        envelope,
        "/soap:Envelope/soap:Body/samlp:AuthnRequest",
        { "soap" => SOAP_ENV, "samlp" => OneLogin::RubySaml::SamlMessage::PROTOCOL }
      )
      refute_nil authn_request
      assert_equal ecp_request.request_id, authn_request.attributes['ID']
      assert_equal PAOS_BINDING, authn_request.attributes['ProtocolBinding']
      assert_equal "http://sp.example.com/acs", authn_request.attributes['AssertionConsumerServiceURL']
    end

    it "declare the response consumer url on a PAOS Request header block" do
      ecp_request = OneLogin::RubySaml::EcpRequest.new
      envelope = REXML::Document.new(ecp_request.create(request_settings))

      paos_request = REXML::XPath.first(
        envelope,
        "/soap:Envelope/soap:Header/paos:Request",
        { "soap" => SOAP_ENV, "paos" => PAOS }
      )
      refute_nil paos_request
      assert_equal "1", paos_request.attributes.get_attribute_ns(SOAP_ENV, "mustUnderstand").value
      assert_equal SOAP_ACTOR_NEXT, paos_request.attributes.get_attribute_ns(SOAP_ENV, "actor").value
      assert_equal "http://sp.example.com/acs", paos_request.attributes['responseConsumerURL']
      assert_equal "http://sp.example.com/acs", ecp_request.assertion_consumer_service_url
    end

    it "transport the RelayState as opaque data on an ECP header block" do
      ecp_request = OneLogin::RubySaml::EcpRequest.new
      envelope = REXML::Document.new(ecp_request.create(request_settings, :RelayState => "opaque-state-123"))

      relay_state = REXML::XPath.first(
        envelope,
        "/soap:Envelope/soap:Header/ecp:RelayState",
        { "soap" => SOAP_ENV, "ecp" => ECP }
      )
      refute_nil relay_state
      assert_equal "opaque-state-123", relay_state.text
      assert_equal "opaque-state-123", ecp_request.relay_state
    end
  end

  describe "EcpResponse" do
    let(:request_settings) do
      s = OneLogin::RubySaml::Settings.new
      s.sp_entity_id = "http://sp.example.com/metadata"
      s.assertion_consumer_service_url = "http://sp.example.com/acs"
      s.idp_sso_service_url = "http://idp.example.com/sso"
      s
    end

    let(:response_settings) do
      s = OneLogin::RubySaml::Settings.new
      s.assertion_consumer_service_url = "http://app.muda.no/sso/consume"
      s.idp_cert_fingerprint = ruby_saml_cert_fingerprint
      s
    end

    let(:soap_message) { read_response(File.join("ecp", "ecp_response.xml")) }

    def ecp_response_for(message, extra_options = {})
      options = { :settings => response_settings, :skip_recipient_check => true }.merge(extra_options)
      OneLogin::RubySaml::EcpResponse.new(message, options)
    end

    it "raise an exception when initialized with nil" do
      assert_raises(ArgumentError) { OneLogin::RubySaml::EcpResponse.new(nil) }
    end

    it "return a valid identity for a fixed SOAP sample that satisfies the policy" do
      ecp_response = ecp_response_for(soap_message, :matches_request_id => "_fc4a34b0-7efb-012e-caae-782bcb13bb38")
      assert ecp_response.is_valid?, ecp_response.errors.join(", ")
      assert_empty ecp_response.errors
      assert_equal "test@onelogin.com", ecp_response.name_id
    end

    it "complete a round trip with the request id and the opaque RelayState" do
      ecp_request = OneLogin::RubySaml::EcpRequest.new
      ecp_request.uuid = "_fc4a34b0-7efb-012e-caae-782bcb13bb38"
      ecp_request.create(request_settings, :RelayState => "opaque-state-123")

      ecp_response = ecp_response_for(soap_message, :matches_request_id => ecp_request.request_id)
      assert ecp_response.is_valid?, ecp_response.errors.join(", ")
      assert_equal "opaque-state-123", ecp_response.relay_state
    end

    it "treat the RelayState as opaque data and never as a trust input" do
      message = soap_message.sub("opaque-state-123", "http://evil.example.com/trust-domain")
      ecp_response = ecp_response_for(message)
      assert ecp_response.is_valid?, ecp_response.errors.join(", ")
      assert_equal "http://evil.example.com/trust-domain", ecp_response.relay_state
    end

    it "reject an unknown SOAP header block flagged as mustUnderstand" do
      message = soap_message.sub(
        "</soap:Header>",
        '<ext:Unknown xmlns:ext="http://example.com/unknown" soap:mustUnderstand="1"/></soap:Header>'
      )
      ecp_response = ecp_response_for(message)
      refute ecp_response.is_valid?
      assert_includes ecp_response.errors.join(" "), "Cannot process the required SOAP header block ext:Unknown"
      assert_nil ecp_response.name_id
    end

    it "ignore an unknown mustUnderstand header block targeted at another actor" do
      message = soap_message.sub(
        "</soap:Header>",
        '<ext:Unknown xmlns:ext="http://example.com/unknown" soap:mustUnderstand="1" soap:actor="http://example.com/other"/></soap:Header>'
      )
      ecp_response = ecp_response_for(message)
      assert ecp_response.is_valid?, ecp_response.errors.join(", ")
    end

    it "reject a responseConsumerURL that does not match the declared assertion consumer service url" do
      message = soap_message.sub(
        'responseConsumerURL="http://app.muda.no/sso/consume"',
        'responseConsumerURL="http://evil.example.com/callback"'
      )
      ecp_response = ecp_response_for(message)
      refute ecp_response.is_valid?
      assert_includes ecp_response.errors.join(" "), "does not match the Assertion Consumer Service URL"
      assert_nil ecp_response.name_id
      refute ecp_response.respond_to?(:response_consumer_url)
    end

    it "reject the response when the ECP Response header block is missing" do
      message = soap_message.sub(/\s*<ecp:Response[^>]*\/>/, "")
      ecp_response = ecp_response_for(message)
      refute ecp_response.is_valid?
      assert_includes ecp_response.errors.join(" "), "does not contain an ECP Response header block"
    end

    it "reject the response when the signature does not satisfy the security policy" do
      response_settings.security[:want_assertions_signed] = true
      ecp_response = ecp_response_for(soap_message)
      refute ecp_response.is_valid?
      assert_includes ecp_response.errors.join(" "), "The Assertion of the Response is not signed and the SP requires it"
      assert_nil ecp_response.name_id
    end

    it "reject the response when the signature does not verify" do
      response_settings.idp_cert_fingerprint = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
      ecp_response = ecp_response_for(soap_message)
      refute ecp_response.is_valid?
      assert_nil ecp_response.name_id
    end

    it "reject the response when the request id does not match" do
      ecp_response = ecp_response_for(soap_message, :matches_request_id => "_wrong_request_id")
      refute ecp_response.is_valid?
      assert_includes ecp_response.errors.join(" "), "does not match the ID of the AuthNRequest sent by the SP"
    end
  end
end
