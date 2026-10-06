require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require "rexml/document"
require "onelogin/ruby-saml/ecp"

class EcpTest < Minitest::Test
  describe "Ecp" do
  ACS_URL = "https://sp.example.com/saml/ecp/acs"
  REQUEST_ID = "_ecp-fixed-request-id"

  let(:settings) do
    settings = OneLogin::RubySaml::Settings.new
    settings.idp_sso_service_url = "https://idp.example.com/sso"
    settings.idp_entity_id = "https://idp.example.com/metadata"
    settings.sp_entity_id = "https://sp.example.com/metadata"
    settings.assertion_consumer_service_url = ACS_URL
    settings.idp_cert = read_certificate("ruby-saml.crt")
    settings
  end

  let(:ecp) do
    authrequest = OneLogin::RubySaml::Authrequest.new
    authrequest.uuid = REQUEST_ID
    OneLogin::RubySaml::Ecp.new(:authrequest => authrequest)
  end

  def ecp_response_xml
    File.read(File.join(File.dirname(__FILE__), "ecp_response.xml"))
  end

  def modify_ecp_response
    document = REXML::Document.new(ecp_response_xml)
    yield document
    result = +""
    document.write(result)
    result
  end

  def ecp_header(document, name)
    REXML::XPath.first(
      document,
      "/soap:Envelope/soap:Header/ecp:#{name}",
      {
        "soap" => OneLogin::RubySaml::Ecp::SOAP11,
        "ecp" => OneLogin::RubySaml::Ecp::ECP
      }
    )
  end

  it "creates a PAOS SOAP request and consumes a signed ECP SOAP response" do
    request_xml = ecp.create_authentication_request(settings, :RelayState => "opaque-state")
    request_document = REXML::Document.new(request_xml)

    paos_request = REXML::XPath.first(
      request_document,
      "/soap:Envelope/soap:Header/paos:Request",
      {
        "soap" => OneLogin::RubySaml::Ecp::SOAP11,
        "paos" => OneLogin::RubySaml::Ecp::PAOS
      }
    )
    authn_request = REXML::XPath.first(
      request_document,
      "/soap:Envelope/soap:Body/samlp:AuthnRequest",
      {
        "soap" => OneLogin::RubySaml::Ecp::SOAP11,
        "samlp" => OneLogin::RubySaml::SamlMessage::PROTOCOL
      }
    )

    assert_equal OneLogin::RubySaml::Ecp::SOAP11, request_document.root.namespace
    assert_equal "1", paos_request.attributes["soap-env:mustUnderstand"]
    assert_equal OneLogin::RubySaml::Ecp::SOAP11_NEXT_ACTOR, paos_request.attributes["soap-env:actor"]
    assert_equal ACS_URL, paos_request.attributes["responseConsumerURL"]
    assert_equal OneLogin::RubySaml::Ecp::ECP, paos_request.attributes["service"]
    assert_equal REQUEST_ID, authn_request.attributes["ID"]
    assert_equal ACS_URL, authn_request.attributes["AssertionConsumerServiceURL"]
    assert_equal OneLogin::RubySaml::Utils::BINDINGS[:paos], authn_request.attributes["ProtocolBinding"]

    assert ecp.consume_response(ecp_response_xml, settings)
    assert_equal "ecp.user@example.com", ecp.response.name_id
    assert_equal "ecp-user", ecp.response.attributes["uid"]
    assert_equal "return-opaque-state", ecp.relay_state
    assert_empty ecp.errors
  end

  it "signs the embedded AuthnRequest when PAOS signed requests are required" do
    settings.certificate = read_certificate("ruby-saml.crt")
    settings.private_key = read_certificate("ruby-saml.key")
    settings.security[:authn_requests_signed] = true

    request_document = REXML::Document.new(ecp.create_authentication_request(settings))
    signature = REXML::XPath.first(
      request_document,
      "/soap:Envelope/soap:Body/samlp:AuthnRequest/ds:Signature",
      {
        "soap" => OneLogin::RubySaml::Ecp::SOAP11,
        "samlp" => OneLogin::RubySaml::SamlMessage::PROTOCOL,
        "ds" => OneLogin::RubySaml::Response::DSIG
      }
    )

    refute_nil signature
  end

  it "rejects an unknown required SOAP header before exposing identity data" do
    soap_response = modify_ecp_response do |document|
      header = REXML::XPath.first(document, "/soap:Envelope/soap:Header", { "soap" => OneLogin::RubySaml::Ecp::SOAP11 })
      header.add_element("unsupported:Extension", {
        "xmlns:unsupported" => "urn:example:unsupported",
        "soap-env:mustUnderstand" => "1",
        "soap-env:actor" => OneLogin::RubySaml::Ecp::SOAP11_NEXT_ACTOR
      })
    end

    refute ecp.consume_response(soap_response, settings)
    assert_nil ecp.response
    assert_includes ecp.errors.join, "Unknown required SOAP header"
  end

  it "rejects a response consumption address that was not declared by the SP" do
    soap_response = modify_ecp_response do |document|
      ecp_header(document, "Response").attributes["AssertionConsumerServiceURL"] = "https://attacker.example/acs"
    end

    refute ecp.consume_response(soap_response, settings)
    assert_nil ecp.response
    assert_includes ecp.errors, "ECP AssertionConsumerServiceURL does not match the Service Provider configuration"
  end

  it "keeps the originally declared response consumption address when settings are later changed" do
    ecp.create_authentication_request(settings)
    settings.assertion_consumer_service_url = "https://attacker.example/acs"

    refute ecp.consume_response(ecp_response_xml, settings)
    assert_nil ecp.response
  end

  it "does not use RelayState as a trust or routing input" do
    soap_response = modify_ecp_response do |document|
      ecp_header(document, "RelayState").text = "https://attacker.example/after-login"
    end

    assert ecp.consume_response(soap_response, settings)
    assert_equal ACS_URL, settings.assertion_consumer_service_url
    assert_equal "https://attacker.example/after-login", ecp.relay_state
    assert_equal ACS_URL, ecp.response.destination
  end

  it "rejects an unsigned assertion when the signature policy requires a signed assertion" do
    settings.security[:want_assertions_signed] = true
    soap_response = modify_ecp_response do |document|
      signature = REXML::XPath.first(
        document,
        "/soap:Envelope/soap:Body/samlp2:Response/saml:Assertion/ds:Signature",
        {
          "soap" => OneLogin::RubySaml::Ecp::SOAP11,
          "samlp2" => OneLogin::RubySaml::SamlMessage::PROTOCOL,
          "saml" => OneLogin::RubySaml::SamlMessage::ASSERTION,
          "ds" => OneLogin::RubySaml::Response::DSIG
        }
      )
      signature.remove
    end

    refute ecp.consume_response(soap_response, settings)
    assert_nil ecp.response
    refute_empty ecp.errors
  end
end
end
