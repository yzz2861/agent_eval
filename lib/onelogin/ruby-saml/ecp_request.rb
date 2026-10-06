require "rexml/document"

require "onelogin/ruby-saml/logging"
require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/authrequest"
require "onelogin/ruby-saml/setting_error"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 ECP Profile. PAOS Request (SP side, Builder)
    #
    # Builds the SOAP envelope that a Service Provider hands to an
    # Enhanced Client or Proxy (ECP). The envelope carries the PAOS
    # Request and ECP Request header blocks and embeds the AuthnRequest
    # (built by OneLogin::RubySaml::Authrequest) in the SOAP body.
    #
    class EcpRequest < SamlMessage

      # RelayState sent on the ECP RelayState header block. It is opaque
      # data that the ECP returns to the SP along with the SAML Response.
      attr_reader :relay_state

      # Assertion Consumer Service URL declared by the SP on the PAOS
      # Request header. The SP must keep this value and compare it with
      # the responseConsumerURL of the ECP Response header block.
      attr_reader :assertion_consumer_service_url

      # AuthnRequest ID
      attr_accessor :uuid

      # Initializes the ECP Request. An EcpRequest Object that is an extension of the SamlMessage class.
      # Asigns an ID, a random uuid, shared with the embedded AuthnRequest.
      #
      def initialize
        @uuid = OneLogin::RubySaml::Utils.uuid
      end

      def request_id
        @uuid
      end

      # Creates the PAOS SOAP envelope that embeds the AuthnRequest.
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @param params [Hash] Some extra parameters, for example the RelayState
      #   which is transported as opaque data inside an ECP RelayState header block
      # @return [String] The SOAP envelope that includes the AuthnRequest
      #
      def create(settings, params = {})
        @relay_state = params[:RelayState] || params['RelayState']
        @assertion_consumer_service_url = settings.assertion_consumer_service_url
        if @assertion_consumer_service_url.nil? || @assertion_consumer_service_url.empty?
          raise SettingError.new "Invalid settings, assertion_consumer_service_url is not set!"
        end

        authn_request_doc = create_authn_request_doc(settings)

        envelope = REXML::Document.new
        root = envelope.add_element "soap:Envelope", { "xmlns:soap" => SamlMessage::SOAP_ENV_NAMESPACE }
        header = root.add_element "soap:Header"

        header.add_element "paos:Request", {
          "xmlns:paos" => SamlMessage::PAOS_NAMESPACE,
          "soap:mustUnderstand" => "1",
          "soap:actor" => SamlMessage::SOAP_ACTOR_NEXT,
          "service" => SamlMessage::ECP_NAMESPACE,
          "responseConsumerURL" => @assertion_consumer_service_url
        }

        ecp_request = header.add_element "ecp:Request", {
          "xmlns:ecp" => SamlMessage::ECP_NAMESPACE,
          "soap:mustUnderstand" => "1",
          "soap:actor" => SamlMessage::SOAP_ACTOR_NEXT,
          "IsPassive" => "0"
        }
        unless settings.sp_entity_id.nil? || settings.sp_entity_id.empty?
          issuer = ecp_request.add_element "saml:Issuer", { "xmlns:saml" => ASSERTION }
          issuer.text = settings.sp_entity_id
        end

        unless @relay_state.nil?
          relay_state_header = header.add_element "ecp:RelayState", {
            "xmlns:ecp" => SamlMessage::ECP_NAMESPACE,
            "soap:mustUnderstand" => "1",
            "soap:actor" => SamlMessage::SOAP_ACTOR_NEXT
          }
          relay_state_header.text = @relay_state
        end

        body = root.add_element "soap:Body"
        body.add_element authn_request_doc.root

        soap_envelope = "".dup
        envelope.write(soap_envelope)

        Logging.debug "Created ECP PAOS Request: " + soap_envelope

        soap_envelope
      end

      private

      # Builds the AuthnRequest document reusing the Authrequest builder,
      # forcing the PAOS protocol binding and the Assertion Consumer
      # Service URL declared by the SP.
      # @param settings [OneLogin::RubySaml::Settings|nil] Toolkit settings
      # @return [XMLSecurity::Document] The AuthnRequest document
      #
      def create_authn_request_doc(settings)
        authn_request = OneLogin::RubySaml::Authrequest.new
        authn_request.uuid = @uuid
        document = authn_request.create_xml_document(settings)

        root = document.root
        root.attributes['ProtocolBinding'] = SamlMessage::PAOS_BINDING
        root.attributes['AssertionConsumerServiceURL'] = @assertion_consumer_service_url

        cert, private_key = settings.get_sp_signing_pair
        if settings.security[:authn_requests_signed] && private_key && cert
          document.sign_document(private_key, cert, settings.security[:signature_method], settings.security[:digest_method])
        end

        document
      end
    end
  end
end
