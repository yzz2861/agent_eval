require "rexml/document"

require "onelogin/ruby-saml/authrequest"
require "onelogin/ruby-saml/error_handling"
require "onelogin/ruby-saml/response"
require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/utils"

module OneLogin
  module RubySaml
    class Ecp
      include ErrorHandling

      SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/".freeze
      SOAP12 = "http://www.w3.org/2003/05/soap-envelope".freeze
      SOAP11_NEXT_ACTOR = "http://schemas.xmlsoap.org/soap/actor/next".freeze
      SOAP12_NEXT_ROLE = "#{SOAP12}/role/next".freeze
      PAOS = "urn:liberty:paos:2003-08".freeze
      ECP = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp".freeze

      attr_reader :request_id
      attr_reader :assertion_consumer_service_url
      attr_reader :response
      attr_reader :relay_state
      attr_reader :soft

      def initialize(options = {})
        @authrequest = options[:authrequest] || Authrequest.new
        @request_id = @authrequest.request_id
        @response = nil
        @relay_state = nil
        @assertion_consumer_service_url = nil
        @soft = true
      end

      def create_authentication_request(settings, params = {})
        if settings.assertion_consumer_service_url.nil? || settings.assertion_consumer_service_url.empty?
          raise SettingError.new("Invalid settings, assertion_consumer_service_url is not set!")
        end

        relay_state = params[:RelayState] || params['RelayState']
        @assertion_consumer_service_url = settings.assertion_consumer_service_url

        document = REXML::Document.new
        envelope = document.add_element("soap-env:Envelope", {
          "xmlns:soap-env" => SOAP11,
          "xmlns:paos" => PAOS,
          "xmlns:ecp" => ECP,
          "xmlns:samlp" => SamlMessage::PROTOCOL,
          "xmlns:saml" => SamlMessage::ASSERTION
        })
        header = envelope.add_element("soap-env:Header")
        body = envelope.add_element("soap-env:Body")

        header.add_element("paos:Request", {
          "soap-env:actor" => SOAP11_NEXT_ACTOR,
          "soap-env:mustUnderstand" => "1",
          "responseConsumerURL" => settings.assertion_consumer_service_url,
          "service" => ECP
        })

        ecp_attributes = {
          "soap-env:actor" => SOAP11_NEXT_ACTOR,
          "soap-env:mustUnderstand" => "1"
        }
        ecp_attributes["ProviderName"] = settings.sp_entity_id unless settings.sp_entity_id.nil? || settings.sp_entity_id.empty?
        ecp_request = header.add_element("ecp:Request", ecp_attributes)
        unless settings.sp_entity_id.nil? || settings.sp_entity_id.empty?
          issuer = ecp_request.add_element("saml:Issuer")
          issuer.text = settings.sp_entity_id
        end

        if relay_state
          relay_state_element = header.add_element("ecp:RelayState", { "soap-env:actor" => SOAP11_NEXT_ACTOR })
          relay_state_element.text = relay_state.to_s
        end

        request_document = create_paos_authentication_document(settings)
        body.add_element(request_document.root.deep_clone)

        request = "".dup
        document.context[:attribute_quote] = :quote if settings.double_quote_xml_attribute_values
        document.write(request)
        Logging.debug("Created ECP PAOS request: #{request}")
        request
      end

      def consume_response(soap_response, settings, options = {})
        reset_errors!
        @soft = options.key?(:soft) ? options[:soft] : settings.soft
        @response = nil
        @relay_state = nil

        document = parse_soap_document(soap_response, settings)
        return false if document.nil?

        return false unless validate_soap_headers(document, settings)
        return false unless extract_relay_state(document)

        saml_response = extract_saml_response(document)
        return false if saml_response.nil?

        response_options = options.dup
        response_options[:settings] = settings
        response_options[:matches_request_id] = request_id unless response_options.key?(:matches_request_id)
        @response = Response.new(saml_response, response_options)
        @response.soft = @soft

        unless @response.is_valid?(!@soft)
          errors.concat(@response.errors)
          @response = nil
          return false
        end

        true
      end
      alias_method :is_valid?, :consume_response

      private

      def create_paos_authentication_document(settings)
        original_binding = settings.protocol_binding
        original_sso_binding = settings.idp_sso_service_binding
        settings.protocol_binding = Utils::BINDINGS[:paos]
        settings.idp_sso_service_binding = Utils::BINDINGS[:paos]
        @authrequest.create_authentication_xml_doc(settings)
      ensure
        settings.protocol_binding = original_binding
        settings.idp_sso_service_binding = original_sso_binding
      end

      def parse_soap_document(soap_response, settings)
        if soap_response.nil? || soap_response.to_s.strip.empty?
          append_error("Blank SOAP response")
          return nil
        end

        if soap_response.to_s.bytesize > settings.message_max_bytesize
          return append_error("SOAP Message exceeds #{settings.message_max_bytesize} bytes, so was rejected")
        end

        XMLSecurity::BaseDocument.safe_load_xml(soap_response.to_s, settings.check_malformed_doc)
        document = REXML::Document.new(soap_response.to_s)
        namespace = document.root && document.root.namespace
        unless [SOAP11, SOAP12].include?(namespace) && document.root.name == "Envelope"
          append_error("Invalid SOAP envelope")
          return nil
        end
        document
      rescue StandardError => error
        append_error("Invalid SOAP document: #{error.message}")
        nil
      end

      def validate_soap_headers(document, settings)
        headers = REXML::XPath.match(document, "/soap:Envelope/soap:Header/*", soap_namespaces(document))
        ecp_responses = headers.select { |node| ecp_element?(node, "Response") }

        unless ecp_responses.size == 1
          return append_error("Expected one ECP Response header")
        end

        ecp_response = ecp_responses.first
        return false unless header_targets_this_node?(ecp_response, document)
        return false unless must_understand?(ecp_response, document)

        consumer_url = ecp_response.attributes['AssertionConsumerServiceURL']
        if consumer_url.nil? || consumer_url.empty?
          return append_error("Missing ECP AssertionConsumerServiceURL")
        end

        expected_consumer_url = assertion_consumer_service_url || settings.assertion_consumer_service_url
        unless consumer_url == expected_consumer_url
          return append_error("ECP AssertionConsumerServiceURL does not match the Service Provider configuration")
        end

        headers.each do |header|
          next if ecp_element?(header, "Response") || ecp_element?(header, "RelayState")
          next unless must_understand?(header, document)
          next unless header_targets_this_node?(header, document)

          return append_error("Unknown required SOAP header #{header.expanded_name}")
        end

        true
      end

      def extract_relay_state(document)
        relay_states = REXML::XPath.match(document, "/soap:Envelope/soap:Header/ecp:RelayState", soap_namespaces(document).merge("ecp" => ECP))
        return true if relay_states.empty?
        return append_error("Expected at most one ECP RelayState header") if relay_states.size > 1

        relay_state = relay_states.first
        return false unless header_targets_this_node?(relay_state, document)

        @relay_state = relay_state.text.to_s
        true
      end

      def extract_saml_response(document)
        responses = REXML::XPath.match(document, "/soap:Envelope/soap:Body/p:Response", soap_namespaces(document).merge("p" => SamlMessage::PROTOCOL))
        if responses.size != 1
          append_error("Expected one SAML Response in the SOAP body")
          return nil
        end

        responses.first.to_s
      end

      def ecp_element?(node, name)
        node.namespace == ECP && node.name == name
      end

      def must_understand?(node, document)
        namespace = soap_namespace(document)
        attribute = nil
        node.attributes.each_attribute do |header_attribute|
          if header_attribute.name == "mustUnderstand" && header_attribute.namespace == namespace
            attribute = header_attribute
            break
          end
        end
        accepted_values = namespace == SOAP11 ? ["1"] : ["1", "true"]
        attribute && accepted_values.include?(attribute.value.downcase)
      end

      def header_targets_this_node?(node, document)
        namespace = soap_namespace(document)
        name = namespace == SOAP11 ? "actor" : "role"
        attribute = nil
        node.attributes.each_attribute do |header_attribute|
          if header_attribute.name == name && header_attribute.namespace == namespace
            attribute = header_attribute
            break
          end
        end

        return true if attribute.nil?
        return true if attribute.value == SOAP11_NEXT_ACTOR && namespace == SOAP11
        return true if [SOAP12_NEXT_ROLE, SOAP12].include?(attribute.value) && namespace == SOAP12

        false
      end

      def soap_namespaces(document)
        { "soap" => soap_namespace(document) }
      end

      def soap_namespace(document)
        document.root.namespace
      end
    end
  end
end
