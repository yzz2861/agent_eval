require "rexml/document"
require "rexml/xpath"

require "onelogin/ruby-saml/logging"
require "onelogin/ruby-saml/saml_message"
require "onelogin/ruby-saml/response"
require "onelogin/ruby-saml/error_handling"

# Only supports SAML 2.0
module OneLogin
  module RubySaml

    # SAML2 ECP Profile. PAOS Response (SP side, Consumer)
    #
    # Processes the SOAP envelope that the Enhanced Client or Proxy (ECP)
    # returns to the Service Provider. It enforces the SOAP processing
    # model (actor/mustUnderstand), checks that the responseConsumerURL
    # of the ECP Response header block matches the Assertion Consumer
    # Service URL declared by the SP (the value sent by the client is
    # never used as a redirect target) and delegates the validation of
    # the embedded SAML Response to OneLogin::RubySaml::Response.
    #
    class EcpResponse < SamlMessage
      include ErrorHandling

      # SOAP header block namespaces that this SP endpoint understands
      UNDERSTOOD_HEADER_NAMESPACES = [SamlMessage::ECP_NAMESPACE, SamlMessage::PAOS_NAMESPACE].freeze

      # Options forwarded to the embedded OneLogin::RubySaml::Response
      FORWARDED_RESPONSE_OPTIONS = (OneLogin::RubySaml::Response::AVAILABLE_OPTIONS - [:settings]).freeze

      # OneLogin::RubySaml::Settings Toolkit settings
      attr_accessor :settings

      # The SAML Response extracted from the SOAP body
      attr_reader :response

      attr_reader :document
      attr_reader :options

      attr_accessor :soft

      # Constructs the ECP Response.
      # @param soap_message [String] The SOAP envelope (plain or Base64 encoded) returned by the ECP
      # @param options [Hash] :settings to provide the OneLogin::RubySaml::Settings object
      #                       :assertion_consumer_service_url to provide the Assertion Consumer
      #                       Service URL declared by the SP on the PAOS Request (defaults to
      #                       settings.assertion_consumer_service_url)
      #                       Plus any OneLogin::RubySaml::Response option like :matches_request_id
      #
      def initialize(soap_message, options = {})
        raise ArgumentError.new("ECP Response cannot be nil") if soap_message.nil?

        @errors = []
        @options = options
        @soft = true
        unless options[:settings].nil?
          @settings = options[:settings]
          unless @settings.soft.nil?
            @soft = @settings.soft
          end
        end

        begin
          @soap_message = decode_raw_saml(soap_message, settings)
          @document = REXML::Document.new(@soap_message)
        rescue StandardError => error
          @parse_error = error.message
        end
      end

      # Validates the ECP Response with the default values (soft = true)
      # @param collect_errors [Boolean] Stop validation when the first error appears or keep validating. (if soft=true)
      # @return [Boolean] TRUE if the ECP Response is valid
      #
      def is_valid?(collect_errors = false)
        validate(collect_errors)
      end

      # @return [String|nil] the NameID provided by the SAML Response of the ECP, only
      #   available when the ECP Response is valid
      #
      def name_id
        valid? && response ? response.name_id : nil
      end

      # @return [String|nil] The RelayState header block returned by the ECP.
      #   It is opaque data echoed back to the SP and must not be used to
      #   take trust decisions.
      #
      def relay_state
        return @relay_state if defined?(@relay_state)

        @relay_state = nil
        header_block_elements.each do |header_block|
          next unless header_targeted_at_us?(header_block)
          next unless header_block.namespace == SamlMessage::ECP_NAMESPACE && header_block.name == "RelayState"

          @relay_state = OneLogin::RubySaml::Utils.element_text(header_block)
          break
        end
        @relay_state
      end

      alias_method :nameid, :name_id

      # @return [OneLogin::RubySaml::Attributes] the Attributes provided by the SAML Response
      #   of the ECP, only available when the ECP Response is valid
      #
      def attributes
        valid? && response ? response.attributes : OneLogin::RubySaml::Attributes.new
      end

      # @return [Boolean] TRUE if the ECP Response was validated successfully.
      #   Identity data is only exposed when the ECP Response is valid.
      #
      def valid?
        !!@valid
      end

      private

      # Validates the ECP Response
      # @param collect_errors [Boolean] Stop validation when first error appears or keep validating. (if soft=true)
      # @return [Boolean] True if the ECP Response is valid, otherwise False if soft == false
      # @raise [ValidationError] if soft == false and validation fails
      #
      def validate(collect_errors = false)
        reset_errors!
        return @valid = false unless validate_ecp_response_state

        validations = [
          :validate_envelope_structure,
          :validate_headers,
          :validate_saml_response
        ]

        if collect_errors
          validations.each { |validation| send(validation) }
          @valid = @errors.empty?
        else
          @valid = validations.all? { |validation| send(validation) }
        end
      end

      # Validates that the ECP Response was parsed and the settings were provided
      # @return [Boolean] True if the required info is found, false otherwise
      #
      def validate_ecp_response_state
        return append_error("Blank ECP response") if @soap_message.nil? || @soap_message.empty?
        return append_error("Invalid ECP response. XML load failed: #{@parse_error}") unless @parse_error.nil?
        return append_error("No settings on ECP response") if settings.nil?

        true
      end

      # Validates that the document is a SOAP Envelope whose Body contains
      # exactly one samlp:Response
      # @return [Boolean] True if the structure is the expected one
      #
      def validate_envelope_structure
        envelope = document.root
        unless envelope && envelope.name == "Envelope" && envelope.namespace == SamlMessage::SOAP_ENV_NAMESPACE
          return append_error("The ECP response is not a SOAP Envelope")
        end

        if response_node.nil?
          return append_error("The ECP response does not contain exactly one SAML Response in the SOAP Body")
        end

        true
      end

      # Applies the SOAP processing model to the header blocks targeted at
      # this node: header blocks with a mustUnderstand attribute that are not
      # understood are rejected. The responseConsumerURL of the ECP Response
      # header block must match the Assertion Consumer Service URL declared
      # by the SP; the value sent by the client is never exposed as a
      # redirect target.
      # @return [Boolean] True if all the required header blocks were processed
      #
      def validate_headers
        valid = true
        header_block_elements.each do |header_block|
          next unless header_targeted_at_us?(header_block)

          if UNDERSTOOD_HEADER_NAMESPACES.include?(header_block.namespace)
            valid = process_understood_header(header_block) && valid
          elsif must_understand?(header_block)
            append_error("Cannot process the required SOAP header block #{header_block.expanded_name} with namespace #{header_block.namespace}")
            valid = false
          end
        end
        unless ecp_response_header_processed
          append_error("The ECP response does not contain an ECP Response header block targeted at this node")
          valid = false
        end
        valid
      end

      # Processes an understood SOAP header block
      # @return [Boolean] False when the header block is invalid
      #
      def process_understood_header(header_block)
        if header_block.namespace == SamlMessage::ECP_NAMESPACE && header_block.name == "Response"
          @ecp_response_header_processed = true
          return validate_response_consumer_url(header_block)
        end

        true
      end

      # @return [Boolean] True if an ECP Response header block targeted at
      #   this node was found on the SOAP Header
      #
      def ecp_response_header_processed
        !!@ecp_response_header_processed
      end

      # Checks that the responseConsumerURL of the ECP Response header block
      # matches the Assertion Consumer Service URL declared by the SP.
      # @return [Boolean] True if both URLs match
      #
      def validate_response_consumer_url(header_block)
        response_consumer_url = header_block.attributes['responseConsumerURL']
        if response_consumer_url.nil? || response_consumer_url.empty?
          return append_error("The ECP Response header block does not declare a responseConsumerURL")
        end

        expected = expected_assertion_consumer_service_url
        if expected.nil? || expected.empty?
          return append_error("No Assertion Consumer Service URL declared by the SP to match the responseConsumerURL against")
        end

        unless OneLogin::RubySaml::Utils.uri_match?(response_consumer_url, expected)
          return append_error("The responseConsumerURL #{response_consumer_url} does not match the Assertion Consumer Service URL #{expected} declared by the SP")
        end

        true
      end

      # Validates the SAML Response embedded in the SOAP Body reusing the
      # standard Response validation (structure, signature policy, conditions,
      # destination, subject confirmation, ...)
      # @return [Boolean] True if the SAML Response is valid
      #
      def validate_saml_response
        return false if response_node.nil?

        @response = build_saml_response
        valid = @response.is_valid?(true)
        @response.errors.each { |error| @errors << error unless @errors.include?(error) }
        valid
      end

      # @return [OneLogin::RubySaml::Response] The SAML Response extracted
      #   from the SOAP Body
      #
      def build_saml_response
        response_options = { :settings => settings }
        FORWARDED_RESPONSE_OPTIONS.each do |option|
          response_options[option] = options[option] if options.key?(option)
        end

        saml_response = encode(response_node.to_s)

        saml_response = OneLogin::RubySaml::Response.new(saml_response, response_options)
        saml_response.soft = soft
        saml_response
      end

      # @return [REXML::Element|nil] The samlp:Response element of the SOAP Body
      #
      def response_node
        return @response_node if defined?(@response_node)

        @response_node = begin
          nodes = REXML::XPath.match(
            document,
            "/soap:Envelope/soap:Body/p:Response",
            { "soap" => SamlMessage::SOAP_ENV_NAMESPACE, "p" => PROTOCOL }
          )
          nodes.size == 1 ? nodes.first : nil
        end
      end

      # @return [Array<REXML::Element>] The SOAP header blocks of the Envelope
      #
      def header_block_elements
        return [] if document.nil? || document.root.nil?

        header = REXML::XPath.first(
          document,
          "/soap:Envelope/soap:Header",
          { "soap" => SamlMessage::SOAP_ENV_NAMESPACE }
        )
        return [] if header.nil?

        header.elements.to_a
      end

      # @return [Boolean] True if the header block is targeted at this SOAP node
      #   (no actor attribute or the "next" actor role)
      #
      def header_targeted_at_us?(header_block)
        actor = soap_attribute(header_block, "actor")
        actor.nil? || actor.empty? || actor == SamlMessage::SOAP_ACTOR_NEXT
      end

      # @return [Boolean] True if the header block has a mustUnderstand attribute
      #
      def must_understand?(header_block)
        value = soap_attribute(header_block, "mustUnderstand")
        value == "1" || value == "true"
      end

      # @return [String|nil] The value of a SOAP Envelope namespaced attribute
      #
      def soap_attribute(element, name)
        attribute = element.attributes.get_attribute_ns(SamlMessage::SOAP_ENV_NAMESPACE, name)
        attribute && attribute.value
      end

      # @return [String|nil] The Assertion Consumer Service URL declared by the SP
      #
      def expected_assertion_consumer_service_url
        options[:assertion_consumer_service_url] || (settings && settings.assertion_consumer_service_url)
      end
    end
  end
end
