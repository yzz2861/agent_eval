# -*- ruby encoding: utf-8 -*-

class Net::LDAP
  class VirtualListView
    TARGET_BY_OFFSET = 0
    TARGET_BY_VALUE = 1

    class Context
      attr_reader :server, :base, :filter, :sort_definitions, :context_id
      attr_reader :estimated_content_count

      def initialize(server:, base:, filter:, sort_definitions:, context_id: nil,
                     estimated_content_count: nil)
        @server = Array(server).freeze
        @base = base
        @filter = filter
        @sort_definitions = sort_definitions
        @context_id = context_id
        @estimated_content_count = estimated_content_count
      end

      def scope
        {
          server: server,
          base: base,
          filter: filter,
          sort_definitions: sort_definitions,
        }
      end

      def continue(context_id:, estimated_content_count:)
        self.class.new(
          server: server,
          base: base,
          filter: filter,
          sort_definitions: sort_definitions,
          context_id: context_id,
          estimated_content_count: estimated_content_count
        )
      end

      def validate!(server:, base:, filter:, sort_definitions:)
        expected = {
          server: Array(server).freeze,
          base: base,
          filter: filter,
          sort_definitions: sort_definitions,
        }

        return if scope == expected

        raise Net::LDAP::InvalidVirtualListViewContextError,
              "VLV context may only be reused with the same server, base, filter, and sort definition"
      end
    end

    class Result < Array
      attr_accessor :target_position, :estimated_content_count, :context,
                    :result, :sort_result_code, :vlv_result_code

      alias_method :entries, :to_a
      alias_method :actual_position, :target_position
      alias_method :position, :target_position
      alias_method :estimated_size, :estimated_content_count

      def content_count
        estimated_content_count
      end

      def context_id
        context&.context_id
      end
    end

    class << self
      def normalize_sort_definitions(sort_definitions)
        Array(sort_definitions).map do |definition|
          definition = Array(definition)
          raise ArgumentError, "VLV requires a sort attribute" if definition.first.nil?

          [
            String(definition[0]),
            definition[1].nil? ? "" : String(definition[1]),
            definition[2] == true,
          ]
        end
      end

      def canonical_filter(filter)
        return Net::LDAP::Filter.construct(filter).to_s if filter.is_a?(String)
        return filter.to_s if filter.respond_to?(:to_s)

        raise ArgumentError, "invalid search filter #{filter.inspect}"
      end

      def encode_request_control(before_count:, after_count:, offset: nil,
                                 sort_value: nil, context: nil)
        unless before_count.is_a?(Integer) && before_count >= 0 &&
               after_count.is_a?(Integer) && after_count >= 0
          raise ArgumentError, "VLV counts cannot be negative"
        end

        target = encode_target(offset: offset, sort_value: sort_value)
        value = [
          before_count.to_ber,
          after_count.to_ber,
          target,
        ]
        value << context.context_id.to_s.to_ber_bin if context&.context_id

        [
          Net::LDAP::LDAPControls::VLV_REQUEST.to_ber,
          true.to_ber,
          value.to_ber_sequence.to_s.to_ber,
        ].to_ber_sequence
      end

      def interpret(result_pdu, context, entries = [])
        sort_control = control(result_pdu, Net::LDAP::LDAPControls::SORT_RESPONSE)
        vlv_control = control(result_pdu, Net::LDAP::LDAPControls::VLV_RESPONSE)
        sort_code = control_code(sort_control)

        raise_sort_error(sort_code, result_pdu) if sort_code && sort_code.nonzero?

        unless successful_search?(result_pdu)
          case result_pdu.result_code
          when Net::LDAP::ResultCodeSortControlMissing
            raise_sort_error(result_pdu.result_code, result_pdu)
          when Net::LDAP::ResultCodeUnavailableCriticalExtension,
               Net::LDAP::ResultCodeOffsetRangeError
            raise_vlv_error(result_pdu.result_code, result_pdu)
          end

          raise_search_error(result_pdu)
        end

        raise_vlv_error(Net::LDAP::ResultCodeUnavailableCriticalExtension, result_pdu) unless vlv_control

        parsed = vlv_control.value
        parsed = parsed.read_ber(Net::LDAP::AsnSyntax) if parsed.is_a?(String)
        unless parsed.is_a?(Array) && parsed.length >= 3
          raise_vlv_error(Net::LDAP::ResultCodeOperationsError, result_pdu)
        end

        response_code = parsed[2].to_i
        raise_vlv_error(response_code, result_pdu) if response_code.nonzero?

        raw_context_id = parsed[3]
        context_id = context_id_value(raw_context_id)
        next_context = context.continue(
          context_id: context_id,
          estimated_content_count: parsed[1].to_i
        )

        Result.new(entries).tap do |result|
          result.target_position = parsed[0].to_i
          result.estimated_content_count = parsed[1].to_i
          result.context = next_context
          result.result = result_pdu
          result.sort_result_code = sort_code
          result.vlv_result_code = response_code
        end
      end

      private

      def encode_target(offset:, sort_value:)
        if !offset.nil? && !sort_value.nil?
          raise ArgumentError, "specify either a VLV offset or a sort value, not both"
        end

        if !offset.nil?
          unless offset.is_a?(Integer) && offset.positive?
            raise ArgumentError, "VLV offset must be greater than zero"
          end

          [
            offset.to_ber,
            1.to_ber,
          ].to_ber_contextspecific(TARGET_BY_OFFSET)
        elsif !sort_value.nil?
          String(sort_value).to_ber_bin(0x80 + TARGET_BY_VALUE)
        else
          raise ArgumentError, "VLV requires either an offset or a sort value"
        end
      end

      def control(result_pdu, oid)
        return unless result_pdu&.respond_to?(:result_controls)

        result_pdu.result_controls.find { |control| control.oid == oid }
      end

      def control_code(control)
        control_sequence(control)&.first
      end

      def control_sequence(control)
        value = control&.value
        return unless value

        parsed = value.is_a?(String) ? value.read_ber(Net::LDAP::AsnSyntax) : value
        parsed.is_a?(Array) ? parsed : nil
      end

      def context_id_value(value)
        return if value.nil? || value.empty?

        value
      end

      def successful_search?(result_pdu)
        result_pdu.respond_to?(:result_code) &&
          Net::LDAP::ResultCodesSearchSuccess.include?(result_pdu.result_code)
      end

      def raise_sort_error(code, result_pdu)
        message = result_pdu.error_message
        message = Net::LDAP.result2string(code) if message.nil? || message.empty?
        raise Net::LDAP::ServerSortError.new(message, result_pdu)
      end

      def raise_vlv_error(code, result_pdu)
        message = result_pdu&.error_message
        message = Net::LDAP.result2string(code) if message.nil? || message.empty?
        error = Net::LDAP::VirtualListViewError.new(message, result_pdu)
        error.code = code
        raise error
      end

      def raise_search_error(result_pdu)
        message = result_pdu.error_message
        message = Net::LDAP.result2string(result_pdu.result_code) if message.nil? || message.empty?
        raise Net::LDAP::SearchError.new(message, result_pdu)
      end
    end
  end
end
