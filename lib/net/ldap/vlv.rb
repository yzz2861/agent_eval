# -*- ruby encoding: utf-8 -*-
# Virtual List View control support (draft-ietf-ldapext-ldapv3-vlv), used
# together with the server-side sort control (RFC 2891).
#
# VLV lets a client request a small "window" of entries from a sorted result
# set, positioned either at an offset or near a sort value, without paging
# through the whole result set.
class Net::LDAP
  module VLV
    # Virtual List View request/response controls.
    VLV_REQUEST  = "2.16.840.1.113730.3.4.9"
    VLV_RESPONSE = "2.16.840.1.113730.3.4.10"

    # VLV-specific result codes returned in the VLV response control.
    # These are distinct from normal LDAP search result codes.
    ResultSuccess            = 0
    ResultOperationsError    = 1
    ResultUnwillingToPerform = 53
    ResultSortControlMissing = 60
    ResultOffsetRangeError   = 61

    # Both response control values wrap a plain SEQUENCE of universal
    # INTEGER/ENUMERATED and OCTET STRING fields. The only context-specific
    # field is the sort response's optional [0] AttributeDescription.
    ResponseSyntax = Net::BER.compile_syntax(
      :context_specific => {
        :primitive => { 0 => :string, 1 => :boolean },
      }
    )

    # Raised when VLV is asked to continue a contextID under a different
    # server, base, filter, or sort definition. The context may only be
    # reused while the surrounding search stays identical.
    class ContextMismatchError < Net::LDAP::Error; end

    # Raised when a VLV response control cannot be parsed or is missing the
    # fields required by the protocol.
    class ResponseError < Net::LDAP::Error; end

    # Normalize the caller-supplied sort definitions into an Array of
    # [attribute, matching_rule, reverse_order] tuples.
    def self.normalize_sort(sort)
      Array(sort).map do |entry|
        attribute, matching_rule, reverse_order = Array(entry)
        [
          String(attribute),
          matching_rule.nil? ? "" : String(matching_rule),
          reverse_order == true,
        ]
      end
    end

    # http://tools.ietf.org/html/rfc2891
    #
    # SortKeyList ::= SEQUENCE OF SEQUENCE {
    #   attributeType   AttributeDescription,
    #   orderingRule    [0] MatchingRuleId OPTIONAL,
    #   reverseOrder    [1] BOOLEAN DEFAULT FALSE }
    def self.encode_sort_control(sort, criticality)
      keys = normalize_sort(sort).map do |attribute, matching_rule, reverse_order|
        key = [attribute.to_ber]
        key << matching_rule.to_ber_contextspecific(0) unless matching_rule.empty?
        # LDAP control values use IMPLICIT TAGS, so [1] BOOLEAN is encoded
        # primitively as 0x81 0x01 0xFF (rather than wrapping a universal
        # BOOLEAN in a constructed [1]).
        key << (reverse_order ? "\x81\x01\xff" : "\x81\x01\x00").b if reverse_order
        key.to_ber_sequence
      end

      [
        Net::LDAP::LDAPControls::SORT_REQUEST.to_ber,
        criticality.to_ber,
        keys.to_ber_sequence.to_s.to_ber,
      ].to_ber_sequence
    end

    # VirtualListViewRequest ::= SEQUENCE {
    #   beforeCount    INTEGER (0..maxInt),
    #   afterCount     INTEGER (0..maxInt),
    #   target         CHOICE {
    #     byOffset           [0] SEQUENCE {
    #       offset          INTEGER (1 .. maxInt),
    #       contentCount    INTEGER (0 .. maxInt) },
    #     greaterThanOrEqual [1] ASSERTION },
    #   contextID      OCTET STRING OPTIONAL }
    #
    # +request+ is either a Hash of :offset and :content_count or a Hash of
    # :greater_than_or_equal. Returns the OCTET STRING carried as the
    # control value.
    def self.encode_request_value(before_count, after_count, request,
                                  context_id = nil)
      value = [
        Integer(before_count).to_ber,
        Integer(after_count).to_ber,
      ]

      if request.key?(:offset)
        offset = Integer(request[:offset])
        raise ArgumentError, "VLV offset must be >= 1" if offset < 1
        value << [
          offset.to_ber,
          Integer(request.fetch(:content_count, 0)).to_ber,
        ].to_ber_contextspecific(0)
      elsif request.key?(:greater_than_or_equal)
        assertion = request[:greater_than_or_equal].to_s
        # IMPLICIT [1] of ASSERTION (OCTET STRING) is a primitive 0x81
        # carrying the assertion bytes directly.
        value << assertion.to_ber_bin(0x81)
      else
        raise ArgumentError,
              "VLV requires :offset or :greater_than_or_equal"
      end

      value << context_id.to_ber_bin if context_id
      value.to_ber_sequence.to_s.to_ber
    end

    def self.encode_request_control(before_count, after_count, request,
                                    context_id, criticality = true)
      [
        VLV_REQUEST.to_ber,
        criticality.to_ber,
        encode_request_value(before_count, after_count, request, context_id),
      ].to_ber_sequence
    end

    # Parse the OCTET STRING value of a sort response control.
    #
    # SortResult ::= SEQUENCE {
    #   sortResult  ENUMERATED { success (0), ... , operationsError (1),
    #     timeLimitExceeded (3), strongAuthRequired (8),
    #     adminLimitExceeded (11), noSuchAttribute (16),
    #     inappropriateMatching (18),
    #     insufficientAccessRights (50), busy (51),
    #     unwillingToPerform (53), other (80) },
    #   attributeType [0] AttributeDescription OPTIONAL }
    def self.parse_sort_response(value)
      return nil unless value

      sequence = value.read_ber(ResponseSyntax)
      unless sequence.is_a?(Array) && sequence.length >= 1
        raise ResponseError, "malformed sort response control"
      end

      {
        :result_code    => sequence[0],
        :attribute_type => sequence[1],
      }
    end

    # Parse the OCTET STRING value of a VLV response control.
    #
    # VirtualListViewResponse ::= SEQUENCE {
    #   targetPosition    INTEGER,
    #   contentCount      INTEGER,
    #   virtualListViewResult ENUMERATED,
    #   contextID         OCTET STRING OPTIONAL }
    def self.parse_response(value)
      raise ResponseError, "missing VLV response control value" unless value

      sequence = value.read_ber(ResponseSyntax)
      unless sequence.is_a?(Array) && sequence.length >= 3
        raise ResponseError, "malformed VLV response control"
      end

      {
        :target_position => sequence[0],
        :content_count   => sequence[1],
        :result_code     => sequence[2],
        :context_id      => sequence[3],
      }
    end

    def self.canonical_filter(filter)
      filter ||= Net::LDAP::Filter.eq("objectClass", "*")
      filter = Net::LDAP::Filter.construct(filter) if filter.is_a?(String)
      filter.to_s
    end

    # A stable identifier of the server/query parameters under which a
    # contextID is valid.
    def self.signature(server_key, base, filter, sort)
      [server_key, base.to_s, canonical_filter(filter),
       normalize_sort(sort).map(&:inspect).join("|")]
    end

    # An opaque server-generated VLV context. It carries the contextID octets
    # plus the signature of the search under which the server issued them.
    # It can only be presented again with the same server, base, filter, and
    # sort definition.
    class Context
      attr_reader :id, :signature

      def initialize(id, signature)
        @id = id
        @signature = signature
      end
    end

    # The result of one VLV search: the entry window plus positioning and
    # error information taken from the response controls.
    class Window
      # The Net::LDAP::Entry objects returned in the requested window. An
      # empty window is not itself an error; inspect the failure predicates
      # to determine what happened.
      attr_reader :entries

      # 1-based position of the target entry in the sorted result set.
      attr_reader :target_position

      # Server's estimate of the total number of entries in the sorted
      # result set. This is an estimate valid only for this response; it
      # must not be cached as a permanently exact size.
      attr_reader :estimated_content_count
      alias_method :content_count_estimate, :estimated_content_count

      # Opaque server context for continuing this VLV search.
      attr_reader :context

      # Raw result data, exposed for diagnostics.
      attr_reader :search_code, :search_error_message, :sort_result_code,
                  :sort_attribute_type, :vlv_result_code

      def initialize(entries, controls_data, search_pdu)
        @entries = entries
        @search_code = search_pdu.result_code
        @search_error_message = search_pdu.error_message
        @context_restarted = false

        controls_data ||= {}
        sort_data = controls_data[:sort]
        vlv_data  = controls_data[:vlv]

        @sort_result_code = sort_data && sort_data[:result_code]
        @sort_attribute_type = sort_data && sort_data[:attribute_type]

        @target_position = vlv_data && vlv_data[:target_position]
        @estimated_content_count = vlv_data && vlv_data[:content_count]
        @vlv_result_code = vlv_data && vlv_data[:result_code]
        raw_context_id = vlv_data && vlv_data[:context_id]
        if raw_context_id
          @context = Context.new(raw_context_id, controls_data[:signature])
        end
      end

      # One of :success, :unsupported, :search_error, :sort_error, or
      # :vlv_error. Checking this is the preferred way to branch.
      def status
        if search_code != Net::LDAP::ResultCodeSuccess
          if search_code == Net::LDAP::ResultCodeUnavailableCriticalExtension
            :unsupported
          else
            :search_error
          end
        elsif sort_result_code && sort_result_code != VLV::ResultSuccess
          :sort_error
        elsif vlv_result_code.nil? || vlv_result_code != VLV::ResultSuccess
          :vlv_error
        else
          :success
        end
      end

      def success?
        status == :success
      end

      def unsupported?
        status == :unsupported
      end

      def sort_failure?
        status == :sort_error
      end

      def vlv_failure?
        status == :vlv_error
      end

      def search_failure?
        status == :search_error
      end

      # True when the server rejected the supplied contextID and the search
      # was retried without one.
      def context_restarted?
        @context_restarted
      end

      # True when the server returned a usable, empty window rather than an
      # error. This is normal when no entries fall inside the requested
      # window.
      def empty_window?
        success? && entries.empty?
      end
    end

    # A scrolling VLV session. The first call establishes the context on the
    # server; later calls continue it. The session is bound to one server,
    # base, filter, and sort definition; changing any of those requires a
    # new session.
    class Session
      attr_reader :ldap, :base, :filter, :sort, :sort_criticality,
                  :vlv_criticality
      attr_reader :context

      def initialize(ldap, options)
        @ldap = ldap
        @base = options[:base] || ldap.base
        @filter = VLV.canonical_filter(options[:filter])
        @sort = VLV.normalize_sort(options.fetch(:sort))
        if @sort.empty?
          raise ArgumentError, "VLV requires a server-side sort definition"
        end
        @sort_criticality = options.fetch(:sort_criticality, true)
        @vlv_criticality = options.fetch(:criticality, true)
        @context = nil
        @last_estimate = 0
      end

      def signature
        @signature ||= VLV.signature(
          ldap.send(:vlv_server_key), @base, @filter, @sort
        )
      end

      # Position by 1-based offset. The contentCount needed for continued
      # offset searches is tracked from the previous response automatically.
      def at(offset, before_count: 0, after_count: 0, size: nil,
             attributes: nil, **args)
        request(:offset, offset, before_count, after_count, size,
                attributes, args)
      end

      # Position at the first entry whose sort value is >= +value+.
      def locate(value, before_count: 0, after_count: 0, size: nil,
                 attributes: nil, **args)
        request(:greater_than_or_equal, value, before_count, after_count,
                size, attributes, args)
      end

      # Begin the VLV search over from scratch, discarding the contextID.
      def reset
        @context = nil
        @last_estimate = 0
        self
      end

      private

      def request(kind, target, before_count, after_count, size,
                  attributes, extra)
        target_hash =
          if kind == :offset
            { :offset => target, :content_count => @last_estimate }
          else
            { :greater_than_or_equal => target }
          end

        args = extra.merge(
          :base       => @base,
          :filter     => @filter,
          :attributes => attributes,
        )
        args[:size] = size if size

        begin
          execute(target_hash, before_count, after_count, args, @context, false)
        rescue WindowRetry => retry_error
          execute(retry_error.target_hash, retry_error.before_count,
                  retry_error.after_count, args, nil, true)
        end
      end

      def execute(target_hash, before_count, after_count, args,
                  context_object, restarted)
        window = @ldap.send(:vlv_search_raw,
          args, before_count, after_count, target_hash,
          context_object, signature, @sort, @sort_criticality,
          @vlv_criticality
        )
        window.instance_variable_set(:@context_restarted, restarted)

        if !window.success? && context_object && !restarted &&
           invalid_context?(window)
          raise WindowRetry.new(target_hash, before_count, after_count)
        end

        if window.success?
          @context = window.context
          @last_estimate = window.estimated_content_count.to_i
        elsif invalid_context?(window)
          @context = nil
          @last_estimate = 0
        end
        window
      end

      def invalid_context?(window)
        [VLV::ResultOperationsError,
         VLV::ResultUnwillingToPerform].include?(window.vlv_result_code)
      end

      class WindowRetry < RuntimeError
        attr_reader :target_hash, :before_count, :after_count
        def initialize(target_hash, before_count, after_count)
          @target_hash = target_hash
          @before_count = before_count
          @after_count = after_count
          super("retry VLV without contextID")
        end
      end
    end

    # Build a Window from a completed connection-level search.
    def self.build_window(entries, result_pdu, sort, signature)
      sort_data = nil
      vlv_data = nil

      if result_pdu.respond_to?(:result_controls)
        result_pdu.result_controls.each do |control|
          case control.oid
          when Net::LDAP::LDAPControls::SORT_RESPONSE
            sort_data = parse_sort_response(control.value)
          when VLV_RESPONSE
            vlv_data = parse_response(control.value)
          end
        end
      end

      Window.new(entries, {
        :sort      => sort_data,
        :vlv       => vlv_data,
        :signature => signature,
      }, result_pdu)
    end
  end
end
