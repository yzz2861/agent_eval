# encoding: utf-8
# frozen_string_literal: true

module Mail
  # = PartialCollector
  #
  # Reassembles messages that a legacy mail system split into
  # +message/partial+ fragments (RFC 2046, section 5.2.2).
  #
  # The collector is completely self contained: it keeps its state in
  # memory and needs no database, mailbox or SMTP connection. Fragments
  # are grouped by their +id+ parameter and may arrive in any order.
  # The +total+ parameter is only required on the last fragment, so it
  # may legitimately show up late; completeness is determined as soon as
  # +total+ is known and every fragment number from 1 to +total+ has
  # been received.
  #
  #   collector = Mail::PartialCollector.new
  #   collector.add(raw_fragment_2) # => :stored
  #   collector.add(raw_fragment_1) # => :stored
  #   collector.missing('some-id')  # => [3]
  #   collector.add(raw_fragment_3) # => :complete
  #   collector.message('some-id')  # => #<Mail::Message ...>
  #
  # A repeated fragment whose payload is identical to the one already
  # stored is ignored. A repeated fragment number with a *different*
  # payload is kept as a conflict and assembly of that message stops
  # until the group is discarded.
  class PartialCollector
    # Header fields that RFC 2046 5.2.2 takes from the encapsulated
    # message rather than from the enclosing fragment: every field
    # starting with "Content-" plus these exact field names.
    INNER_HEADER_NAMES = %w[subject message-id encrypted mime-version].freeze

    # Returns true if the given header field name belongs to the
    # encapsulated message according to RFC 2046 5.2.2 (any +Content-*+
    # field, or +Subject+, +Message-ID+, +Encrypted+, +MIME-Version+).
    def self.inner_header?(name)
      name = name.to_s.downcase
      name.start_with?('content-') || INNER_HEADER_NAMES.include?(name)
    end

    # Describes a rejected fragment that contradicts data already
    # collected for the same message id.
    class Conflict
      # Fragment number of the rejected fragment.
      attr_reader :number

      # Why the fragment was rejected: +:fragment_mismatch+ (same number,
      # different payload), +:total_mismatch+ (disagrees on the total
      # count) or +:number_exceeds_total+.
      attr_reader :reason

      # The Mail::Message already stored for this number, if any.
      attr_reader :existing

      # The rejected Mail::Message.
      attr_reader :incoming

      def initialize(number:, reason:, existing:, incoming:)
        @number   = number
        @reason   = reason
        @existing = existing
        @incoming = incoming
      end
    end

    def initialize
      @groups = {}
    end

    # Adds one +message/partial+ fragment. Accepts a Mail::Message or a
    # raw message source string. Returns one of:
    #
    # +:stored+::    fragment was stored, more fragments are needed
    # +:complete+::  fragment was stored and the message is now complete
    # +:duplicate+:: identical fragment was already stored, ignored
    # +:conflict+::  fragment contradicts stored data and was rejected
    #
    # Raises ArgumentError if the message is not +message/partial+ or
    # lacks a valid +id+ or +number+ parameter.
    def add(fragment)
      message = fragment.is_a?(Mail::Message) ? fragment : Mail.new(fragment.to_s)
      id, number, total = fragment_params(message)
      group_for(id).add(message, number, total)
    end

    # All message ids currently being collected.
    def ids
      @groups.keys
    end

    # The announced total fragment count for +id+, or nil if no fragment
    # carrying a +total+ parameter has been seen yet.
    def total(id)
      @groups[id] && @groups[id].total
    end

    # Sorted list of fragment numbers received for +id+.
    def received(id)
      group = @groups[id]
      group ? group.numbers : []
    end

    # Sorted list of fragment numbers still missing for +id+. Returns
    # nil when the total count is not known yet (or the id is unknown),
    # because completeness cannot be determined before then.
    def missing(id)
      @groups[id] && @groups[id].missing
    end

    # True when every fragment of +id+ is present and no conflict was
    # recorded, so #message can assemble it.
    def complete?(id)
      !!(@groups[id] && @groups[id].complete?)
    end

    # True when a conflicting fragment was rejected for +id+.
    def conflict?(id)
      !!(@groups[id] && @groups[id].conflict?)
    end

    # The Conflict records rejected for +id+, oldest first.
    def conflicts(id)
      group = @groups[id]
      group ? group.conflicts : []
    end

    # The reassembled Mail::Message for +id+, or nil unless the group
    # is complete and conflict free.
    def message(id)
      @groups[id] && @groups[id].assemble
    end

    # Actively drops every fragment and conflict recorded for +id+.
    # Returns true if anything was discarded.
    def discard(id)
      !@groups.delete(id).nil?
    end

    # Drops all collected state.
    def clear
      @groups.clear
    end

    private

    def group_for(id)
      @groups[id] ||= Group.new
    end

    def fragment_params(message)
      unless message.main_type.to_s.downcase == 'message' && message.sub_type.to_s.downcase == 'partial'
        raise ArgumentError, "expected a message/partial fragment, got #{message.content_type.to_s.empty? ? 'no content type' : message.content_type.inspect}"
      end

      params = message.content_type_parameters || {}

      id = params['id'].to_s
      raise ArgumentError, 'message/partial fragment is missing its id parameter' if id.empty?

      number = positive_integer(params['number'], 'number')
      total  = positive_integer(params['total'], 'total') if params['total']

      [id, number, total]
    end

    def positive_integer(value, name)
      string = value.to_s
      unless string =~ /\A[1-9]\d*\z/
        raise ArgumentError, "invalid message/partial #{name} parameter: #{value.inspect}"
      end
      string.to_i
    end

    # Holds the fragments received so far for one message id.
    class Group
      attr_reader :total, :conflicts

      def initialize
        @fragments = {}
        @total = nil
        @conflicts = []
      end

      def add(message, number, total)
        expected_total = total || @total
        if expected_total && number > expected_total
          return reject(message, number, :number_exceeds_total)
        end
        if total && @total && total != @total
          return reject(message, number, :total_mismatch)
        end
        @total ||= total

        if (existing = @fragments[number])
          if existing.body.raw_source == message.body.raw_source
            return :duplicate
          end
          return reject(message, number, :fragment_mismatch, existing)
        end

        @fragments[number] = message
        complete? ? :complete : :stored
      end

      def numbers
        @fragments.keys.sort
      end

      def missing
        return nil unless @total
        (1..@total).to_a - @fragments.keys
      end

      def conflict?
        !@conflicts.empty?
      end

      def complete?
        return false if conflict? || @total.nil?
        (1..@total).all? { |number| @fragments.key?(number) }
      end

      # Reassembles the original message following RFC 2046 5.2.2: all
      # header fields of the first fragment's enclosing message are
      # copied except Content-* and Subject, Message-ID, Encrypted and
      # MIME-Version; then those very fields are appended from the
      # encapsulated message. All other encapsulated header fields are
      # ignored.
      def assemble
        return nil unless complete?

        ordered = (1..@total).map { |number| @fragments[number] }
        inner = Mail.new(ordered.map { |fragment| fragment.body.raw_source.to_s }.join)

        raw = String.new(encoding: Encoding::BINARY)
        ordered.first.header.fields.each do |field|
          raw << binary(field.encoded) unless PartialCollector.inner_header?(field.name)
        end
        inner.header.fields.each do |field|
          raw << binary(field.encoded) if PartialCollector.inner_header?(field.name)
        end
        raw << "\r\n"
        raw << binary(inner.body.raw_source)

        Mail.new(raw)
      end

      private

      def reject(message, number, reason, existing = nil)
        @conflicts << Conflict.new(number: number, reason: reason,
                                   existing: existing, incoming: message)
        :conflict
      end

      def binary(string)
        string.to_s.dup.force_encoding(Encoding::BINARY)
      end
    end
  end
end
