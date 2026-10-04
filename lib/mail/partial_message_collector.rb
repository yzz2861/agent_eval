# encoding: utf-8
# frozen_string_literal: true

module Mail
  # Collects RFC 2046 message/partial fragments and reassembles the
  # original message once enough fragments have arrived.
  #
  # The collector is purely in-memory: it talks to no database, mailbox
  # or SMTP service. Feed it fragments as Mail::Message instances or raw
  # RFC 2822 strings, in any order:
  #
  #   collector = Mail::PartialMessageCollector.new
  #   collector.add(fragment)       # => :stored, :duplicate or :conflict
  #   collector.missing(id)         # => [2, 3] (nil while total is unknown)
  #   collector.complete?(id)       # => true/false
  #   collector.reassemble(id)      # => Mail::Message or nil
  #   collector.discard(id)         # drop all state for an id
  #
  # The +total+ parameter is only required on the last fragment, so it
  # may arrive late; an id becomes complete once +total+ is known and
  # every fragment 1..total has been stored.
  #
  # A repeated fragment whose payload is identical to the stored one is
  # ignored. A repeated fragment with a different payload (or a
  # contradictory +total+) is kept as a conflict and stops assembly for
  # that id.
  #
  # Reassembly follows RFC 2046 section 5.2.2.1:
  #
  # * headers of the first fragment's enclosing entity are copied,
  #   except Content-* and Message-ID/Encrypted/MIME-Version
  # * only Content-* and Message-ID/Encrypted/MIME-Version headers of
  #   the enclosed message are appended
  # * headers of the second and subsequent enclosing entities are dropped
  class PartialMessageCollector
    CRLF = "\r\n"
    BLANK_LINE = /\r\n\r\n|\n\n/
    SPECIAL_INNER_HEADERS = %w[message-id encrypted mime-version].freeze

    # Describes why two fragments for the same id could not be
    # reconciled. +reason+ is one of :mismatched_fragment,
    # :mismatched_total or :number_out_of_range.
    Conflict = Struct.new(:number, :reason, :stored, :received)

    # Tracks every fragment seen for one message/partial id.
    class Group # :nodoc:
      attr_reader :id, :total, :conflicts

      def initialize(id)
        @id = id
        @total = nil
        @fragments = {} # number => raw fragment source
        @conflicts = []
      end

      def add(number, total, source, payload)
        if (existing = @fragments[number])
          return :duplicate if existing[:payload] == payload

          @conflicts << Conflict.new(number, :mismatched_fragment, existing[:source], source)
          return :conflict
        end

        if total && @total && total != @total
          @conflicts << Conflict.new(number, :mismatched_total, @total, total)
          return :conflict
        end

        @total ||= total

        if @total && number > @total
          @conflicts << Conflict.new(number, :number_out_of_range, @total, number)
          return :conflict
        end

        @fragments[number] = { source: source, payload: payload }

        if @total && (out_of_range = @fragments.keys.select { |n| n > @total }).any?
          @conflicts << Conflict.new(number, :number_out_of_range, out_of_range, @total)
          return :conflict
        end

        :stored
      end

      def conflicted?
        @conflicts.any?
      end

      def complete?
        !conflicted? && !@total.nil? && (1..@total).all? { |n| @fragments.key?(n) }
      end

      def missing
        return nil if @total.nil?

        (1..@total).reject { |n| @fragments.key?(n) }
      end

      def received
        @fragments.keys.sort
      end

      def source(number)
        @fragments[number] && @fragments[number][:source]
      end
    end

    def initialize
      @partials = {}
    end

    # Adds one message/partial fragment. Accepts a Mail::Message or a
    # raw RFC 2822 string. Returns :stored, :duplicate or :conflict.
    # Raises ArgumentError for non message/partial input or missing or
    # invalid id/number/total parameters.
    def add(message)
      mail = message.is_a?(Mail::Message) ? message : Mail.new(message.to_s)
      id, number, total = partial_parameters(mail)
      source = raw_source_of(mail)
      group_for(id).add(number, total, source, split_source(source).last)
    end

    # Ids of every partial message currently being collected.
    def ids
      @partials.keys
    end

    # True when every fragment 1..total is present and no conflicting
    # fragment was ever seen for this id.
    def complete?(id)
      group = @partials[id]
      !!(group && group.complete?)
    end

    # True when a conflicting fragment or total was seen for this id.
    def conflict?(id)
      group = @partials[id]
      !!(group && group.conflicted?)
    end

    # The Conflict records seen for this id, oldest first.
    def conflicts(id)
      group = @partials[id]
      group ? group.conflicts.dup : []
    end

    # Fragment numbers still missing. Returns nil when the id is
    # unknown or no fragment has reported +total+ yet.
    def missing(id)
      group = @partials[id]
      group && group.missing
    end

    # Fragment numbers received so far, ascending.
    def received(id)
      group = @partials[id]
      group ? group.received : []
    end

    # The announced total fragment count, or nil if not seen yet.
    def total(id)
      group = @partials[id]
      group && group.total
    end

    # Reassembles the original message per RFC 2046 5.2.2.1. Returns
    # nil while the id is incomplete or conflicted.
    def reassemble(id)
      group = @partials[id]
      return nil unless group && group.complete?

      outer_head, = split_source(group.source(1))
      inner_raw = (1..group.total).map { |n| split_source(group.source(n)).last }.join
      inner_head, inner_body = split_source(inner_raw)

      headers = select_headers(outer_head, inner: false) +
                select_headers(inner_head, inner: true)
      Mail.new(headers.join(CRLF) + CRLF + CRLF + inner_body)
    end

    # Drops every fragment and conflict recorded for an id. Returns
    # true when anything was discarded.
    def discard(id)
      !@partials.delete(id).nil?
    end

    private

    def group_for(id)
      @partials[id] ||= Group.new(id)
    end

    def partial_parameters(mail)
      type = mail.mime_type
      unless type && type.to_s.downcase == 'message/partial'
        raise ArgumentError, 'expected a message/partial entity'
      end

      params = (mail.content_type_parameters || {}).each_with_object({}) do |(key, value), hash|
        hash[key.to_s.downcase] = value
      end

      id = params['id']
      raise ArgumentError, 'message/partial is missing its id parameter' if id.nil? || id.to_s.empty?

      number = parse_positive_integer(params['number'], 'number')
      total = params['total'] && parse_positive_integer(params['total'], 'total')
      [id.to_s, number, total]
    end

    def parse_positive_integer(value, name)
      raise ArgumentError, "message/partial is missing its #{name} parameter" if value.nil?

      begin
        integer = Integer(value.to_s, 10)
      rescue ArgumentError, TypeError
        raise ArgumentError, "message/partial has an invalid #{name} parameter: #{value.inspect}"
      end
      raise ArgumentError, "message/partial #{name} must be positive" if integer < 1

      integer
    end

    def raw_source_of(mail)
      source = mail.raw_source
      source = mail.to_s if source.nil? || source.empty?
      source.dup.force_encoding(Encoding::BINARY)
    end

    # Splits a raw message into [header_block, body] at the first
    # blank line, tolerating both CRLF and LF line endings.
    def split_source(source)
      if source =~ BLANK_LINE
        [source[0...$~.begin(0)], source[$~.end(0)..-1]]
      else
        [source, +""]
      end
    end

    # Splits a raw header block into field chunks (folded lines stay
    # with their field), normalizing line endings to CRLF.
    def header_chunks(head)
      head.split(/\r?\n(?![ \t])/).map { |chunk| chunk.gsub(/\r?\n/, CRLF) }
    end

    # RFC 2046 5.2.2.1 header merge: with inner: false keeps everything
    # except Content-* and Message-ID/Encrypted/MIME-Version (headers of
    # the first enclosing entity); with inner: true keeps only those
    # (headers of the enclosed message).
    def select_headers(head, inner:)
      header_chunks(head).select do |chunk|
        name = chunk[/\A([^:]+):/, 1].to_s.strip.downcase
        special = name.start_with?('content-') || SPECIAL_INNER_HEADERS.include?(name)
        inner ? special : !special
      end
    end
  end
end
