# encoding: utf-8
# frozen_string_literal: true
require 'mail/constants'
require 'mail/utilities'

module Mail
  # Parses the body of a message/delivery-status part (RFC 3464) without
  # flattening its blocks. A delivery status body contains one optional
  # report-level block followed by one block per recipient:
  #
  #   Reporting-MTA: dns; example.org
  #
  #   Final-Recipient: rfc822; alice@example.org
  #   Action: failed
  #   Status: 5.1.1
  #
  #   Final-Recipient: rfc822; bob@example.org
  #   Action: delayed
  #   Status: 4.2.0
  #
  # Report-level fields stay on the report and each recipient block is kept
  # together as a Recipient, so values never have to be joined back together
  # by array position. Missing fields are nil; malformed fields are reported
  # in #errors while their raw value is still retained.
  class DeliveryStatusReport
    # A structural or syntactic problem found in one block.
    ParseError = Struct.new(:field_name, :value, :reason)

    # RFC 3464 section 2.6 valid actions.
    ACTIONS = %w[failed delayed delivered relayed expanded].freeze

    # RFC 3464 enhanced status codes share the class/subject/detail shape of
    # RFC 3463 (class 2, 4 or 5).
    STATUS = /\A[245]\.\d{1,3}\.\d{1,3}\z/

    FIELD_LINE = /\A(#{Constants::FIELD_NAME})\s*#{Constants::COLON}\s*(.*)\z/
    BLOCK_SEPARATOR = /\r\n[ \t]*\r\n/

    SEMICOLON = ';'

    TYPED_VALUE = lambda { |value|
      type, address = value.to_s.split(SEMICOLON, 2).map { |part| part && part.strip }
      !type.to_s.empty? && !address.to_s.empty?
    }

    RECIPIENT_FIELD_VALIDATORS = {
      'action' => ->(value) { ACTIONS.include?(value.strip.downcase) },
      'status' => ->(value) { STATUS.match?(value.strip) },
      'final-recipient' => TYPED_VALUE,
      'diagnostic-code' => TYPED_VALUE,
    }.freeze

    # Represents a single per-recipient block of a delivery status report.
    class Recipient
      # Mail::Field objects in the order they appeared in the block,
      # including unknown extension fields.
      attr_reader :fields

      # Array of ParseError objects for malformed lines in this block.
      attr_reader :errors

      def initialize(fields, errors)
        @fields = fields
        @errors = errors
      end

      # Returns the raw value of any field in the block (case insensitive),
      # or nil when the field is absent. Unknown extension fields are
      # accessible here too.
      def [](name)
        field = @fields.find { |f| f.responsible_for?(name) }
        field && field.value
      end

      def field?(name)
        @fields.any? { |f| f.responsible_for?(name) }
      end

      # Raw Final-Recipient value, e.g. "rfc822; alice@example.org".
      def final_recipient
        self['final-recipient']
      end

      # Address type of Final-Recipient, e.g. "rfc822".
      def address_type
        typed_value(final_recipient).first
      end

      # Bare address extracted from Final-Recipient (without type or angle
      # brackets), or nil when the field is absent.
      def address
        value = typed_value(final_recipient).last
        return nil if value.nil?
        value.delete_prefix('<').delete_suffix('>')
      end

      def action
        self['action']
      end

      # Raw enhanced status code (the Status field).
      def status
        self['status']
      end
      alias_method :error_status, :status
      alias_method :enhanced_status_code, :status

      # Raw Diagnostic-Code value, or nil when absent.
      def diagnostic_code
        self['diagnostic-code']
      end

      def remote_mta
        self['remote-mta']
      end

      def bounced?
        !!(action && action =~ /failed/i)
      end

      # Mirrors Mail::Part#retryable?: a non-5xx (or absent) status is
      # considered retryable.
      def retryable?
        status.nil? || status !~ /\A5/
      end

      private

      def typed_value(value)
        return [nil, nil] if value.nil?
        return [nil, nil] unless value.include?(SEMICOLON)
        type, address = value.split(SEMICOLON, 2)
        type = type && type.strip
        address = address && address.strip
        type = nil if type && type.empty?
        address = nil if address && address.empty?
        [type, address]
      end
    end

    # Mail::Field objects from the report-level block, in order.
    attr_reader :fields

    # Recipient objects, one per per-recipient block, in order.
    attr_reader :recipients

    # ParseError objects from the report-level block.
    attr_reader :errors

    def initialize(source)
      @fields = []
      @recipients = []
      @errors = []
      parse(source.to_s)
    end

    # Returns the raw value of a report-level field, an array of raw values
    # if it appeared more than once, or nil when it is absent. Unknown
    # extension fields are accessible here too.
    def [](name)
      values = @fields.select { |field| field.responsible_for?(name) }.map(&:value)
      values.size > 1 ? values : values.first
    end

    def field?(name)
      @fields.any? { |field| field.responsible_for?(name) }
    end

    private

    def parse(source)
      blocks = Mail::Utilities.to_crlf(source).split(BLOCK_SEPARATOR)
      blocks.each_with_index do |block, index|
        next if block.strip.empty?

        fields, block_errors = parse_block(block)
        if report_block?(index, fields)
          @fields.concat(fields)
          @errors.concat(block_errors)
        else
          @recipients << Recipient.new(fields, validate_recipient(fields, block_errors))
        end
      end
    end

    # The first block is the report-level block unless it already contains a
    # Final-Recipient field; every later block is a per-recipient block even
    # if it is missing fields.
    def report_block?(index, fields)
      index.zero? && fields.none? { |field| field.responsible_for?('final-recipient') }
    end

    def parse_block(block)
      fields = []
      errors = []

      unfold(block).split(Constants::CRLF).each do |line|
        next if line.strip.empty?

        if (match = line.match(FIELD_LINE))
          fields << Mail::Field.new(match[1], match[2].strip)
        else
          errors << ParseError.new(nil, line.strip, 'invalid field line')
        end
      end

      [fields, errors]
    end

    def validate_recipient(fields, errors)
      validated = {}

      fields.each do |field|
        name = field.name.to_s.downcase
        next unless RECIPIENT_FIELD_VALIDATORS.key?(name)
        next if validated[name]
        validated[name] = true

        unless RECIPIENT_FIELD_VALIDATORS[name].call(field.value.to_s)
          errors << ParseError.new(field.name, field.value, "invalid #{name}")
        end
      end

      errors
    end

    def unfold(source)
      source.gsub(Constants::UNFOLD_WS, '\\1')
    end
  end
end
