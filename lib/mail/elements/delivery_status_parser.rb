# encoding: utf-8
# frozen_string_literal: true
require 'mail/constants'
require 'mail/utilities'
require 'mail/indifferent_hash'

module Mail
  # Parses a message/delivery-status body as defined by RFC 3464.
  #
  # A delivery status body is a sequence of field groups separated by blank
  # lines.  The first group carries per-message (report level) fields and each
  # following group describes exactly one recipient.  Group boundaries are
  # preserved so the relationship between a recipient and its status never has
  # to be reconstructed from parallel arrays.
  #
  #   dsn = Mail::DeliveryStatusParser.new(part.body.to_s)
  #   dsn.report_fields   # { "reporting-mta" => "dns; example.org", ... }
  #   dsn.recipients      # [#<Mail::DeliveryStatusRecipient ...>, ...]
  #   dsn.recipients.first.address   #=> "user@example.org"
  #   dsn.recipients.first.action    #=> "failed"
  #   dsn.recipients.first.status    #=> "5.1.1"
  #   dsn.recipients.first.diagnostic_code
  #
  # A field that is absent from a group is represented with nil.  A field
  # that is present but violates its expected syntax is still returned and is
  # additionally recorded in #errors, so missing fields and syntax errors are
  # distinguishable.
  class DeliveryStatusParser
    # Per-message fields defined by RFC 3464 2.2.
    REPORT_FIELDS = %w[
      reporting-mta
      dsn-gateway
      received-from-mta
      arrival-date
    ].freeze

    # Per-recipient fields defined by RFC 3464 2.3.
    RECIPIENT_FIELDS = %w[
      original-recipient
      final-recipient
      action
      status
      remote-mta
      diagnostic-code
      last-attempt-date
      final-log-id
      will-retry-until
    ].freeze

    # action = "failed" / "delayed" / "delivered" / "relayed" / "expanded"
    ACTIONS = %w[failed delayed delivered relayed expanded].freeze

    # enhanced-status-codes per RFC 3463: class "." subject "." detail
    STATUS = /\A[245]\.[0-9]{1,3}\.[0-9]{1,3}\z/.freeze

    # Blank lines separate per-message and per-recipient field groups.
    GROUP_SEPARATOR = /(?:#{Constants::LAX_CRLF}){2,}/

    def self.parse(string)
      new(string)
    end

    def initialize(string)
      @raw_source = string.to_s
      parse!
    end

    attr_reader :raw_source, :report_group, :recipients

    # Per-message field group as an indifferent hash.  Values are unfolded
    # strings; a repeated field becomes an array.  Unknown extension fields
    # (such as X-Postfix-Queue-ID) are preserved in this same group.  Returns
    # an empty hash when there is no report level group.
    def report_fields
      @report_group ? @report_group.fields : IndifferentHash.new
    end

    def inspect
      "#<#{self.class.name} report=#{!@report_group.nil?} recipients=#{recipients.length} errors=#{errors.length}>"
    end

    # Structural [group_index, line, reason] tuples for lines that could not
    # be parsed as a field.  Field level syntax errors (bad action or status)
    # are reported by each recipient's #errors method.
    def errors
      @errors ||= []
    end

    private

    def parse!
      normalized = Utilities.to_crlf(raw_source).sub(/(?:\r\n)+\z/, '')
      @errors = []
      parsed_groups = normalized.split(GROUP_SEPARATOR).each_with_index.map do |raw_group, index|
        parse_group(raw_group, index)
      end
      parsed_groups.reject! { |group| group.field_objects.empty? }

      if report_group?(parsed_groups.first)
        @report_group = parsed_groups.first
        @recipients = parsed_groups[1..].map { |group| DeliveryStatusRecipient.new(group) }
      else
        @report_group = nil
        @recipients = parsed_groups.map { |group| DeliveryStatusRecipient.new(group) }
      end
    end

    def report_group?(group)
      return false if group.nil?
      names = group.fields.keys.map(&:to_s)
      return false if names.any? { |name| RECIPIENT_FIELDS.include?(name) }
      names.any? { |name| REPORT_FIELDS.include?(name) }
    end

    def parse_group(raw_group, group_index)
      fields = []
      previous = nil

      raw_group.to_s.each_line do |raw_line|
        line = raw_line.sub(/\r?\n\z/, '')

        if line =~ /\A[\t ]/
          if previous
            previous.append_continuation(line)
          else
            @errors << [group_index, line, 'continuation line without a field']
          end
          next
        end

        next if line.strip.empty?

        name, value = split_field(line)
        if name
          previous = DeliveryStatusField.new(name, value)
          fields << previous
        else
          @errors << [group_index, line, 'line is not a field']
          previous = nil
        end
      end

      DeliveryStatusFieldGroup.new(fields)
    end

    # Split a single "name: value" delivery status line without depending on
    # the full Mail::Field stack.  Mirrors Mail::Field.split semantics.
    def split_field(line)
      index = line.index(Constants::COLON) or return nil
      name = line[0...index].rstrip
      return nil unless /\A#{Constants::FIELD_NAME}\z/.match?(name)
      value = line[(index + 1)..].strip
      [name, value]
    end
  end

  # One field of a delivery status field group, kept in its original order.
  class DeliveryStatusField
    attr_reader :name, :value

    def initialize(name, value)
      @name = name.to_s.downcase
      @value = value.to_s
    end

    def append_continuation(line)
      @value << ' ' << line.strip
    end

    def to_s
      "#{name}: #{value}"
    end
  end

  # An ordered set of fields belonging to one delivery status group.
  class DeliveryStatusFieldGroup
    def initialize(fields)
      @field_list = fields
    end

    # Every field as a hash of unfolded values.  A field appearing more than
    # once becomes an array of values, preserving order.
    def fields
      @fields ||= begin
        hash = IndifferentHash.new
        @field_list.each do |field|
          if hash.key?(field.name)
            hash[field.name] = Array(hash[field.name]) << field.value
          else
            hash[field.name] = field.value
          end
        end
        hash
      end
    end

    def field_objects
      @field_list
    end

    def [](name)
      fields[name.to_s.downcase]
    end

    def key?(name)
      fields.key?(name.to_s.downcase)
    end
  end

  # The per-recipient block of a delivery status notification.
  #
  # Standard fields have dedicated readers; unknown extension fields remain
  # available through #fields.  Missing fields return nil while fields whose
  # value violates the expected syntax are listed in #errors.
  class DeliveryStatusRecipient
    ADDRESS_FIELDS = %w[final-recipient original-recipient].freeze

    def initialize(group)
      @group = group
      @errors = []
      @validated = false
    end

    # All fields of the recipient block, unknown extension fields included.
    def fields
      @group.fields
    end

    # The underlying DeliveryStatusFieldGroup for this recipient block.
    def field_group
      @group
    end

    # Returns the raw value of any field in the block (an array if repeated).
    def [](name)
      @group[name]
    end

    def key?(name)
      @group.key?(name)
    end

    # [field_name, raw_value, reason] tuples for fields present with a value
    # that violates the expected syntax.
    def errors
      validate!
      @errors
    end

    # Address from Final-Recipient with its type marker stripped, e.g. the
    # "user@example.org" part of "rfc822; user@example.org".  Nil when the
    # field is absent.
    def address
      strip_type_marker(final_recipient)
    end

    def final_recipient
      single_value('final-recipient')
    end

    def original_recipient
      single_value('original-recipient')
    end

    # Lowercased Action value, or nil when the field is absent.  An unknown
    # action keyword is still returned and recorded in #errors.
    def action
      validate!
      single_value('action')&.strip&.downcase
    end

    # Enhanced status code such as "5.1.1", or nil when Status is absent.
    # An invalid code is still returned and recorded in #errors.
    def status
      validate!
      single_value('status')&.strip
    end

    def diagnostic_code
      single_value('diagnostic-code')
    end
    alias diagnostic diagnostic_code

    def remote_mta
      single_value('remote-mta')
    end

    def last_attempt_date
      single_value('last-attempt-date')
    end

    def inspect
      "#<#{self.class.name} address=#{address.inspect} action=#{action.inspect} status=#{status.inspect}>"
    end

    private

    def single_value(name)
      value = @group[name]
      value.is_a?(Array) ? value.last : value
    end

    def strip_type_marker(value)
      return nil if value.nil?
      value.include?(';') ? value.split(';', 2).last.strip : value.strip
    end

    def validate!
      return if @validated
      @validated = true

      action_value = single_value('action')
      if action_value && !DeliveryStatusParser::ACTIONS.include?(action_value.strip.downcase)
        @errors << ['action', action_value, 'action is not one of failed, delayed, delivered, relayed, expanded']
      end

      status_value = single_value('status')
      if status_value && DeliveryStatusParser::STATUS !~ status_value.strip
        @errors << ['status', status_value, 'status is not a valid enhanced status code']
      end

      ADDRESS_FIELDS.each do |name|
        value = single_value(name)
        if value && !value.strip.empty? && !value.include?(';')
          @errors << [name, value, 'address field is missing its type marker']
        end
      end
    end
  end
end
