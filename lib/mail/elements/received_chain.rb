# encoding: utf-8
# frozen_string_literal: true
require 'mail/elements/received_hop'

module Mail
  class ReceivedChain
    include Enumerable

    attr_reader :raw_fields

    def self.parse(fields_or_source)
      fields =
        if fields_or_source.is_a?(Array)
          fields_or_source
        else
          source = fields_or_source.to_s
          if source =~ /\A\s*Received\s*:/i
            Mail::Header.new(source).fields.select do |field|
              field.responsible_for?('Received')
            end
          else
            [fields_or_source]
          end
        end

      new(fields)
    end

    def initialize(fields)
      @raw_fields = []
      @hops = build_hops(fields)
    end

    def each(&block)
      @hops.each(&block)
    end

    def [](index)
      @hops[index]
    end

    def first
      @hops.first
    end

    def last
      @hops.last
    end

    def size
      @hops.size
    end
    alias_method :length, :size

    def to_a
      @hops.dup
    end

    def to_h
      @hops.map(&:to_h)
    end

    def to_s
      @hops.map.with_index { |hop, index| hop.to_s(index, size) }.join("\n")
    end

    private

    def build_hops(fields)
      fields.each_with_object([]) do |field, hops|
        raw = field_raw(field)
        raw_field = "Received: #{raw}"
        @raw_fields << raw_field
        hops << ReceivedHop.parse(raw, hops.last, raw_field: raw_field)
      end
    end

    def field_raw(field)
      if field.respond_to?(:unparsed_value) && !field.unparsed_value.nil?
        field.unparsed_value
      elsif field.respond_to?(:value)
        field.value
      else
        field.to_s
      end
    end
  end
end
