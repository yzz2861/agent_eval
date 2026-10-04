# encoding: utf-8
# frozen_string_literal: true

module Mail
  class DisplayPartSelection
    def initialize(part, resources)
      @part = part
      @resources = resources.dup.freeze
    end

    EMPTY = new(nil, []).freeze

    attr_reader :part, :resources
    alias_method :cid_resources, :resources

    def empty?
      part.nil? && resources.empty?
    end

    def to_a
      [part, resources].freeze
    end

    def to_ary
      to_a
    end

    def deconstruct
      to_a
    end

    def [](index)
      to_a[index]
    end
  end
end
