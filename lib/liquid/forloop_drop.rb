# frozen_string_literal: true

module Liquid
  # @liquid_public_docs
  # @liquid_type object
  # @liquid_name forloop
  # @liquid_summary
  #   Information about a parent [`for` loop](/docs/api/liquid/tags/for).
  class ForloopDrop < Drop
    def initialize(name, length, parentloop, last_check: nil)
      @name       = name
      @length     = length
      @parentloop = parentloop
      @index      = 0
      @last_check = last_check
    end

    # @liquid_public_docs
    # @liquid_name length
    # @liquid_summary
    #   The total number of iterations in the loop.
    # @liquid_return [number]
    attr_reader :length

    # @liquid_public_docs
    # @liquid_name parentloop
    # @liquid_summary
    #   The parent `forloop` object.
    # @liquid_description
    #   If the current `for` loop isn't nested inside another `for` loop, then `nil` is returned.
    # @liquid_return [forloop]
    attr_reader :parentloop

    attr_reader :name

    # @liquid_public_docs
    # @liquid_summary
    #   The 1-based index of the current iteration.
    # @liquid_return [number]
    def index
      @index + 1
    end

    # @liquid_public_docs
    # @liquid_summary
    #   The 0-based index of the current iteration.
    # @liquid_return [number]
    def index0
      @index
    end

    # @liquid_public_docs
    # @liquid_summary
    #   The 1-based index of the current iteration, in reverse order.
    # @liquid_return [number]
    def rindex
      @length && @length - @index
    end

    # @liquid_public_docs
    # @liquid_summary
    #   The 0-based index of the current iteration, in reverse order.
    # @liquid_return [number]
    def rindex0
      @length && @length - @index - 1
    end

    # @liquid_public_docs
    # @liquid_summary
    #   Returns `true` if the current iteration is the first. Returns `false` if not.
    # @liquid_return [boolean]
    def first
      @index == 0
    end

    # @liquid_public_docs
    # @liquid_summary
    #   Returns `true` if the current iteration is the last. Returns `false` if not.
    # @liquid_return [boolean]
    def last
      @last_check ? @last_check.call : @index == @length - 1
    end

    protected

    def increment!
      @index += 1
    end
  end
end
