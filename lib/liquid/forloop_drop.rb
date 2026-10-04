# frozen_string_literal: true

module Liquid
  # @liquid_public_docs
  # @liquid_type object
  # @liquid_name forloop
  # @liquid_summary
  #   Information about a parent [`for` loop](/docs/api/liquid/tags/for).
  class ForloopDrop < Drop
    def initialize(name, length, parentloop, last_checker: nil, length_checker: nil)
      @name       = name
      @length     = length
      @parentloop = parentloop
      @index      = 0
      @last       = false
      @last_checker = last_checker
      @length_checker = length_checker
    end

    # @liquid_public_docs
    # @liquid_name length
    # @liquid_summary
    #   The total number of iterations in the loop.
    # @liquid_return [number, nil]
    def length
      @length ||= @length_checker&.call
    end

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
    # @liquid_return [number, nil]
    def rindex
      length - @index if @length
    end

    # @liquid_public_docs
    # @liquid_summary
    #   The 0-based index of the current iteration, in reverse order.
    # @liquid_return [number, nil]
    def rindex0
      @length - @index - 1 if @length
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
      if @length
        @index == @length - 1
      elsif @last_checker
        @last_checker.call
      else
        @last
      end
    end

    protected

    def increment!
      @index += 1
    end

    def set_length!(length)
      @length = length
    end

    def set_last!(last)
      @last = last
      set_length!(@index + 1) if last
    end
  end
end
