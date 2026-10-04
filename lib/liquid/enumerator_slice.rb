# frozen_string_literal: true

module Liquid
  class EnumeratorSlice
    UNCONSUMED = Object.new.freeze

    attr_reader :position

    def initialize(enumerator, from:, limit:, resource_limits:)
      @enumerator = enumerator
      @resource_limits = resource_limits
      @total_length = finite_size
      @position = 0
      @lookahead = nil
      @primed = false
      @exhausted = false

      rebind(from: from, limit: limit)
    end

    def length
      return unless @total_length

      available = @total_length - @from
      return 0 if available <= 0
      return available if @remaining_limit.nil?

      [@remaining_limit, available].min
    end

    def rebind(from:, limit:)
      @from = [from, 0].max
      @remaining_limit = normalize_limit(limit)
      seek(@from)
      self
    end

    def empty?
      bounded_empty? || !primed?
    end

    def each
      return enum_for(:each) unless block_given?

      loop do
        item = next_item
        break if item == UNCONSUMED
        yield item
      end
    end

    def last?
      return true if !@remaining_limit.nil? && @remaining_limit.zero?

      !primed?
    end

    def seek(target)
      raise Liquid::ArgumentError, "cannot rewind a one-time enumerator" if target < @position

      while @position < target
        break unless skip_one
      end
      self
    end

    private

    def next_item
      return UNCONSUMED if bounded_empty?
      item = peek_next
      return UNCONSUMED if @exhausted

      @lookahead = nil
      @position += 1
      @primed = false
      @remaining_limit -= 1 unless @remaining_limit.nil?
      item
    end

    def skip_one
      return false unless primed?

      @lookahead = nil
      @position += 1
      @primed = false
      true
    end

    def peek_next
      return if @exhausted
      return @lookahead if @primed

      begin
        item = @enumerator.next
        @resource_limits.increment_render_score(1)
        @lookahead = item
        @primed = true
        item
      rescue StopIteration
        @exhausted = true
        @primed = false
      end
    end

    def primed?
      @primed || peek_next
      @primed
    end

    def bounded_empty?
      !@remaining_limit.nil? && @remaining_limit <= 0
    end

    def normalize_limit(limit)
      return nil if limit.nil?
      return 0 if limit < 0

      limit
    end

    def finite_size
      return unless @enumerator.respond_to?(:size)

      size = @enumerator.size
      size if size.is_a?(Integer) && size >= 0
    end
  end
end
