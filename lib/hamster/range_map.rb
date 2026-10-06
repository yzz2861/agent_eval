require "hamster/immutable"

module Hamster
  # A persistent map from half-open intervals to values.
  #
  # Intervals are represented as separate +lower+ and +upper+ endpoints and use
  # the left-closed/right-open convention: +lower+ is included and +upper+ is
  # not. The map stores maximal adjacent segments, so gaps remain gaps and are
  # omitted from enumeration.
  #
  # @example
  #   map = Hamster::RangeMap.empty.put(0, 10, "a").put(4, 6, "b")
  #   map.get(4)       # => "b"
  #   map.segments     # => [[0, 4, "a"], [4, 6, "b"], [6, 10, "a"]]
  class RangeMap
    include Immutable
    include Enumerable

    DEFAULT_COMPARATOR = lambda { |left, right| left <=> right }

    class << self
      # Create a range map from +[lower, upper, value]+ segment triples.
      #
      # @return [RangeMap]
      def [](*segments)
        new(segments)
      end

      # Return an empty range map. A comparator block or callable may be
      # supplied when endpoints do not use natural ordering.
      #
      # @return [RangeMap]
      def empty(comparator = nil, &block)
        comparator = block || comparator || DEFAULT_COMPARATOR
        if comparator.equal?(DEFAULT_COMPARATOR)
          @empty ||= alloc([], comparator)
        else
          alloc([], comparator)
        end
      end

      # @return [RangeMap]
      # @private
      def alloc(segments, comparator = DEFAULT_COMPARATOR)
        result = allocate
        result.instance_variable_set(:@segments, segments)
        result.instance_variable_set(:@comparator, comparator)
        result.send(:immutable!)
        result
      end
    end

    # @param segments [::Enumerable] optional +[lower, upper, value]+ triples
    # @param comparator [#call] optional callable accepting two endpoints
    # @yield [left, right] optional endpoint comparator, as used by +Array#sort+
    def initialize(segments = nil, comparator = nil, &block)
      if segments.respond_to?(:call) && comparator.nil? && block.nil?
        comparator = segments
        segments = nil
      end

      if segments.is_a?(RangeMap)
        initial_segments = segments.segments
        @comparator = block || comparator || segments.comparator
      else
        initial_segments = segments || []
        @comparator = block || comparator || DEFAULT_COMPARATOR
      end

      @segments = []
      entries = []
      initial_segments.each do |lower, upper, value|
        next if validate_interval(lower, upper) == 0
        entries << [lower, upper, value]
      end
      entries.sort! do |left, right|
        comparison = compare(left[0], right[0])
        comparison == 0 ? compare(left[1], right[1]) : comparison
      end
      entries.each do |lower, upper, value|
        @segments = replace_interval(@segments, lower, upper, value)
      end
      prepare_segments!(@segments)
    end

    # @return [Integer] number of stored segments
    def size
      @segments.size
    end
    alias_method :length, :size

    # @return [Boolean] whether no segments are stored
    def empty?
      @segments.empty?
    end

    # @return [#call] the endpoint comparator
    attr_reader :comparator

    # Assign +value+ to every point in the half-open interval +[lower, upper)+
    # and return a new map. Existing segments are split at the interval edges.
    # An empty interval leaves the map unchanged; a reversed interval raises
    # ArgumentError.
    #
    # @return [RangeMap]
    def put(lower, upper, value)
      updated = replace_interval(@segments, lower, upper, value)
      return self if updated.equal?(@segments) || updated == @segments
      self.class.alloc(prepare_segments!(updated), @comparator)
    end
    alias_method :assign, :put
    alias_method :store, :put

    # Remove values from an interval. With no arguments, remove all segments.
    # Gaps created by removal stay absent.
    #
    # @return [RangeMap]
    def clear(lower = nil, upper = nil)
      return self if lower.nil? && upper.nil? && empty?
      return self.class.alloc([], @comparator) if lower.nil? && upper.nil?
      raise ArgumentError, "expected lower and upper endpoints" if upper.nil?

      comparison = validate_interval(lower, upper)
      return self if comparison == 0

      updated = []
      changed = false
      @segments.each do |segment|
        segment_start, segment_end, value = segment

        if compare(segment_end, lower) <= 0 || compare(segment_start, upper) >= 0
          updated << segment
        else
          changed = true
          updated << [segment_start, lower, value] if compare(segment_start, lower) < 0
          updated << [upper, segment_end, value] if compare(upper, segment_end) < 0
        end
      end

      return self unless changed
      self.class.alloc(prepare_segments!(updated), @comparator)
    end
    alias_method :delete, :clear
    alias_method :remove, :clear

    # Return the value at +point+, or +nil+ when +point+ is in a gap.
    #
    # @return [Object, nil]
    def get(point)
      segment = segment_at(point)
      segment ? segment[2] : nil
    end
    alias_method :value_at, :get
    alias_method :at, :get

    # Return the value at +point+, the provided default, or the block result.
    # Without a fallback, raise KeyError in a gap.
    #
    # @return [Object]
    def fetch(point, *args, &block)
      raise ArgumentError, "wrong number of arguments (given #{args.length + 1}, expected 1..2)" if args.size > 1
      segment = segment_at(point)
      return segment[2] if segment
      return yield(point) if block
      return args.first if args.any?
      raise KeyError, "point not found: #{point.inspect}"
    end

    # @return [Boolean] whether +point+ is covered by a stored segment
    def cover?(point)
      !segment_at(point).nil?
    end
    alias_method :include?, :cover?
    alias_method :key?, :cover?
    alias_method :member?, :cover?

    # Yield each stored +[lower, upper, value]+ segment. With endpoints, only
    # yield the parts intersecting +[lower, upper)+. Gaps are not yielded.
    #
    # @return [RangeMap, Enumerator]
    def each(lower = nil, upper = nil)
      return to_enum(:each, lower, upper) unless block_given?
      return each_segment { |segment| yield(segment) } if lower.nil? && upper.nil?
      raise ArgumentError, "expected lower and upper endpoints" if upper.nil?

      comparison = validate_interval(lower, upper)
      return self if comparison == 0

      @segments.each do |segment|
        segment_start, segment_end, value = segment
        next if compare(segment_end, lower) <= 0 || compare(segment_start, upper) >= 0

        clipped_start = compare(segment_start, lower) < 0 ? lower : segment_start
        clipped_end = compare(segment_end, upper) > 0 ? upper : segment_end
        yield([clipped_start, clipped_end, value].freeze)
      end
      self
    end

    # Return segment triples, optionally restricted to a query interval.
    #
    # @return [Array<Array(Object, Object, Object)>]
    def segments(lower = nil, upper = nil)
      if lower.nil? && upper.nil?
        @segments.dup
      else
        raise ArgumentError, "expected lower and upper endpoints" if upper.nil?
        each(lower, upper).to_a
      end
    end
    alias_method :slices, :segments
    alias_method :each_in_range, :each
    alias_method :to_segments, :segments

    # Return a map containing only the parts intersecting +[lower, upper)+.
    #
    # @return [RangeMap]
    def slice(lower, upper)
      validate_interval(lower, upper)
      self.class.alloc(prepare_segments!(each(lower, upper).to_a), @comparator)
    end
    alias_method :restrict, :slice

    # Point lookup with one argument; restricted map with two endpoints.
    def [](lower, upper = nil)
      upper.nil? ? get(lower) : slice(lower, upper)
    end

    def eql?(other)
      other.instance_of?(self.class) &&
        @segments == other.instance_variable_get(:@segments)
    end
    alias_method :==, :eql?

    def hash
      @segments.hash
    end

    def inspect
      "#{self.class}[#{@segments.map(&:inspect).join(", ")}]"
    end

    # @return [Array<Array(Object, Object, Object)>]
    # @private
    def marshal_dump
      unless @comparator.equal?(DEFAULT_COMPARATOR)
        raise TypeError, "can't dump RangeMap with a custom endpoint comparator"
      end
      @segments
    end

    # @private
    def marshal_load(segments)
      @segments = segments
      @comparator = DEFAULT_COMPARATOR
      prepare_segments!(@segments)
      immutable!
    end

    private

    def compare(left, right)
      @comparator.call(left, right)
    end

    def validate_interval(lower, upper)
      comparison = compare(lower, upper)
      unless comparison.is_a?(Integer)
        raise ArgumentError, "endpoint comparator must return an Integer"
      end
      if comparison > 0
        raise ArgumentError, "interval [#{lower.inspect}, #{upper.inspect}) is reversed"
      end
      comparison
    end

    def segment_at(point)
      lower_index = 0
      upper_index = @segments.size

      while lower_index < upper_index
        middle = (lower_index + upper_index) / 2
        if compare(@segments[middle][0], point) <= 0
          lower_index = middle + 1
        else
          upper_index = middle
        end
      end

      index = lower_index - 1
      return nil if index < 0

      segment = @segments[index]
      compare(point, segment[1]) < 0 ? segment : nil
    end

    def each_segment
      @segments.each { |segment| yield(segment) }
      self
    end

    def replace_interval(current_segments, lower, upper, value)
      comparison = validate_interval(lower, upper)
      return current_segments if comparison == 0

      updated = []
      inserted = false
      current_segments.each do |segment|
        segment_start, segment_end, old_value = segment

        if compare(segment_end, lower) <= 0
          updated << segment
        elsif compare(segment_start, upper) >= 0
          unless inserted
            updated << [lower, upper, value]
            inserted = true
          end
          updated << segment
        else
          updated << [segment_start, lower, old_value] if compare(segment_start, lower) < 0
          unless inserted
            updated << [lower, upper, value]
            inserted = true
          end
          updated << [upper, segment_end, old_value] if compare(upper, segment_end) < 0
        end
      end
      updated << [lower, upper, value] unless inserted
      merge_adjacent(updated)
    end

    def merge_adjacent(segments)
      merged = []
      segments.each do |segment|
        if merged.any? && can_merge?(merged.last, segment)
          previous = merged.pop
          segment = [previous[0], segment[1], previous[2]]
        end
        merged << segment
      end
      merged
    end

    def can_merge?(left, right)
      compare(left[1], right[0]) == 0 && left[2] == right[2]
    end

    def prepare_segments!(segments)
      segments.each { |segment| segment.freeze unless segment.frozen? }
      segments.freeze unless segments.frozen?
      segments
    end
  end

  IntervalMap = RangeMap
  EmptyRangeMap = RangeMap.empty
end
