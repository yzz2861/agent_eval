require "hamster/immutable"

module Hamster

  # An `IntervalMap` associates values with disjoint, left-closed, right-open
  # intervals `[start, stop)` over an ordered domain of endpoints. Points which
  # have never been assigned (or which have been explicitly cleared) are "holes"
  # and have no value.
  #
  # Intervals are stored as a sorted list of fragments, one per maximal run of
  # points sharing the same value, so memory usage is proportional to the number
  # of fragments -- not to the size of the domain or the magnitude of the
  # endpoints. Individual points are never stored.
  #
  # The ordering of endpoints is defined either by their natural `#<=>`
  # comparison, or by a comparator block provided at initialization time. Like
  # {SortedSet}, the block may take 2 arguments (returning -1, 0, or 1, like
  # `Array#sort`) or 1 argument (deriving a sort key, like `Array#sort_by`).
  #
  #     map = Hamster::IntervalMap.new.put(0, 10, "a").put(5, 15, "b")
  #     map.get(3)   # => "a"
  #     map.get(7)   # => "b"
  #     map.get(20)  # => nil
  #
  # Or with a custom endpoint ordering:
  #
  #     Hamster::IntervalMap.new { |a, b| a.length <=> b.length }
  #     Hamster::IntervalMap.new { |endpoint| endpoint.priority }
  #
  # An empty range (where `start` and `stop` compare equal) contains no
  # points, so writing or clearing it is a no-op. A reversed range (where
  # `start` compares greater than `stop`) is meaningless and raises
  # `ArgumentError`.
  #
  # Like all Hamster collections, `IntervalMap` is immutable. {#put} and
  # {#clear} return new maps and leave the receiver unchanged, so earlier
  # versions can be retained and queried forever.
  #
  class IntervalMap
    include Immutable
    include Enumerable

    # @private
    DEFAULT_COMPARATOR = lambda { |a, b| a <=> b }.freeze

    # @private
    EMPTY_FRAGMENTS = [].freeze

    class << self
      # "Raw" allocation of a new `IntervalMap`. Used internally to create a
      # new instance quickly after computing a modified fragment list.
      #
      # @private
      def alloc(fragments, comparator)
        result = allocate
        result.instance_variable_set(:@fragments, fragments)
        result.instance_variable_set(:@comparator, comparator)
        result
      end
    end

    # Return an empty `IntervalMap`. Endpoint ordering comes from a comparator
    # block (2-argument, like `Array#sort`), a sort-key block (1-argument,
    # like `Array#sort_by`), or natural `#<=>` comparison when no block is
    # given.
    def initialize(&block)
      @comparator = if block.nil?
        DEFAULT_COMPARATOR
      elsif block.arity == 1
        key = block
        lambda { |a, b| key.call(a) <=> key.call(b) }
      else
        block
      end
      @fragments = EMPTY_FRAGMENTS
    end

    # Return `true` if no point in the domain has a value.
    #
    # @return [Boolean]
    def empty?
      @fragments.empty?
    end

    # Return the number of stored fragments. This is the number of maximal
    # same-valued intervals, not the number of points covered.
    #
    # @return [Integer]
    def size
      @fragments.size
    end

    # Return the value associated with the given point, or `nil` if the point
    # falls in a hole.
    #
    # @example
    #   Hamster::IntervalMap.new.put(0, 10, "a").get(5)  # => "a"
    #
    # @param point [Object] a point in the endpoint domain
    # @return [Object]
    def get(point)
      low, high = 0, @fragments.size - 1
      while low <= high
        mid = (low + high) / 2
        fragment = @fragments[mid]
        if @comparator.call(point, fragment[0]) < 0
          high = mid - 1
        elsif @comparator.call(point, fragment[1]) >= 0
          low = mid + 1
        else
          return fragment[2]
        end
      end
      nil
    end
    alias_method :[], :get

    # Return a new `IntervalMap` in which every point in `[start, stop)` is
    # associated with `value`, overwriting whatever was there before.
    # Overlapping fragments are split or trimmed as needed, and adjacent
    # fragments with equal values are merged. Holes outside the range are
    # left alone.
    #
    # Assigning over an empty range (`start` equals `stop`) changes nothing
    # and returns `self`.
    #
    # @param start [Object] left endpoint, inclusive
    # @param stop [Object] right endpoint, exclusive
    # @param value [Object]
    # @return [IntervalMap]
    # @raise [ArgumentError] if `start` compares greater than `stop`
    def put(start, stop, value)
      order = check_order(start, stop)
      return self if order == 0

      before, after = split_around(start, stop)
      fragments = before + [[start, stop, value].freeze] + after
      fragments = merge_adjacent(fragments)
      return self if fragments == @fragments
      self.class.alloc(fragments.freeze, @comparator)
    end

    # Return a new `IntervalMap` in which every point in `[start, stop)` is
    # a hole. Fragments overlapping the range are split or trimmed; the rest
    # are kept as they are. Clearing an empty range returns `self`.
    #
    # @param start [Object] left endpoint, inclusive
    # @param stop [Object] right endpoint, exclusive
    # @return [IntervalMap]
    # @raise [ArgumentError] if `start` compares greater than `stop`
    def clear(start, stop)
      order = check_order(start, stop)
      return self if order == 0

      before, after = split_around(start, stop)
      fragments = before + after
      return self if fragments == @fragments
      self.class.alloc(fragments.freeze, @comparator)
    end

    # Yield each stored fragment which intersects `[start, stop)`, in order,
    # as a frozen 3-element array of `[start, stop, value]`. Fragments are
    # yielded whole, not clipped to the query range. With no arguments, all
    # fragments are yielded. An empty range yields nothing.
    #
    # @example
    #   map = Hamster::IntervalMap.new.put(0, 10, "a").put(20, 30, "b")
    #   map.each(5, 25).to_a  # => [[0, 10, "a"], [20, 30, "b"]]
    #
    # @overload each()
    # @overload each(start, stop)
    # @return [self, Enumerator]
    # @raise [ArgumentError] if `start` compares greater than `stop`
    def each(*range)
      return enum_for(:each, *range) unless block_given?
      case range.size
      when 0
        @fragments.each { |fragment| yield fragment }
      when 2
        start, stop = range
        order = check_order(start, stop)
        if order < 0
          @fragments.each do |fragment|
            if @comparator.call(fragment[0], stop) < 0 &&
               @comparator.call(fragment[1], start) > 0
              yield fragment
            end
          end
        end
      else
        raise ArgumentError, "wrong number of arguments (given #{range.size}, expected 0 or 2)"
      end
      self
    end

    # Return all stored fragments as an `Array` of frozen
    # `[start, stop, value]` arrays, in order.
    #
    # @return [Array]
    def to_a
      each.to_a
    end

    # @return [String]
    def inspect
      "Hamster::IntervalMap#{to_a.inspect}"
    end

    private

    # Compare endpoints, returning -1, 0, or 1. Raise on reversed ranges.
    def check_order(start, stop)
      order = @comparator.call(start, stop)
      if order > 0
        raise ArgumentError, "range start #{start.inspect} is greater than range stop #{stop.inspect}"
      end
      order
    end

    # Partition the stored fragments around `[start, stop)` into two arrays:
    # pieces lying entirely before the range, and pieces lying entirely after
    # it. Overlapping fragments are trimmed to their non-overlapping parts.
    def split_around(start, stop)
      before, after = [], []
      @fragments.each do |fragment|
        if @comparator.call(fragment[1], start) <= 0
          before << fragment
        elsif @comparator.call(fragment[0], stop) >= 0
          after << fragment
        else
          if @comparator.call(fragment[0], start) < 0
            before << [fragment[0], start, fragment[2]].freeze
          end
          if @comparator.call(stop, fragment[1]) < 0
            after << [stop, fragment[1], fragment[2]].freeze
          end
        end
      end
      [before, after]
    end

    # Merge runs of adjacent fragments which touch (the stop of one equals the
    # start of the next) and carry equal values. Gaps are never bridged.
    def merge_adjacent(fragments)
      merged = []
      fragments.each do |fragment|
        last = merged[-1]
        if last && @comparator.call(last[1], fragment[0]) == 0 && last[2] == fragment[2]
          merged[-1] = [last[0], fragment[1], last[2]].freeze
        else
          merged << fragment
        end
      end
      merged
    end
  end
end
