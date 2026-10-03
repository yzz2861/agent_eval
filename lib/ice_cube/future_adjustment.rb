module IceCube
  # A future modification of a recurring series, applied from one original
  # recurrence occurrence (the +anchor+) onwards. This models a calendar
  # editor's "edit this and future events" action without enumerating and
  # persisting an unbounded number of future instances.
  #
  # Two kinds of change are supported:
  #
  # * +start_offset+ - seconds added to the start time of every occurrence on
  #   the original recurrence axis at or after the anchor. Use +nil+ to leave
  #   the offset of the preceding segment untouched (default 0),
  # * +duration+ - the new, uniform duration (in seconds) of those
  #   occurrences. Use +nil+ to leave the duration of the preceding segment
  #   untouched (default the schedule duration).
  #
  # The anchor is always interpreted on the original recurrence axis (the
  # schedule's rrules plus its implicit start occurrence), never against
  # times produced by earlier adjustments. Offsets are also expressed
  # relative to that original axis, so a second adjustment of 2 hours starts
  # two hours late rather than stacking on top of a previous offset.
  class FutureAdjustment
    attr_reader :anchor, :start_offset, :duration

    # @param anchor [Time] an occurrence of the original recurrence axis;
    #   the adjustment takes effect from this occurrence (inclusive)
    # @param start_offset [Integer, nil] seconds to add to each occurrence
    #   start (may be negative), or nil to inherit the preceding segment
    # @param duration [Integer, nil] new duration in seconds for the segment,
    #   or nil to inherit the duration of the preceding segment
    def initialize(anchor, start_offset: nil, duration: nil)
      @anchor = TimeUtil.ensure_time(anchor)
      @start_offset = start_offset.nil? ? nil : Integer(start_offset)
      if duration
        duration = Integer(duration)
        raise ArgumentError, "duration must be non-negative, got #{duration}" if duration < 0
      end
      @duration = duration
      freeze
    end

    # Serialize to a hash suitable for Schedule#to_hash / to_yaml.
    def to_hash
      data = {
        anchor: TimeUtil.serialize_time(anchor)
      }
      data[:start_offset] = start_offset unless start_offset.nil?
      data[:duration] = duration unless duration.nil?
      data
    end
    alias_method :to_h, :to_hash

    # Rebuild an adjustment from a hash produced by #to_hash.
    def self.from_hash(hash)
      hash = IceCube::FlexibleHash.new(hash)
      new(
        TimeUtil.deserialize_time(hash[:anchor]),
        start_offset: hash[:start_offset],
        duration: hash[:duration]
      )
    end

    def hash
      [TimeUtil.hash(anchor), start_offset, duration].hash
    end

    def eql?(other)
      other.is_a?(self.class) &&
        anchor.to_i == other.anchor.to_i &&
        start_offset == other.start_offset &&
        duration == other.duration
    end
    alias_method :==, :eql?
  end
end
