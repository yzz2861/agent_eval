module IceCube
  # An adjustment to a schedule that takes effect from a given original
  # recurrence time ("edit this and following events") without enumerating
  # future instances.
  #
  # The anchor identifies an occurrence on the original recurrence axis
  # (its unadjusted start time). The adjustment shifts the start time of
  # that occurrence and every later rule-generated occurrence by
  # start_offset seconds, and optionally replaces the schedule's duration
  # with a unified duration (in seconds) for those occurrences.
  #
  # Multiple adjustments on one schedule act as consecutive segments: each
  # occurrence belongs to the segment of the latest adjustment whose anchor
  # is not after the occurrence's original start time. Occurrences before
  # the first anchor are never affected, and COUNT / UNTIL / exception
  # rules keep being interpreted on the original recurrence axis.
  #
  # Explicit recurrence times (added via Schedule#add_recurrence_time, e.g.
  # individually rescheduled instances) are exempt: they represent times
  # already chosen by the user and are never shifted.
  class ScheduleAdjustment
    attr_reader :anchor, :start_offset, :duration

    def initialize(anchor, start_offset: 0, duration: nil)
      @anchor = TimeUtil.ensure_time(anchor)
      raise ArgumentError, "anchor time is required" unless @anchor
      @start_offset = start_offset
      @duration = duration
    end

    # Apply this adjustment to an occurrence on the original axis, using
    # base_duration (the schedule's duration) when no unified duration
    # is set.
    def apply(occurrence, base_duration)
      new_start = occurrence.start_time + start_offset
      Occurrence.new(new_start, new_start + (duration || base_duration))
    end

    def to_hash
      data = {}
      data[:anchor] = TimeUtil.serialize_time(anchor)
      data[:start_offset] = start_offset
      data[:duration] = duration if duration
      data
    end

    def self.from_hash(original_hash)
      hash = FlexibleHash.new(original_hash)
      new(
        TimeUtil.deserialize_time(hash[:anchor]),
        start_offset: hash[:start_offset] || 0,
        duration: hash[:duration]
      )
    end

    def ==(other)
      other.is_a?(ScheduleAdjustment) &&
        anchor == other.anchor &&
        start_offset == other.start_offset &&
        duration == other.duration
    end
    alias_method :eql?, :==

    def hash
      [TimeUtil.hash(anchor), start_offset, duration].hash
    end
  end
end
