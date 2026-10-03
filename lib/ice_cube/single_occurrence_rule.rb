module IceCube
  class SingleOccurrenceRule < Rule
    attr_reader :time, :end_time

    def initialize(time, end_time = nil)
      @time = TimeUtil.ensure_time time
      end_time = TimeUtil.match_zone(end_time, @time) unless end_time.nil?
      if end_time && end_time < @time
        raise ArgumentError, "end_time must not be before start_time"
      end
      @end_time = end_time if end_time && end_time != @time
    end

    def period?
      !@end_time.nil?
    end

    def occurrence
      Occurrence.new(@time, @end_time || @time)
    end

    def duration
      period? ? @end_time - @time : nil
    end

    # Always terminating
    def terminating?
      true
    end

    def next_time(t, _, closing_time, increment: true)
      return if closing_time && closing_time < t
      time if time.to_i >= t.to_i
    end

    def to_hash
      hash = {time: time}
      hash[:end_time] = end_time if period?
      hash
    end

    def ==(other)
      other.is_a?(self.class) && time == other.time
    end
    alias_method :eql?, :==

    def hash
      [time, end_time].hash
    end

    def full_required?
      false
    end
  end
end
