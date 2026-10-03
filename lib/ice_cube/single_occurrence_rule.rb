module IceCube
  class SingleOccurrenceRule < Rule
    attr_reader :time, :end_time, :period_duration

    def initialize(time, end_time = nil, period_duration: nil, explicit: nil)
      @time = TimeUtil.ensure_time(time)
      @end_time = TimeUtil.match_zone(end_time, @time) unless end_time.nil?
      @period_duration = period_duration
      @explicit = explicit.nil? ? !end_time.nil? : explicit
      raise ArgumentError, "end_time cannot precede start_time" if @end_time && @end_time < @time
    end

    # Always terminating
    def terminating?
      true
    end

    def next_time(t, _, closing_time, increment: true)
      unless closing_time && closing_time < t
        time if time.to_i >= t.to_i
      end
    end

    def explicit?
      @explicit
    end

    def occurrence(default_duration)
      return Occurrence.new(time, end_time) if explicit?

      Occurrence.new(time, time + default_duration)
    end

    def to_hash
      return {time: time} unless explicit?

      hash = {start_time: time, end_time: end_time}
      hash[:period_duration] = period_duration unless period_duration.nil?
      hash
    end

    def full_required?
      false
    end
  end
end
