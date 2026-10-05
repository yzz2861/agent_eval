require 'time'

module Flipper
  # Public: A declarative schedule that maps the current time to a rollout
  # percentage of actors. Nothing about the schedule is written over time:
  # the percentage is computed at query time from the injected clock.
  #
  # Each point is a [time, percentage] pair where:
  #
  #   time       - A Time with an explicit offset, or an ISO 8601 String with
  #                an explicit offset (e.g. "2026-01-01T09:00:00+08:00" or
  #                "2026-01-01T01:00:00Z"). Times without an offset are
  #                rejected so schedule behavior never depends on the host
  #                machine's time zone.
  #   percentage - An Integer between 0 and 100.
  #
  # Growth between two consecutive points is either :linear (interpolated at
  # query time, floored to a whole percentage) or :step (the lower point's
  # percentage stays in effect until the next point is reached).
  #
  # Before the first point the percentage is 0. After the last point the
  # final percentage is held indefinitely (the plan does not snap on or off
  # when it ends).
  class RolloutSchedule
    MODES = [:linear, :step].freeze

    Error = Class.new(Flipper::Error)
    InvalidSchedule = Class.new(Error)

    # Public: The Flipper feature key this schedule belongs to.
    attr_reader :feature

    # Public: The callable clock used to determine the current time.
    attr_reader :clock

    # Public: The growth mode, :linear or :step.
    attr_reader :mode

    # Public: Returns a frozen Array of [Time, Integer] points sorted by time.
    attr_reader :points

    def initialize(feature, points, mode: :linear, clock: -> { Time.now })
      @feature = feature.to_s
      @mode = mode.to_sym
      raise InvalidSchedule, "mode must be one of #{MODES.inspect}, was #{@mode.inspect}" unless MODES.include?(@mode)

      raise InvalidSchedule, 'schedule must contain at least two points' if points.nil? || points.length < 2

      normalized_points = points.map { |point| normalize_point(point) }

      normalized_points.each_cons(2) do |(one_time, _), (another_time, _)|
        if another_time < one_time
          raise InvalidSchedule, "points must be given in increasing time order: #{another_time.iso8601} is before #{one_time.iso8601}"
        end
      end

      @points = normalized_points.sort_by(&:first).freeze

      previous_time = nil
      @points.each do |time, percentage|
        unless percentage.is_a?(Integer) && percentage >= 0 && percentage <= 100
          raise InvalidSchedule, "percentage must be an integer between 0 and 100, was #{percentage.inspect}"
        end

        if previous_time && time <= previous_time
          raise InvalidSchedule, "points must be at distinct, increasing times: #{time.iso8601} is not after #{previous_time.iso8601}"
        end
        previous_time = time
      end

      @clock = clock
    end

    # Public: The rollout percentage (0-100) at the given time, defaulting to
    # the injected clock's current time.
    #
    # Returns an Integer between 0 and 100.
    def percentage_at(time = now)
      time = coerce_time(time)

      first_time, first_percentage = @points.first
      return 0 if time < first_time

      last_time, last_percentage = @points.last
      return last_percentage if time >= last_time

      index = @points.index { |point_time, _| time < point_time }
      start_time, start_percentage = @points[index - 1]
      end_time, end_percentage = @points[index]

      return start_percentage if @mode == :step

      fraction = (time - start_time).to_r / (end_time - start_time).to_r
      (start_percentage + fraction * (end_percentage - start_percentage)).floor
    end

    # Public: Whether the schedule spans (and therefore governs) the given
    # time, i.e. the time is at or after the first point and at or before the
    # last point.
    def covers?(time = now)
      time = coerce_time(time)
      time >= @points.first.first && time <= @points.last.first
    end

    # Public: The time the schedule starts (the first point).
    def starts_at
      @points.first.first
    end

    # Public: The time the schedule ends (the last point).
    def ends_at
      @points.last.first
    end

    # Public: The held percentage after the schedule's last point.
    def final_percentage
      @points.last.last
    end

    # ISO 8601 strings are only accepted when they carry an explicit offset
    # (Z or +/-HH:MM); Time.iso8601 otherwise silently applies the host zone.
    EXPLICIT_OFFSET = /(?:z|Z|[+-]\d{2}:?\d{2})\z/
    private_constant :EXPLICIT_OFFSET

    private

    def now
      coerce_time(@clock.call)
    end

    def normalize_point(point)
      unless point.is_a?(Array) && point.length == 2
        raise InvalidSchedule, "each point must be a [time, percentage] pair, was #{point.inspect}"
      end
      [coerce_time(point.first), point.last]
    end

    def coerce_time(value)
      case value
      when Time
        time = value
      when String
        unless value.match?(EXPLICIT_OFFSET)
          raise InvalidSchedule, "#{value.inspect} has no explicit time zone offset; include Z or an offset such as +08:00"
        end
        begin
          time = Time.iso8601(value)
        rescue ArgumentError
          raise InvalidSchedule, "#{value.inspect} is not a valid ISO 8601 time"
        end
      else
        raise InvalidSchedule, "time must be a Time or ISO 8601 String with an explicit offset, was #{value.inspect}"
      end

      if time.utc_offset.nil?
        raise InvalidSchedule, "#{value.inspect} has no explicit time zone offset; use an offset-bearing Time or ISO 8601 String"
      end

      time
    end
  end
end
