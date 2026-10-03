require "ice_cube/errors/too_many_occurrences"

module IceCube
  # Compute free, non-overlapping time windows from a set of available and
  # busy schedules, restricted to a finite query window.
  #
  # All intervals are half-open: [start_time, end_time). An availability
  # window ending at the same time a busy window starts is still free; they
  # touch but never overlap.
  module Availability
    # Default safety cap on the number of occurrences expanded per schedule.
    DEFAULT_MAX_OCCURRENCES = 10_000

    # Free windows within +window_start+ and +window_end+.
    #
    # @param window_start [Time] inclusive start of the query window
    # @param window_end [Time] exclusive end of the query window
    # @param available_schedules [Array<IceCube::Schedule>] schedules that
    #   describe opening/availability times
    # @param busy_schedules [Array<IceCube::Schedule>] schedules that
    #   describe blocked/busy times
    # @param max_occurrences [Integer] safety cap on occurrences expanded
    #   from a single schedule inside the window; infinite rules must be
    #   bounded by the window, and this guards against pathological rules
    # @return [Array<Range>] sorted, disjoint, half-open Time ranges
    def self.free_windows(window_start, window_end, available_schedules: [],
                          busy_schedules: [], max_occurrences: DEFAULT_MAX_OCCURRENCES)
      window_start, window_end = normalize_window(window_start, window_end)
      open = merged_coverage(available_schedules, window_start, window_end, max_occurrences)
      busy = merged_coverage(busy_schedules, window_start, window_end, max_occurrences)
      subtract(open, busy)
    end

    # Place fixed-duration appointments (e.g. 45 minutes) into free windows.
    # Returns sorted, disjoint, half-open ranges of exactly +duration+
    # seconds, packed from the start of each free window.
    #
    # @param duration [Numeric, ActiveSupport::Duration] appointment length
    #   in seconds (a Numeric is expected unless ActiveSupport is loaded)
    def self.appointment_windows(window_start, window_end, duration:,
                                 available_schedules: [], busy_schedules: [],
                                 max_occurrences: DEFAULT_MAX_OCCURRENCES)
      window_start, window_end = normalize_window(window_start, window_end)
      duration = duration.to_i
      raise ArgumentError, "duration must be greater than 0" if duration <= 0
      free_windows(
        window_start, window_end,
        available_schedules: available_schedules,
        busy_schedules: busy_schedules,
        max_occurrences: max_occurrences
      ).flat_map do |free_window|
        slots_for(free_window, duration)
      end
    end

    # Merge overlapping or touching half-open intervals. Touching intervals
    # ([a,b) and [b,c)) merge into [a,c) because the boundary instant is
    # shared without conflict.
    def self.merge_intervals(intervals)
      intervals = intervals
                  .map { |interval| to_interval(interval) }
                  .reject { |start_time, end_time| start_time >= end_time }
                  .sort_by { |start_time, end_time| [start_time, end_time] }
      intervals.each_with_object([]) do |(start_time, end_time), merged|
        if merged.empty? || start_time > merged.last[1]
          merged << [start_time, end_time]
        elsif end_time > merged.last[1]
          merged.last[1] = end_time
        end
      end
    end

    # Subtract sorted, disjoint half-open +busy+ intervals from sorted,
    # disjoint half-open +open+ intervals.
    def self.subtract(open_intervals, busy_intervals)
      open_intervals = merge_intervals(open_intervals)
      busy_intervals = merge_intervals(busy_intervals)
      busy_intervals.each do |busy_start, busy_end|
        remaining = []
        open_intervals.each do |open_start, open_end|
          if open_end <= busy_start || open_start >= busy_end
            remaining << [open_start, open_end]
          else
            remaining << [open_start, busy_start] if open_start < busy_start
            remaining << [busy_end, open_end] if busy_end < open_end
          end
        end
        open_intervals = remaining
        break if open_intervals.empty?
      end
      open_intervals.select { |start_time, end_time| start_time < end_time }
                   .map { |start_time, end_time| half_open_range(start_time, end_time) }
    end

    def self.merged_coverage(schedules, window_start, window_end, max_occurrences)
      intervals = Array(schedules).flat_map do |schedule|
        clipped_occurrences(schedule, window_start, window_end, max_occurrences)
      end
      merge_intervals(intervals)
    end
    private_class_method :merged_coverage

    # Expand a schedule into [start_time, end_time) intervals clipped to the
    # query window.
    #
    # Occurrences that begin before the window but extend into it are
    # included with their start clipped to the window start; occurrences
    # beginning inside the window always carry their own duration even when
    # they extend past the window end, then are clipped.
    #
    # Zero-duration occurrences are point events and cover no time, so they
    # never block availability: they are ignored here.
    def self.clipped_occurrences(schedule, window_start, window_end, max_occurrences)
      # Enumerate lazily so an unbounded rule trips the cap without being
      # fully expanded. spans: true also yields occurrences that start before
      # the window but extend into it (their start lies within one duration
      # of the window start).
      enumerator = schedule.send(:enumerate_occurrences, window_start, window_end, spans: true)
      occurrences = enumerator.take(max_occurrences + 1)
      if occurrences.length > max_occurrences
        raise IceCube::TooManyOccurrences.new(schedule, occurrences.length, max_occurrences)
      end

      occurrences.filter_map do |occurrence|
        next if occurrence.duration.zero?

        start_time = [occurrence.start_time, window_start].max
        end_time = [occurrence.end_time, window_end].min
        next if start_time >= end_time

        [start_time, end_time]
      end
    end
    private_class_method :clipped_occurrences

    def self.slots_for(free_window, duration)
      start_time = free_window.begin
      window_end = free_window.end
      slots = []
      while start_time + duration <= window_end
        slots << half_open_range(start_time, start_time + duration)
        start_time += duration
      end
      slots
    end
    private_class_method :slots_for

    def self.normalize_window(window_start, window_end)
      if window_start.nil? || window_end.nil?
        raise ArgumentError, "window_start and window_end are required"
      end

      window_start = TimeUtil.ensure_time(window_start)
      window_end = TimeUtil.match_zone(window_end, window_start)
      if window_end <= window_start
        raise ArgumentError, "window_end must be after window_start"
      end

      [window_start, window_end]
    end
    private_class_method :normalize_window

    def self.to_interval(interval)
      case interval
      when Range
        [interval.begin, interval.end]
      when IceCube::Occurrence
        [interval.start_time, interval.end_time]
      else
        start_time, end_time = interval
        [start_time, end_time]
      end
    end
    private_class_method :to_interval

    def self.half_open_range(start_time, end_time)
      Range.new(start_time, end_time, true)
    end
    private_class_method :half_open_range
  end
end
