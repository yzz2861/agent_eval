module IceCube
  # Computes bookable free intervals inside a finite query window from a set
  # of "available" schedules (e.g. business hours) minus a set of "busy"
  # schedules (e.g. existing appointments).
  #
  # Semantics:
  #
  # * Every interval is a half-open range [start_time, end_time): an
  #   appointment may begin exactly when a busy interval ends, and may end
  #   exactly when the next one begins.
  # * Occurrences of all available schedules are merged into one union, as
  #   are occurrences of all busy schedules; overlapping or touching
  #   occurrences collapse into a single interval before the busy union is
  #   subtracted from the available union.
  # * Occurrences are clipped to the query window, so an occurrence that
  #   begins before the window (including one crossing midnight) still
  #   contributes the part that falls inside it, and the window bounds every
  #   returned interval.
  # * Zero-duration occurrences occupy no time: they neither provide
  #   availability nor block it.
  # * Rules without a count/until are truncated by the query window, and
  #   +max_occurrences+ bounds how many occurrences a single schedule may
  #   contribute within the window before LimitExceeded is raised.
  #
  #     hours = IceCube::Schedule.new(Time.utc(2026, 10, 5, 9), duration: 8 * 3600) do |s|
  #       s.add_recurrence_rule IceCube::Rule.daily
  #     end
  #     lunch = IceCube::Schedule.new(Time.utc(2026, 10, 5, 12), duration: 3600)
  #
  #     availability = IceCube::Availability.new(available: hours, busy: [lunch], duration: 45 * 60)
  #     availability.free_intervals(Time.utc(2026, 10, 5), Time.utc(2026, 10, 6))
  #     # => [2026-10-05 09:00...2026-10-05 12:00, 2026-10-05 13:00...2026-10-05 17:00]
  #
  class Availability
    # Raised when a schedule produces more than +max_occurrences+
    # occurrences inside the query window.
    class LimitExceeded < StandardError; end

    DEFAULT_MAX_OCCURRENCES = 1_000

    attr_reader :available_schedules, :busy_schedules, :duration, :max_occurrences

    def initialize(available:, busy: [], duration:, max_occurrences: DEFAULT_MAX_OCCURRENCES)
      @available_schedules = Array(available)
      raise ArgumentError, "at least one available schedule is required" if @available_schedules.empty?
      @busy_schedules = Array(busy)
      unless duration.is_a?(Numeric) && duration > 0
        raise ArgumentError, "duration must be a positive number of seconds"
      end
      @duration = duration
      unless max_occurrences.is_a?(Integer) && max_occurrences > 0
        raise ArgumentError, "max_occurrences must be a positive integer"
      end
      @max_occurrences = max_occurrences
    end

    # Sorted, non-overlapping half-open ranges (start...end) inside
    # [opening_time, closing_time) where a +duration+ long appointment fits.
    def free_intervals(opening_time, closing_time)
      opening_time = TimeUtil.ensure_time(opening_time)
      closing_time = TimeUtil.ensure_time(closing_time)
      unless closing_time > opening_time
        raise ArgumentError, "closing_time must be after opening_time"
      end

      available = merged_intervals(available_schedules, opening_time, closing_time)
      busy = merged_intervals(busy_schedules, opening_time, closing_time)

      subtract(available, busy).filter_map do |start_time, end_time|
        (start_time...end_time) if end_time - start_time >= duration
      end
    end

    private

    # Merged (overlapping or touching) [start, end) pairs from the
    # occurrences of all given schedules, clipped to the window. Results
    # are sorted and pairwise disjoint with a gap between neighbours.
    def merged_intervals(schedules, opening_time, closing_time)
      intervals = schedules.flat_map do |schedule|
        clipped_occurrences(schedule, opening_time, closing_time)
      end
      intervals.sort_by!(&:first)
      intervals.each_with_object([]) do |(start_time, end_time), merged|
        if merged.empty? || start_time > merged.last[1]
          merged << [start_time, end_time]
        elsif end_time > merged.last[1]
          merged.last[1] = end_time
        end
      end
    end

    # Occurrences of a single schedule as [start, end) pairs clipped to the
    # window. +spans: true+ pulls in occurrences that began before the
    # window but overlap it. Zero-length results are dropped since they
    # occupy no time.
    def clipped_occurrences(schedule, opening_time, closing_time)
      enumerator = schedule.occurrences_between_enumerator(opening_time, closing_time, spans: true)
      occurrences = enumerator.lazy.take(max_occurrences + 1).to_a
      if occurrences.size > max_occurrences
        raise LimitExceeded, "schedule produced more than #{max_occurrences} occurrences within the window"
      end
      occurrences.filter_map do |occurrence|
        start_time = [occurrence.start_time, opening_time].max
        end_time = [occurrence.end_time, closing_time].min
        [start_time, end_time] if start_time < end_time
      end
    end

    # Subtract merged busy intervals from merged available intervals.
    # Both inputs are sorted and disjoint, so a single linear sweep works.
    def subtract(available, busy)
      free = []
      busy_index = 0
      available.each do |avail_start, avail_end|
        cursor = avail_start
        index = busy_index
        while index < busy.size && busy[index][0] < avail_end
          busy_start, busy_end = busy[index]
          if busy_end > cursor
            free << [cursor, busy_start] if busy_start > cursor
            cursor = busy_end
            break if cursor >= avail_end
          end
          index += 1
        end
        free << [cursor, avail_end] if cursor < avail_end
        # Busy intervals ending at or before avail_end cannot overlap the
        # next available interval (merged intervals never touch).
        busy_index += 1 while busy_index < busy.size && busy[busy_index][1] <= avail_end
      end
      free
    end
  end
end
