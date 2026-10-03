# encoding: UTF-8
# frozen_string_literal: true

module TZInfo
  # Represents time zones that are defined by rules that set out when
  # transitions occur.
  class DataTimezone < InfoTimezone
    # (see Timezone#period_for)
    def period_for(time)
      raise ArgumentError, 'time must be specified' unless time
      timestamp = Timestamp.for(time)
      raise ArgumentError, 'time must have a specified utc_offset' unless timestamp.utc_offset
      info.period_for(timestamp)
    end

    # Converts a sequence of times in UTC to the local time for the time zone,
    # expecting the input to be in non-decreasing chronological order.
    #
    # This is a batch equivalent of {#utc_to_local} intended for use cases such
    # as processing an ordered log archive. Rather than performing an
    # independent search for the period that applies to each time, a single
    # position is advanced forwards through the time zone's transitions, which
    # avoids the per-element binary search overhead of calling
    # {#utc_to_local} repeatedly.
    #
    # The UTC offset of each input time is ignored (each is treated as a UTC
    # time). Each result is returned in the same type as the corresponding
    # input (`Time`, `DateTime` or {Timestamp}), preserving its sub-second
    # precision:
    #
    # - a `Time` results in a {TimeWithOffset},
    # - a `DateTime` results in a {DateTimeWithOffset},
    # - a {Timestamp} results in a {TimestampWithOffset}.
    #
    # Equal consecutive timestamps are allowed. The timestamps are not sorted:
    # if a timestamp is earlier than the preceding timestamp, a
    # {DataSources::OutOfOrderTimestampError} is raised with the zero-based
    # {DataSources::OutOfOrderTimestampError#index index} of the offending
    # timestamp.
    #
    # Processing is lazy when an `Enumerator` is returned (no block given).
    # The input is consumed incrementally as results are pulled; it is not
    # necessary (and not possible for a one-shot `Enumerator`) to read the
    # entire sequence first.
    #
    # @param utc_times [Enumerable] an `Enumerable` of `Time`, `DateTime` or
    #   {Timestamp} instances in non-decreasing chronological order.
    # @yield [local_time] if a block is provided, each local time is yielded
    #   to the block in the same order as the input, before processing the
    #   next element.
    # @yieldparam local_time [Object] the local equivalent as a
    #   {TimeWithOffset}, {DateTimeWithOffset} or {TimestampWithOffset}.
    # @return [Enumerator] if no block is provided, an `Enumerator` of the
    #   local equivalents of each input time.
    # @return [nil] if a block is provided.
    # @raise [ArgumentError] if `utc_times` is `nil`.
    # @raise [ArgumentError] if an element is `nil` or an unsupported type.
    # @raise [ArgumentError] if an element is a {Timestamp} with an
    #   unspecified UTC offset.
    # @raise [DataSources::OutOfOrderTimestampError] if an element is earlier
    #   than the preceding element.
    def utc_to_local_all(utc_times)
      raise ArgumentError, 'utc_times must be specified' unless utc_times
      return enum_for(:utc_to_local_all, utc_times) unless block_given?

      info.period_for_all(each_utc_timestamp(utc_times)) do |period|
        original, timestamp = current_timestamp
        yield convert_to_input_type(original,
          TimestampWithOffset.set_timezone_offset(timestamp, period.offset))
      end

      nil
    end

    # (see Timezone#periods_for_local)
    def periods_for_local(local_time)
      raise ArgumentError, 'local_time must be specified' unless local_time
      info.periods_for_local(Timestamp.for(local_time, :ignore))
    end

    # (see Timezone#transitions_up_to)
    def transitions_up_to(to, from = nil)
      raise ArgumentError, 'to must be specified' unless to
      to_timestamp = Timestamp.for(to)
      from_timestamp = from && Timestamp.for(from)

      begin
        info.transitions_up_to(to_timestamp, from_timestamp)
      rescue ArgumentError => e
        raise ArgumentError, e.message.gsub('_timestamp', '')
      end
    end

    # Returns the canonical {Timezone} instance for this {DataTimezone}.
    #
    # For a {DataTimezone}, this is always `self`.
    #
    # @return [Timezone] `self`.
    def canonical_zone
      self
    end

    private

    # Returns an `Enumerator` that converts each element of `utc_times` to a
    # UTC {Timestamp}, remembering the original element and converted
    # {Timestamp} of the most recently pulled element (accessible via
    # {#current_timestamp}).
    #
    # @param utc_times [Enumerable] an `Enumerable` of `Time`, `DateTime` or
    #   {Timestamp} instances.
    # @return [Enumerator] an `Enumerator` that yields {Timestamp} instances
    #   with a UTC offset.
    def each_utc_timestamp(utc_times)
      Enumerator.new do |yielder|
        utc_times.each do |time|
          timestamp = Timestamp.for(time, :treat_as_utc)
          @current_original = time
          @current_timestamp = timestamp
          yielder.yield timestamp
        end
      end
    end

    # @return [Array(Object, Timestamp)] the original element and converted
    #   {Timestamp} most recently produced by {#each_utc_timestamp}.
    def current_timestamp
      [@current_original, @current_timestamp]
    end

    # Converts a local {TimestampWithOffset} back to the type of the original
    # input, preserving sub-second precision. This mirrors the conversion that
    # {Timestamp.for} performs on its block result.
    #
    # @param original [Object] the original input (`Time`, `DateTime`,
    #   {Timestamp} or a `Time`-like object).
    # @param local_timestamp [TimestampWithOffset] the local result.
    # @return [Object] the local result as a {TimeWithOffset},
    #   {DateTimeWithOffset} or {TimestampWithOffset}.
    def convert_to_input_type(original, local_timestamp)
      if original.kind_of?(DateTime)
        local_timestamp.to_datetime
      elsif original.kind_of?(Timestamp)
        local_timestamp
      else
        # A Time or a Time-like object (responds to to_i and subsec).
        local_timestamp.to_time
      end
    end
  end
end
