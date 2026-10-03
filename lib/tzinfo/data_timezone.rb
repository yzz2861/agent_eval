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

    # (see Timezone#to_local_in_order)
    def to_local_in_order(times)
      raise ArgumentError, 'times must be specified' unless times
      return to_enum(:to_local_in_order, times) unless block_given?

      convert_in_order(times, :preserve) {|local_time| yield local_time }
      nil
    end

    # (see Timezone#utc_to_local_in_order)
    def utc_to_local_in_order(utc_times)
      raise ArgumentError, 'utc_times must be specified' unless utc_times
      return to_enum(:utc_to_local_in_order, utc_times) unless block_given?

      convert_in_order(utc_times, :treat_as_utc) {|local_time| yield local_time }
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

    # Drives a single lazy pass over `times`, converting each input to the
    # local time observed in this zone.
    #
    # The timestamps are advanced through the transition list by the
    # {DataSources::DataTimezoneInfo#periods_for_in_order
    # periods_for_in_order} cursor, avoiding a binary search per input. The
    # original input is carried alongside its {Timestamp} representation in
    # the `current_pair` closure variable: the timestamps enumerator is only
    # ever pulled by the periods enumerator, so while each period is being
    # yielded the corresponding input is available. The input sequence is
    # therefore traversed once, lazily, and never needs to be fully consumed.
    #
    # @param times [Enumerable] the inputs in non-decreasing chronological
    #   order.
    # @param offset [Symbol] either `:preserve` or `:treat_as_utc`.
    # @yield [Object] the converted local time for each input.
    def convert_in_order(times, offset)
      current_pair = nil

      timestamps = Enumerator.new do |yielder|
        previous_timestamp = nil
        times.each_with_index do |time, index|
          raise ArgumentError, 'time must be specified' unless time
          timestamp = Timestamp.for(time, offset)
          raise ArgumentError, 'time must have a specified utc_offset' unless timestamp.utc_offset

          if previous_timestamp && timestamp < previous_timestamp
            raise ChronologicalOrderError.new(index)
          end
          previous_timestamp = timestamp

          current_pair = [time, timestamp]
          yielder.yield(timestamp)
        end
      end

      info.periods_for_in_order(timestamps).each do |period|
        time, timestamp = current_pair
        local_timestamp = TimestampWithOffset.set_timezone_offset(timestamp, period.offset)

        result = case time
          when Time
            local_timestamp.to_time
          when DateTime
            local_timestamp.to_datetime
          else
            # A Timestamp, or a Time-like value (which is returned as a Time,
            # matching Timestamp.for and Timezone#to_local).
            time.kind_of?(Timestamp) ? local_timestamp : local_timestamp.to_time
        end

        yield result
      end
    end
  end
end
