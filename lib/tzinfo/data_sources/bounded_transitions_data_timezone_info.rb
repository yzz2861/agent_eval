# encoding: UTF-8
# frozen_string_literal: true

module TZInfo
  module DataSources
    # Represents a time zone for which only transitions within a finite period
    # of coverage are available. The final offset is not extrapolated beyond
    # {#coverage_end_value}.
    class BoundedTransitionsDataTimezoneInfo < DataTimezoneInfo
      # @return [Integer] the earliest UTC timestamp, inclusive, for which
      #   period information is available.
      attr_reader :coverage_start_value

      # @return [Integer] the latest UTC timestamp, inclusive, for which
      #   period information is available.
      attr_reader :coverage_end_value

      # @return [Array<TimezoneTransition>] the real transitions stored for the
      #   covered periods.
      attr_reader :transitions

      # Initializes a new {BoundedTransitionsDataTimezoneInfo}.
      #
      # @param identifier [String] the identifier of the time zone.
      # @param transitions [Array<TimezoneTransition>] the real transitions
      #   needed to represent the covered periods. Transitions immediately
      #   outside the coverage may be included to provide period boundaries.
      # @param coverage_start_value [Integer] the inclusive UTC start of the
      #   coverage.
      # @param coverage_end_value [Integer] the inclusive UTC end of the
      #   coverage.
      # @raise [ArgumentError] if an argument is invalid.
      def initialize(identifier, transitions, coverage_start_value, coverage_end_value)
        super(identifier)
        raise ArgumentError, 'transitions must be specified' unless transitions
        raise ArgumentError, 'transitions must not be an empty Array' if transitions.empty?
        raise ArgumentError, 'coverage_start_value must be an Integer' unless coverage_start_value.kind_of?(Integer)
        raise ArgumentError, 'coverage_end_value must be an Integer' unless coverage_end_value.kind_of?(Integer)
        raise ArgumentError, 'coverage_start_value must be less than or equal to coverage_end_value' unless coverage_start_value <= coverage_end_value

        @full_info = TransitionsDataTimezoneInfo.new(identifier, transitions)
        @transitions = @full_info.transitions
        @coverage_start_value = coverage_start_value
        @coverage_end_value = coverage_end_value
      end

      # (see DataTimezoneInfo#period_for)
      def period_for(timestamp)
        raise ArgumentError, 'timestamp must be specified' unless timestamp
        raise ArgumentError, 'timestamp must have a specified utc_offset' unless timestamp.utc_offset

        raise PeriodNotFound, 'The specified time is before the earliest time zone period in this package.' if timestamp < Timestamp.utc(@coverage_start_value)
        raise PeriodNotFound, 'The specified time is after the latest time zone period in this package.' if timestamp > Timestamp.utc(@coverage_end_value)

        bound_period(@full_info.period_for(timestamp))
      end

      # (see DataTimezoneInfo#periods_for_local)
      def periods_for_local(local_timestamp)
        raise ArgumentError, 'local_timestamp must be specified' unless local_timestamp
        raise ArgumentError, 'local_timestamp must have an unspecified utc_offset' if local_timestamp.utc_offset

        @full_info.periods_for_local(local_timestamp).select do |period|
          utc_value = local_timestamp.value - period.observed_utc_offset
          utc_value >= @coverage_start_value && utc_value <= @coverage_end_value
        end
      end

      # (see DataTimezoneInfo#transitions_up_to)
      def transitions_up_to(to_timestamp, from_timestamp = nil)
        result = @full_info.transitions_up_to(to_timestamp, from_timestamp).select do |transition|
          transition.timestamp_value >= @coverage_start_value &&
            transition.timestamp_value <= @coverage_end_value
        end
        result
      end

      private

      def bound_period(period)
        start_transition = period.start_transition
        end_transition = period.end_transition

        if !start_transition || start_transition.timestamp_value < @coverage_start_value
          start_transition = boundary_transition(period.offset, @coverage_start_value)
        end

        if !end_transition || end_transition.timestamp_value > @coverage_end_value
          end_transition = boundary_transition(period.offset, @coverage_end_value)
        end

        if start_transition.equal?(period.start_transition) && end_transition.equal?(period.end_transition)
          period
        else
          TransitionsTimezonePeriod.new(start_transition, end_transition)
        end
      end

      def boundary_transition(offset, timestamp_value)
        TimezoneTransition.new(offset, offset, timestamp_value)
      end
    end
  end
end
