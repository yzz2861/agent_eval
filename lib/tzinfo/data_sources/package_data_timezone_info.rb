# encoding: UTF-8
# frozen_string_literal: true

require_relative 'timezone_package'

module TZInfo
  module DataSources
    # A {DataTimezoneInfo} backed by an imported, limited time zone package.
    #
    # Queries are restricted to the package coverage window. A query outside
    # the window raises {TimezonePackageTimeOutOfRange}; the final offset is
    # never extrapolated into the future.
    class PackageDataTimezoneInfo < DataTimezoneInfo
      # @return [Integer] the inclusive start of the coverage window as seconds
      #   since 1970-01-01 UTC.
      attr_reader :window_from

      # @return [Integer] the inclusive end of the coverage window as seconds
      #   since 1970-01-01 UTC.
      attr_reader :window_to

      # Initializes a new {PackageDataTimezoneInfo}.
      #
      # @param identifier [String] the identifier of the time zone.
      # @param window_from [Integer] the inclusive UTC window start.
      # @param window_to [Integer] the inclusive UTC window end.
      def initialize(identifier, window_from, window_to)
        super(identifier)
        @window_from = window_from
        @window_to = window_to
      end

      private

      # Raises {TimezonePackageTimeOutOfRange} unless a UTC timestamp falls on
      # or inside the coverage window, taking sub-seconds into account.
      #
      # @param timestamp [Timestamp] the timestamp to check.
      def ensure_utc_in_window(timestamp)
        value = timestamp.value
        return if value > @window_from && value < @window_to
        return if value == @window_from && timestamp.sub_second == 0
        return if value == @window_to && timestamp.sub_second == 0

        raise TimezonePackageTimeOutOfRange,
          "#{identifier} does not cover #{timestamp.value} (package window is #{@window_from}..#{@window_to} UTC inclusive)"
      end

      # Raises {TimezonePackageTimeOutOfRange} unless a local timestamp could
      # correspond to a UTC instant on or inside the coverage window. Local
      # times can only be related to UTC within one day's worth of offset, so a
      # one-day margin is allowed at each end.
      #
      # @param local_timestamp [Timestamp] the local timestamp to check.
      def ensure_local_could_be_in_window(local_timestamp)
        value = local_timestamp.value
        margin = TimezonePackageFormat::LOCAL_WINDOW_MARGIN_SECONDS
        earliest = value - margin
        latest = value + margin

        if latest < @window_from || (latest == @window_from && local_timestamp.sub_second != 0) ||
           earliest > @window_to || (earliest == @window_to && local_timestamp.sub_second != 0)
          raise TimezonePackageTimeOutOfRange,
            "#{identifier} does not cover local time #{local_timestamp.value} (package window is #{@window_from}..#{@window_to} UTC inclusive)"
        end
      end

      # Raises {TimezonePackageTimeOutOfRange} unless a UTC timestamp is on or
      # inside the coverage window, or equals the exclusive instant immediately
      # after the window (used as the `to` bound of transitions_up_to).
      #
      # @param timestamp [Timestamp] the timestamp to check.
      def ensure_utc_in_window_or_exclusive_end(timestamp)
        value = timestamp.value
        return if value > @window_from && value <= @window_to
        return if value == @window_from && timestamp.sub_second == 0
        return if value == @window_to + 1 && timestamp.sub_second == 0

        raise TimezonePackageTimeOutOfRange,
          "#{identifier} does not cover #{timestamp.value} (package window is #{@window_from}..#{@window_to} UTC inclusive)"
      end
    end

    # A constant-offset time zone restricted to a coverage window.
    class PackageConstantOffsetDataTimezoneInfo < PackageDataTimezoneInfo
      # @return [TimezoneOffset] the offset observed throughout the window.
      attr_reader :constant_offset

      # Initializes a new {PackageConstantOffsetDataTimezoneInfo}.
      #
      # @param identifier [String] the identifier of the time zone.
      # @param constant_offset [TimezoneOffset] the constant offset.
      # @param window_from [Integer] the inclusive UTC window start.
      # @param window_to [Integer] the inclusive UTC window end.
      def initialize(identifier, constant_offset, window_from, window_to)
        super(identifier, window_from, window_to)
        @constant_offset = constant_offset
      end

      # (see DataTimezoneInfo#period_for)
      def period_for(timestamp)
        ensure_utc_in_window(timestamp)
        OffsetTimezonePeriod.new(@constant_offset)
      end

      # (see DataTimezoneInfo#periods_for_local)
      def periods_for_local(local_timestamp)
        ensure_local_could_be_in_window(local_timestamp)
        [OffsetTimezonePeriod.new(@constant_offset)]
      end

      # (see DataTimezoneInfo#transitions_up_to)
      def transitions_up_to(to_timestamp, from_timestamp = nil)
        ensure_utc_in_window_or_exclusive_end(to_timestamp)
        ensure_utc_in_window(from_timestamp) if from_timestamp
        []
      end
    end

    # A transitions-based time zone restricted to a coverage window.
    class PackageTransitionsDataTimezoneInfo < PackageDataTimezoneInfo
      # @return [Array<TimezoneTransition>] the transitions carried by the
      #   package.
      attr_reader :transitions

      # Initializes a new {PackageTransitionsDataTimezoneInfo}. The supplied
      # transitions array must be ordered, must begin with a transition at or
      # before the window start and must end with a transition strictly after
      # the window end.
      #
      # @param identifier [String] the identifier of the time zone.
      # @param transitions [Array<TimezoneTransition>] the package transitions.
      # @param window_from [Integer] the inclusive UTC window start.
      # @param window_to [Integer] the inclusive UTC window end.
      def initialize(identifier, transitions, window_from, window_to)
        super(identifier, window_from, window_to)
        @transitions = transitions.freeze
      end

      # (see DataTimezoneInfo#period_for)
      def period_for(timestamp)
        ensure_utc_in_window(timestamp)
        delegate.period_for(timestamp)
      end

      # (see DataTimezoneInfo#periods_for_local)
      def periods_for_local(local_timestamp)
        ensure_local_could_be_in_window(local_timestamp)
        delegate.periods_for_local(local_timestamp)
      end

      # (see DataTimezoneInfo#transitions_up_to)
      def transitions_up_to(to_timestamp, from_timestamp = nil)
        ensure_utc_in_window_or_exclusive_end(to_timestamp)
        ensure_utc_in_window(from_timestamp) if from_timestamp
        delegate.transitions_up_to(to_timestamp, from_timestamp)
      end

      private

      # @return [TransitionsDataTimezoneInfo] a delegate that performs period
      #   lookup against the package transitions.
      def delegate
        @delegate ||= TransitionsDataTimezoneInfo.new(identifier, @transitions)
      end
    end
  end
end
