# encoding: UTF-8
# frozen_string_literal: true

module TZInfo
  module DataSources
    # Raised by {DataTimezoneInfo#period_for_all} (and methods that use it,
    # such as {DataTimezone#utc_to_local_all}) when a timestamp is
    # encountered that is earlier than a preceding timestamp.
    #
    # The input must be supplied in non-decreasing chronological order. The
    # timestamps are not sorted automatically so that the input can be
    # processed lazily without first being read in full.
    class OutOfOrderTimestampError < ArgumentError
      # @return [Integer] the zero-based index within the input of the
      #   timestamp that was out of order.
      attr_reader :index

      # Initializes a new {OutOfOrderTimestampError}.
      #
      # @param index [Integer] the zero-based index within the input of the
      #   timestamp that was out of order.
      def initialize(index)
        @index = index
        super("timestamp at index #{index} is earlier than the preceding timestamp (timestamps must be supplied in non-decreasing order)")
      end
    end

    # The base class for time zones defined as either a series of transitions
    # ({TransitionsDataTimezoneInfo}) or a constantly observed offset
    # ({ConstantOffsetDataTimezoneInfo}).
    #
    # @abstract Data sources return instances of {DataTimezoneInfo} subclasses.
    class DataTimezoneInfo < TimezoneInfo
      # @param timestamp [Timestamp] a {Timestamp} with a specified
      #   {Timestamp#utc_offset utc_offset}.
      # @return [TimezonePeriod] the {TimezonePeriod} observed at the time
      #   specified by `timestamp`.
      # @raise [ArgumentError] may be raised if `timestamp` is `nil` or does not
      #   have a specified {Timestamp#utc_offset utc_offset}.
      def period_for(timestamp)
        raise_not_implemented('period_for')
      end

      # Returns the {TimezonePeriod TimezonePeriods} observed for a sequence
      # of timestamps in non-decreasing chronological order.
      #
      # The default implementation validates the ordering of the timestamps
      # and calls {#period_for} for each one. Subclasses with transition
      # data ({TransitionsDataTimezoneInfo}) override this with a linear
      # advance through the transitions that avoids an independent binary
      # search for each timestamp.
      #
      # Timestamps that are equal to a preceding timestamp are allowed.
      # Processing is lazy when an `Enumerator` is returned (no block given).
      #
      # @param timestamps [Enumerable] an `Enumerable` of {Timestamp}
      #   instances in non-decreasing chronological order.
      # @yield [period] if a block is provided, each {TimezonePeriod} is
      #   yielded to the block, in the same order as the timestamps, before
      #   processing the next timestamp.
      # @yieldparam period [TimezonePeriod] the {TimezonePeriod} observed at
      #   the corresponding timestamp.
      # @return [Enumerator<TimezonePeriod>] if no block is provided, an
      #   `Enumerator` of the {TimezonePeriod TimezonePeriods} observed at
      #   each timestamp.
      # @return [nil] if a block is provided.
      # @raise [ArgumentError] if `timestamps` is `nil`.
      # @raise [OutOfOrderTimestampError] if a timestamp is earlier than the
      #   preceding timestamp.
      def period_for_all(timestamps)
        raise ArgumentError, 'timestamps must be specified' unless timestamps
        return enum_for(:period_for_all, timestamps) unless block_given?

        previous_timestamp = nil

        timestamps.each_with_index do |timestamp, index|
          if index > 0 && timestamp < previous_timestamp
            raise OutOfOrderTimestampError.new(index)
          end

          previous_timestamp = timestamp
          yield period_for(timestamp)
        end

        nil
      end

      # Returns an `Array` containing the {TimezonePeriod TimezonePeriods} that
      # could be observed at the local time specified by `local_timestamp`. The
      # results are are ordered by increasing UTC start date. An empty `Array`
      # is returned if no periods are found for the given local time.
      #
      # @param local_timestamp [Timestamp] a {Timestamp} representing a local
      #   time - must have an unspecified {Timestamp#utc_offset utc_offset}.
      # @return [Array<TimezonePeriod>] an `Array` containing the
      #   {TimezonePeriod TimezonePeriods} that could be observed at the local
      #   time specified by `local_timestamp`.
      # @raise [ArgumentError] may be raised if `local_timestamp` is `nil`, or
      #   has a specified {Timestamp#utc_offset utc_offset}.
      def periods_for_local(local_timestamp)
        raise_not_implemented('periods_for_local')
      end

      # Returns an `Array` of {TimezoneTransition} instances representing the
      # times where the UTC offset of the time zone changes.
      #
      # Transitions are returned up to a given {Timestamp} (`to_timestamp`).
      #
      # A from {Timestamp} may also be supplied using the `from_timestamp`
      # parameter. If `from_timestamp` is specified, only transitions from that
      # time onwards will be returned.
      #
      # Comparisons with `to_timestamp` are exclusive. Comparisons with
      # `from_timestamp` are inclusive. If a transition falls precisely on
      # `to_timestamp`, it will be excluded. If a transition falls on
      # `from_timestamp`, it will be included.
      #
      # Transitions returned are ordered by when they occur, from earliest to
      # latest.
      #
      # @param to_timestamp [Timestamp] a {Timestamp} with a specified
      #   {Timestamp#utc_offset utc_offset}. Transitions are returned if they
      #   occur before this time.
      # @param from_timestamp [Timestamp] an optional {Timestamp} with a
      #   specified {Timestamp#utc_offset utc_offset}. If specified, transitions
      #   are returned if they occur at or after this time.
      # @return [Array<TimezoneTransition>] an `Array` of {TimezoneTransition}
      #   instances representing the times where the UTC offset of the time zone
      #   changes.
      # @raise [ArgumentError] may be raised if `to_timestamp` is `nil` or does
      #   not have a specified {Timestamp#utc_offset utc_offset}.
      # @raise [ArgumentError] may be raised if `from_timestamp` is specified
      #   but does not have a specified {Timestamp#utc_offset utc_offset}.
      # @raise [ArgumentError] may be raised if `from_timestamp` is specified
      #   but is not earlier than or at the same time as `to_timestamp`.
      def transitions_up_to(to_timestamp, from_timestamp = nil)
        raise_not_implemented('transitions_up_to')
      end

      # @return [DataTimezone] a new {DataTimezone} instance for the time zone
      #   represented by this {DataTimezoneInfo}.
      def create_timezone
        DataTimezone.new(self)
      end

      private

      # Raises a {NotImplementedError} to indicate that the base class is
      # incorrectly being used directly.
      #
      # raise [NotImplementedError] always.
      def raise_not_implemented(method_name)
        raise NotImplementedError, "Subclasses must override #{method_name}"
      end
    end
  end
end
