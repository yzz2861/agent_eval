# encoding: UTF-8
# frozen_string_literal: true

module TZInfo
  # Represents a half-open interval of UTC time within which two time zones
  # differ, as determined by {Timezone#compare_with}.
  #
  # The interval runs from {starts_at} (inclusive) to {ends_at} (exclusive).
  # {first_period} and {second_period} describe the {TimezonePeriod} of each
  # of the two compared time zones that is in effect during the interval.
  class TimezoneDifference
    # @return [Timestamp] the UTC start of the interval (inclusive).
    attr_reader :starts_at

    # @return [Timestamp] the UTC end of the interval (exclusive).
    attr_reader :ends_at

    # @return [TimezonePeriod] the period of the {Timezone} {Timezone#compare_with}
    #   was called on that is in effect during the interval.
    attr_reader :first_period

    # @return [TimezonePeriod] the period of the {Timezone} passed to
    #   {Timezone#compare_with} that is in effect during the interval.
    attr_reader :second_period

    # Initializes a {TimezoneDifference}.
    #
    # @param starts_at [Timestamp] the UTC start of the interval (inclusive).
    # @param ends_at [Timestamp] the UTC end of the interval (exclusive).
    # @param first_period [TimezonePeriod] the period of the first time zone
    #   that is in effect during the interval.
    # @param second_period [TimezonePeriod] the period of the second time zone
    #   that is in effect during the interval.
    # @raise [ArgumentError] if any parameter is `nil`.
    def initialize(starts_at, ends_at, first_period, second_period)
      raise ArgumentError, 'starts_at must be specified' unless starts_at
      raise ArgumentError, 'ends_at must be specified' unless ends_at
      raise ArgumentError, 'first_period must be specified' unless first_period
      raise ArgumentError, 'second_period must be specified' unless second_period

      @starts_at = starts_at
      @ends_at = ends_at
      @first_period = first_period
      @second_period = second_period
    end

    # Determines if this {TimezoneDifference} is equal to another instance.
    #
    # @param d [Object] the instance to test for equality.
    # @return [Boolean] `true` if `d` is a {TimezoneDifference} with the same
    #   {starts_at}, {ends_at}, {first_period} and {second_period}, otherwise
    #   `false`.
    def ==(d)
      d.kind_of?(TimezoneDifference) &&
        starts_at == d.starts_at && ends_at == d.ends_at &&
        first_period == d.first_period && second_period == d.second_period
    end
    alias eql? ==

    # @return [Integer] a hash based on {starts_at}, {ends_at}, {first_period}
    #   and {second_period}.
    def hash
      [@starts_at, @ends_at, @first_period, @second_period].hash
    end

    # @return [String] the internal object state as a programmer-readable
    #   `String`.
    def inspect
      "#<#{self.class}: @starts_at=#{@starts_at.inspect}, @ends_at=#{@ends_at.inspect}, @first_period=#{@first_period.inspect}, @second_period=#{@second_period.inspect}>"
    end
  end
end
