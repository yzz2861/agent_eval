# encoding: UTF-8
# frozen_string_literal: true

module TZInfo
  # Describes an explicit exception to the transitions of a time zone, to be
  # overlaid onto an existing {Timezone} with {PatchedTimezone}.
  #
  # A {TimezonePatch} replaces the behavior of a time zone within a UTC
  # window. From {starts_at} (inclusive) the zone observes {offset}. The
  # {transitions} of the patch take effect within the window. From {ends_at}
  # (exclusive) the rules of the underlying time zone are restored.
  #
  # {TimezonePatch} instances are value objects. Once constructed they are not
  # modified.
  class TimezonePatch
    # @return [TimezoneOffset] the offset observed from {starts_at} (until the
    #   first of the {transitions}, if any).
    attr_reader :offset

    # @return [Array<TimezoneTransition>] the transitions that occur within
    #   the window, in order of ascending
    #   {TimezoneTransition#timestamp_value timestamp_value}.
    attr_reader :transitions

    # Initializes a new {TimezonePatch}.
    #
    # @param starts_at [Object] the start of the window (inclusive) as a
    #   Time, DateTime or {Timestamp}, or an Integer number of seconds
    #   since 1970-01-01 00:00:00 UTC.
    # @param ends_at [Object] the end of the window (exclusive) as a Time,
    #   DateTime or {Timestamp}, or an Integer number of seconds since
    #   1970-01-01 00:00:00 UTC.
    # @param offset [TimezoneOffset] the {TimezoneOffset} observed from
    #   +starts_at+.
    # @param transitions [Array<TimezoneTransition>] the transitions that
    #   occur within the window. Each transition must occur after +starts_at+
    #   and before +ends_at+. The transitions must be ordered by ascending
    #   {TimezoneTransition#timestamp_value timestamp_value} and must chain:
    #   the {TimezoneTransition#previous_offset previous_offset} of the first
    #   transition must equal +offset+ and the
    #   {TimezoneTransition#previous_offset previous_offset} of each
    #   subsequent transition must equal the {TimezoneTransition#offset
    #   offset} of the prior transition.
    # @raise [ArgumentError] if any of the parameters are invalid.
    def initialize(starts_at, ends_at, offset, transitions = [])
      raise ArgumentError, 'starts_at must be specified' unless starts_at
      raise ArgumentError, 'ends_at must be specified' unless ends_at
      raise ArgumentError, 'offset must be specified' unless offset
      raise ArgumentError, 'offset must be a TimezoneOffset' unless offset.kind_of?(TimezoneOffset)
      raise ArgumentError, 'transitions must be an Array' unless transitions.kind_of?(Array)

      @starts_at_value = self.class.send(:utc_timestamp_value, starts_at, 'starts_at')
      @ends_at_value = self.class.send(:utc_timestamp_value, ends_at, 'ends_at')
      raise ArgumentError, 'ends_at must be after starts_at' if @ends_at_value <= @starts_at_value

      previous_offset = offset
      previous_timestamp_value = @starts_at_value

      transitions.each do |transition|
        unless transition.kind_of?(TimezoneTransition)
          raise ArgumentError, 'transitions must contain only TimezoneTransition instances'
        end

        timestamp_value = transition.timestamp_value

        if timestamp_value <= previous_timestamp_value
          raise ArgumentError, 'transitions must be ordered by ascending timestamp_value and occur after starts_at'
        end

        if timestamp_value >= @ends_at_value
          raise ArgumentError, 'transitions must occur before ends_at'
        end

        unless transition.previous_offset == previous_offset
          raise ArgumentError, 'the previous_offset of each transition must equal the offset in effect before it'
        end

        previous_offset = transition.offset
        previous_timestamp_value = timestamp_value
      end

      @offset = offset
      @transitions = transitions.dup.freeze
    end

    # @return [Timestamp] the start of the window (inclusive) as a UTC
    #   {Timestamp}.
    def starts_at
      Timestamp.utc(@starts_at_value)
    end

    # @return [Timestamp] the end of the window (exclusive) as a UTC
    #   {Timestamp}.
    def ends_at
      Timestamp.utc(@ends_at_value)
    end

    # @return [Integer] the start of the window (inclusive) as a number of
    #   seconds since 1970-01-01 00:00:00 UTC.
    def starts_at_value
      @starts_at_value
    end

    # @return [Integer] the end of the window (exclusive) as a number of
    #   seconds since 1970-01-01 00:00:00 UTC.
    def ends_at_value
      @ends_at_value
    end

    # Determines if this {TimezonePatch} is equal to another instance.
    #
    # @param p [Object] the instance to test for equality.
    # @return [Boolean] +true+ if +p+ is a {TimezonePatch} with the same
    #   window, {offset} and {transitions}, otherwise +false+.
    def ==(p)
      p.kind_of?(TimezonePatch) &&
        starts_at_value == p.starts_at_value && ends_at_value == p.ends_at_value &&
        offset == p.offset && transitions == p.transitions
    end
    alias eql? ==

    # @return [Integer] a hash based on the window, {offset} and
    #   {transitions}.
    def hash
      [@starts_at_value, @ends_at_value, @offset, @transitions].hash
    end

    # @return [String] the internal object state as a programmer-readable
    #   String.
    def inspect
      "#<#{self.class}: @starts_at_value=#{@starts_at_value}, @ends_at_value=#{@ends_at_value}, @offset=#{@offset.inspect}, @transitions=#{@transitions.inspect}>"
    end

    # Converts a time representation to a number of seconds since
    # 1970-01-01 00:00:00 UTC.
    #
    # @param value [Object] an Integer, Time, DateTime or {Timestamp}.
    # @param name [String] the name of the parameter being converted (used in
    #   error messages).
    # @return [Integer] the number of seconds since 1970-01-01 00:00:00 UTC.
    # @raise [ArgumentError] if +value+ is not a supported representation.
    def self.utc_timestamp_value(value, name)
      if value.kind_of?(Integer)
        value
      elsif value.kind_of?(Time) || value.kind_of?(DateTime) || value.kind_of?(Timestamp)
        Timestamp.for(value).value
      else
        raise ArgumentError, "#{name} must be an Integer, Time, DateTime or Timestamp"
      end
    end
    private_class_method :utc_timestamp_value
  end
end
