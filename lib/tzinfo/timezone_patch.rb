# encoding: UTF-8
# frozen_string_literal: true

module TZInfo
  # Describes an explicit, bounded set of transitions that can be overlaid
  # onto an existing {Timezone} using {PatchedTimezone}.
  #
  # A patch is defined by a UTC window (from {starts_at}, inclusive, up to
  # {ends_at}, exclusive), the {TimezoneOffset} that is observed from the
  # start of the window and any {TimezoneTransition TimezoneTransitions} that
  # occur within the window. When the window ends, a {PatchedTimezone} reverts
  # to the rules of its base time zone.
  #
  # {TimezonePatch} instances are immutable once created.
  class TimezonePatch
    # @return [Timestamp] the start of the window (inclusive) as a
    #   {Timestamp} with a defined UTC offset.
    attr_reader :starts_at

    # @return [Timestamp] the end of the window (exclusive) as a
    #   {Timestamp} with a defined UTC offset.
    attr_reader :ends_at

    # @return [TimezoneOffset] the offset observed from {starts_at} until the
    #   first of {transitions} (or {ends_at} if there are no transitions).
    attr_reader :offset

    # @return [Array<TimezoneTransition>] the transitions that occur within
    #   the window, in ascending order (frozen).
    attr_reader :transitions

    # Initializes a new {TimezonePatch}.
    #
    # The window bounds are considered at a resolution of whole seconds (the
    # {Timestamp#value values} of `starts_at` and `ends_at`). Each transition
    # must occur after the start of the window and before the end of the
    # window.
    #
    # @param starts_at [Object] a `Time`, `DateTime` or {Timestamp} specifying
    #   the start of the window (inclusive).
    # @param ends_at [Object] a `Time`, `DateTime` or {Timestamp} specifying
    #   the end of the window (exclusive).
    # @param offset [TimezoneOffset] the {TimezoneOffset} observed from the
    #   start of the window.
    # @param transitions [Array<TimezoneTransition>] the transitions that
    #   occur within the window, in ascending order.
    # @raise [ArgumentError] if `starts_at` or `ends_at` is `nil` or does not
    #   have a specified UTC offset.
    # @raise [ArgumentError] if `ends_at` is not later than `starts_at`.
    # @raise [ArgumentError] if `offset` is not a {TimezoneOffset}.
    # @raise [ArgumentError] if `transitions` is not an `Array` of
    #   {TimezoneTransition} instances that occur, in ascending order, within
    #   the window.
    def initialize(starts_at, ends_at, offset, transitions = [])
      raise ArgumentError, 'starts_at must be specified' unless starts_at
      raise ArgumentError, 'ends_at must be specified' unless ends_at

      starts_at = Timestamp.for(starts_at)
      ends_at = Timestamp.for(ends_at)

      raise ArgumentError, 'starts_at must have a specified utc_offset' unless starts_at.utc_offset
      raise ArgumentError, 'ends_at must have a specified utc_offset' unless ends_at.utc_offset
      raise ArgumentError, 'ends_at must be later than starts_at' unless ends_at.value > starts_at.value
      raise ArgumentError, 'offset must be a TimezoneOffset' unless offset.kind_of?(TimezoneOffset)
      raise ArgumentError, 'transitions must be an Array' unless transitions.kind_of?(Array)

      first = starts_at.value
      last = ends_at.value
      previous = nil

      transitions.each do |transition|
        unless transition.kind_of?(TimezoneTransition)
          raise ArgumentError, 'transitions must contain only TimezoneTransition instances'
        end

        timestamp_value = transition.timestamp_value

        if timestamp_value <= first || timestamp_value >= last
          raise ArgumentError, 'transitions must occur within the window'
        end

        if previous && timestamp_value <= previous
          raise ArgumentError, 'transitions must be in ascending order'
        end

        previous = timestamp_value
      end

      @starts_at = starts_at
      @ends_at = ends_at
      @offset = offset
      @transitions = transitions.dup.freeze
      freeze
    end

    # Determines if this {TimezonePatch} is equal to another instance.
    #
    # @param p [Object] the instance to test for equality.
    # @return [Boolean] `true` if `p` is a {TimezonePatch} with the same
    #   {starts_at}, {ends_at}, {offset} and {transitions} as this
    #   {TimezonePatch}, otherwise `false`.
    def ==(p)
      p.kind_of?(TimezonePatch) &&
        starts_at == p.starts_at && ends_at == p.ends_at &&
        offset == p.offset && transitions == p.transitions
    end
    alias eql? ==

    # @return [Integer] a hash based on {starts_at}, {ends_at}, {offset} and
    #   {transitions}.
    def hash
      [@starts_at, @ends_at, @offset, @transitions].hash
    end

    # @return [String] the internal object state as a programmer-readable
    #   `String`.
    def inspect
      "#<#{self.class}: @starts_at=#{@starts_at.inspect}, @ends_at=#{@ends_at.inspect}, " \
        "@offset=#{@offset.inspect}, @transitions=#{@transitions.inspect}>"
    end
  end
end
