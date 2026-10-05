# encoding: UTF-8
# frozen_string_literal: true

module TZInfo
  # A {Timezone} that overlays one or more explicit {TimezonePatch} windows
  # onto an existing base {Timezone}.
  #
  # Within the UTC window of each {TimezonePatch}, the offsets and
  # transitions defined by the patch are observed instead of those of the
  # base time zone. When the window of a patch ends, the rules of the base
  # time zone apply again.
  #
  # A {PatchedTimezone} is a standalone object. The base time zone and the
  # underlying {DataSource} are never modified.
  #
  # Patches must be supplied in ascending order and must not overlap. Patches
  # that abut (the {TimezonePatch#ends_at ends_at} of one patch equal to the
  # {TimezonePatch#starts_at starts_at} of the next) are permitted and are
  # joined by a single transition.
  class PatchedTimezone < Timezone
    # @return [Timezone] the base time zone the {patches} are overlaid onto.
    attr_reader :base_timezone

    # @return [Array<TimezonePatch>] the patches overlaid onto the base time
    #   zone, in ascending order (frozen).
    attr_reader :patches

    # Initializes a new {PatchedTimezone}.
    #
    # @param base_timezone [Timezone] the {Timezone} the patches are overlaid
    #   onto.
    # @param patches [Array<TimezonePatch>] the {TimezonePatch} instances to
    #   overlay, in ascending order and not overlapping.
    # @param identifier [String] an optional identifier for the patched time
    #   zone. Defaults to the identifier of the base time zone with
    #   " (patched)" appended.
    # @raise [ArgumentError] if the base time zone is not a {Timezone}.
    # @raise [ArgumentError] if the patches are not an Array of
    #   {TimezonePatch} instances, are not in ascending order or overlap.
    def initialize(base_timezone, patches, identifier = nil)
      super()
      raise ArgumentError, 'base_timezone must be a Timezone' unless base_timezone.kind_of?(Timezone)
      raise ArgumentError, 'patches must be an Array' unless patches.kind_of?(Array)

      patches.each_with_index do |patch, i|
        unless patch.kind_of?(TimezonePatch)
          raise ArgumentError, 'patches must contain only TimezonePatch instances'
        end

        if i > 0
          previous = patches[i - 1]

          if patch.starts_at.value < previous.starts_at.value
            raise ArgumentError, 'patches must be in ascending order'
          end

          if patch.starts_at.value < previous.ends_at.value
            raise ArgumentError, 'patches must not overlap'
          end
        end
      end

      @base_timezone = base_timezone
      @patches = patches.dup.freeze
      @identifier = identifier ? identifier.freeze : "#{base_timezone.identifier} (patched)"

      build_overlay
    end

    # (see Timezone#identifier)
    def identifier
      @identifier
    end

    # (see Timezone#period_for)
    def period_for(time)
      raise ArgumentError, 'time must be specified' unless time
      timestamp = Timestamp.for(time)
      raise ArgumentError, 'time must have a specified utc_offset' unless timestamp.utc_offset

      return @base_timezone.period_for(timestamp) if @patches.empty?

      value = timestamp.value
      index = patch_index_covering(value)

      if index
        @periods[index].find {|period| period.end_transition.timestamp_value > value }
      else
        clip_base_period(@base_timezone.period_for(timestamp), value)
      end
    end

    # (see Timezone#periods_for_local)
    def periods_for_local(local_time)
      raise ArgumentError, 'local_time must be specified' unless local_time
      local_timestamp = Timestamp.for(local_time, :ignore)

      return @base_timezone.periods_for_local(local_timestamp) if @patches.empty?

      local_value = local_timestamp.value
      matches = []

      @base_timezone.periods_for_local(local_timestamp).each do |period|
        utc_value = local_value - period.offset.observed_utc_offset

        unless patch_index_covering(utc_value)
          matches << [utc_value, clip_base_period(period, utc_value)]
        end
      end

      @patches.each_with_index do |_patch, i|
        next if local_value < @starts[i] - 86400 || local_value > @ends[i] + 86400

        @periods[i].each do |period|
          utc_value = local_value - period.offset.observed_utc_offset

          if utc_value >= period.start_transition.timestamp_value &&
              utc_value < period.end_transition.timestamp_value
            matches << [utc_value, period]
          end
        end
      end

      matches.sort_by! {|utc_value, _period| utc_value }
      matches.map! {|_utc_value, period| period }
    end

    # (see Timezone#transitions_up_to)
    def transitions_up_to(to, from = nil)
      raise ArgumentError, 'to must be specified' unless to
      to_timestamp = Timestamp.for(to)
      raise ArgumentError, 'to must have a specified utc_offset' unless to_timestamp.utc_offset

      if from
        from_timestamp = Timestamp.for(from)
        raise ArgumentError, 'from must have a specified utc_offset' unless from_timestamp.utc_offset
        raise ArgumentError, 'to must be greater than from' if to_timestamp <= from_timestamp
      end

      return @base_timezone.transitions_up_to(to_timestamp, from_timestamp) if @patches.empty?

      result = @base_timezone.transitions_up_to(to_timestamp, from_timestamp).reject do |t|
        timestamp_value_covered?(t.timestamp_value)
      end

      to_value = to_timestamp.value
      to_sub_second = to_timestamp.sub_second

      if from_timestamp
        from_value = from_timestamp.value
        from_sub_second = from_timestamp.sub_second
      end

      @transitions.each do |t|
        value = t.timestamp_value
        next if value > to_value || (value == to_value && to_sub_second == 0)
        next if from_timestamp && (value < from_value || (value == from_value && from_sub_second > 0))
        result << t
      end

      result.sort_by! {|t| t.timestamp_value }
      result
    end

    # Returns the canonical {Timezone} instance for this {PatchedTimezone}.
    #
    # For a {PatchedTimezone}, this is always self.
    #
    # @return [Timezone] self.
    def canonical_zone
      self
    end

    private

    # Precomputes the effective transitions and periods for each patch.
    #
    # A transition is synthesized at the start of each patch window (from the
    # offset observed by the base time zone to the initial offset of the
    # patch) and at the end of each window (from the final offset of the
    # patch back to the offset observed by the base time zone). Where two
    # patches abut, a single transition is synthesized joining the final
    # offset of the earlier patch to the initial offset of the later patch.
    def build_overlay
      count = @patches.length
      @starts = @patches.map {|p| p.starts_at.value }.freeze
      @ends = @patches.map {|p| p.ends_at.value }.freeze
      @start_transitions = []
      @end_transitions = []
      @periods = []
      @transitions = []

      count.times do |i|
        patch = @patches[i]

        start_transition = if i > 0 && @ends[i - 1] == @starts[i]
          @end_transitions[i - 1]
        else
          TimezoneTransition.new(patch.offset, base_offset_before(@starts[i]), @starts[i])
        end

        end_transition = if i < count - 1 && @ends[i] == @starts[i + 1]
          TimezoneTransition.new(@patches[i + 1].offset, final_patch_offset(patch), @ends[i])
        else
          TimezoneTransition.new(base_offset_at(@ends[i]), final_patch_offset(patch), @ends[i])
        end

        @start_transitions << start_transition
        @end_transitions << end_transition

        periods = []
        period_start = start_transition

        patch.transitions.each do |t|
          periods << TransitionsTimezonePeriod.new(period_start, t)
          period_start = t
        end

        periods << TransitionsTimezonePeriod.new(period_start, end_transition)
        @periods << periods.freeze

        @transitions << start_transition unless @transitions.last.equal?(start_transition)
        @transitions.concat(patch.transitions)
        @transitions << end_transition
      end

      @start_transitions.freeze
      @end_transitions.freeze
      @periods.freeze
      @transitions.freeze
    end

    # Returns the index of the patch with a window containing the given
    # (whole second) timestamp value, or nil if there is no such patch. The
    # window contains values v where starts_at.value <= v < ends_at.value.
    #
    # @param value [Integer] a timestamp value.
    # @return [Integer] the index of the covering patch or nil.
    def patch_index_covering(value)
      index = @starts.rindex {|start| start <= value }
      index && @ends[index] > value ? index : nil
    end

    # Determines if a (whole second) timestamp value falls within the window
    # of a patch, including the end of the window. Used to suppress base time
    # zone transitions that are replaced by a patch (a base transition
    # falling precisely on the end of a window is replaced by the synthesized
    # transition that reverts to the base time zone).
    #
    # @param value [Integer] a timestamp value.
    # @return [Boolean] true if the value falls within the window of a patch.
    def timestamp_value_covered?(value)
      index = @starts.rindex {|start| start <= value }
      !index.nil? && value <= @ends[index]
    end

    # Clips a {TimezonePeriod} obtained from the base time zone so that it
    # does not extend into the window of a patch, replacing its bounding
    # transitions with the synthesized patch boundary transitions where
    # necessary.
    #
    # @param period [TimezonePeriod] a {TimezonePeriod} obtained from the
    #   base time zone for a time outside of all patch windows.
    # @param value [Integer] the timestamp value the period was obtained for.
    # @return [TransitionsTimezonePeriod] the clipped {TimezonePeriod}.
    def clip_base_period(period, value)
      start_transition = period.start_transition
      end_transition = period.end_transition

      end_index = @ends.rindex {|e| e <= value }

      if end_index && (!start_transition || start_transition.timestamp_value <= @ends[end_index])
        start_transition = @end_transitions[end_index]
      end

      start_index = @starts.index {|s| s > value }

      if start_index && (!end_transition || end_transition.timestamp_value >= @starts[start_index])
        end_transition = @start_transitions[start_index]
      end

      TransitionsTimezonePeriod.new(start_transition, end_transition)
    end

    # Returns the {TimezoneOffset} observed by the base time zone at a given
    # (whole second) timestamp value.
    #
    # @param value [Integer] a timestamp value.
    # @return [TimezoneOffset] the offset observed by the base time zone.
    def base_offset_at(value)
      @base_timezone.period_for(Timestamp.utc(value)).offset
    end

    # Returns the {TimezoneOffset} observed by the base time zone immediately
    # before a given (whole second) timestamp value.
    #
    # @param value [Integer] a timestamp value.
    # @return [TimezoneOffset] the offset observed by the base time zone
    #   before the given value.
    def base_offset_before(value)
      period = @base_timezone.period_for(Timestamp.utc(value))
      start_transition = period.start_transition

      if start_transition && start_transition.timestamp_value == value
        start_transition.previous_offset
      else
        period.offset
      end
    end

    # Returns the final {TimezoneOffset} observed within the window of a
    # patch.
    #
    # @param patch [TimezonePatch] a patch.
    # @return [TimezoneOffset] the offset of the last transition of the patch,
    #   or the initial offset of the patch if it has no transitions.
    def final_patch_offset(patch)
      last = patch.transitions[-1]
      last ? last.offset : patch.offset
    end
  end
end

