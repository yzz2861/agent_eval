# encoding: UTF-8
# frozen_string_literal: true

module TZInfo
  # A {Timezone} that overlays explicit transition exceptions
  # ({TimezonePatch TimezonePatches}) onto an existing base {Timezone},
  # producing a new, independent {Timezone} instance.
  #
  # Each {TimezonePatch} replaces the transitions of the base time zone
  # within its UTC window. When the window of a patch starts, the zone begins
  # observing the offset given by the patch. When the window ends, the rules
  # of the base time zone are restored (observing the offset the base zone
  # would use at that time).
  #
  # The base time zone and the {DataSource} it was loaded from are not
  # modified. The effective transitions are computed when the
  # {PatchedTimezone} is constructed, so {Timezone#period_for},
  # {Timezone#periods_for_local} and {Timezone#transitions_up_to} all return
  # consistent results, including for local times that fall into the gaps or
  # overlaps created at the boundaries of each patch.
  #
  # For example:
  #
  #   base = TZInfo::Timezone.get('Europe/London')
  #   offset = TZInfo::TimezoneOffset.new(0, 7200, 'BDST')
  #   patch = TZInfo::TimezonePatch.new(
  #     Time.utc(2026, 4, 1), Time.utc(2026, 5, 1), offset)
  #   patched = TZInfo::PatchedTimezone.new(base, [patch])
  class PatchedTimezone < DataTimezone
    # Transitions of the base time zone are loaded up to this time (exclusive)
    # when constructing the merged view. 10000-01-01 00:00:00 UTC.
    FAR_FUTURE_TIMESTAMP = Timestamp.utc(253402300800).freeze
    private_constant :FAR_FUTURE_TIMESTAMP

    # @return [Timezone] the base time zone the patches are overlaid onto.
    attr_reader :base_timezone

    # @return [Array<TimezonePatch>] the patches applied to the base time
    #   zone.
    attr_reader :patches

    # Initializes a new {PatchedTimezone}.
    #
    # @param base_timezone [Timezone] the base {Timezone} the patches are
    #   overlaid onto. This {Timezone} is not modified.
    # @param patches [Array<TimezonePatch>] the patches to apply, in order of
    #   ascending {TimezonePatch#starts_at starts_at}. The windows of the
    #   patches must not overlap or abut.
    # @param identifier [String] the identifier for the new time zone.
    #   Defaults to the identifier of +base_timezone+ with '+patched'
    #   appended.
    # @raise [ArgumentError] if +base_timezone+ is not a {Timezone}, if
    #   +patches+ is not an +Array+ of {TimezonePatch} instances, or if the
    #   patches are not in ascending order or have overlapping or abutting
    #   windows.
    def initialize(base_timezone, patches, identifier = nil)
      raise ArgumentError, 'base_timezone must be specified' unless base_timezone
      raise ArgumentError, 'base_timezone must be a Timezone' unless base_timezone.kind_of?(Timezone)
      raise ArgumentError, 'patches must be specified' unless patches
      raise ArgumentError, 'patches must be an Array' unless patches.kind_of?(Array)

      previous_patch = nil

      patches.each do |patch|
        unless patch.kind_of?(TimezonePatch)
          raise ArgumentError, 'patches must contain only TimezonePatch instances'
        end

        if previous_patch
          if patch.starts_at_value < previous_patch.starts_at_value
            raise ArgumentError, 'patches must be in ascending order of their start times'
          elsif patch.starts_at_value <= previous_patch.ends_at_value
            raise ArgumentError, 'patches must not have overlapping or abutting windows'
          end
        end

        previous_patch = patch
      end

      @base_timezone = base_timezone
      @patches = patches.dup.freeze
      identifier ||= "#{base_timezone.identifier}+patched"

      super(build_info(identifier))
    end

    private

    # Builds a {DataSources::DataTimezoneInfo} containing the merged view of
    # the base time zone and the patches.
    #
    # @param identifier [String] the identifier for the new time zone.
    # @return [DataSources::DataTimezoneInfo] the merged
    #   {DataSources::DataTimezoneInfo}.
    def build_info(identifier)
      transitions = merged_transitions

      if transitions.empty?
        DataSources::ConstantOffsetDataTimezoneInfo.new(identifier, base_offset_at(0))
      else
        DataSources::TransitionsDataTimezoneInfo.new(identifier, transitions)
      end
    end

    # Combines the transitions of the base time zone with the transitions of
    # each patch.
    #
    # Base transitions that fall within the window of a patch (or exactly on
    # the end of a window, where the transition restoring the base rules is
    # inserted instead) are dropped. Transitions are inserted at the start
    # and end of each window where the observed offset changes.
    #
    # @return [Array<TimezoneTransition>] the merged transitions in order of
    #   ascending {TimezoneTransition#timestamp_value timestamp_value}.
    def merged_transitions
      base_transitions = @base_timezone.transitions_up_to(FAR_FUTURE_TIMESTAMP)
      merged = []
      index = 0

      @patches.each do |patch|
        starts_at_value = patch.starts_at_value
        ends_at_value = patch.ends_at_value

        # Base transitions before the window are retained.
        while index < base_transitions.length && base_transitions[index].timestamp_value < starts_at_value
          merged << base_transitions[index]
          index += 1
        end

        # Base transitions within the window are replaced by the patch. A
        # base transition falling exactly on the end of the window is also
        # dropped - the transition restoring the base rules is inserted in
        # its place (with a corrected previous_offset).
        while index < base_transitions.length && base_transitions[index].timestamp_value <= ends_at_value
          index += 1
        end

        previous_offset = merged.empty? ? base_offset_before(starts_at_value) : merged.last.offset

        unless patch.offset == previous_offset
          merged << TimezoneTransition.new(patch.offset, previous_offset, starts_at_value)
        end

        patch.transitions.each {|t| merged << t }

        final_offset = patch.transitions.empty? ? patch.offset : patch.transitions.last.offset
        restored_offset = base_offset_at(ends_at_value)

        unless restored_offset == final_offset
          merged << TimezoneTransition.new(restored_offset, final_offset, ends_at_value)
        end
      end

      # Base transitions after the last window are retained.
      while index < base_transitions.length
        merged << base_transitions[index]
        index += 1
      end

      merged
    end

    # @param timestamp_value [Integer] a number of seconds since 1970-01-01
    #   00:00:00 UTC.
    # @return [TimezoneOffset] the offset the base time zone observes at
    #   +timestamp_value+.
    def base_offset_at(timestamp_value)
      @base_timezone.period_for(Timestamp.utc(timestamp_value)).offset
    end

    # @param timestamp_value [Integer] a number of seconds since 1970-01-01
    #   00:00:00 UTC.
    # @return [TimezoneOffset] the offset the base time zone observes
    #   immediately before +timestamp_value+.
    def base_offset_before(timestamp_value)
      period = @base_timezone.period_for(Timestamp.utc(timestamp_value))
      start_transition = period.start_transition

      if start_transition && start_transition.timestamp_value == timestamp_value
        start_transition.previous_offset
      else
        period.offset
      end
    end
  end
end

