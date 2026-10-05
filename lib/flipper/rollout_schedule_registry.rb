require 'flipper/rollout_schedule'
require 'concurrent/map'

module Flipper
  # Internal: Holds the declarative rollout schedules configured on a DSL
  # instance, plus explicit per-feature kill switches. Schedules are plain
  # configuration: nothing writes percentages back to them over time.
  class RolloutScheduleRegistry
    Entry = Struct.new(:schedule, :disabled, keyword_init: true) do
      def disabled?
        !!disabled
      end
    end

    def initialize
      @entries = Concurrent::Map.new
    end

    # Public: Configure (or replace) the schedule for a feature. Configuring
    # a schedule clears any previous manual kill switch.
    #
    # name     - The String/Symbol feature name.
    # schedule - A RolloutSchedule, or config Hash/block accepted by
    #            RolloutSchedule.build.
    #
    # Returns the RolloutSchedule.
    def set(name, schedule = nil, &block)
      schedule = RolloutSchedule.build(schedule, &block) unless schedule.is_a?(RolloutSchedule)
      @entries[name.to_s] = Entry.new(schedule: schedule, disabled: false)
      schedule
    end

    # Public: Manually turn the feature's scheduled rollout off. The kill
    # switch stays in place until #enable or #set is called.
    def disable(name)
      entry = @entries[name.to_s]
      raise ArgumentError, "no rollout schedule configured for #{name.inspect}" unless entry
      @entries[name.to_s] = Entry.new(schedule: entry.schedule, disabled: true)
      true
    end

    # Public: Clear the manual kill switch without changing the schedule.
    def enable(name)
      entry = @entries[name.to_s]
      raise ArgumentError, "no rollout schedule configured for #{name.inspect}" unless entry
      @entries[name.to_s] = Entry.new(schedule: entry.schedule, disabled: false)
      true
    end

    # Public: True when the feature is manually turned off.
    def disabled?(name)
      entry = @entries[name.to_s]
      entry ? entry.disabled? : false
    end

    # Public: Returns the RolloutSchedule for a feature or nil.
    def schedule(name)
      @entries[name.to_s]&.schedule
    end

    # Public: Returns the registry Entry for a feature or nil.
    def entry(name)
      @entries[name.to_s]
    end

    # Public: Remove the schedule and its kill switch entirely.
    def remove(name)
      @entries.delete(name.to_s)
    end

    # Public: Returns the configured feature names.
    def feature_names
      @entries.keys
    end
  end
end
