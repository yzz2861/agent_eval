require 'flipper/adapters/wrapper'
require 'flipper/rollout_schedule'
require 'set'

module Flipper
  module Adapters
    # Public: An adapter wrapper that drives Flipper's built-in, stable
    # percentage-of-actors gate from one or more declarative
    # Flipper::RolloutSchedule objects. No background job ever writes a
    # percentage: each read computes the current threshold from an injected
    # clock and hands it to the existing actor bucketing.
    #
    # Precedence for a feature, highest first:
    #
    #   1. Manual rollout kill switch (see #disable_rollout): the feature is
    #      forced fully off regardless of schedules or other gates until
    #      #enable_rollout clears the kill switch. This is an explicit,
    #      # dedicated override (stored separately from the boolean gate).
    #   2. Boolean fully-on / explicit actors / groups / expression gates:
    #      evaluated normally against the wrapped adapter.
    #   3. The scheduled percentage of actors, while at least one schedule
    #      applies to the feature at the current time.
    #
    # Before a feature's first schedule starts it receives 0% from the
    # schedules. After its last schedule ends its final percentage is held
    # indefinitely. Schedules registered for the same feature must not have
    # overlapping [start, end) intervals; this is rejected at registration
    # (configuration) time, along with reverse intervals inside a schedule.
    class RolloutSchedule < Wrapper
      class InvalidScheduleError < Flipper::Error; end

      # Internal: Gate values returned while the manual kill switch is held.
      DISABLED_CONFIG = {
        boolean: false,
        groups: Set.new.freeze,
        actors: Set.new.freeze,
        expression: nil,
        percentage_of_actors: 0,
        percentage_of_time: 0,
      }.freeze

      def initialize(adapter, clock: -> { Time.now })
        super(adapter)
        @clock = clock
        @schedules = {}
        @disabled = Set.new
        @lock = Mutex.new
      end

      # Public: Register a Flipper::RolloutSchedule (or build one from
      # feature/points/options). Raises InvalidScheduleError if the new
      # schedule overlaps another schedule for the same feature.
      def add_schedule(feature, points = nil, mode: :linear, clock: nil)
        schedule = if feature.is_a?(Flipper::RolloutSchedule)
          feature
        else
          Flipper::RolloutSchedule.new(feature, points, mode: mode, clock: clock || @clock)
        end

        synchronize do
          existing = @schedules[schedule.feature] || []
          if existing.any? { |other| overlaps?(schedule, other) }
            raise InvalidScheduleError,
              "rollout schedule for feature #{schedule.feature.inspect} overlaps an existing schedule (#{schedule.starts_at.iso8601}..#{schedule.ends_at.iso8601})"
          end
          (@schedules[schedule.feature] ||= []) << schedule
        end

        schedule
      end
      alias_method :schedule, :add_schedule

      # Public: Returns the schedules registered for a feature key.
      def schedules_for(feature_key)
        synchronize { (@schedules[feature_key.to_s] || []).dup }
      end

      # Public: Manually force a feature fully off, overriding all schedules
      # and other gates. The kill switch is held in this wrapper until cleared
      # with #enable_rollout and therefore takes precedence over everything.
      def disable_rollout(feature)
        synchronize { @disabled.add(feature_key(feature)) }
        true
      end

      # Public: Clear a manual rollout kill switch so schedules/gates apply
      # again. Returns true.
      def enable_rollout(feature)
        synchronize { @disabled.delete(feature_key(feature)) }
        true
      end

      # Public: Whether the manual kill switch is set for a feature.
      def rollout_disabled?(feature)
        synchronize { @disabled.include?(feature_key(feature)) }
      end

      def get(feature)
        apply_schedule(feature, @adapter.get(feature))
      end

      def get_multi(features)
        result = @adapter.get_multi(features)
        features.each do |feature|
          result[feature.key] = apply_schedule(feature, result[feature.key])
        end
        result
      end

      private

      def apply_schedule(feature, values)
        values = (values || default_config).dup
        key = feature.key

        if rollout_disabled?(key)
          # Explicit kill switch: force every gate closed while it is held.
          return DISABLED_CONFIG.dup
        end

        percentage = scheduled_percentage(key)
        return values if percentage.nil?

        # A fully-on boolean or already-100% actor gate keeps winning; the
        # schedule only drives the stable percentage-of-actors gate.
        values[:percentage_of_actors] = percentage
        values
      end

      # Returns the Integer percentage for a feature at the current time, or
      # nil if no schedule is registered. While a registered window is active
      # its percentage wins. Between/after windows the most recently started
      # schedule's held final percentage stays in effect; before any schedule
      # has started the result is 0.
      def scheduled_percentage(feature_key)
        schedules = schedules_for(feature_key)
        return nil if schedules.empty?

        now = @clock.call
        # Overlaps are rejected at registration, so active windows are at
        # most one. Windows are half-open [starts_at, ends_at): at the exact
        # instant one ends and another starts, the newer one governs.
        active = schedules.find do |schedule|
          now >= schedule.starts_at && now < schedule.ends_at
        end
        return active.percentage_at(now) if active

        started = schedules.select { |schedule| now >= schedule.starts_at }
        return 0 if started.empty?

        started.max_by(&:starts_at).final_percentage
      end

      # Two schedules overlap when their closed [start, end] spans share more
      # than an endpoint. Touching end/start points are allowed so one plan
      # can hand off exactly when another begins.
      def overlaps?(one, other)
        one.starts_at < other.ends_at && other.starts_at < one.ends_at
      end

      def feature_key(feature)
        feature.respond_to?(:key) ? feature.key : feature.to_s
      end

      def synchronize(&block)
        @lock.synchronize(&block)
      end
    end
  end
end
