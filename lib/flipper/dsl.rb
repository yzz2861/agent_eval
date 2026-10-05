require 'forwardable'
require 'concurrent/map'
require 'flipper/rollout_schedule_registry'

module Flipper
  class DSL
    extend Forwardable

    # Private
    attr_reader :adapter

    # Private: What is being used to instrument all the things.
    attr_reader :instrumenter

    def_delegators :@adapter, :memoize=, :memoizing?, :import, :export, :adapter_stack

    # Public: Returns a new instance of the DSL.
    #
    # adapter - The adapter that this DSL instance should use.
    # options - The Hash of options.
    #           :instrumenter - What should be used to instrument all the things.
    #           :memoize - Should adapter be wrapped by memoize adapter or not.
    #           :clock - Callable returning the current Time for schedules.
    def initialize(adapter, options = {})
      @instrumenter = options.fetch(:instrumenter, Instrumenters::Noop)
      memoize = options.fetch(:memoize, true)
      adapter = Adapters::Memoizable.new(adapter) if memoize
      @adapter = adapter
      @clock = options[:clock]
      @rollout_schedules = RolloutScheduleRegistry.new
      # Concurrent::Map so a single DSL instance shared across threads (e.g. a
      # Flipper.new(adapter) or Flipper::Cloud.new held in a constant) can
      # memoize features without a non-atomic Hash mutation racing.
      @memoized_features = Concurrent::Map.new
    end

    # Public: Check if a feature is enabled.
    #
    # name - The String or Symbol name of the feature.
    # args - The args passed through to the enabled check.
    #
    # Returns true if feature is enabled, false if not.
    def enabled?(name, *args)
      feature(name).enabled?(*args)
    end

    # Public: Enable a feature.
    #
    # name - The String or Symbol name of the feature.
    # args - The args passed through to the feature instance enable call.
    #
    # Returns the result of the feature instance enable call.
    def enable(name, *args)
      feature(name).enable(*args)
    end

    # Public: Enable a feature for an expression.
    #
    # name - The String or Symbol name of the feature.
    # expression - a Flipper::Expression instance or a Hash.
    #
    # Returns result of Feature#enable.
    def enable_expression(name, expression)
      feature(name).enable_expression(expression)
    end

    # Public: Add an expression to a feature.
    #
    # expression - an expression or Hash that can be converted to an expression.
    #
    # Returns result of enable.
    def add_expression(name, expression)
      feature(name).add_expression(expression)
    end

    # Public: Enable a feature for an actor.
    #
    # name - The String or Symbol name of the feature.
    # actor - a Flipper::Types::Actor instance or an object that responds
    #         to flipper_id.
    #
    # Returns result of Feature#enable.
    def enable_actor(name, actor)
      feature(name).enable_actor(actor)
    end

    # Public: Enable a feature for a group.
    #
    # name - The String or Symbol name of the feature.
    # group - a Flipper::Types::Group instance or a String or Symbol name of a
    #         registered group.
    #
    # Returns result of Feature#enable.
    def enable_group(name, group)
      feature(name).enable_group(group)
    end

    # Public: Enable a feature a percentage of time.
    #
    # name - The String or Symbol name of the feature.
    # percentage - a Flipper::Types::PercentageOfTime instance or an object
    #              that responds to to_i.
    #
    # Returns result of Feature#enable.
    def enable_percentage_of_time(name, percentage)
      feature(name).enable_percentage_of_time(percentage)
    end

    # Public: Enable a feature for a percentage of actors.
    #
    # name - The String or Symbol name of the feature.
    # percentage - a Flipper::Types::PercentageOfActors instance or an object
    #              that responds to to_i.
    #
    # Returns result of Feature#enable.
    def enable_percentage_of_actors(name, percentage)
      feature(name).enable_percentage_of_actors(percentage)
    end

    # Public: Disable a feature.
    #
    # name - The String or Symbol name of the feature.
    # args - The args passed through to the feature instance enable call.
    #
    # Returns the result of the feature instance disable call.
    def disable(name, *args)
      feature(name).disable(*args)
    end

    # Public: Disable expression for feature.
    #
    # name - The String or Symbol name of the feature.
    #
    # Returns result of Feature#disable.
    def disable_expression(name)
      feature(name).disable_expression
    end

    # Public: Remove an expression from a feature.
    #
    # expression - an Expression or Hash that can be converted to an expression.
    #
    # Returns result of enable.
    def remove_expression(name, expression)
      feature(name).remove_expression(expression)
    end

    # Public: Disable a feature for an actor.
    #
    # name - The String or Symbol name of the feature.
    # actor - a Flipper::Types::Actor instance or an object that responds
    #         to flipper_id.
    #
    # Returns result of disable.
    def disable_actor(name, actor)
      feature(name).disable_actor(actor)
    end

    # Public: Disable a feature for a group.
    #
    # name - The String or Symbol name of the feature.
    # group - a Flipper::Types::Group instance or a String or Symbol name of a
    #         registered group.
    #
    # Returns result of disable.
    def disable_group(name, group)
      feature(name).disable_group(group)
    end

    # Public: Disable a feature a percentage of time.
    #
    # name - The String or Symbol name of the feature.
    # percentage - a Flipper::Types::PercentageOfTime instance or an object
    #              that responds to to_i.
    #
    # Returns result of disable.
    def disable_percentage_of_time(name)
      feature(name).disable_percentage_of_time
    end

    # Public: Disable a feature for a percentage of actors.
    #
    # name - The String or Symbol name of the feature.
    # percentage - a Flipper::Types::PercentageOfActors instance or an object
    #              that responds to to_i.
    #
    # Returns result of disable.
    def disable_percentage_of_actors(name)
      feature(name).disable_percentage_of_actors
    end

    # Public: Add a feature.
    #
    # name - The String or Symbol name of the feature.
    #
    # Returns result of add.
    def add(name)
      feature(name).add
    end

    # Public: Has a feature been added in the adapter.
    #
    # name - The String or Symbol name of the feature.
    #
    # Returns true if added else false.
    def exist?(name)
      feature(name).exist?
    end

    # Public: Remove a feature.
    #
    # name - The String or Symbol name of the feature.
    #
    # Returns result of remove.
    def remove(name)
      feature(name).remove
    end

    # Public: Access a feature instance by name.
    #
    # name - The String or Symbol name of the feature.
    #
    # Returns an instance of Flipper::Feature.
    def feature(name)
      if !name.is_a?(String) && !name.is_a?(Symbol)
        raise ArgumentError, "#{name} must be a String or Symbol"
      end

      @memoized_features.compute_if_absent(name.to_sym) do
        Feature.new(
          name,
          @adapter,
          instrumenter: instrumenter,
          rollout_schedule_provider: @rollout_schedules,
          clock: @clock
        )
      end
    end

    # Public: Configure a declarative rollout schedule for a feature.
    #
    # name - The String or Symbol feature name.
    # config - Optional Hash accepted by RolloutSchedule.new.
    #
    # Yields the schedule builder when a block is given.
    #
    # Returns the RolloutSchedule.
    #
    #   flipper.set_rollout_schedule(:search,
    #     windows: [{ starts_at: '...', ends_at: '...',
    #                 from_percentage: 10, to_percentage: 50 }])
    #
    #   flipper.set_rollout_schedule(:search) do |s|
    #     s.window '2026-10-05T10:00:00+08:00',
    #              '2026-10-05T18:00:00+08:00',
    #              from: 10, to: 50
    #   end
    def set_rollout_schedule(name, config = nil, &block)
      @rollout_schedules.set(name, config, &block)
    end

    # Public: Returns the RolloutSchedule configured for a feature or nil.
    def rollout_schedule(name)
      @rollout_schedules.schedule(name)
    end

    # Public: Remove a configured schedule (and its kill switch).
    def remove_rollout_schedule(name)
      @rollout_schedules.remove(name)
    end

    # Public: Manually disable a scheduled rollout. The kill switch overrides
    # every other gate except a full boolean enable.
    def disable_rollout(name)
      @rollout_schedules.disable(name)
    end

    # Public: Clear the manual rollout kill switch.
    def enable_rollout(name)
      @rollout_schedules.enable(name)
    end

    # Public: True when the feature's rollout is manually disabled.
    def rollout_disabled?(name)
      @rollout_schedules.disabled?(name)
    end

    # Public: Preload the features with the given names.
    #
    # names - An Array of String or Symbol names of the features.
    #
    # Returns an Array of Flipper::Feature.
    def preload(names)
      features = names.map { |name| feature(name) }
      @adapter.get_multi(features)
      features
    end

    # Public: Preload all the adapters features.
    #
    # Returns an Array of Flipper::Feature.
    def preload_all
      keys = @adapter.get_all.keys
      keys.map { |key| feature(key) }
    end

    # Public: Shortcut access to a feature instance by name.
    #
    # name - The String or Symbol name of the feature.
    #
    # Returns an instance of Flipper::Feature.
    alias_method :[], :feature

    # Public: Access a flipper group by name.
    #
    # name - The String or Symbol name of the feature.
    #
    # Returns an instance of Flipper::Group.
    def group(name)
      Flipper.group(name)
    end

    # Public: Gets the expression for the feature.
    #
    # name - The String or Symbol name of the feature.
    #
    # Returns an instance of Flipper::Expression.
    def expression(name)
      feature(name).expression
    end

    # Public: Returns a Set of the known features for this adapter.
    #
    # Returns Set of Flipper::Feature instances.
    def features
      adapter.features.map { |name| feature(name) }.to_set
    end

    # Public: Does this adapter support writes or not.
    def read_only?
      adapter.read_only?
    end

    # Cloud DSL method that does nothing for open source version.
    def sync
    end

    # Cloud DSL method that does nothing for open source version.
    def sync_secret
    end
  end
end
