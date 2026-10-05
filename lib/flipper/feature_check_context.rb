require 'flipper/feature_evaluation'

module Flipper
  class FeatureCheckContext
    # Public: The name of the feature.
    attr_reader :feature_name

    # Public: The GateValues instance that keeps track of the values for the
    # gates for the feature.
    attr_reader :values

    # Public: The actors we want to know if a feature is enabled for.
    attr_reader :actors

    # Internal: All actors from the original enabled? call.
    attr_reader :original_actors

    # Internal: State shared while evaluating dependent features.
    attr_reader :evaluation

    # Internal: Returns the Feature for a dependent feature name.
    attr_reader :feature_provider

    def initialize(feature_name:, values:, actors:, original_actors: nil, evaluation: nil, feature_provider: nil)
      @feature_name = feature_name
      @values = values
      @actors = actors
      @original_actors = original_actors || actors
      @evaluation = evaluation || FeatureEvaluation.new(actors: actors)
      @feature_provider = feature_provider || ->(name) { Flipper.feature(name) }
    end

    def actors?
      !@actors.nil? && !@actors.empty?
    end

    def feature(name)
      raise ArgumentError, 'feature provider is not configured' unless @feature_provider
      @feature_provider.call(name)
    end

    # Public: Convenience method for groups value like Feature has.
    def groups_value
      values.groups
    end

    # Public: Convenience method for actors value value like Feature has.
    def actors_value
      values.actors
    end

    # Public: Convenience method for boolean value value like Feature has.
    def boolean_value
      values.boolean
    end

    # Public: Convenience method for percentage of actors value like Feature has.
    def percentage_of_actors_value
      values.percentage_of_actors
    end

    # Public: Convenience method for percentage of time value like Feature has.
    def percentage_of_time_value
      values.percentage_of_time
    end
  end
end
