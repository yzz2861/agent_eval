require 'flipper/errors'

module Flipper
  # Internal: Evaluates the prerequisites of features for a single enabled?
  # check.
  #
  # A new evaluator is created for every top-level Feature#enabled? call and
  # is shared by all nested prerequisite checks, so:
  #
  # * every dependency is evaluated with the same actors/context as the
  #   original check,
  # * a dependency shared by several features in the same check is only
  #   evaluated once (memoized per evaluation),
  # * results are never reused across checks, so nothing is cached into
  #   another request,
  # * direct and indirect prerequisite cycles are detected and raised as
  #   Flipper::CircularPrerequisite with the chain of features involved.
  class PrerequisiteEvaluator
    def initialize(feature_lookup)
      @feature_lookup = feature_lookup
      # Memoized enabled? result for each dependency, keyed by feature name.
      # A nil value means the dependency does not exist in the adapter.
      @enabled_results = {}
      # Names of the features currently being resolved, used to detect
      # cycles. Ordered so a raised chain reads like a path.
      @resolving = []
    end

    # Internal: Are all prerequisites of the feature satisfied for the
    # actors?
    #
    # feature - The Flipper::Feature whose prerequisites should be checked.
    # actors - The wrapped actors from the original enabled? call.
    #
    # Returns true if all prerequisites are satisfied, false otherwise.
    # Raises Flipper::CircularPrerequisite if resolving the prerequisites
    # leads back to a feature already being resolved.
    def satisfied?(feature, actors)
      name = feature.name.to_sym

      if @resolving.include?(name)
        raise CircularPrerequisite, (@resolving + [name])
      end

      @resolving.push(name)
      begin
        feature.prerequisites.all? do |prerequisite|
          prerequisite_met?(prerequisite, actors)
        end
      ensure
        @resolving.pop
      end
    end

    private

    def prerequisite_met?(prerequisite, actors)
      enabled = dependency_enabled?(prerequisite.feature_name, actors)

      # A dependency missing from the adapter never satisfies a
      # prerequisite, even one that requires the feature to be off.
      return false if enabled.nil?

      prerequisite.on? ? enabled : !enabled
    end

    def dependency_enabled?(name, actors)
      name = name.to_sym
      return @enabled_results[name] if @enabled_results.key?(name)

      dependency = @feature_lookup.call(name)

      @enabled_results[name] =
        if dependency.exist?
          dependency.enabled?(*actors, prerequisite_evaluator: self)
        else
          nil
        end
    end
  end
end
