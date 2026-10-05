module Flipper
  class FeatureEvaluation
    attr_reader :actors
    attr_reader :original_actors

    def self.for_actors(actors, results: {}, path: [])
      return [new(actors: nil, actor_index: nil, results: results, path: path)] if actors.nil? || actors.empty?
      actors.each_with_index.map do |actor, index|
        new(actors: [actor], actor_index: index, original_actors: actors, results: results, path: path)
      end
    end

    def initialize(actors:, actor_index: 0, original_actors: nil, results: nil, path: nil)
      @actors = actors
      @actor_index = actor_index
      @original_actors = original_actors || actors
      @results = results || {}
      @path = path || []
    end

    def for_actor(actor, index)
      self.class.new(
        actors: [actor],
        actor_index: index,
        original_actors: @original_actors,
        results: @results,
        path: @path,
      )
    end

    def enabled?(feature)
      cached(:feature, feature.key) { evaluate(feature) }
    end

    def evaluate_root(feature, payload = nil)
      key = feature.key.to_s
      path_key = [:feature, key, @actor_index]
      @path.push(path_key)
      begin
        @results[path_key] = evaluate(feature, payload)
      ensure
        @path.pop
      end

      @results.fetch(path_key)
    end

    private

    def cached(type, key)
      cache_key = [type, key.to_s, @actor_index]
      return @results.fetch(cache_key) if @results.key?(cache_key)

      cycle_start = @path.index(cache_key)
      if cycle_start
        chain = @path[cycle_start..].filter_map { |path_type, path_key, _| path_key if path_type == :feature } + [key.to_s]
        raise CircularDependency, chain
      end

      @path.push(cache_key)
      begin
        @results[cache_key] = yield
      ensure
        @path.pop
      end

      @results.fetch(cache_key)
    end

    def evaluate(feature, payload = nil)
      values = feature.gate_values
      values = Flipper::GateValues.new({}) if values.nil?
      feature.enabled_in_evaluation?(self, payload, values)
    end
  end
end
