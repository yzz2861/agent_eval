require 'digest'

module Flipper
  # Public: The result of Feature#evaluate_with_explanation.
  #
  # Captures the evidence gathered while evaluating a feature exactly once,
  # so "why can this actor see this feature?" can be answered without
  # re-running the evaluation. Re-running would be wrong: percentage of
  # time can flip between calls and custom group blocks would be invoked
  # more times than a real check invokes them.
  class EvaluationExplanation
    # Public: Describes what happened at a single gate during evaluation.
    class GateEvaluation
      # The gate was evaluated.
      EXECUTED = :executed

      # The gate was not evaluated. See #reason for why.
      SKIPPED = :skipped

      # The gate raised while evaluating. See #error for details. The
      # gate is treated as closed and evaluation continues, so the
      # explanation can still describe the remaining gates.
      ERROR = :error

      # Public: The name of the gate (e.g. :boolean, :actor, :group).
      attr_reader :name

      # Public: One of EXECUTED, SKIPPED or ERROR.
      attr_reader :status

      # Public: Why the gate was skipped. :short_circuit when an earlier
      # gate already opened, :no_actor when the gate needs an actor but
      # none was given. nil for executed or errored gates.
      attr_reader :reason

      # Public: For errored gates, a Hash with :class and :message of the
      # raised exception. nil otherwise.
      attr_reader :error

      def initialize(name:, status:, open: nil, reason: nil, error: nil)
        @name = name
        @status = status
        @open = open
        @reason = reason
        @error = error
      end

      def executed?
        @status == EXECUTED
      end

      def skipped?
        @status == SKIPPED
      end

      def error?
        @status == ERROR
      end

      # Public: Whether the gate was evaluated and found open. Always
      # false for skipped and errored gates.
      def open?
        !!@open
      end

      def to_h
        hash = { name: name, status: status }
        hash[:open] = @open unless @open.nil?
        hash[:reason] = reason if reason
        hash[:error] = error if error
        hash
      end
    end

    # Public: The name of the feature that was evaluated.
    attr_reader :feature_name

    # Public: A fingerprint of the exact gate values (configuration) used
    # for this evaluation. Changes whenever any gate value changes, so an
    # explanation can be correlated with the configuration that produced
    # it.
    attr_reader :config_version

    # Public: Diagnostic summaries of the actors the feature was evaluated
    # for. Each entry always includes :flipper_id and only the properties
    # explicitly allowed via Flipper::Configuration#explanation_actor_properties
    # or the actor_properties option. Actors are never inspect-ed whole.
    attr_reader :actors

    # Public: One GateEvaluation per gate, in evaluation order.
    attr_reader :gates

    def initialize(feature_name:, config_version:, actors:)
      @feature_name = feature_name
      @config_version = config_version
      @actors = actors
      @gates = []
    end

    # Internal: Append evidence for a gate. Called by Feature during
    # evaluation.
    def record(gate_evaluation)
      @gates << gate_evaluation
    end

    # Public: The GateEvaluation that opened, if any.
    def matched_gate
      @gates.detect(&:open?)
    end

    # Public: The name of the gate that opened (e.g. :actor), nil if the
    # feature is disabled for the given actors.
    def gate_name
      matched_gate && matched_gate.name
    end

    # Public: The boolean outcome of the evaluation. Same answer enabled?
    # would have returned for these actors at this moment.
    def result
      !matched_gate.nil?
    end
    alias_method :enabled?, :result

    def to_h
      {
        feature: feature_name,
        result: result,
        gate: gate_name,
        config_version: config_version,
        actors: actors,
        gates: gates.map(&:to_h),
      }
    end

    def inspect
      attributes = [
        "feature=#{feature_name.inspect}",
        "result=#{result.inspect}",
        "gate=#{gate_name.inspect}",
        "config_version=#{config_version.inspect}",
      ]
      "#<#{self.class.name}:#{object_id} #{attributes.join(', ')}>"
    end

    # Internal: Fingerprint the gate values used for an evaluation.
    #
    # Returns a short hex String.
    def self.config_version(gate_values)
      parts = [
        "boolean=#{gate_values.boolean.inspect}",
        "actors=#{gate_values.actors.sort.inspect}",
        "groups=#{gate_values.groups.sort.inspect}",
        "expression=#{gate_values.expression.inspect}",
        "percentage_of_actors=#{gate_values.percentage_of_actors.inspect}",
        "percentage_of_time=#{gate_values.percentage_of_time.inspect}",
      ]
      Digest::SHA256.hexdigest(parts.join("|"))[0, 12]
    end
  end
end
