module Flipper
  class Evaluation
    class GateResult
      attr_reader :name, :status, :result, :reason, :error, :configured
      alias_method :gate, :name

      def initialize(name:, status:, result: nil, reason: nil, error: nil, configured: false)
        @name = name
        @gate = name
        @status = status
        @result = result
        @reason = reason
        @error = error
        @configured = configured
      end

      def executed?
        status == :executed
      end

      def skipped?
        status == :skipped
      end

      def executed
        status == :executed
      end

      def skipped
        status == :skipped
      end

      def error?
        status == :error
      end

      def open?
        result == true
      end

      def to_h
        {
          gate: gate,
          name: name,
          status: status,
          executed: executed,
          skipped: skipped,
          result: result,
          reason: reason,
          error: error,
          configured: configured,
        }
      end
    end

    attr_reader :result, :gate, :config_version, :gates, :actors, :actor, :error

    def initialize(result:, config_version:, gates:, actors:, gate: nil, error: nil)
      @result = result
      @gate = gate
      @config_version = config_version
      @gates = gates
      @actors = actors
      @actor = actors.first
      @error = error
    end

    def enabled?
      result
    end

    def enabled
      result
    end

    def matched_gate
      gate
    end

    alias_method :matched?, :enabled?
    alias_method :hit?, :enabled?

    alias_method :hit_gate, :gate
    alias_method :version, :config_version

    alias_method :configuration_version, :config_version

    def open_gate
      gate
    end

    def branches
      gates
    end

    def actor_present?
      !actors.empty?
    end

    def error?
      !error.nil?
    end

    def status
      return :error if error?
      result ? :matched : :not_matched
    end

    def to_h
      {
        result: result,
        enabled: result,
        status: status,
        gate: gate,
        version: config_version,
        matched_gate: gate,
        open_gate: gate,
        config_version: config_version,
        configuration_version: config_version,
        gates: gates.map(&:to_h),
        branches: gates.map(&:to_h),
        actors: actors,
        actor: actor,
        actor_present: actor_present?,
        error: error,
      }
    end

    def [](key)
      to_h[key]
    end
  end
end
