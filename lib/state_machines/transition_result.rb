# frozen_string_literal: true

module StateMachines
  # Represents the completed result of an event invocation.
  class TransitionResult
    STATUSES = %i[cancelled guard_rejected action_failed succeeded].freeze

    class << self
      def cancelled
        new(:cancelled)
      end

      def guard_rejected
        new(:guard_rejected)
      end

      def action_failed(result = nil, exception: nil)
        new(:action_failed, result: result, exception: exception)
      end

      def succeeded(result = true)
        new(:succeeded, result: result)
      end

      def from_perform(transition, result)
        reason = transition.last_failure_reason

        if reason
          public_send(reason, result)
        elsif result == false
          action_failed(result)
        else
          succeeded(result)
        end
      end
    end

    attr_reader :status, :result, :exception

    def initialize(status, result: nil, exception: nil)
      raise ArgumentError, "Unknown transition status: #{status.inspect}" unless STATUSES.include?(status)

      @status = status
      @result = result
      @exception = exception
    end

    def cancelled?
      status == :cancelled
    end

    def guard_rejected?
      status == :guard_rejected
    end

    def action_failed?
      status == :action_failed
    end

    def succeeded?
      status == :succeeded
    end

    def success?
      succeeded?
    end

    def value
      success? ? result : false
    end

    def ==(other)
      case other
      when Symbol then status == other
      when self.class then status == other.status && result == other.result && exception == other.exception
      else result == other
      end
    end
    alias eql? ==

    def hash
      [self.class, status, result, exception].hash
    end

    def inspect
      "#<#{self.class} status=#{status.inspect} result=#{result.inspect} exception=#{exception.inspect}>"
    end
  end
end
