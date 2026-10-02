# frozen_string_literal: true

require 'digest'

module Rack
  class Attack
    # Raised exclusively for failures of the configured cache store while
    # Rack::Attack is performing a storage call. Errors raised by user
    # supplied rule blocks are never translated into this error.
    class StoreError < Error
      def initialize(message = nil)
        super(message || 'Rack::Attack cache store failed')
      end
    end

    # Storage failure handling shared by all rule types. Each rule declares
    # its policy with the :storage_failure option:
    #
    #   * :allow - fail open, let the request proceed (default)
    #   * :deny  - fail closed, answer with the storage failure responder
    module StoreFailure
      POLICIES = %i[allow deny].freeze

      # Stable verdict returned by a rule whose store call failed with a
      # :deny policy. It is distinct from a regular rule match so that the
      # "backend unavailable" outcome never gets confused with an actual
      # "quota exhausted"/blocklisted match.
      DENY = :rack_attack_storage_failure_deny

      FAILURE_KEY = 'rack.attack.storage_failure'.freeze
      FAILURES_KEY = 'rack.attack.storage_failures'.freeze

      FINGERPRINT_LENGTH = 12

      class << self
        def policy_from(options)
          policy = options.fetch(:storage_failure, Rack::Attack.storage_failure_policy)
          unless POLICIES.include?(policy)
            raise ArgumentError, "Invalid storage failure policy #{policy.inspect}. " \
              "Valid policies are: #{POLICIES.map(&:inspect).join(', ')}"
          end

          policy
        end

        # Records the failure on the request env and instruments it.
        # Returns the verdict the rule must surface: DENY for :deny
        # policies, false for :allow policies.
        def handle(request, rule, error, discriminator = nil)
          record = record!(request, rule, error, discriminator)
          Rack::Attack.instrument_storage_failure(request, record)

          record[:policy] == :deny ? DENY : false
        end

        def denied?(verdict)
          verdict == DENY
        end

        def record!(request, rule, error, discriminator = nil)
          record = {
            rule: rule.name,
            type: rule.type,
            policy: rule.storage_failure_policy,
            error: error.class.name,
            discriminator_fingerprint: fingerprint_for(rule.name, discriminator)
          }

          (request.env[FAILURES_KEY] ||= []) << record
          request.env[FAILURE_KEY] = record if record[:policy] == :deny && request.env[FAILURE_KEY].nil?

          record
        end

        # The full discriminator must never reach notifications or responders.
        # Expose a short, non-reversible fingerprint instead so distinct
        # clients can still be correlated by an operator.
        def fingerprint_for(rule_name, discriminator)
          return unless discriminator

          Digest::SHA256.hexdigest("rack::attack:#{rule_name}:#{discriminator}")[0, FINGERPRINT_LENGTH]
        end
      end
    end
  end
end
