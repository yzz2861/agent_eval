require 'securerandom'

module Flipper
  module Exposure
    # Public: A confirmable evaluation result, also known as an exposure
    # credential. It binds the feature, actor identity, decision and config
    # version captured at evaluation time, so confirming never re-evaluates
    # and attribution cannot drift.
    class Decision
      # Public: Unique id of this credential.
      attr_reader :credential_id

      # Public: The name of the feature that was evaluated.
      attr_reader :feature_name

      # Public: The flipper_id of the actor the decision was made for, or nil.
      attr_reader :actor_id

      # Public: Digest of the gate values captured at evaluation time.
      attr_reader :config_version

      def initialize(feature_name:, actor_id:, enabled:, config_version:,
                     collector:, credential_id: nil)
        @feature_name = feature_name
        @actor_id = actor_id
        @enabled = enabled
        @config_version = config_version
        @collector = collector
        @credential_id = credential_id || SecureRandom.uuid
        @confirmed = false
      end

      # Public: The decision made at evaluation time. Safe to call regardless
      # of collector state.
      def enabled?
        @enabled
      end

      # Public: Whether this decision was successfully confirmed.
      def confirmed?
        @confirmed
      end

      # Public: Confirm the decision was actually used and submit an exposure
      # event to the collector. Never re-evaluates the feature.
      #
      # idempotency_key - Optional caller supplied key. Collectors dedupe on
      #                   it so repeated confirms do not double count.
      #
      # Returns true if the event was recorded, false if it was a duplicate
      # or the collector failed. Collector failures never raise and never
      # affect the decision itself.
      def confirm(idempotency_key: nil)
        event = Event.new(
          credential_id: @credential_id,
          feature_name: @feature_name,
          actor_id: @actor_id,
          enabled: @enabled,
          config_version: @config_version,
          idempotency_key: idempotency_key
        )

        recorded = @collector.record(event)
        @confirmed = true
        recorded
      rescue StandardError
        false
      end
    end
  end
end
