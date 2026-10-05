module Flipper
  module Exposure
    # Public: Immutable record of a confirmed exposure. Created by
    # Decision#confirm and handed to the configured collector.
    class Event
      # Public: Unique credential id minted at evaluation time.
      attr_reader :credential_id

      # Public: The name of the feature that was evaluated.
      attr_reader :feature_name

      # Public: The flipper_id of the actor the decision was made for, or nil.
      attr_reader :actor_id

      # Public: The decision that was confirmed (true if enabled).
      attr_reader :enabled

      # Public: Digest of the gate values captured at evaluation time.
      attr_reader :config_version

      # Public: Caller supplied idempotency key, or nil.
      attr_reader :idempotency_key

      def initialize(credential_id:, feature_name:, actor_id:, enabled:,
                     config_version:, idempotency_key: nil)
        @credential_id = credential_id
        @feature_name = feature_name
        @actor_id = actor_id
        @enabled = enabled
        @config_version = config_version
        @idempotency_key = idempotency_key
      end

      def to_h
        {
          credential_id: credential_id,
          feature_name: feature_name,
          actor_id: actor_id,
          enabled: enabled,
          config_version: config_version,
          idempotency_key: idempotency_key,
        }
      end
    end
  end
end
