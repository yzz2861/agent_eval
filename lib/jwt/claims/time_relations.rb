# frozen_string_literal: true

module JWT
  module Claims
    # Verifies composable relationships between the temporal claims +iat+,
    # +nbf+ and +exp+. Every configured relation is evaluated against one single
    # injected point in time, and any leeway is applied at most once per
    # relation.
    #
    # Supported relations (all bounds are inclusive):
    #
    # +iat_before_nbf+::  +iat <= nbf + leeway+
    # +nbf_before_exp+::  +nbf <= exp + leeway+
    # +iat_before_exp+::  +iat <= exp + leeway+
    # +max_lifetime+::    +exp - iat <= max + leeway+
    # +max_validity+::    +exp - nbf <= max + leeway+
    # +max_future_iat+:: +iat - now <= leeway+ (the issuer clock drift)
    #
    # A relation only runs when both of its claims are present, unless it is
    # explicitly required with <code>required: true</code>. Claim values must
    # be finite Numeric values; strings and non-finite numbers (+Infinity+,
    # +-Infinity+, +NaN+) fail the relation.
    #
    # @example Ordering only, ignoring missing claims
    #   JWT::Claims::TimeRelations.new(order: true).verify!(context: context)
    #
    # @example Bounded lifetime with an injected clock
    #   JWT::Claims::TimeRelations.new(
    #     max_lifetime: { max: 3600, required: true, leeway: 5 },
    #     max_future_iat: { leeway: 10 },
    #     now: -> { Time.now.to_f }
    #   ).verify!(context: context)
    class TimeRelations
      # The pairs of claims checked by each ordering relation.
      ORDER_CLAIMS = {
        iat_before_nbf: %w[iat nbf],
        nbf_before_exp: %w[nbf exp],
        iat_before_exp: %w[iat exp]
      }.freeze

      # The pairs of claims checked by each span (duration) relation.
      SPAN_CLAIMS = {
        max_lifetime: %w[exp iat],
        max_validity: %w[exp nbf]
      }.freeze

      # The relation enabled for every item of the +order: true+ shortcut.
      ORDER_SHORTCUT_KEYS = ORDER_CLAIMS.keys.freeze

      # The keys that configure individual relations.
      RELATION_KEYS = (ORDER_CLAIMS.keys + SPAN_CLAIMS.keys + [:max_future_iat]).freeze

      # Keys that are settings rather than relations.
      OPTION_KEYS = %i[order leeway now].freeze

      # Marker returned for a claim that is absent from the payload.
      MISSING = Object.new.freeze

      private_constant(:ORDER_CLAIMS, :SPAN_CLAIMS, :ORDER_SHORTCUT_KEYS, :RELATION_KEYS, :OPTION_KEYS, :MISSING)

      # Builds a verifier from the options hash used by the claims Verifier.
      #
      # @param options [Hash, nil] relation configuration.
      # @return [TimeRelations] the verifier.
      def self.from_options(options = nil)
        config = options.is_a?(Hash) ? options.fetch(:time_relations, nil) : nil
        return new(order: true) if config.nil? || config == true || config == {}
        return new if config == false

        new(config)
      end

      # @param config [Hash{Symbol => Object}] relation configuration.
      def initialize(config = {})
        @leeway = assert_finite_numeric(config.fetch(:leeway, 0), 'leeway')
        @clock = config[:now]
        @relations = normalize_relations(config)
      end

      # Verifies all configured relations.
      #
      # @param context [Object] the context containing the JWT payload.
      # @raise [JWT::InvalidTimeRelation] if a relation does not hold.
      # @return [nil]
      def verify!(context:, **)
        return unless context.payload.is_a?(Hash)
        return if @relations.empty?

        now = resolve_now
        @relations.each do |name, relation_config|
          verify_relation!(name, relation_config, context.payload, now)
        end
        nil
      end

      private

      def normalize_relations(config)
        unknown = config.keys.map(&:to_sym) - RELATION_KEYS - OPTION_KEYS
        raise(ArgumentError, "unknown time relation option: #{unknown.first}") unless unknown.empty?

        relations = expand_order(config[:order])
        RELATION_KEYS.each do |name|
          value = config[name]
          next if value.nil?

          relations[name] = build_relation(name, value == true ? {} : value)
        end
        relations
      end

      def expand_order(value)
        return {} if value.nil? || value == false

        order_config = value == true ? {} : value
        unless order_config.is_a?(Hash)
          raise(ArgumentError, 'order must be true, false, or a Hash of options')
        end

        ORDER_SHORTCUT_KEYS.each_with_object({}) do |name, relations|
          relations[name] = build_relation(name, order_config)
        end
      end

      def build_relation(name, value)
        raise(ArgumentError, "#{name} must be configured with true or a Hash") unless value.is_a?(Hash)

        unknown = value.keys.map(&:to_sym) - %i[required leeway max]
        raise(ArgumentError, "unknown #{name} option: #{unknown.first}") unless unknown.empty?

        relation = { required: value.fetch(:required, false) }
        relation[:leeway] = if value.key?(:leeway)
                              assert_finite_numeric(value[:leeway], "#{name} leeway")
                            else
                              @leeway
                            end

        if SPAN_CLAIMS.key?(name)
          raise(ArgumentError, "#{name} requires a :max") unless value.key?(:max)

          relation[:max] = assert_finite_numeric(value[:max], "#{name} max")
        end
        relation
      end

      def assert_finite_numeric(value, label)
        numeric = value.is_a?(::Numeric) && value.finite?
        raise(ArgumentError, "#{label} must be a finite Numeric value") unless numeric

        value
      end

      def resolve_now
        now = @clock.is_a?(::Proc) ? @clock.call : @clock
        now ||= Time.now
        now = now.to_f if now.is_a?(::Time)
        raise(ArgumentError, 'now must resolve to a finite Numeric or Time value') unless now.is_a?(::Numeric) && now.finite?

        now
      end

      def verify_relation!(name, relation_config, payload, now)
        leeway = relation_config[:leeway]
        required = relation_config[:required]

        if ORDER_CLAIMS.key?(name)
          verify_order!(name, ORDER_CLAIMS[name], payload, leeway, required)
        elsif SPAN_CLAIMS.key?(name)
          verify_span!(name, SPAN_CLAIMS[name], payload, relation_config[:max], leeway, required)
        else
          verify_future_iat!(payload, now, leeway, required)
        end
      end

      def verify_order!(name, (earlier_claim, later_claim), payload, leeway, required)
        earlier = extract(payload, earlier_claim, name, required)
        later = extract(payload, later_claim, name, required)
        return if earlier == MISSING || later == MISSING
        return unless finite?(earlier, name, earlier_claim) && finite?(later, name, later_claim)

        fail!(name, "#{earlier_claim} claim must not be later than #{later_claim} claim") if earlier > later + leeway
      end

      def verify_span!(name, (later_claim, earlier_claim), payload, max, leeway, required)
        later = extract(payload, later_claim, name, required)
        earlier = extract(payload, earlier_claim, name, required)
        return if later == MISSING || earlier == MISSING
        return unless finite?(later, name, later_claim) && finite?(earlier, name, earlier_claim)

        fail!(name, "token #{name} of #{(later - earlier).inspect} seconds exceeds the maximum of #{max.inspect} seconds") if later - earlier > max + leeway
      end

      def verify_future_iat!(payload, now, leeway, required)
        iat = extract(payload, 'iat', :max_future_iat, required)
        return if iat == MISSING
        return unless finite?(iat, :max_future_iat, 'iat')

        fail!(:max_future_iat, 'iat claim is too far in the future') if iat > now + leeway
      end

      def extract(payload, claim, name, required)
        value = payload.key?(claim) ? payload[claim] : MISSING
        fail!(name, "missing required #{claim} claim for relation #{name}") if value == MISSING && required
        value
      end

      def finite?(value, name, claim)
        return true if value.is_a?(::Numeric) && value.finite?

        fail!(name, "#{claim} claim must be a finite Numeric value but it is a #{value.class}")
      end

      def fail!(relation, message)
        raise(::JWT::InvalidTimeRelation.new(message, relation: relation))
      end
    end
  end
end
