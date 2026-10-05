require 'zlib'

module Flipper
  module Variants
    # Public: The total number of stable buckets that variant weights are
    # spread across. Weights are integer percentages, so they must sum to
    # exactly this value.
    BUCKET_COUNT = 100

    # Public: A configured variant experiment.
    #
    # A configuration assigns integer weights (percentages) to named
    # variants. Actors are deterministically placed into one of
    # BUCKET_COUNT buckets based on the feature name, an explicit salt, and
    # the actor's flipper_id; the bucket is then mapped to a variant by
    # cumulative weight.
    #
    # The order variants are passed in never affects assignment: variants
    # are always ordered by their normalized (String) names before weight
    # intervals are laid out. Reordering a config hash therefore keeps
    # every actor in the same variant, while changing a weight only moves
    # the boundaries at and after the changed variant.
    class Configuration
      # Public: The Hash of variant name (String) => Integer weight.
      attr_reader :weights

      # Public: The String salt that separates this bucketing from other
      # uses of the same feature name.
      attr_reader :salt

      # Public: The Integer or String version stamped onto every result for
      # traceability.
      attr_reader :version

      def initialize(weights, salt:, version: 1)
        normalized = normalize_weights(weights)
        salt = validate_salt(salt)
        version = validate_version(version)

        @weights = normalized.freeze
        @salt = salt
        @version = version
        @ordered = @weights.sort_by(&:first).map { |name, weight| [name, weight].freeze }.freeze
      end

      # Public: The variants in the canonical (name-sorted) order used for
      # weight interval layout.
      #
      # Returns an Array of [name, weight] pairs.
      def ordered
        @ordered
      end

      # Public: The variant names in canonical order.
      def names
        @ordered.map(&:first)
      end

      # Public: Evaluate the variant for a single actor.
      #
      # feature_name - The String or Symbol name of the feature.
      # actor_id     - The String flipper_id of the actor.
      #
      # Returns a Flipper::Variants::Result.
      def evaluate(feature_name, actor_id)
        bucket = bucket_for(feature_name, actor_id)
        variant = variant_for_bucket(bucket)
        Result.new(
          feature: feature_name.to_s,
          variant: variant,
          salt: salt,
          version: version,
          bucket: bucket,
          configuration: self,
        )
      end

      # Public: Compute the stable bucket for an actor. Exposed so callers
      # and tests can reason about weight intervals.
      def bucket_for(feature_name, actor_id)
        id = "#{feature_name}#{FIELD_SEPARATOR}#{salt}#{FIELD_SEPARATOR}#{actor_id}"
        Zlib.crc32(id) % BUCKET_COUNT
      end

      private

      FIELD_SEPARATOR = "\u001f".freeze
      private_constant :FIELD_SEPARATOR

      def variant_for_bucket(bucket)
        threshold = 0
        @ordered.each do |name, weight|
          threshold += weight
          return name if bucket < threshold
        end
        raise InvalidVariantConfiguration,
              "variant weights do not cover bucket #{bucket}"
      end

      def normalize_weights(weights)
        unless weights.is_a?(Hash)
          raise InvalidVariantConfiguration,
                "variant weights must be a Hash of variant name => weight, but was #{weights.inspect}"
        end

        if weights.empty?
          raise InvalidVariantConfiguration, "variant weights cannot be empty"
        end

        normalized = {}
        weights.each do |name, weight|
          name = normalize_name(name)
          weight = normalize_weight(name, weight)

          if normalized.key?(name)
            raise InvalidVariantConfiguration,
                  "variant #{name.inspect} is declared more than once"
          end

          normalized[name] = weight
        end

        total = normalized.values.sum
        unless total == BUCKET_COUNT
          raise InvalidVariantConfiguration,
                "variant weights must sum to #{BUCKET_COUNT} (percent), but summed to #{total}"
        end

        if normalized.values.all?(&:zero?)
          raise InvalidVariantConfiguration,
                "at least one variant must have a weight greater than 0"
        end

        normalized
      end

      def normalize_name(name)
        if !name.is_a?(String) && !name.is_a?(Symbol)
          raise InvalidVariantConfiguration,
                "variant names must be Strings or Symbols, but #{name.inspect} is a #{name.class}"
        end

        normalized = name.to_s
        if normalized.strip.empty?
          raise InvalidVariantConfiguration, "variant names cannot be blank"
        end

        normalized
      end

      def normalize_weight(name, weight)
        unless weight.is_a?(Integer)
          raise InvalidVariantConfiguration,
                "weight for variant #{name.inspect} must be an Integer, but was #{weight.inspect}"
        end

        if weight < 0
          raise InvalidVariantConfiguration,
                "weight for variant #{name.inspect} must be greater than or equal to 0, but was #{weight}"
        end

        weight
      end

      def validate_salt(salt)
        if !salt.is_a?(String) && !salt.is_a?(Symbol)
          raise InvalidVariantConfiguration,
                "salt must be a String or Symbol, but was #{salt.inspect}"
        end

        salt = salt.to_s
        if salt.strip.empty?
          raise InvalidVariantConfiguration, "salt cannot be blank"
        end

        salt
      end

      def validate_version(version)
        unless version.is_a?(Integer) || version.is_a?(String)
          raise InvalidVariantConfiguration,
                "version must be an Integer or a String, but was #{version.inspect}"
        end

        if version.is_a?(String) && version.strip.empty?
          raise InvalidVariantConfiguration, "version cannot be blank"
        end

        version
      end
    end
  end
end
