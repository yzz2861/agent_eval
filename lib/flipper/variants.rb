require 'zlib'

module Flipper
  # Public: Independent variant (multi-arm) evaluation. Unlike Feature#enabled?,
  # which keeps its boolean gate semantics, this module deterministically
  # assigns an actor to one of several named variants (e.g. control, A, B)
  # based on a stable hash of the actor id, the feature name, and an explicit
  # salt, then distributes actors across variants according to configured
  # weights.
  module Variants
    # Private: Supports up to 3 decimal places in weights, matching the
    # percentage of actors gate.
    SCALING_FACTOR = 1_000

    # Private: Total number of buckets actors are hashed into.
    BUCKET_COUNT = 100 * SCALING_FACTOR

    # Public: A single named arm of an experiment and its weight (0-100).
    class Variant
      attr_reader :name, :weight

      def initialize(name, weight)
        name = name.to_s
        if name.empty?
          raise ArgumentError, "variant name must not be empty"
        end

        weight = Typecast.to_number(weight)
        if weight < 0 || weight > 100
          raise ArgumentError,
                "weight must be a number between 0 and 100, but was #{weight}"
        end

        @name = name
        @weight = weight
      end

      def ==(other)
        other.is_a?(Variant) && name == other.name && weight == other.weight
      end
      alias eql? ==
    end

    # Public: The variant setup for one feature: which variants exist, the
    # salt that scopes hashing, and a version used to track which config
    # produced a given assignment.
    class Configuration
      attr_reader :variants, :salt, :version

      def initialize(variants:, salt:, version:)
        @salt = salt.to_s
        if @salt.empty?
          raise ArgumentError, "salt must not be empty"
        end

        if version.nil? || version.to_s.empty?
          raise ArgumentError, "version must be present"
        end
        @version = version.to_s

        if variants.nil? || variants.empty?
          raise ArgumentError, "variants must not be empty"
        end
        @variants = variants.map do |variant|
          variant.is_a?(Variant) ? variant : Variant.new(variant[0], variant[1])
        end

        names = @variants.map(&:name)
        counts = Hash.new(0)
        names.each { |name| counts[name] += 1 }
        duplicates = counts.select { |_, count| count > 1 }.keys
        unless duplicates.empty?
          raise ArgumentError, "duplicate variant names: #{duplicates.join(', ')}"
        end

        total = @variants.sum(&:weight)
        if total > 100
          raise ArgumentError,
                "variant weights must sum to at most 100, but sum to #{total}"
        end
      end

      # Internal: Variants in canonical (name-sorted) order. Intervals are
      # derived from this order so that reordering the configuration array
      # never changes which actor maps to which variant.
      def canonical_variants
        @canonical ||= @variants.sort_by(&:name)
      end

      # Internal: The share of buckets (0-100) not covered by any variant.
      # Actors landing in this gap are assigned no variant.
      def gap
        100 - @variants.sum(&:weight)
      end
    end

    # Public: The outcome of evaluating one actor against one configuration.
    class Result
      attr_reader :feature_name, :actor_id, :version, :bucket

      def initialize(feature_name:, actor_id:, variant:, version:, bucket:)
        @feature_name = feature_name
        @actor_id = actor_id
        @variant = variant
        @version = version
        @bucket = bucket
      end

      # Public: The assigned variant name, or nil when the actor falls in the
      # unallocated gap between the total weight and 100.
      def variant
        @variant&.name
      end

      # Public: True when the actor was assigned to any variant.
      def assigned?
        !@variant.nil?
      end

      # Public: True when the actor was assigned to the given variant name.
      def variant?(name)
        variant == name.to_s
      end
    end

    # Public: Assign an actor to a variant for a feature.
    #
    # feature_name - The Symbol or String name of the feature/experiment.
    # actor_id     - The String or Symbol id of the actor. Anything responding
    #                to +to_s+ works; the same id always hashes to the same
    #                bucket for a given feature and salt.
    # configuration - A Variants::Configuration describing variants, salt and
    #                 version.
    #
    # Returns a Variants::Result.
    def self.evaluate(feature_name, actor_id, configuration)
      bucket = bucket_for(configuration.salt, feature_name, actor_id)

      offset = 0
      assigned = nil
      configuration.canonical_variants.each do |variant|
        width = (variant.weight * SCALING_FACTOR).to_i
        if bucket >= offset && bucket < offset + width
          assigned = variant
          break
        end
        offset += width
      end

      Result.new(
        feature_name: feature_name.to_s,
        actor_id: actor_id.to_s,
        variant: assigned,
        version: configuration.version,
        bucket: bucket,
      )
    end

    # Internal: Stable bucket (0...BUCKET_COUNT) for a salt/feature/actor
    # triple. Uses crc32 like the percentage of actors gate; see that gate
    # for why the tiny modulo bias is intentionally kept.
    def self.bucket_for(salt, feature_name, actor_id)
      Zlib.crc32("#{salt}:#{feature_name}:#{actor_id}") % BUCKET_COUNT
    end
  end
end
