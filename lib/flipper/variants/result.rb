module Flipper
  module Variants
    # Public: The result of evaluating an actor against a variant
    # Configuration.
    class Result
      # Public: The String name of the feature that was evaluated.
      attr_reader :feature

      # Public: The String name of the variant the actor was assigned to.
      attr_reader :variant
      alias_method :name, :variant

      # Public: The String salt used for bucketing.
      attr_reader :salt

      # Public: The Integer or String version of the configuration.
      attr_reader :version

      # Public: The Integer bucket (0...BUCKET_COUNT) the actor hashed to.
      attr_reader :bucket

      # Public: The Flipper::Variants::Configuration that produced this
      # result.
      attr_reader :configuration

      def initialize(feature:, variant:, salt:, version:, bucket:, configuration:)
        @feature = feature
        @variant = variant
        @salt = salt
        @version = version
        @bucket = bucket
        @configuration = configuration
      end

      # Public: Check if the result is the given variant. Accepts a String
      # or Symbol.
      def variant?(name)
        variant == name.to_s
      end

      # Public: The String flipper_id of the actor that was evaluated, if
      # it was resolved during evaluation.
      attr_accessor :actor_id

      def to_h
        {
          feature: feature,
          variant: variant,
          salt: salt,
          version: version,
          bucket: bucket,
        }
      end

      def inspect
        "#<#{self.class.name} feature=#{feature.inspect} variant=#{variant.inspect} " \
          "bucket=#{bucket} salt=#{salt.inspect} version=#{version.inspect}>"
      end
    end
  end
end
