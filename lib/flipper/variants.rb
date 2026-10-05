require 'flipper/errors'
require 'flipper/types/actor'
require 'flipper/variants/configuration'
require 'flipper/variants/result'

module Flipper
  # Variants provides stable, weight-based multi-variant assignment that is
  # independent of the boolean enabled? gates.
  module Variants
    extend self

    # Public: Resolve an actor to its String id used for bucketing.
    #
    # actor - A Flipper::Actor, a Flipper::Types::Actor, a String/Symbol
    #         actor id, or any object that responds to flipper_id.
    #
    # Returns the String actor id.
    # Raises ArgumentError if the actor has no usable id or the id is blank.
    def actor_id(actor)
      id = case actor
           when Flipper::Actor then actor.flipper_id
           when Types::Actor then actor.value
           when String, Symbol then actor
           else
             if actor.respond_to?(:flipper_id)
               actor.flipper_id
             else
               raise ArgumentError,
                     "actor must respond to flipper_id or be a String/Symbol, but #{actor.inspect} does not"
             end
           end

      id = id.to_s
      if id.strip.empty?
        raise ArgumentError, "actor id cannot be blank"
      end

      id
    end

    # Public: Evaluate a variant for an actor without registering anything
    # on a Flipper DSL instance.
    #
    # feature_name - The String or Symbol name of the feature.
    # actor        - The actor to bucket (see Variants.actor_id).
    # weights      - The Hash of variant name => Integer weight.
    # salt         - The explicit String or Symbol salt (required).
    # version      - The configuration version stamped on the result
    #                (default: 1).
    #
    # Returns a Flipper::Variants::Result.
    def evaluate(feature_name, actor, weights, salt:, version: 1)
      configuration = Configuration.new(weights, salt: salt, version: version)
      evaluate_with(configuration, feature_name, actor)
    end

    # Internal: Evaluate using an existing Configuration.
    def evaluate_with(configuration, feature_name, actor)
      raise ArgumentError, "actor cannot be nil" if actor.nil?

      id = actor_id(actor)
      result = configuration.evaluate(feature_name, id)
      result.actor_id = id
      result
    end
  end
end
