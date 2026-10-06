# frozen_string_literal: true

module Dry
  module Configurable
    # A named configuration profile.
    #
    # A profile captures a configuration block along with the names of the
    # profiles it inherits from. Profiles are resolved through C3
    # linearization (see {Profiles#linearize}) and applied to a fresh config
    # when selected via {ClassMethods#config_for}.
    #
    # @api public
    class Profile
      include Dry::Equalizer(:name, :parents, inspect: false)

      # @api public
      attr_reader :name

      # Names of the profiles this profile inherits from, in the order they
      # were declared. Earlier parents take precedence over later ones.
      #
      # @return [Array<Symbol>]
      #
      # @api public
      attr_reader :parents

      # @api private
      attr_reader :block
      protected :block

      # @api private
      def initialize(name, parents: EMPTY_ARRAY, block:)
        @name = name.to_sym
        @parents = parents.map(&:to_sym).freeze
        @block = block
      end

      # @api private
      def apply(config)
        block.call(config)
      end
    end
  end
end
