# frozen_string_literal: true

module Dry
  module Configurable
    # A named configuration profile.
    #
    # A profile holds the overrides declared in its `profile` block plus the
    # list of base profiles it inherits from. The tree itself is structurally
    # frozen: leaf values keep the objects given by the caller.
    #
    # @api public
    class Profile
      # @return [Symbol] the profile name
      #
      # @api public
      attr_reader :name

      # @return [Array<Symbol>] the names of the directly inherited base profiles, in
      #   declaration order
      #
      # @api public
      attr_reader :parents

      # @return [Hash] the override tree collected from the profile block
      #
      # @api public
      attr_reader :tree

      # @api private
      def initialize(name, parents, tree)
        @name = name
        @parents = parents
        @tree = tree
        freeze_structure(tree)
      end

      # @api private
      def to_s
        "#<#{self.class.name || self.class} #{name.inspect}>"
      end

      # @api private
      alias_method :inspect, :to_s

      private

      # Freeze only the container hashes collected by the DSL, so profiles are
      # immutable definitions without unexpectedly freezing caller-provided values.
      def freeze_structure(hash)
        hash.each_value do |value|
          freeze_structure(value) if value.is_a?(::Hash)
        end
        hash.freeze
      end
    end
  end
end
