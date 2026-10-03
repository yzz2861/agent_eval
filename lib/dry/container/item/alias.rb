# frozen_string_literal: true

module Dry
  class Container
    class Item
      # Reference to another registered item
      #
      # @api public
      class Alias
        # @return [String] the aliased registration key
        attr_reader :target

        # @return [Array<#call>] decorators applied to the alias itself
        attr_reader :decorators

        # @param [Mixed] target
        # @param [Hash] _options
        #
        # @return [Dry::Container::Item::Alias]
        def initialize(target, _options = {})
          @target = target.to_s
          @decorators = []
        end

        # Build a decorated copy of the alias
        #
        # @param [#call] decorator
        #
        # @return [Dry::Container::Item::Alias]
        #
        # @api private
        def map(decorator)
          copy = self.class.new(target)
          copy.decorators.concat(decorators)
          copy.decorators << decorator
          copy
        end

        # Build a copy with its target moved under a namespace
        #
        # @param [Mixed] namespace
        # @param [Dry::Container::Config] config
        #
        # @return [Dry::Container::Item::Alias]
        #
        # @api private
        def prefixed(namespace, config)
          copy = self.class.new([namespace, target].join(config.namespace_separator))
          copy.decorators.concat(decorators)
          copy
        end
      end
    end
  end
end
