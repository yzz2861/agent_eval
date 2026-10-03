# frozen_string_literal: true

module Dry
  class Container
    # Base class to abstract Memoizable and Callable implementations
    #
    # @api abstract
    #
    class Item
      # Whether the given object is a factory that can receive the
      # currently resolving container as its single argument
      #
      # @private
      def self.containerizable?(item)
        item.is_a?(::Proc) &&
          item.parameters.map(&:first).count { |type|
            %i[req opt].include?(type)
          } == 1
      end

      # @return [Mixed] the item to be solved later
      attr_reader :item

      # @return [Hash] the options to memoize, call or no.
      attr_reader :options

      # @api abstract
      def initialize(item, options = {})
        @item = item
        @options = {
          call: item.is_a?(::Proc) && item.parameters.empty?
        }.merge(options)
      end

      # @api abstract
      def call
        raise NotImplementedError
      end

      # @private
      def value?
        !callable?
      end

      # @private
      def callable?
        options[:call]
      end

      # Build a new item with transformation applied
      #
      # @private
      def map(func)
        if callable?
          self.class.new(-> { func.(item.call) }, options)
        else
          self.class.new(func.(item), options)
        end
      end

      # Build a copy with fresh memoized state for a forked container
      #
      # @private
      def fork
        self
      end

      private

      # Invoke a factory, passing the resolving container when the factory
      # declares a single positional parameter
      #
      # @private
      def invoke(factory, container = nil)
        if Item.containerizable?(factory)
          factory.call(container)
        elsif factory.respond_to?(:call)
          factory.call
        else
          factory
        end
      end

      # A callable item wrapped by one or more decorators
      #
      # @private
      class DecoratedCall < Item
        attr_reader :decorator

        def initialize(item, decorator, options = {})
          super(item, options)
          @decorator = decorator
        end

        def call(container = nil)
          result = item.is_a?(::Proc) ? invoke(item, container) : item.call(container)
          decorator.call(result)
        end

        # Stack another decorator on top of the existing chain
        #
        # @private
        def map(func)
          self.class.new(self, func, options.merge(call: true))
        end

        def fork
          inner_item = item.is_a?(Item) ? item.fork : item
          self.class.new(inner_item, decorator, options.merge(call: true))
        end
      end
    end
  end
end
