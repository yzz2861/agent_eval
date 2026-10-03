# frozen_string_literal: true

# rubocop:disable Naming/ConstantName
# rubocop:disable Style/MutableConstant

module Dry
  module Monads
    to_list = List::Validated.method(:pure)

    id = -> x { x }

    # List of default traverse functions for types.
    # It is implicitly used by List#traverse for
    # making common cases easier to handle.
    #
    # Handlers receive the element and its index in the list. A handler
    # provided by the user may still take just the element, only lambdas
    # with a single required parameter are called without the index.
    #
    # The Validated handler keeps the old behavior for plain errors: they
    # are wrapped with a list. When the error is an {ErrorTree}, the tree
    # is prefixed with the element's index so the resulting tree keeps
    # track of which list element every error came from.
    Traverse = {
      Validated => lambda { |el, index|
        el.alt_map do |error|
          if error.is_a?(ErrorTree)
            error.prepend(ErrorTree::Index[index])
          else
            to_list.(error)
          end
        end
      }
    }

    # By default the identity function is used
    Traverse.default = id

    class << Traverse
      # Invokes a traverse handler, passing the index only when the
      # handler accepts it. Plain procs silently ignore extra arguments.
      #
      # @api private
      def call(handler, element, index)
        if handler.lambda? && handler.arity == 1
          handler.(element)
        else
          handler.(element, index)
        end
      end
    end

    Traverse.freeze
  end
end

# rubocop:enable Style/MutableConstant
# rubocop:enable Naming/ConstantName
