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
    # The callable receives the element together with its index. A callable
    # taking one argument (like `id`) is called without the index.
    Traverse = {
      Validated => ->(el, index) {
        el.alt_map do |error|
          if error.is_a?(Validated::ErrorTree)
            error.prefix(Validated::ErrorTree::Index.new(index))
          else
            to_list.(error)
          end
        end
      }
    }

    # By default the identity function is used
    Traverse.default = id
    Traverse.freeze
  end
end

# rubocop:enable Style/MutableConstant
# rubocop:enable Naming/ConstantName
