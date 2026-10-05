module Flipper
  # Top level error that all other errors inherit from.
  class Error < StandardError; end

  # Raised when gate can not be found for an actor.
  class GateNotFound < Error
    def initialize(actor)
      super "Could not find gate for #{actor.inspect}"
    end
  end

  # Raised when attempting to declare a group name that has already been used.
  class DuplicateGroup < Error; end

  # Raised when features require each other, directly or through a chain of
  # prerequisites (e.g. a requires b, b requires c, c requires a).
  class CircularPrerequisite < Error
    # Public: The chain of feature names involved in the cycle, in the order
    # they were resolved. The first feature that closes the loop is repeated
    # at the end (e.g. [:a, :b, :c, :a]).
    attr_reader :chain

    def initialize(chain)
      @chain = chain
      super "Circular prerequisite detected: #{chain.join(' -> ')}"
    end
  end

  # Raised when an invalid value is set to a configuration property
  class InvalidConfigurationValue < Flipper::Error
    def initialize(message = nil)
      default = "Configuration value is not valid."
      super(message || default)
    end
  end
end
