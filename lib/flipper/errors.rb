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

  # Raised when an invalid value is set to a configuration property
  class InvalidConfigurationValue < Flipper::Error
    def initialize(message = nil)
      default = "Configuration value is not valid."
      super(message || default)
    end
  end

  # Raised when a variant is evaluated for a feature that has no variant
  # configuration.
  class VariantsNotConfigured < Flipper::Error
    def initialize(feature_name)
      super "Variants have not been configured for #{feature_name.inspect}."
    end
  end

  # Raised when a variant configuration is invalid (bad weights, salt, or
  # variant names).
  class InvalidVariantConfiguration < Flipper::Error; end
end
