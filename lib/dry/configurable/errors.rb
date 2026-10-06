# frozen_string_literal: true

module Dry
  # Shared errors
  #
  # @api public
  module Configurable
    extend Dry::Core::Deprecations["dry-configurable"]

    Error = Class.new(::StandardError)

    FrozenConfigError = Class.new(Error)

    # Base error for problems resolving secret settings
    SecretError = Class.new(Error)

    # Raised when no secret exists for a given reference
    SecretNotFoundError = Class.new(SecretError)

    # Raised when the provider could not read an existing secret
    SecretReadError = Class.new(SecretError)

    # Raised when an injected provider does not fulfill the secret provider contract
    SecretProviderError = Class.new(SecretError)

    AlreadyIncludedError = Class.new(Error)
    deprecate_constant(
      :AlreadyIncludedError,
      message: "`include Dry::Configurable` more than once (if needed)"
    )
  end
end
