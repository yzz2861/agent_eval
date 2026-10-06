# frozen_string_literal: true

module Dry
  # Shared errors
  #
  # @api public
  module Configurable
    extend Dry::Core::Deprecations["dry-configurable"]

    Error = Class.new(::StandardError)

    FrozenConfigError = Class.new(Error)

    # Raised when something is wrong with a named profile definition or lookup
    #
    # @api public
    ProfileError = Class.new(Error)

    # Raised when a profile's parent profiles cannot be resolved into a
    # consistent linearization (C3)
    #
    # @api public
    ProfileLinearizationError = Class.new(ProfileError)

    # Raised when a profile assigns a value that does not match the setting
    # schema (an unknown setting, or a scalar given to a nested setting)
    #
    # @api public
    ProfileSettingError = Class.new(ProfileError)

    AlreadyIncludedError = Class.new(Error)
    deprecate_constant(
      :AlreadyIncludedError,
      message: "`include Dry::Configurable` more than once (if needed)"
    )
  end
end
