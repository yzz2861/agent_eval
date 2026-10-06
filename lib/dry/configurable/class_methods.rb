# frozen_string_literal: true

module Dry
  module Configurable
    module ClassMethods
      include Methods

      # @api private
      def inherited(subclass)
        super

        subclass.instance_variable_set(:@__config_extension__, __config_extension__)

        new_settings = settings.dup
        subclass.instance_variable_set(:@__settings__, new_settings)
        subclass.instance_variable_set(:@__profiles__, profiles.dup)

        # Only classes **extending** Dry::Configurable have class-level config. When
        # Dry::Configurable is **included**, the class-level config method is undefined because it
        # resides at the instance-level instead (see `Configurable.included`).
        if respond_to?(:config)
          subclass.instance_variable_set(:@__config__, config.dup_for_settings(new_settings))
        end
      end

      # Add a setting to the configuration
      #
      # @param [Mixed] name
      #   The accessor key for the configuration value
      # @param [Mixed] default
      #   Default value for the setting
      # @param [#call] constructor
      #   Transformation given value will go through
      # @param [Boolean] reader
      #   Whether a reader accessor must be created
      # @yield
      #   A block can be given to add nested settings.
      #
      # @return [Dry::Configurable::Config]
      #
      # @api public
      def setting(...)
        setting = __config_dsl__.setting(...)

        settings << setting

        __config_reader__.define(setting.name) if setting.reader?

        self
      end

      # Returns the defined settings for the class.
      #
      # @return [Settings]
      #
      # @api public
      def settings
        @__settings__ ||= Settings.new
      end

      # Defines a named configuration profile.
      #
      # A profile is a reusable, named bundle of configuration changes. It may
      # inherit from one or more previously defined profiles via +:inherits+;
      # the inheritance chain is resolved through C3 linearization (see
      # {Profiles#linearize}) whenever the profile is selected.
      #
      # The block receives a {Config} and is applied on top of the profile's
      # ancestors when the profile is built via {#config_for}. Within the
      # block, the three kinds of "no value" stay distinct:
      #
      # - a setting the block never touched keeps the value inherited from
      #   the ancestor profiles (or the setting's own default);
      # - +config.key = nil+ assigns an explicit +nil+;
      # - +config.restore_default(:key)+ discards any inherited value and
      #   restores the setting's declared default.
      #
      # @param [String, Symbol] name
      #   The profile name
      # @param [Array<String, Symbol>] inherits
      #   Names of the parent profiles, in decreasing order of precedence
      # @yieldparam [Dry::Configurable::Config] config
      #
      # @return [self]
      #
      # @api public
      def profile(name, inherits: EMPTY_ARRAY, &block)
        raise ArgumentError, "a profile requires a configuration block" unless block

        profiles << Profile.new(name, parents: inherits, block: block)

        self
      end

      # Returns the defined profiles for the class.
      #
      # @return [Profiles]
      #
      # @api public
      def profiles
        @__profiles__ ||= Profiles.new
      end

      # Builds a fresh, independent config for the given profile.
      #
      # The profile's linearized inheritance chain is applied to a pristine
      # config, ancestors first, so more specific profiles override their
      # ancestors and every profile in the chain is applied exactly once. The
      # returned config shares no mutable state with the class-level config
      # or with configs built for other profiles: nested configs and mutable
      # defaults are freshly generated for each call.
      #
      # @param [String, Symbol] profile_name
      #
      # @return [Dry::Configurable::Config]
      #
      # @raise [UnknownProfileError] if the profile is not defined
      # @raise [ProfileLinearizationError] if the inheritance chain cannot be
      #   linearized
      #
      # @api public
      def config_for(profile_name)
        order = profiles.linearize(profile_name)

        __config_build__.tap do |config|
          order.reverse_each { |name| profiles[name].apply(config) }
        end
      end

      # Returns the resolved inheritance order for the given profile.
      #
      # The list is ordered from highest to lowest precedence: it starts with
      # the profile itself and ends with its most ancestral parents. This is
      # the exact order used by {#config_for} (which applies it in reverse).
      #
      # @param [String, Symbol] profile_name
      #
      # @return [Array<Symbol>]
      #
      # @api public
      def profile_order(profile_name)
        profiles.linearize(profile_name)
      end

      # Return configuration
      #
      # @return [Config]
      #
      # @api public
      def config
        @__config__ ||= __config_build__
      end

      # @api private
      def __config_build__(settings = self.settings)
        __config_extension__.config_class.new(settings)
      end

      # @api private
      def __config_extension__
        @__config_extension__
      end

      # @api private
      def __config_dsl__
        @__config_dsl__ ||= DSL.new(
          config_class: __config_extension__.config_class,
          default_undefined: __config_extension__.default_undefined
        )
      end

      # @api private
      def __config_reader__
        @__config_reader__ ||=
          begin
            reader = Module.new do
              def self.define(name)
                define_method(name) do
                  config[name]
                end
              end
            end

            if included_modules.include?(InstanceMethods)
              include(reader)
            end

            extend(reader)

            reader
          end
      end
    end
  end
end
