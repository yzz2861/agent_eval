# frozen_string_literal: true

module Dry
  module Configurable
    module ClassMethods
      include Methods

      # @api private
      def inherited(subclass)
        super

        subclass.instance_variable_set(:@__config_extension__, __config_extension__)

        subclass.instance_variable_set(:@__profiles__, profiles.dup)

        new_settings = settings.dup
        subclass.instance_variable_set(:@__settings__, new_settings)

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

      # Return configuration
      #
      # @return [Config]
      #
      # @api public
      def config
        @__config__ ||= __config_build__
      end

      # Defines a named configuration profile.
      #
      # A profile holds overrides for the settings and may inherit from one or
      # more other profiles. Base profiles are listed in priority order: an
      # earlier parent takes precedence over a later parent. The effective
      # precedence order is computed with C3 linearization; see
      # {Profiles#lineage}.
      #
      # @example
      #
      #   class App
      #     extend Dry::Configurable
      #
      #     setting :db
      #     setting :cache, :memory
      #
      #     profile :development do
      #       db "sqlite:memory"
      #     end
      #
      #     profile :production, inherits: :development do
      #       db "postgresql://prod"
      #     end
      #   end
      #
      # @param name [Symbol] the profile name
      # @param inherits [Symbol, Array<Symbol>] one or more base profile names
      # @yield block declaring setting overrides (see {ProfileDSL})
      #
      # @return [Dry::Configurable::Profile]
      #
      # @api public
      def profile(name, inherits: EMPTY_ARRAY, &block)
        parents = inherits.is_a?(::Array) ? inherits : [inherits]
        profiles.register(name, parents, block, settings: settings)
      end

      # Returns the registry of named profiles defined on this class.
      #
      # @return [Profiles]
      #
      # @api public
      def profiles
        @__profiles__ ||= Profiles.new
      end

      # Builds and returns an independent configuration for the named profile.
      #
      # The returned {Config} is a fresh object: mutable values and nested
      # configs are copied, so it is never shared with another profile or with
      # the class-level {#config}.
      #
      # @param name [Symbol] the profile to resolve
      #
      # @return [Dry::Configurable::Config]
      #
      # @api public
      def config_for(name)
        profiles.build_config(name, settings, __config_extension__.config_class)
      end
      alias_method :profile_config, :config_for

      # Returns the resolved inheritance order (C3 linearization) for the named
      # profile, from highest precedence (the profile itself) to lowest.
      #
      # @param name [Symbol]
      #
      # @return [Array<Symbol>]
      #
      # @api public
      def profile_lineage(name)
        profiles.lineage(name)
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
