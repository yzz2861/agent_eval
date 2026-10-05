# frozen_string_literal: true

module Dry
  module System
    class Provider
      # Configures a Dry::System::Provider::Source subclass using a DSL that makes it
      # nicer to define source behaviour via a single block.
      #
      # @see Dry::System::Container.register_provider
      #
      # @api private
      class SourceDSL
        def self.evaluate(source_class, &)
          new(source_class).instance_eval(&)
        end

        attr_reader :source_class

        def initialize(source_class)
          @source_class = source_class
        end

        def setting(...)
          source_class.setting(...)
        end

        # Declares the providers that must be prepared and started before this one.
        #
        # Dependencies are taken into account whenever a provider is prepared or
        # started (including via container finalization): the named providers run
        # their own lifecycle steps first, in dependency order. Providers are stopped
        # in the reverse order on shutdown.
        #
        # @example
        #   register_provider(:persistence) do
        #     depends_on :settings, :logger
        #
        #     start do
        #       # ...
        #     end
        #   end
        #
        # @param names [Array<Symbol>] the names of the providers to depend on
        #
        # @return [Array<Symbol>] the provider's dependencies
        #
        # @api public
        def depends_on(*names)
          source_class.dependencies.concat(names.flatten.map(&:to_sym))
        end

        def prepare(&)
          source_class.define_method(:prepare, &)
        end

        def start(&)
          source_class.define_method(:start, &)
        end

        def stop(&)
          source_class.define_method(:stop, &)
        end

        private

        def method_missing(name, ...)
          if source_class.respond_to?(name)
            source_class.public_send(name, ...)
          else
            super
          end
        end

        def respond_to_missing?(name, include_all = false)
          source_class.respond_to?(name, include_all) || super
        end
      end
    end
  end
end
