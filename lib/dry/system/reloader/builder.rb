# frozen_string_literal: true

require "set"

require "dry/system/constants"

module Dry
  module System
    class Reloader
      # Holds the current source definitions for providers and components and builds
      # them inside a given {Generation}.
      #
      # A new builder is created for every successful reload, carrying forward every
      # unchanged definition. This means a generation always observes a single, fixed
      # snapshot of definitions: a reload never mutates a generation that is still
      # serving in-flight work.
      #
      # @api private
      # @since 1.3.0
      class Builder
        # @return [Hash{Symbol => Hash}] the provider definitions, keyed by provider
        #   name, each with `:options` and `:block`
        attr_reader :provider_definitions

        # @return [Hash{String => Proc}] the component build blocks, keyed by key
        attr_reader :component_blocks

        # Called with every provider immediately after it has started in a generation.
        # Used by the reloader to maintain cross-generation provider reference counts.
        #
        # @return [#call, nil]
        #
        # @api private
        attr_accessor :on_provider_started

        # @api private
        def initialize(provider_definitions: nil, component_blocks: nil)
          @provider_definitions = provider_definitions || {}
          @component_blocks = component_blocks || {}
        end

        # @return [Builder] a copied builder with the same definitions
        #
        # @api private
        def dup
          copy = self.class.new(
            provider_definitions: deep_dup_providers(@provider_definitions),
            # Blocks are immutable source code closures; a shallow copy is enough.
            component_blocks: @component_blocks.dup
          )
          copy.on_provider_started = @on_provider_started
          copy
        end

        # @api private
        def register_provider(name, **options, &block)
          @provider_definitions[name.to_sym] = {options: options, block: block}
          self
        end

        # @api private
        def register_component(key, &block)
          @component_blocks[key.to_s] = block
          self
        end

        # @return [Boolean]
        #
        # @api private
        def provider?(name)
          @provider_definitions.key?(name.to_sym)
        end

        # Builds a single component into the given generation. The component block is
        # evaluated eagerly and its result registered, so that any dependencies it
        # resolves are recorded before the component is considered built.
        #
        # @return [void]
        #
        # @api private
        def call(generation, key)
          key = key.to_s

          block = @component_blocks[key]
          if block
            generation.register(key, memoize: true) { block.call(generation) }
            # Eagerly resolve so the component's dependency edges are recorded now and a
            # failure to build surfaces during the reload that changed it.
            generation.resolve(key)
            return
          end

          root_key = key.split(KEY_SEPARATOR, 2).first.to_sym
          if @provider_definitions.key?(root_key)
            generation.start_provider(root_key)
            return if generation.registered?(key)
          end

          raise ComponentNotFoundError.new(key, generation.number)
        end

        # @return [Provider]
        #
        # @api private
        def build_provider(generation, name)
          definition = @provider_definitions.fetch(name.to_sym) do
            raise ProviderNotFoundError, name
          end

          source_class = Provider::Source.for(name: name, &definition[:block])

          Provider.new(
            name: name,
            target_container: generation,
            source_class: source_class,
            source_options: {},
            **definition[:options]
          )
        end

        # @return [void]
        #
        # @api private
        def notify_provider_started(provider)
          @on_provider_started&.call(provider)
          nil
        end

        # @return [Array<Symbol>] names of providers whose definition changed compared
        #   with the previous builder
        #
        # @api private
        def changed_provider_names(previous)
          @provider_definitions.filter_map do |name, definition|
            previous_definition = previous.provider_definitions[name]
            changed = previous_definition.nil? ||
              previous_definition[:options] != definition[:options] ||
              block_changed?(definition[:block], previous_definition[:block])
            name if changed
          end
        end

        # @return [Array<String>] keys whose component block changed compared with the
        #   previous builder, plus keys that no longer have a definition
        #
        # @api private
        def changed_component_keys(previous)
          changed = @component_blocks.filter_map do |key, block|
            previous_block = previous.component_blocks[key]
            key if block_changed?(block, previous_block)
          end

          changed + (previous.component_blocks.keys - @component_blocks.keys)
        end

        private

        # Compares two blocks by their source file/line and evaluated source text, which
        # distinguishes a genuinely redefined block from a carried-over identical block.
        def block_changed?(block, previous_block)
          return true if previous_block.nil?
          return false if block.equal?(previous_block)
          block.source_location != previous_block.source_location ||
            block.source != previous_block.source
        end

        def deep_dup_providers(definitions)
          definitions.transform_values do |definition|
            {options: definition[:options].dup, block: definition[:block]}
          end
        end
      end
    end
  end
end
