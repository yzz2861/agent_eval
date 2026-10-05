# frozen_string_literal: true

module Dry
  module System
    class Reloader
      # Pins a {Generation} for the duration of a unit of work, such as an in-flight
      # request in a development server.
      #
      # Every resolution made through the scope uses the generation that was current
      # when the scope opened, even if a reload installs a newer generation in the
      # meantime. When the scope closes, it releases its generation; once the final
      # scope for a superseded generation closes, that generation's providers are
      # stopped.
      #
      # @api public
      # @since 1.3.0
      class GenerationScope
        # @return [Generation] the generation pinned by this scope
        #
        # @api public
        attr_reader :generation

        # @api private
        def initialize(generation)
          @generation = generation
          @closed = false

          generation.retain!
        end

        # Resolves a component from the pinned generation.
        #
        # @param key [String, Symbol]
        #
        # @return [Object]
        #
        # @api public
        def resolve(key)
          raise ScopeClosedError if @closed
          @generation.resolve(key)
        end

        alias_method :[], :resolve

        # @param key [String, Symbol]
        #
        # @return [Boolean]
        #
        # @api public
        def registered?(key)
          @generation.registered?(key)
        end

        # @return [Integer]
        #
        # @api public
        def generation_number
          @generation.number
        end

        # Runs the given block with the scope, then closes the scope (releasing its
        # generation) even if the block raises.
        #
        # @return [Object] the block's return value
        #
        # @api public
        def wrap
          raise ScopeClosedError if @closed
          begin
            yield(self)
          ensure
            close!
          end
        end

        # Closes the scope and releases the pinned generation.
        #
        # @return [void]
        #
        # @api public
        def close!
          return if @closed
          @closed = true
          @generation.release!
          nil
        end

        # @return [Boolean]
        #
        # @api public
        def closed?
          @closed
        end
      end
    end
  end
end
