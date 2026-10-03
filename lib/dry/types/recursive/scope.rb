# frozen_string_literal: true

module Dry
  module Types
    class Recursive
      # A registry of named type definitions participating in a
      # (possibly mutual) recursion.
      #
      # Definitions are not evaluated while the scope is being built.
      # Each name is resolved lazily on the first application of its
      # reference and the resolved type is cached.
      #
      # @api public
      class Scope
        @counter = 0
        @mutex = ::Mutex.new

        class << self
          # Allocate a stable id for a freshly created user scope
          #
          # @return [Integer]
          #
          # @api private
          def next_id
            @mutex.synchronize { @counter += 1 }
          end
        end

        # @return [Object] stable identifier of this scope (used in the AST)
        attr_reader :scope_id

        # @param [String, nil] scope_id Stable identifier of the scope.
        #   When nil a unique id is generated. The AST compiler passes the
        #   id found in the AST so compiled references keep matching.
        # @param [#call,nil] block Receives the scope itself so that
        #   mutually recursive names can be registered
        #
        # @api public
        def initialize(scope_id = nil, &block)
          @scope_id = scope_id || "scope-#{self.class.next_id}"
          @definitions = {}
          @resolved = {}
          block&.(self)
        end

        # Register a named type definition
        #
        # @param [Symbol] name
        # @param [#call,nil] block Receives the scope itself, must return
        #   a concrete type or another lazy reference
        #
        # @return [Recursive] the lazy reference for the name
        #
        # @api public
        def register(name, &block)
          raise ::ArgumentError, "a block is required" unless block
          raise ::ArgumentError, "#{name.inspect} is already registered" if @definitions.key?(name)

          @definitions[name] = block
          self[name]
        end

        # Fetch the lazy reference to a registered name
        #
        # @param [Symbol] name
        #
        # @return [Recursive]
        #
        # @api public
        def [](name)
          Recursive.new(name, self)
        end

        # Whether a name has been registered
        #
        # @param [Symbol] name
        #
        # @return [Boolean]
        #
        # @api private
        def registered?(name)
          @definitions.key?(name)
        end

        # Resolve a name to a concrete type, caching the result.
        # Raises {AliasCycleError} when the name belongs to an alias-only
        # cycle that never reaches a concrete type.
        #
        # @param [Symbol] name
        #
        # @return [Type]
        #
        # @api private
        def resolve(name)
          @resolved[name] || build(name)
        end

        private

        # Build and cache the concrete type behind a name.
        #
        # Two kinds of recursion are distinguished:
        #
        # 1. A definition returns a concrete type that merely *contains*
        #    lazy references (e.g. a schema with a recursive key). This is
        #    a legitimate recursive data type: the definition terminates.
        # 2. A definition directly returns another lazy reference, and the
        #    chain of aliases closes without ever reaching a concrete type.
        #    This is an alias cycle and raises {AliasCycleError}.
        #
        # @api private
        def build(name)
          chain = resolution_chain

          if chain.include?(name)
            raise AliasCycleError.new(chain[chain.index(name)..])
          end

          definition = @definitions.fetch(name) do
            raise ::KeyError, "recursive type #{name.inspect} is not defined"
          end

          chain << name

          begin
            result = definition.(self)
            concrete = land(result)
            @resolved[name] ||= concrete
            concrete
          ensure
            chain.pop
          end
        end

        # Per-thread chain of names currently being resolved. References
        # that merely occur inside a concrete type's structure are not
        # followed, so the chain only tracks direct alias results.
        #
        # @return [Array<Symbol>]
        #
        # @api private
        def resolution_chain
          key = :"recursive-scope-chain-#{object_id}"
          ::Thread.current[key] ||= []
        end

        # Follow direct alias results until a concrete type is reached.
        # A closing alias chain raises {AliasCycleError}.
        #
        # @param [Type, Recursive] result
        #
        # @return [Type]
        #
        # @raise [AliasCycleError]
        #
        # @api private
        def land(result)
          case result
          when Recursive
            result.scope.resolve(result.ref_name)
          else
            result
          end
        end
      end
    end
  end
end
