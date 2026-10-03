# frozen_string_literal: true

module Dry
  module Types
    # Recursive types: named lazy references and mutually referencing types.
    #
    # Use {Dry::Types::BuilderMethods#Recursive} on a types module to build
    # recursive types, e.g. `Types.Recursive(:node) { |node| ... }`.
    #
    # @api public
    module Recursive
      # Structural AST node tags. Crossing one of these during a type
      # application consumes input and therefore breaks an alias cycle.
      #
      # @api private
      STRUCTURAL_TAGS = %i[
        nominal any array hash schema map enum
      ].to_set.freeze

      # AST node tags that do not consume input by themselves
      #
      # @api private
      PASS_THROUGH_TAGS = %i[
        constrained constructor lax safe intersection implication
      ].to_set.freeze

      # Thread-local stack of traversal frames shared by Root/Ref applications
      #
      # @api private
      def self.frames
        Thread.current[:__dry_types_recursive_frames__] ||= []
      end

      # Run a block within a fresh or the already-active traversal frame
      #
      # @api private
      def self.with_frame
        created = frames.empty?
        frames << Frame.new if created
        yield
      ensure
        frames.pop if created
      end

      # @api private
      def self.frame = frames.first

      # Run a type application while tracking a path segment
      #
      # @api private
      def self.segment(key)
        frame = Recursive.frame
        frame ? frame.segment(key) { yield } : yield
      end

      # A traversal frame tracks ancestor input objects and the current path
      # within one top-level recursive type application.
      #
      # @api private
      class Frame
        def initialize
          @levels = []
          @ancestors = Set.new
          @descended = false
          @visits = {}
        end

        # Enter a reference application. Raises when the input object is
        # already an ancestor in the current traversal.
        #
        # @api private
        def enter(name, input)
          ancestor_cycle = @descended && @ancestors.include?(input.object_id)

          # A Sum alternative may view the same input through the same
          # reference without consuming it; that can never terminate.
          key = [name, input.object_id]
          branch_cycle = !@descended && @visits[key].equal?(input)
          @visits[key] = input unless branch_cycle

          cycle = ancestor_cycle || branch_cycle
          @descended = false

          if cycle
            path = path_for(name)
            raise CircularStructureError.new(
              "cyclic structure detected at #{path}",
              path
            )
          end

          @ancestors << input.object_id
          @levels << Level.new(name, input)
        end

        # @api private
        def exit
          level = @levels.pop
          if level
            @ancestors.delete(level.input.object_id)
            @visits.delete([level.name, level.input.object_id])
          end
        end

        # Run a type application within a path segment
        #
        # @api private
        def segment(key)
          previous = @descended
          @descended = true
          @levels.last.segments << key unless @levels.empty?
          yield
        ensure
          @levels.last.segments.pop unless @levels.empty?
          @descended = previous
        end

        private

        # @api private
        def path_for(name)
          parts = @levels.flat_map do |level|
            level.segments.map { |key| Recursive.format_segment(key) }
          end
          parts << Recursive.format_segment(name)
          "$#{parts.join}"
        end

        # @api private
        class Level
          attr_reader :name, :input, :segments

          def initialize(name, input)
            @name = name
            @input = input
            @segments = []
          end
        end
      end

      # @api private
      def self.format_segment(key)
        case key
        when ::Symbol then ".#{key}"
        when ::Integer then "[#{key}]"
        else "[#{key.inspect}]"
        end
      end

      # A named lazy reference to a type participating in a recursive group
      #
      # @api public
      class Ref
        include Type
        include Options
        include Meta
        include Builder
        include Printable

        # @return [Symbol]
        #
        # @api public
        attr_reader :name

        # @return [Definition]
        #
        # @api private
        attr_reader :definition

        # @param [Symbol] name
        # @param [Definition] definition
        #
        # @api private
        def initialize(name, definition, **options)
          @name = name
          @definition = definition
          @queries = []
          super(**options)
        end

        # Resolved type, memoized after the first resolution
        #
        # @return [Type]
        #
        # @api private
        def target
          return self if definition.resolving?(name)
          @target ||= definition.resolve(name)
        end

        # @api private
        def call_unsafe(input)
          invoke(input) { target.call_unsafe(input) }
        end

        # @api private
        def call_safe(input, &block)
          invoke(input) { target.call_safe(input, &block) }
        end

        # @api public
        def try(input, &block)
          invoke(input) { target.try(input, &block) }
        end

        # @api private
        def primitive?(value) = query { target.primitive?(value) } || false

        # @api private
        def default? = query { target.default? } || false

        # @api private
        def constrained? = query { target.constrained? } || false

        # @api private
        def optional? = query { target.optional? } || false

        # @return [Array]
        #
        # @api public
        def to_ast(meta: true)
          emitter = AstEmitter.current
          emitter ? emitter.ref_ast(name, meta) : [:ref, [name, meta ? self.meta : EMPTY_HASH]]
        end

        # @return [Ref]
        #
        # @api public
        def with(**new_options)
          if new_options.empty?
            self
          else
            new_meta = new_options.delete(:meta) { Undefined }
            meta = Undefined.equal?(new_meta) ? @meta : @meta.merge(new_meta)
            self.class.new(name, definition, **new_options, meta: meta)
          end
        end

        private

        # Run a structural query, guarding against unresolved alias chains
        #
        # @api private
        def query
          return false if @queries.include?(name)
          @queries << name
          yield
        ensure
          @queries.delete(name)
        end

        # @api private
        def invoke(input)
          frame = Recursive.frame
          frame&.enter(name, input)
          yield
        ensure
          frame&.exit
        end
      end

      # The public entry type of a recursive group. It is a thin, lazy wrapper
      # around the group's root declaration.
      #
      # @api public
      class Root
        include Type
        include Printable

        # @return [Symbol]
        #
        # @api public
        attr_reader :name

        # @return [Definition]
        #
        # @api private
        attr_reader :definition

        # @param [Definition] definition
        # @param [Symbol] name root declaration name
        #
        # @api private
        def initialize(definition, name, meta: EMPTY_HASH)
          @definition = definition
          @name = name
          @meta = meta.freeze
        end

        # @return [Type] the resolved root type
        #
        # @api private
        def type
          @type ||= definition.resolve(name)
        end

        # @api private
        def call_unsafe(input)
          apply(input) { type.call_unsafe(input) }
        end

        # @api private
        def call_safe(input, &block)
          apply(input) { type.call_safe(input, &block) }
        rescue CircularStructureError
          block ? yield(input) : raise
        end

        # @api public
        def try(input, &block)
          apply(input) { type.try(input, &block) }
        rescue CircularStructureError => error
          failure = Result::Failure.new(input, error)
          block ? block.call(failure) : failure
        end

        # @api private
        def primitive?(value) = type.primitive?(value)

        # @api private
        def default? = type.default?

        # @api private
        def constrained? = type.constrained?

        # @api private
        def optional? = type.optional?

        # @return [Lax]
        #
        # @api public
        def lax = Lax.new(self)

        # @return [Hash]
        #
        # @api public
        def meta(data = Undefined)
          if Undefined.equal?(data)
            @meta
          elsif data.empty?
            self
          else
            Root.new(definition, name, meta: @meta.merge(data))
          end
        end

        # @return [Array]
        #
        # @api public
        def to_ast(meta: true)
          definition.assert_grounded!
          AstEmitter.emit(self, meta: meta)
        end

        # @return [Root]
        #
        # @api public
        def with(**new_options)
          new_meta = new_options.delete(:meta) { Undefined }

          if new_options.empty? && Undefined.equal?(new_meta)
            self
          else
            meta = Undefined.equal?(new_meta) ? @meta : @meta.merge(new_meta)
            self.class.new(definition, name, **new_options, meta: meta)
          end
        end

        # Delegate builder/introspection methods to the resolved root type.
        # The returned wrapper still applies through the recursive frame.
        #
        # @api private
        def method_missing(meth, *args, **kwargs, &block)
          if type.respond_to?(meth)
            type.public_send(meth, *args, **kwargs, &block)
          else
            super
          end
        end

        # @api private
        def respond_to_missing?(meth, include_private = false)
          type.respond_to?(meth, include_private) || super
        end

        private

        # @api private
        def apply(input)
          definition.assert_grounded!
          Recursive.with_frame do
            Recursive.frame.enter(name, input)
            begin
              yield
            ensure
              Recursive.frame.exit
            end
          end
        end
      end

      # Holds the declaration table of a recursive group and resolves the
      # declarations lazily, caching the results.
      #
      # @api private
      class Definition
        # DSL yielded to multi-declaration definitions
        #
        # @api public
        class Dsl
          # @return [Symbol, nil]
          #
          # @api private
          attr_reader :declared_default_name

          # @api private
          def initialize(definition)
            @definition = definition
            @declared_default_name = nil
          end

          # Declare a named type. The body block receives the lazy Ref for
          # this name and the Dsl itself.
          #
          # @param [Symbol] name
          #
          # @return [Ref]
          #
          # @api public
          def declare(name, &block)
            @declared_default_name ||= name.to_sym
            @definition.declare(name, &block)
            @definition.ref(name)
          end

          # Return a lazy reference to a declared name
          #
          # @param [Symbol] name
          #
          # @return [Ref]
          #
          # @api public
          def [](name) = @definition.ref(name)
        end

        def initialize
          @blocks = {}
          @types = {}
          @refs = {}
          @asts = {}
          @resolving = []
          @root_name = nil
          @grounded_checked = false
        end

        # @return [Array<Symbol>]
        #
        # @api private
        def names = @blocks.keys

        # @return [Boolean]
        #
        # @api private
        def declared?(name) = @blocks.key?(name.to_sym)

        # @return [Symbol, nil]
        #
        # @api private
        attr_accessor :root_name

        # Register a declaration without expanding its body
        #
        # @api private
        def declare(name, &block)
          name = name.to_sym
          if @blocks.key?(name)
            raise ::ArgumentError, "recursive type #{name.inspect} is already declared"
          end
          @blocks[name] = block
          self
        end

        # @return [Ref]
        #
        # @api private
        def ref(name)
          name = name.to_sym
          @refs[name] ||= Ref.new(name, self)
        end

        # Choose the root name based on the user block's result
        #
        # @api private
        def set_root_from(result, default_name)
          @root_name = result.is_a?(Ref) ? result.name : default_name
        end

        # Resolve a declaration to its type, caching the result
        #
        # @api private
        def resolve(name) = @types[name.to_sym] || build_type(name.to_sym)

        # @api private
        def resolving?(name) = @resolving.include?(name.to_sym)

        # Verify every declaration eventually reaches an entity type.
        # Raises {RecursiveAliasError} for pure alias cycles.
        #
        # @api private
        def assert_grounded!
          return if @grounded_checked

          cycle = find_alias_cycle
          raise RecursiveAliasError.new(cycle) if cycle

          @grounded_checked = true
        end

        # @api private
        def ast_for(name) = @asts[name.to_sym] ||= resolve(name).to_ast(meta: true)

        # @api private
        def dsl = @dsl ||= Dsl.new(self)

        private

        # @api private
        def body(name)
          unless @blocks.key?(name)
            raise ::ArgumentError, "recursive type #{name.inspect} is not declared"
          end
          @blocks[name]
        end

        # @api private
        def build_type(name)
          block = body(name)
          @resolving << name
          type = block.call(ref(name), dsl)

          if type.is_a?(Ref) && @resolving.include?(type.name)
            # In-progress alias, e.g. `a = a` or `a = b; b = a`.
            # Leave it unresolved; assert_grounded! reports the alias cycle.
            return type
          end

          type = type.target if type.is_a?(Ref)

          unless type.is_a?(Type)
            raise ::ArgumentError,
              "recursive declaration #{name.inspect} must return a type, #{type.class} given"
          end

          @types[name] = type
        ensure
          @resolving.delete(name)
        end

        # Fixed-point traversal: follow refs until every reachable name has
        # crossed a structural node. Names that remain form alias cycles.
        #
        # @api private
        def find_alias_cycle
          grounded = Set.new
          changed = true

          while changed
            changed = false
            @blocks.each_key do |name|
              next if grounded.include?(name)
              if grounded_reachable?(ast_for(name), grounded, Set.new, false)
                grounded << name
                changed = true
              end
            end
          end

          cyclic = @blocks.keys.reject { |name| grounded.include?(name) }
          cyclic.empty? ? nil : cyclic
        end

        # @api private
        def grounded_reachable?(node, grounded, seen, behind_structural)
          tag, body = node

          if tag == :ref
            ref_name = body[0]
            return true if behind_structural || grounded.include?(ref_name)
            return false unless @blocks.key?(ref_name)
            return false if seen.include?(ref_name)
            seen << ref_name
            return grounded_reachable?(
              ast_for(ref_name), grounded, seen, behind_structural
            )
          end

          return true if STRUCTURAL_TAGS.include?(tag)

          children = ast_children(tag, body)
          children.any? do |child|
            grounded_reachable?(child, grounded, seen, behind_structural)
          end
        end

        # @api private
        def ast_children(tag, body)
          case tag
          when :key
            [body[2]]
          when :enum
            [body[0]]
          when :map
            [body[0], body[1]]
          when :schema
            body[0]
          when :sum, :intersection, :implication
            [body[0], body[1]]
          else
            PASS_THROUGH_TAGS.include?(tag) && body.is_a?(::Array) ? [body[0]] : []
          end
        end
      end

      # Emits a self-describing recursive AST: the root reference plus a
      # declaration table. Refs inside declaration bodies emit as bare refs.
      #
      # @api private
      class AstEmitter
        def self.current
          stack = Thread.current[:__dry_types_recursive_emitters__] ||= []
          stack.last
        end

        def self.emit(root, meta: true)
          stack = Thread.current[:__dry_types_recursive_emitters__] ||= []
          emitter = new
          stack << emitter
          begin
            declarations = root.definition.names.map do |name|
              [:declaration, [name, root.definition.ast_for(name)]]
            end
            [:recursive, [root.name, declarations, meta ? root.meta : EMPTY_HASH]]
          ensure
            stack.pop
          end
        end

        def ref_ast(name, _meta) = [:ref, [name]]
      end

      # Compiles declaration bodies with bare refs resolved within the group
      #
      # @api private
      class DefinitionCompiler < Compiler
        def initialize(registry, definition)
          super(registry)
          @definition = definition
        end

        def visit_ref(node)
          name = node[0]
          @definition.ref(name)
        end
      end

      # Build a recursive type
      #
      # @see BuilderMethods#Recursive
      #
      # @api public
      def self.build(root_name = Undefined, &block)
        raise ::ArgumentError, "a block is required to define a recursive type" unless block

        definition = Definition.new

        if Undefined.equal?(root_name)
          # mutually referencing form: Types.Recursive { |t| t.declare(:a) { ... } }
          dsl = Definition::Dsl.new(definition)
          result = block.call(dsl)
          definition.set_root_from(result, dsl.declared_default_name)

          if definition.names.empty?
            raise ::ArgumentError, "no recursive types were declared"
          end

          root_name = definition.root_name || definition.names.first
        else
          # self-referencing form: Types.Recursive(:node) { |node| ... }
          root_name = root_name.to_sym
          definition.declare(root_name, &block)
        end

        Root.new(definition, root_name)
      end

      # Reconstruct a recursive type from its AST
      #
      # @api private
      def self.compile_ast(node, compiler)
        root_name, declarations, meta = node
        definition = Definition.new
        group_compiler = DefinitionCompiler.new(compiler.registry, definition)

        declarations.each do |declaration|
          name, body = declaration[1]
          definition.declare(name) { group_compiler.visit(body) }
        end

        Root.new(definition, root_name.to_sym, meta: meta || EMPTY_HASH)
      end
    end
  end
end
