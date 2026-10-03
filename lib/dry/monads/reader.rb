# frozen_string_literal: true

module Dry
  module Monads
    # Reader (also known as the Environment or Function monad) represents a
    # computation that receives its environment at run time.
    #
    # Building a Reader does not perform any reads: the wrapped computation
    # is only evaluated when {#run} (or its alias {#call}) is called with an
    # environment. This makes it possible to build a computation once and run
    # it against multiple environments.
    #
    # Exceptions raised by the wrapped computation are propagated as usual,
    # they are never converted into {Result::Failure}.
    #
    # @example
    #   require "dry-monads"
    #   include Dry::Monads[:reader]
    #
    #   greeting =
    #     Reader.ask.fmap { |user| "Hello, #{user[:name]}!" }
    #
    #   greeting.run(name: "Anna")  # => "Hello, Anna!"
    #   greeting.run(name: "Bjorn") # => "Hello, Bjorn!"
    #
    # @api public
    class Reader
      # The environment -> value computation.
      attr_reader :proc

      class << self
        # Lifts a plain value into a Reader that ignores the environment
        # and always returns the value.
        #
        # @overload pure(value)
        #   @param value [Object]
        #   @return [Reader]
        #
        # @overload pure(&block)
        #   @param block [Proc] a block used as the lifted value
        #   @return [Reader]
        #
        def pure(value = Undefined, &block)
          new(-> _ { Undefined.default(value, block) })
        end

        # Builds a Reader that returns the environment unchanged.
        # It is the Reader counterpart of Haskell's @ask@.
        #
        # @return [Reader]
        def ask = new(IDENTITY)

        # Builds a Reader from a block (or any callable) that receives
        # the environment at run time.
        #
        # @example
        #   Reader { |env| env[:db] }
        #
        # @param block [#call] an explicit callable to wrap
        # @return [Reader]
        def new(block = Undefined, &blk)
          fn = Undefined.default(block, blk)
          raise ArgumentError, "a block or callable is required" if fn.nil?
          unless fn.respond_to?(:call) || fn.respond_to?(:to_proc)
            raise TypeError, "#{fn.inspect} is not callable"
          end

          super(fn.to_proc)
        end
      end

      # @param block [#call] an environment -> value computation
      def initialize(block)
        @proc = block
      end

      # Evaluates the computation with the given environment.
      #
      # @param env [Object]
      # @return [Object]
      def run(env)
        @proc.(env)
      end
      alias_method :call, :run

      # Alias of {.ask} available on instances, handy inside chains.
      #
      # @return [Reader]
      def ask = Reader.ask

      # Maps the result of the computation with the given block/callable.
      # The block is not called until {#run}.
      #
      # @example
      #   Reader.ask.fmap { |env| env[:x] + 1 }.run(x: 1) # => 2
      #
      # @param args [Array<Object>] extra args passed to the block
      # @return [Reader]
      def fmap(*args, **kwargs, &block)
        fn = @proc
        mapping = resolve_callable(args, kwargs, block)
        Reader.new { |env| mapping.(fn.(env)) }
      end

      # Composes two Readers: the block receives the result of self and
      # must return another Reader. The inner Reader is then run with the
      # same environment. Neither the block nor the inner Reader's
      # computation runs until {#run}.
      #
      # @example
      #   Reader.ask.bind { |env| Reader.pure(env[:x] * 2) }.run(x: 21) # => 42
      #
      # @param args [Array<Object>] extra args passed to the block
      # @return [Reader]
      def bind(*args, **kwargs, &block)
        outer = @proc
        continuation = resolve_callable(args, kwargs, block)
        Reader.new do |env|
          inner = continuation.(outer.(env))
          unless inner.is_a?(Reader)
            raise TypeError,
                  "block given to Reader#bind must return a Reader, " \
                  "got #{inner.inspect}"
          end

          inner.run(env)
        end
      end

      # Runs the given sub-computation with an environment transformed by
      # the block. The transformation only applies to the wrapped Reader:
      # after {#run}, surrounding computations still see the original
      # environment and the environment object itself is never mutated.
      #
      # @example
      #   scaled = Reader.ask.local { |env| env * 10 }
      #   scaled.run(1) # => 10
      #
      # @param args [Array<Object>] extra args passed to the transform
      # @return [Reader]
      def local(*args, **kwargs, &block)
        inner = @proc
        transform = resolve_callable(args, kwargs, block)
        Reader.new { |env| inner.(transform.(env)) }
      end

      # Reader is its own monadic representation.
      #
      # @return [Reader]
      def to_monad = self

      # Returns the Reader monad.
      #
      # @return [Reader]
      def monad = Reader

      # @return [String]
      def to_s = "Reader(#{@proc.inspect})"
      alias_method :inspect, :to_s

      private

      # Normalizes a block or a positional callable into a single-argument
      # proc, mirroring the calling convention of the other monads.
      def resolve_callable(args, kwargs, block)
        return block if block

        callable, *rest = args
        raise ArgumentError, "a block or callable is required" if callable.nil?

        fn = callable.respond_to?(:call) ? callable : callable.to_proc
        if rest.empty? && kwargs.empty?
          fn
        else
          ->(value) { fn.(value, *rest, **kwargs) }
        end
      end

      # A module that can be included for easier access to Reader monads.
      module Mixin
        # @see Dry::Monads::Reader
        Reader = Reader

        # Reader constructors
        module Constructors
          # Reader constructor
          #
          # @overload Reader(&block)
          #   @param block [Proc] an environment -> value computation
          #   @return [Reader]
          #
          # @overload Reader(callable)
          #   @param callable [#call] an environment -> value computation
          #   @return [Reader]
          #
          def Reader(callable = Undefined, &block)
            Reader.new(callable, &block)
          end
        end

        include Constructors
      end
    end

    require "dry/monads/registry"
    register_mixin(:reader, Reader::Mixin)
  end
end
