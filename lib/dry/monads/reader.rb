# frozen_string_literal: true

module Dry
  module Monads
    # The Reader monad represents a computation that depends on a shared
    # environment (typically configuration or dependencies). Nothing is
    # evaluated when a Reader is built or composed with fmap/bind/local;
    # the environment is only read when the computation is executed with
    # #run. This makes Reader a convenient way to thread dependencies
    # through a call tree without passing them explicitly, and the same
    # computation can be run any number of times with different
    # environments.
    #
    # Reader does not rescue anything: an exception raised by the
    # computation propagates from #run as is, it is not converted to
    # a Failure or any other monadic value.
    #
    # @api public
    class Reader
      include Transformer

      class << self
        # Lifts a value into a computation that ignores the environment.
        #
        # @overload pure(value)
        #   @param value [Object]
        #   @return [Reader]
        #
        # @overload pure(&block)
        #   @param block [Proc] a block producing the value
        #   @return [Reader]
        def pure(value = Undefined, &block)
          v = Undefined.default(value, block)
          new { v }
        end

        # Builds a computation that returns the environment itself,
        # or a part of it when a selector is given.
        #
        # @overload ask
        #   @return [Reader]
        #
        # @overload ask(selector)
        #   @param selector [#call] maps the environment to a part of it
        #   @return [Reader]
        def ask(selector = nil)
          if selector
            new { |env| selector.(env) }
          else
            new { |env| env }
          end
        end
      end

      # @api private
      def initialize(&fn)
        @fn = fn
      end

      # Runs the computation against the given environment. This is the
      # moment the environment is actually read: every ask/fmap/bind/local
      # built beforehand is just a description of a computation.
      #
      # @param env [Object] the environment the computation depends on
      # @return [Object]
      def run(env) = @fn.(env)

      # Maps a function over the result of the computation. The function
      # is applied on every #run, within the same environment.
      #
      # @param block [Proc]
      # @return [Reader]
      def fmap(&block)
        self.class.new { |env| block.(run(env)) }
      end

      # Feeds the result of the computation into a block returning
      # another Reader. Both computations see the same environment.
      #
      # @param block [Proc]
      # @return [Reader]
      def bind(&block)
        self.class.new { |env| block.(run(env)).run(env) }
      end

      # Runs the computation against a transformed environment. The
      # transformation only applies to this sub-computation: the block
      # receives the current environment and returns the one to use,
      # leaving the original environment object untouched. Outer and
      # sibling computations still see the unmodified environment.
      #
      # @param block [Proc] maps the outer environment to a local one
      # @return [Reader]
      def local(&block)
        self.class.new { |env| run(block.(env)) }
      end

      # Returns self, added to keep the interface compatible with other monads.
      #
      # @return [Reader]
      def to_reader = self

      # Returns self.
      #
      # @return [Reader]
      def to_monad = self

      # Returns the Reader monad.
      #
      # @return [Monad]
      def monad = Reader

      # @return [String]
      def to_s = "Reader(?)"
      alias_method :inspect, :to_s

      # Reader constructors
      #
      module Mixin
        # @see Dry::Monads::Reader
        Reader = Reader

        # @see Dry::Monads::Unit
        Unit = Unit

        # Reader constructors
        module Constructors
          # Reader constructor
          #
          # @example
          #   Reader { |env| env.fetch(:repo) }
          #
          # @param block [Proc] a computation depending on the environment
          # @return [Reader]
          def Reader(&) = Reader.new(&)

          # Environment accessor constructor
          #
          # @example
          #   Ask()                       # => returns the whole environment
          #   Ask(-> env { env[:repo] })  # => returns env[:repo]
          #   Ask { |env| env[:repo] }    # => same, with a block
          #
          # @param selector [#call, nil] maps the environment to a part of it
          # @param block [Proc] selector given as a block
          # @return [Reader]
          def Ask(selector = nil, &block) = Reader.ask(selector || block)
        end

        include Constructors
      end
    end

    require "dry/monads/registry"
    register_mixin(:reader, Reader::Mixin)
  end
end
