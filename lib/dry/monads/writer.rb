# frozen_string_literal: true

module Dry
  module Monads
    # Writer is a monad that pairs a computed value with a log, a structured
    # record explaining how the value was produced. A typical use case is
    # returning a business decision along with a human-readable trace of the
    # rules that fired while computing it.
    #
    # The log algebra is configurable with two class-level settings:
    #
    # * +empty+ — the empty log. It can be a callable (invoked every time
    #   a fresh log is needed) or a plain value (duplicated every time so
    #   that a mutable empty log is never shared between instances).
    # * +combine+ — a callable appending one log to another. It is not
    #   required to be commutative, logs are always concatenated in the
    #   order the computations were sequenced.
    #
    # Logs are accumulated per computation and never written to a shared
    # global structure. Every operation returns a new Writer, nothing is
    # mutated in place.
    #
    # @example basic usage
    #   Writer.pure(2).tell([:started]).fmap { _1 * 10 }.tell([:doubled])
    #   # => Writer(20, [:started, :doubled])
    #
    # @example custom log algebra
    #   class DecisionLog < Dry::Monads::Writer
    #     empty -> { [] }
    #     combine ->(acc, log) { acc + log }
    #   end
    #
    # @api public
    class Writer
      include Dry::Equalizer(:value!, :log)
      extend Core::ClassAttributes

      defines :empty, :combine

      # @see Writer
      empty -> { [] }
      combine ->(acc, log) { acc + log }

      class << self
        # Wraps a value with an empty log.
        #
        # @overload pure(value)
        #   @param value [Object] value to be wrapped
        #   @return [Writer]
        #
        # @overload pure(&block)
        #   @param block [Proc] block to be wrapped
        #   @return [Writer]
        #
        def pure(value = Undefined, &block)
          new(Undefined.default(value, block))
        end

        # Builds a computation that carries no meaningful value
        # and only records the given log.
        #
        # @param log [Object] log to record
        # @return [Writer]
        def tell(log)
          new(Unit, log)
        end

        # Builds a fresh empty log. Callables are invoked, plain values
        # are duplicated so that mutable logs are never shared between
        # instances.
        #
        # @return [Object]
        # @api private
        def empty_log
          proto = empty()

          if proto.respond_to?(:call)
            proto.call
          else
            begin
              proto.dup
            rescue TypeError
              proto
            end
          end
        end

        # @api private
        def combine_logs(left, right)
          combine.call(left, right)
        end
      end

      # The accumulated log
      #
      # @return [Object]
      attr_reader :log

      def initialize(value, log = Undefined)
        @value = value
        @log = Undefined.default(log) { self.class.empty_log }
      end

      # Extracts the value.
      #
      # @return [Object]
      def value! = @value

      # Lifts a block/proc over the value, the log is kept intact.
      #
      # @overload fmap(proc)
      #   @param proc [#call]
      #   @return [Writer]
      #
      # @overload fmap
      #   @param block [Proc]
      #   @return [Writer]
      #
      def fmap(proc = Undefined, &block)
        f = Undefined.default(proc, block)
        self.class.new(f.(@value), @log)
      end

      # Sequences two computations. The log of the inner computation is
      # appended to the log accumulated so far, preserving the order in
      # which the computations ran.
      #
      # @overload bind(proc)
      #   @param proc [#call]
      #   @return [Writer]
      #
      # @overload bind
      #   @param block [Proc]
      #   @return [Writer]
      #
      def bind(proc = Undefined, &block)
        f = Undefined.default(proc, block)
        result = f.(@value)
        self.class.new(result.value!, self.class.combine_logs(@log, result.log))
      end

      # Appends to the log, the value is kept intact.
      #
      # @param log [Object] log to append
      # @return [Writer]
      def tell(log)
        self.class.new(@value, self.class.combine_logs(@log, log))
      end

      # Exposes the log of this computation as part of the value.
      # The log itself is left untouched so outer computations keep
      # accumulating as usual.
      #
      # @return [Writer] a Writer with a [value, log] pair as its value
      def listen
        self.class.new([@value, @log], @log)
      end

      # Transforms the log of this computation with a block/proc.
      # Only the log accumulated within this computation is affected,
      # logs of outer computations are out of scope.
      #
      # @overload censor(proc)
      #   @param proc [#call]
      #   @return [Writer]
      #
      # @overload censor
      #   @param block [Proc]
      #   @return [Writer]
      #
      def censor(proc = Undefined, &block)
        f = Undefined.default(proc, block)
        self.class.new(@value, f.(@log))
      end

      # Returns self.
      #
      # @return [Writer]
      def to_monad = self

      # Returns the Writer class.
      #
      # @return [Class]
      def monad = self.class

      # @return [String]
      def inspect = "Writer(#{@value.inspect}, #{@log.inspect})"
      alias_method :to_s, :inspect

      # @param other [Object]
      # @return [Boolean]
      def ===(other)
        other.instance_of?(self.class) && value! === other.value! && log === other.log
      end

      # @return [Array]
      def deconstruct = [@value, @log]

      # @param keys [Array<Symbol>, nil]
      # @return [Hash]
      def deconstruct_keys(keys)
        hash = {value: @value, log: @log}
        keys.nil? ? hash : hash.slice(*keys)
      end

      # Mixin with Writer constructors
      #
      module Mixin
        # @see Dry::Monads::Writer
        Writer = Writer

        # Actual constructor methods
        #
        module Constructors
          # Writer constructor, wraps a value with an empty log
          #
          # @overload Writer(value)
          #   @param value [Object]
          #   @return [Writer]
          #
          # @overload Writer(&block)
          #   @param block [Proc]
          #   @return [Writer]
          #
          def Writer(value = Undefined, &block)
            Writer.new(Undefined.default(value, block))
          end

          # Tell constructor, records a log with no meaningful value
          #
          # @param log [Object]
          # @return [Writer]
          def Tell(log)
            Writer.tell(log)
          end
        end

        include Constructors
      end
    end

    extend Writer::Mixin::Constructors

    require "dry/monads/registry"
    register_mixin(:writer, Writer::Mixin)
  end
end
