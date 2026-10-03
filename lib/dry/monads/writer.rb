# frozen_string_literal: true

module Dry
  module Monads
    # The Writer monad. Combines a value with an accumulated log, which is
    # useful for computations that should return a result along with a
    # structured trail of what happened (audit logs, explanations, and so on).
    #
    # The log type is configurable with two class-level settings:
    #
    # - +log_empty+ - a callable producing a fresh empty log (or a value that
    #   can be duplicated). Every Writer instance gets its own empty log, so
    #   no mutable state is shared between instances.
    # - +log_combine+ - a callable appending one log to another. The default
    #   is array concatenation, which is not commutative: entries appear in
    #   the order the computations ran.
    #
    # Both settings are inheritable, so custom log types can be introduced
    # with a subclass.
    #
    # @example basic usage
    #   Writer.tell([:checked_age]).bind { Writer.pure(:approved) }
    #   # => Writer(:approved, log: [:checked_age])
    #
    # @example custom log type
    #   class StringWriter < Dry::Monads::Writer
    #     log_empty -> { +"" }
    #     log_combine ->(acc, fragment) { acc + fragment }
    #   end
    #
    # @api public
    class Writer
      extend Core::ClassAttributes

      defines :log_empty, :log_combine

      # Callable producing a fresh empty log for every new Writer
      log_empty -> { [] }

      # Callable appending a log fragment to an accumulated log
      log_combine ->(acc, fragment) { acc + fragment }

      include Dry::Equalizer(:value!, :log)

      # The accumulated log
      #
      # @return [Object]
      attr_reader :log

      class << self
        # Wraps a value with Writer, starting with an empty log.
        #
        # @overload pure(value)
        #   @param value [Object] value to be wrapped with Writer
        #   @return [Writer]
        #
        # @overload pure(&block)
        #   @param block [Proc] block to be wrapped with Writer
        #   @return [Writer]
        #
        def pure(value = Undefined, &block)
          new(Undefined.default(value, block))
        end

        # Records a log fragment. The value of the resulting Writer is Unit.
        #
        # @param fragment [Object] log fragment appended to an empty log
        # @return [Writer]
        def tell(fragment)
          new(Unit, append_log(fresh_log, fragment))
        end

        # Builds a fresh empty log so that mutable logs are never shared
        # between instances.
        #
        # @return [Object]
        # @api private
        def fresh_log
          empty = log_empty
          empty.respond_to?(:call) ? empty.call : empty.dup
        end

        # Appends a fragment to a log using the configured combinator.
        #
        # @return [Object]
        # @api private
        def append_log(acc, fragment) = log_combine.(acc, fragment)
      end

      # @param value [Object] the wrapped value
      # @param log [Object] the accumulated log, defaults to a fresh empty log
      def initialize(value = Unit, log = Undefined)
        super()

        @value = value
        @log = log.equal?(Undefined) ? self.class.fresh_log : log
      end

      # Extracts the value.
      #
      # @return [Object]
      def value! = @value

      # Returns self.
      #
      # @return [Writer]
      def to_monad = self

      # Returns the Writer class (or subclass) of this instance.
      #
      # @return [Monad]
      def monad = self.class

      # Lifts a block/proc over the value, keeping the log untouched.
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

      # Sequences two Writer computations, appending the log of the
      # sub-computation after the current log. Since the default combinator
      # is not commutative, entries are ordered by execution.
      #
      # @overload bind(proc)
      #   @param proc [#call]
      #   @return [Writer]
      #
      # @overload bind
      #   @yieldreturn [Writer]
      #   @return [Writer]
      #
      def bind(proc = Undefined, &block)
        f = Undefined.default(proc, block)
        result = f.(@value)
        self.class.new(result.value!, self.class.append_log(@log, result.log))
      end

      # Observes the log accumulated by this computation so far, exposing it
      # as part of the value. The log itself is kept, so downstream
      # computations still append to it.
      #
      # @example
      #   Writer.tell([:a]).listen.bind { |(v, log)| Writer.pure(log) }
      #   # => Writer([:a], log: [:a])
      #
      # @return [Writer] value is a (value, log) pair
      def listen
        self.class.new([@value, @log], @log)
      end

      # Transforms the log accumulated by this computation. Logs appended
      # later by surrounding computations are not affected.
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

      # @return [String]
      def inspect
        if Unit.equal?(@value)
          "Writer(log: #{@log.inspect})"
        else
          "Writer(#{@value.inspect}, log: #{@log.inspect})"
        end
      end
      alias_method :to_s, :inspect

      # @param other [Object]
      # @return [Boolean]
      def ===(other)
        other.instance_of?(self.class) &&
          value! === other.value! &&
          log === other.log
      end

      # Pattern matching on the value and the log
      #
      # @example
      #   case Writer.tell([:denied])
      #   in Writer[Unit, Array => log]
      #     # ...
      #   end
      #
      # @api private
      def deconstruct = [@value, @log]

      # Pattern matching on the value and the log by key
      #
      # @example
      #   case writer
      #   in Writer(value: :approved, log: Array => explanation)
      #     # ...
      #   end
      #
      # @api private
      def deconstruct_keys(_keys) = {value: @value, log: @log}

      # Mixin with Writer constructors
      #
      module Mixin
        # @see Dry::Monads::Writer
        Writer = Writer

        # Actual constructor methods
        #
        module Constructors
          # Writer constructor, starts with an empty log
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
            v = Undefined.default(value, block)
            raise ArgumentError, "No value given" if !value.nil? && v.nil?

            Writer.new(v)
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
