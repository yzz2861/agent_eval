# frozen_string_literal: true

require "dry/validation/constants"

module Dry
  module Validation
    # Explicit batch-validation session for mergeable external checks
    #
    # A batch collects the normalized keys emitted by checks declared as
    # {Evaluator#external mergeable} across many contract calls. When the batch
    # is flushed, keys are grouped per query definition and context partition,
    # deduplicated (preserving input order) and handed to the query callable in
    # a single call. The per-key outcomes are then replayed back onto the
    # individual results.
    #
    # @example
    #   batch = Dry::Validation::Batch.new
    #
    #   batch.register_query(:department) do |keys, partition|
    #     gateway.fetch_departments(keys, tenant: partition)
    #   end
    #
    #   results = contracts.zip(rows).map { |contract, row|
    #     batch.call(contract, row)
    #   }
    #
    #   batch.flush
    #
    # @api public
    class Batch
      # Outcome of looking up a single normalized key
      #
      # Three mutually exclusive states are distinguished so that a network
      # failure is never reported as if the record did not exist:
      #
      # - {#found?} - the record exists and satisfies the business condition
      # - {#missing?} - the query completed but no such record was found
      # - {#error?} - the query failed (e.g. the network was unavailable)
      #
      # @api public
      class Outcome
        # @return [Symbol] one of +:found+, +:missing+ or +:error+
        # @api public
        attr_reader :status

        # @return [Object] the fetched record (for +found+ outcomes)
        # @api public
        attr_reader :record

        # @return [Object] the underlying failure (for +error+ outcomes)
        # @api public
        attr_reader :error

        # Build a found outcome
        #
        # @param record [Object]
        #
        # @return [Outcome]
        #
        # @api public
        def self.found(record = true)
          new(:found, record: record)
        end

        # Build a missing-record outcome
        #
        # @return [Outcome]
        #
        # @api public
        def self.missing
          new(:missing)
        end

        # Build a query-failure outcome
        #
        # @param error [Object] exception or another failure value
        #
        # @return [Outcome]
        #
        # @api public
        def self.error(error)
          new(:error, error: error)
        end

        # @api private
        def initialize(status, record: nil, error: nil)
          @status = status
          @record = record
          @error = error
          freeze
        end

        # @return [Boolean]
        # @api public
        def found?
          status.equal?(:found)
        end

        # @return [Boolean]
        # @api public
        def missing?
          status.equal?(:missing)
        end

        # @return [Boolean]
        # @api public
        def error?
          status.equal?(:error)
        end

        # @api private
        def ==(other)
          other.is_a?(self.class) &&
            status == other.status &&
            record == other.record &&
            error == other.error
        end
        alias_method :eql?, :==

        # @api private
        def hash
          [self.class, status, record, error].hash
        end

        # @return [String]
        # @api public
        def inspect
          case status
          when :found then "#<#{self.class} found record=#{record.inspect}>"
          when :missing then "#<#{self.class} missing>"
          else "#<#{self.class} error=#{error.inspect}>"
          end
        end
      end

      # Definition of a mergeable query
      #
      # @!attribute [r] name
      #   @return [Symbol]
      # @!attribute [r] callable
      #   @return [#call]
      # @!attribute [r] normalizer
      #   @return [#call]
      # @!attribute [r] partitioner
      #   @return [Symbol, #call, nil]
      #
      # @api private
      Query = ::Struct.new(:name, :callable, :normalizer, :partitioner)

      # Suspended external check awaiting the flush
      #
      # @!attribute [r] query_name
      #   @return [Symbol]
      # @!attribute [r] key
      #   @return [Object] normalized key
      # @!attribute [r] partition
      #   @return [Object] context partition value
      # @!attribute [r] evaluator
      #   @return [Evaluator]
      # @!attribute [r] block
      #   @return [Proc]
      #
      # @api private
      Pending = ::Struct.new(:query_name, :key, :partition, :evaluator, :block)

      # Registered queries keyed by their name
      #
      # @return [Hash{Symbol => Query}]
      #
      # @api public
      attr_reader :queries

      # Create a new batch session and evaluate the block on it
      #
      # @example
      #   batch = Dry::Validation::Batch.new do
      #     register_query(:department) { |keys| ... }
      #   end
      #
      # @yieldparam batch [Batch]
      #
      # @api public
      def initialize
        @queries = {}
        @pending = []
        @results = []
        @flushed = false
        yield(self) if block_given?
      end

      # Register a mergeable query definition
      #
      # The callable receives the deduplicated keys and must return a Hash
      # mapping each key to a record, +nil+ (record missing) or an {Outcome}.
      # Keys missing from the returned Hash are treated as missing records.
      #
      # @param name [Symbol] query definition name referenced by the rule
      # @param partition [Symbol, #call] how the context partition is derived;
      #   a Symbol reads that key from the rule context, a callable receives
      #   the context Hash, nil keeps every key in the same partition
      # @param normalize [#call] optional key normalizer applied before the
      #   keys are collected and deduplicated
      #
      # @return [self]
      #
      # @api public
      def register_query(name, partition: nil, normalize: nil, &callable)
        raise ::ArgumentError, "a query callable is required" if callable.nil?
        raise ::ArgumentError, "query #{name.inspect} is already registered" if @queries.key?(name)

        @queries[name] = Query.new(name, callable, normalize, partition)
        self
      end

      # Run a contract within the batch session
      #
      # Checks declared as mergeable are suspended until {#flush} is called;
      # ordinary rules run normally. The result stays unfrozen until the flush.
      #
      # @param contract [Contract]
      # @param input [Hash]
      # @param context [Hash]
      #
      # @return [Result]
      #
      # @api public
      def call(contract, input, context = EMPTY_HASH)
        ensure_not_flushed!
        contract.call(input, context.merge(BATCH_CONTEXT_KEY => self)).tap do |result|
          @results << result
        end
      end

      # Flush the collected checks
      #
      # Every query definition/context partition combination performs exactly
      # one callable invocation. Outcomes are replayed onto the results in the
      # same order the checks were registered, then all results are frozen.
      #
      # @return [Array<Result>] the frozen results, in submission order
      #
      # @api public
      def flush
        ensure_not_flushed!
        @flushed = true

        @pending.each { |pending| run_group(pending.query_name, pending.partition) }
        @pending.each(&method(:replay))

        @results.uniq(&:object_id).each(&:freeze)
        @results
      end

      # Whether {#flush} has already been called
      #
      # @return [Boolean]
      #
      # @api public
      def flushed?
        @flushed
      end

      # @api private
      def register_pending(query_name, raw_key, evaluator, &block)
        ensure_not_flushed!

        query = @queries.fetch(query_name) {
          raise UnknownQueryError.new(query_name, @queries.keys)
        }

        partition = resolve_partition(query.partitioner, evaluator._context)
        key = query.normalizer ? query.normalizer.call(raw_key) : raw_key

        @pending << Pending.new(query_name, key, partition, evaluator, block)
        key
      end

      private

      # @api private
      def ensure_not_flushed!
        return unless @flushed

        raise BatchFlushedError, "batch session has already been flushed"
      end

      # @api private
      def resolve_partition(partitioner, context)
        case partitioner
        when nil
          nil
        when ::Symbol
          context[partitioner]
        else
          partitioner.call(public_context(context))
        end
      end

      # @api private
      def run_group(query_name, partition)
        @outcomes ||= {}
        group_key = [query_name, partition]

        return if @outcomes.key?(group_key)

        query = @queries.fetch(query_name)
        group = @pending.select { |pending|
          pending.query_name.equal?(query_name) && pending.partition == partition
        }
        keys = group.map(&:key).uniq

        outcomes = invoke(
          query.callable,
          keys,
          partition,
          group.first.evaluator._context
        )

        @outcomes[group_key] = keys.each_with_object({}) do |key, map|
          map[key] = outcomes.fetch(key, Outcome.missing)
        end
      end

      # @api private
      def public_context(context)
        context.each.to_h.reject { |key,| key.equal?(BATCH_CONTEXT_KEY) }
      end

      # @api private
      def invoke(callable, keys, partition, context)
        arity = callable.respond_to?(:arity) ? callable.arity : 3
        context_snapshot = public_context(context)
        value =
          case arity
          when 1 then callable.call(keys)
          when 2 then callable.call(keys, partition)
          when 0 then callable.call
          else callable.call(keys, partition, context_snapshot)
          end

        coerce(value)
      rescue ::StandardError => e
        # A malformed return value is a programming error, not a lookup outage
        raise if e.is_a?(QueryResultError)

        keys.each_with_object({}) { |key, hash| hash[key] = Outcome.error(e) }
      end

      # @api private
      def coerce(value)
        unless value.is_a?(::Hash)
          raise QueryResultError,
                "query must return a Hash of outcomes, #{value.class} was returned"
        end

        value.transform_values do |entry|
          case entry
          when Outcome then entry
          when nil then Outcome.missing
          else Outcome.found(entry)
          end
        end
      end

      # @api private
      def replay(pending)
        outcome = @outcomes.fetch([pending.query_name, pending.partition]).fetch(pending.key)
        replayed = pending.evaluator.with(macros: EMPTY_ARRAY)

        replayed.instance_exec(
          **replay_kwargs(pending.block, replayed, outcome),
          &pending.block
        )

        replayed._contract.apply_rule_failures(
          replayed.result,
          replayed.failures
        )
      end

      # @api private
      def replay_kwargs(block, evaluator, outcome)
        block.parameters.each_with_object({}) do |(kind, name), kwargs|
          next unless kind.equal?(:keyreq) || kind.equal?(:key)

          if name.equal?(:outcome)
            kwargs[name] = outcome
          else
            option_name = BLOCK_OPTIONS_MAPPINGS[name]

            if evaluator._options.key?(option_name)
              kwargs[name] = evaluator._options[option_name]
            end
          end
        end
      end
    end
  end
end
