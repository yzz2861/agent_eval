# frozen_string_literal: true

module GraphQL
  module Execution
    # An explicit, opt-in debugging session for stepping through query execution.
    #
    # This is _not_ used by {Schema.execute} or {Schema.multiplex}; it only runs
    # when application code builds one by hand. It executes a single query inside
    # session-owned Fibers and lets the caller pause execution at:
    #
    # - field starts (just before a resolver is called)
    # - field ends (just after a resolver returned)
    # - batch load boundaries (just before a {GraphQL::Dataloader::Source} runs its pending keys)
    #
    # While paused, {#pending_state} returns a read-only snapshot of queued and
    # waiting work. Execution is forward-only: resuming a session never
    # re-invokes a resolver that already ran. Call {#terminate} to abort a
    # session, which unwinds the session-owned Fibers and discards queued and
    # waiting work.
    #
    # @example Step through every boundary, then read the result
    #   session = GraphQL::Execution::DebugSession.new(MySchema, "{ a b }")
    #   while (pause = session.step)
    #     puts "#{pause.kind}: #{pause.label}"
    #   end
    #   session.result.to_h
    #
    class DebugSession
      # Raised when stepping a session that was terminated.
      class TerminatedError < GraphQL::Error; end

      # Raised inside session-owned fibers to unwind them during {#terminate}.
      # Inherits from Exception so that GraphQL's "rescue StandardError"
      # error handling doesn't intercept it.
      class TerminateExecution < Exception; end # rubocop:disable Lint/InheritException

      # All boundary kinds that {#step} can pause at.
      BOUNDARY_KINDS = [:field_start, :field_end, :batch].freeze

      # Yielded by paused fibers; recognized by {SteppingDataloader#run_fiber},
      # which propagates it up through the Dataloader's fiber hierarchy.
      PAUSE_SIGNAL = Object.new.freeze

      # A frozen, read-only description of where execution is paused.
      class Pause
        # @return [:field_start, :field_end, :batch]
        attr_reader :kind

        # @return [String] Field path (eg "Query.viewer.name") or Dataloader source class name
        attr_reader :label

        # @return [GraphQL::Schema::Field, nil] The field being resolved, for :field_start and :field_end
        attr_reader :field

        # @return [GraphQL::Dataloader::Source, nil] The source about to run, for :batch
        attr_reader :source

        # @return [Hash] Frozen snapshot of queued and waiting work, see {DebugSession#pending_state}
        attr_reader :pending_state

        def initialize(kind:, label:, pending_state:, field: nil, source: nil)
          @kind = kind
          @label = label
          @field = field
          @source = source
          @pending_state = pending_state
          freeze
        end

        def field_start?
          @kind == :field_start
        end

        def field_end?
          @kind == :field_end
        end

        def batch?
          @kind == :batch
        end
      end

      # Mixed into a schema-specific {GraphQL::Dataloader} subclass so that
      # pause signals propagate from job/source fibers up to the session,
      # and so the session can inspect queued and waiting work.
      module SteppingDataloader
        # Resume "fiber"; if it pauses, propagate the pause to this fiber's
        # resumer, then resume "fiber" again when control comes back.
        # This makes pauses transparent to the stock scheduling logic.
        def run_fiber(fiber)
          result = fiber.resume
          while PAUSE_SIGNAL.equal?(result) && fiber.alive?
            Fiber.yield(result)
            result = fiber.resume
          end
          result
        end

        def spawn_fiber(&block)
          fiber = super
          debug_fibers << fiber
          fiber
        end

        def yield(source = Fiber[:__graphql_current_dataloader_source])
          @debug_waiting_fibers = debug_waiting_fibers + 1
          super
          # When the session is terminated, waiting fibers are resumed
          # so that they can unwind themselves here:
          if debug_terminated?
            raise TerminateExecution
          end
        ensure
          @debug_waiting_fibers = debug_waiting_fibers - 1
        end

        # @return [Boolean] Whether the session is being terminated
        def debug_terminated?
          @debug_terminated ||= false
        end

        # Mark this dataloader as terminated; waiting fibers will unwind
        # when they're resumed by {#debug_reclaim_fibers!}.
        # @return [void]
        def debug_terminate!
          @debug_terminated = true
          nil
        end

        # Resume any still-alive fibers (eg, fibers waiting for batch-loaded
        # data) so they unwind themselves, then forget them.
        # @return [void]
        def debug_reclaim_fibers!
          debug_fibers.each do |fiber|
            if fiber.alive?
              begin
                fiber.resume
              rescue TerminateExecution
                # Expected: the fiber unwound itself.
              end
            end
          end
          debug_fibers.clear
          nil
        end

        # @return [Hash] Frozen, read-only snapshot of queued and waiting work
        def debug_pending_state
          waiting_sources = []
          if defined?(@pending_sources) && @pending_sources
            @pending_sources.each do |source|
              waiting_sources << { source_class: source.class.name, pending_keys: source.pending.size }.freeze
            end
          end
          waiting_lazies = 0
          if defined?(@lazies_at_depth) && @lazies_at_depth
            @lazies_at_depth.each_value { |lazies| waiting_lazies += lazies.size }
          end
          pending_jobs = defined?(@pending_jobs) && @pending_jobs ? @pending_jobs.size : 0
          {
            pending_jobs: pending_jobs,
            waiting_sources: waiting_sources.freeze,
            waiting_lazies: waiting_lazies,
            waiting_fibers: debug_waiting_fibers,
            alive_fibers: debug_alive_fiber_count,
          }.freeze
        end

        # Discard queued jobs, waiting sources, and pending lazy values.
        # @return [void]
        def debug_clear_pending!
          @pending_jobs&.clear
          @pending_sources&.clear
          @pending_source_set&.clear
          @lazies_at_depth&.clear
          if defined?(@source_cache) && @source_cache
            @source_cache.each_value do |batched_sources|
              batched_sources.each_value { |source| source.pending.clear }
            end
          end
          nil
        end

        private

        def debug_fibers
          @debug_fibers ||= []
        end

        def debug_waiting_fibers
          @debug_waiting_fibers ||= 0
        end

        def debug_alive_fiber_count
          debug_fibers.reject! { |fiber| !fiber.alive? }
          debug_fibers.size
        end
      end

      # Mixed into a subclass of the schema's own trace class so that
      # resolver and batch-load boundaries are reported to the session.
      module TraceHooks
        attr_accessor :debug_session

        def begin_execute_field(field, object, arguments, query)
          debug_session&.send(:field_boundary, :field_start, field)
          super
        end

        def end_execute_field(field, object, arguments, query, result)
          super
          debug_session&.send(:field_boundary, :field_end, field)
        end

        def begin_dataloader_source(source)
          debug_session&.send(:batch_boundary, source)
          super
        end
      end

      # @return [Pause, nil] The boundary where execution is currently paused
      attr_reader :pause

      # @param schema [Class<GraphQL::Schema>]
      # @param query_str [String, nil] GraphQL query string (or pass "query:" in "query_options")
      # @param max_complexity [nil, Integer]
      # @param query_options [Hash] Other options accepted by {Schema#execute} ("variables:", "context:", "operation_name:", "root_value:", ...)
      def initialize(schema, query_str = nil, max_complexity: nil, **query_options)
        @schema = schema
        if query_str
          query_options[:query] = query_str
        end
        @query_options = query_options
        @max_complexity = max_complexity
        @state = :ready
        @pause = nil
        @awaiting = BOUNDARY_KINDS
        @results = nil
        @error = nil
        @driver_done = false

        @dataloader = build_dataloader
        @trace = build_trace

        @driver_fiber = Fiber.new do
          begin
            multiplex_context = {
              dataloader: @dataloader,
              trace: @trace,
            }
            @results = GraphQL::Execution::Interpreter.run_all(
              @schema, [@query_options],
              context: multiplex_context,
              max_complexity: @max_complexity
            )
          rescue TerminateExecution
            # #terminate was called; the session is unwinding quietly.
          rescue Exception => err # rubocop:disable Lint/RescueException
            @error = err
          ensure
            @driver_done = true
          end
        end
      end

      # Advance to the next boundary of any kind and pause there.
      # @return [Pause, nil] nil when execution finished without pausing again
      def step
        advance(BOUNDARY_KINDS)
      end

      # Advance to just before the next resolver call and pause there.
      # @return [Pause, nil]
      def step_to_field_start
        advance([:field_start])
      end

      # Advance to just after the next resolver return and pause there.
      # @return [Pause, nil]
      def step_to_field_end
        advance([:field_end])
      end

      # Advance to just before the next Dataloader batch load and pause there.
      # @return [Pause, nil]
      def step_to_batch
        advance([:batch])
      end

      # Finish executing the query without pausing again.
      # @return [GraphQL::Query::Result, nil]
      def run
        advance(EMPTY_ARRAY)
        result
      end

      # @return [GraphQL::Query::Result, nil] The query result, once {#finished?}
      def result
        @driver_done && @results ? @results.first : nil
      end

      # @return [Hash] Frozen, read-only snapshot of queued and waiting work:
      #   :pending_jobs (Integer) queued execution jobs,
      #   :waiting_sources (Array<Hash>) sources with keys waiting to be loaded,
      #   :waiting_lazies (Integer) lazy values waiting to be resolved,
      #   :waiting_fibers (Integer) fibers blocked waiting for batch-loaded data,
      #   :alive_fibers (Integer) session-owned fibers still alive
      def pending_state
        @dataloader.debug_pending_state
      end

      # Abort this session: unwind session-owned fibers and discard queued
      # and waiting work. Stepping a terminated session raises {TerminatedError}.
      # @return [void]
      def terminate
        return if terminated?
        was_paused = paused?
        @state = :terminated
        @dataloader.debug_terminate!
        if was_paused
          # Wakes the paused boundary hook, which raises TerminateExecution
          # and unwinds the paused fiber chain.
          @driver_fiber.resume
        end
        @dataloader.debug_reclaim_fibers!
        @dataloader.debug_clear_pending!
        @pause = nil
        nil
      end

      def paused?
        @state == :paused
      end

      def finished?
        @state == :finished
      end

      def terminated?
        @state == :terminated
      end

      def ready?
        @state == :ready
      end

      private

      EMPTY_ARRAY = [].freeze

      def advance(kinds)
        if terminated?
          raise TerminatedError, "This debug session was terminated; it can't be resumed."
        end
        return nil if finished?
        @awaiting = kinds
        @pause = nil
        @state = :running
        @driver_fiber.resume
        if @error
          error = @error
          @error = nil
          @state = :finished
          raise error
        end
        if @driver_done
          @state = :finished
          nil
        else
          @pause
        end
      end

      # Called from {TraceHooks} inside session-owned fibers.
      # @return [void]
      def field_boundary(kind, field)
        return unless @state == :running && @awaiting.include?(kind)
        pause_at(Pause.new(
          kind: kind,
          label: field.path,
          field: field,
          pending_state: @dataloader.debug_pending_state,
        ))
      end

      # Called from {TraceHooks} inside session-owned fibers.
      # @return [void]
      def batch_boundary(source)
        return unless @state == :running && @awaiting.include?(:batch)
        pause_at(Pause.new(
          kind: :batch,
          label: source.class.name || source.class.to_s,
          source: source,
          pending_state: @dataloader.debug_pending_state,
        ))
      end

      def pause_at(pause)
        @pause = pause
        @state = :paused
        Fiber.yield(PAUSE_SIGNAL)
        # Resumed by the next #advance call -- or by #terminate:
        if terminated?
          raise TerminateExecution
        end
        nil
      end

      def build_dataloader
        base_class = @schema.dataloader_class
        stepping_class = Class.new(base_class) do
          include SteppingDataloader
        end
        # Force blocking fibers so that Fiber.yield can pause execution;
        # NullDataloader ignores the keyword.
        stepping_class.new(nonblocking: false)
      end

      def build_trace
        trace_class = Class.new(@schema.trace_class) do
          include TraceHooks
        end
        trace_options = if @schema.respond_to?(:trace_options_for)
          @schema.trace_options_for(:default)
        else
          EMPTY_HASH
        end
        trace = trace_class.new(multiplex: nil, **trace_options)
        trace.debug_session = self
        trace
      end
    end
  end
end
