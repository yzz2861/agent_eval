# frozen_string_literal: true

module GraphQL
  module Execution
    # A debugging session for watching query execution step by step.
    #
    # A StepSession executes a single query on its own set of fibers and
    # pauses at resolver and batch-loading boundaries, so that complex
    # resolver behavior can be inspected while it happens. It is only used
    # when explicitly constructed: Schema.execute and Schema.multiplex
    # never go through this code path.
    #
    # While paused, #snapshot returns a read-only view of work that is
    # still pending (jobs, batch loads, lazies) and of fibers waiting on
    # batch loads. Resuming never re-runs a resolver that already ran:
    # execution continues exactly where it paused.
    #
    # Schema-level tracers and trace_with modes are not run inside a
    # session; the session installs its own trace instead.
    #
    # @example Step through a query field by field
    #   session = GraphQL::Execution::StepSession.new(MySchema, "{ user { name } }")
    #   while (snapshot = session.step)
    #     puts snapshot.event.type.to_s + ": " + snapshot.event.field_path.to_s
    #   end
    #   result = session.result
    #
    class StepSession
      # Raised when a session is used in a way incompatible with its state,
      # for example stepping a terminated session.
      class SessionError < GraphQL::Error; end

      # Raised inside session-owned fibers to unwind execution when
      # #terminate is called. It inherits from Exception so that it
      # isn't swallowed by "rescue StandardError" handlers in the runtime;
      # it never escapes the session itself.
      # @api private
      class Terminated < Exception; end

      # Valid targets for #step:
      #
      # - :field_start -- pause right before a field resolver is called
      # - :field_end -- pause right after a field resolver returned
      # - :batch -- pause when a batch load is about to happen
      #   (a GraphQL::Dataloader::Source fetch or a lazy-resolution round)
      MODES = [:field_start, :field_end, :batch].freeze

      # A point where execution paused. Instances are frozen.
      class Event
        # @return [:field_start, :field_end, :batch] What kind of boundary was reached
        attr_reader :type

        # @return [String, nil] eg "Query.user", for :field_start and :field_end events
        attr_reader :field_path

        # @return [String, nil] eg "Sources::RecordById", for :batch events
        #   caused by a GraphQL::Dataloader::Source; nil for lazy-resolution rounds
        attr_reader :source_class

        def initialize(type, field: nil, source: nil)
          @type = type
          @field_path = field ? field.path : nil
          @source_class = source ? source.class.name : nil
          freeze
        end

        def to_h
          { type: @type, field_path: @field_path, source_class: @source_class }.freeze
        end

        def inspect
          parts = to_h.map { |key, value| value.nil? ? nil : "#{key}=#{value.inspect}" }.compact.join(" ")
          "#<#{self.class.name} #{parts}>"
        end
      end

      # A read-only view of the session's pending and waiting state,
      # captured while execution is paused. Instances are deeply frozen.
      class Snapshot
        # @return [:pending, :paused, :finished, :terminated, :failed]
        attr_reader :status

        # @return [Event, nil] The boundary where execution is paused, if any
        attr_reader :event

        # @return [Integer] Execution jobs queued but not started yet
        attr_reader :pending_jobs

        # @return [Array<Hash>] Batch loads waiting to run, as frozen
        #   { source: "SourceClassName", keys: Integer } hashes
        attr_reader :pending_sources

        # @return [Integer] Lazy values scheduled but not resolved yet
        attr_reader :pending_lazies

        # @return [Integer] Execution fibers currently waiting for batch loads
        attr_reader :waiting_fibers

        # @return [Array<String>] Names of source classes that fibers are waiting on
        attr_reader :waiting_sources

        # @return [Integer] Field resolutions started so far
        attr_reader :fields_started

        # @return [Integer] Field resolutions finished so far
        attr_reader :fields_finished

        def initialize(status:, event:, pending_jobs:, pending_sources:, pending_lazies:, waiting_fibers:, waiting_sources:, fields_started:, fields_finished:)
          @status = status
          @event = event
          @pending_jobs = pending_jobs
          @pending_sources = pending_sources.map { |source_info| source_info.freeze }.freeze
          @pending_lazies = pending_lazies
          @waiting_fibers = waiting_fibers
          @waiting_sources = waiting_sources.freeze
          @fields_started = fields_started
          @fields_finished = fields_finished
          freeze
        end

        def to_h
          {
            status: @status,
            event: @event ? @event.to_h : nil,
            pending_jobs: @pending_jobs,
            pending_sources: @pending_sources.map(&:dup).freeze,
            pending_lazies: @pending_lazies,
            waiting_fibers: @waiting_fibers,
            waiting_sources: @waiting_sources.dup.freeze,
            fields_started: @fields_started,
            fields_finished: @fields_finished,
          }.freeze
        end
      end

      # The trace installed on the session's query and multiplex. It
      # notifies the session about resolver and batch-loading boundaries.
      # @api private
      class StepTrace < GraphQL::Tracing::Trace
        def initialize(session)
          @session = session
          super()
        end

        def begin_execute_field(field, object, arguments, query)
          @session.__send__(:field_started, field)
          super
        end

        def end_execute_field(field, object, arguments, query, result)
          @session.__send__(:field_finished, field)
          super
        end

        def begin_dataloader_source(source)
          @session.__send__(:batch_started, source)
          super
        end

        def execute_query_lazy(query:, multiplex:)
          @session.__send__(:lazy_round_started)
          super
        end

        def dataloader_fiber_yield(source)
          @session.__send__(:fiber_waiting, source)
          super
        end

        def dataloader_fiber_resume(source)
          @session.__send__(:fiber_resumed, source)
          super
        end
      end

      # @return [GraphQL::Query] The query being executed by this session
      attr_reader :query

      # @param schema [Class<GraphQL::Schema>]
      # @param query_string [String, nil] The query to execute
      # @param query_kwargs [Hash] Other options for GraphQL::Query#initialize,
      #   eg variables:, operation_name:, root_value:, context:
      def initialize(schema, query_string = nil, **query_kwargs)
        @schema = schema
        @trace = StepTrace.new(self)
        query_context = (query_kwargs.delete(:context) || {}).dup
        query_context[:trace] = @trace
        @query = schema.query_class.new(schema, query_string, **query_kwargs, context: query_context)
        @multiplex_context = { trace: @trace }
        @mode = :field_start
        @status = :pending
        @started = false
        @terminating = false
        @exec_fiber = nil
        @paused_fiber = nil
        @control_fiber = nil
        @current_event = nil
        @result = nil
        @failure = nil
        @fields_started = 0
        @fields_finished = 0
        @waiting_fibers = 0
        @waiting_sources = Hash.new(0)
      end

      # @return [Boolean] true if execution is paused at a boundary
      def paused?
        @status == :paused
      end

      # @return [Boolean] true if execution ran to completion
      def finished?
        @status == :finished
      end

      # @return [Boolean] true if #terminate was called
      def terminated?
        @status == :terminated
      end

      # @return [Boolean] true if execution raised an error
      def failed?
        @status == :failed
      end

      # @return [Event, nil] The boundary where execution is currently paused
      def current_event
        @current_event
      end

      # Advance execution to the next boundary of the given kind and pause
      # there. With no argument, keeps advancing toward the same kind of
      # boundary as the previous call (initially :field_start).
      #
      # @param mode [:field_start, :field_end, :batch, nil]
      # @return [Snapshot, nil] the paused state, or nil if execution
      #   finished without reaching another boundary
      def step(mode = nil)
        if terminated?
          raise SessionError, "This session was terminated; it can't be stepped."
        elsif failed?
          raise SessionError, "This session failed with #{@failure.class}; it can't be stepped."
        elsif finished?
          return nil
        end

        if mode
          if !MODES.include?(mode)
            raise ArgumentError, "Unknown step mode #{mode.inspect}; expected one of #{MODES.map(&:inspect).join(", ")}"
          end
          @mode = mode
        end

        @control_fiber = Fiber.current
        message = if !@started
          @started = true
          @exec_fiber = Fiber.new { run_execution }
          @exec_fiber.transfer
        else
          @paused_fiber.transfer
        end
        handle_execution_message(message)
        finished? ? nil : snapshot
      end

      # Run the query to completion, ignoring any remaining boundaries.
      # @return [GraphQL::Query::Result]
      def run_to_completion
        step until finished?
        result
      end

      # Stop execution immediately. Any fibers, queued jobs, pending batch
      # loads and scheduled lazies owned by this session are discarded.
      # @return [void]
      def terminate
        return nil if terminated? || finished? || failed?

        @terminating = true
        if @started && @paused_fiber && @paused_fiber.alive?
          @control_fiber = Fiber.current
          # The paused fiber notices @terminating and raises Terminated,
          # unwinding every fiber owned by this session.
          message = @paused_fiber.transfer
          handle_execution_message(message)
        end
        reclaim_execution_state
        @status = :terminated
        nil
      end

      # @return [GraphQL::Query::Result]
      # @raise [SessionError] if execution hasn't finished (or was terminated)
      def result
        case @status
        when :finished
          @result
        when :terminated
          raise SessionError, "This session was terminated before execution finished."
        when :failed
          raise @failure
        else
          raise SessionError, "Execution hasn't finished yet; keep calling #step (or #run_to_completion) first."
        end
      end

      # @return [Snapshot] A read-only view of the current pending and
      #   waiting state; all zeros before the first #step
      def snapshot
        pending_jobs = 0
        pending_sources = []
        pending_lazies = 0
        if (dataloader = current_dataloader)
          # These internals aren't public API; read them defensively since
          # NullDataloader doesn't initialize all of them.
          jobs = dataloader.instance_variable_get(:@pending_jobs)
          pending_jobs = jobs ? jobs.size : 0
          source_cache = dataloader.instance_variable_get(:@source_cache)
          source_cache&.each_value do |batched_sources|
            batched_sources.each_value do |source|
              if source.pending?
                pending_sources << { source: source.class.name, keys: source.pending.size }
              end
            end
          end
          lazies_at_depth = dataloader.instance_variable_get(:@lazies_at_depth)
          lazies_at_depth&.each_value do |lazies|
            pending_lazies += lazies.size
          end
        end
        Snapshot.new(
          status: @status,
          event: @current_event,
          pending_jobs: pending_jobs,
          pending_sources: pending_sources,
          pending_lazies: pending_lazies,
          waiting_fibers: @waiting_fibers,
          waiting_sources: @waiting_sources.select { |_name, count| count > 0 }.keys,
          fields_started: @fields_started,
          fields_finished: @fields_finished,
        )
      end

      private

      # Runs inside @exec_fiber; transfers messages back to the control
      # fiber at every pause and when execution ends.
      def run_execution
        results = GraphQL::Execution::Interpreter.run_all(@schema, [@query], context: @multiplex_context)
        @control_fiber.transfer([:done, results.first])
      rescue Terminated
        @control_fiber.transfer([:terminated])
      rescue Exception => err
        @control_fiber.transfer([:failed, err])
      end

      def handle_execution_message(message)
        case message[0]
        when :pause
          @paused_fiber = message[1]
          @status = :paused
        when :done
          @paused_fiber = nil
          @status = :finished
          @result = message[1]
        when :terminated
          @paused_fiber = nil
          @status = :terminated
        when :failed
          @paused_fiber = nil
          @status = :failed
          @failure = message[1]
          raise @failure
        else
          raise "Invariant: unexpected message from execution fiber: #{message.inspect}"
        end
      end

      # Called from session-owned execution fibers. Transfers control back
      # to the fiber that called #step; returns when execution resumes.
      def suspend(event)
        @current_event = event
        @control_fiber.transfer([:pause, Fiber.current])
        if @terminating
          raise Terminated
        end
      end

      def field_started(field)
        return if @terminating

        @fields_started += 1
        suspend(Event.new(:field_start, field: field)) if @mode == :field_start
      end

      def field_finished(field)
        return if @terminating

        @fields_finished += 1
        suspend(Event.new(:field_end, field: field)) if @mode == :field_end
      end

      def batch_started(source)
        return if @terminating

        suspend(Event.new(:batch, source: source)) if @mode == :batch
      end

      def lazy_round_started
        return if @terminating

        suspend(Event.new(:batch)) if @mode == :batch
      end

      def fiber_waiting(source)
        @waiting_fibers += 1
        @waiting_sources[source.class.name] += 1 if source
      end

      def fiber_resumed(source)
        @waiting_fibers -= 1
        @waiting_sources[source.class.name] -= 1 if source
      end

      def current_dataloader
        @multiplex_context[:dataloader]
      end

      # Discard everything the session's dataloader still has queued, so
      # nothing is left runnable after #terminate.
      def reclaim_execution_state
        if (dataloader = current_dataloader)
          dataloader.instance_variable_get(:@pending_jobs)&.clear
          dataloader.instance_variable_get(:@pending_sources)&.clear
          dataloader.instance_variable_get(:@pending_source_set)&.clear
          dataloader.instance_variable_get(:@lazies_at_depth)&.clear
          dataloader.instance_variable_get(:@source_cache)&.each_value do |batched_sources|
            batched_sources.each_value { |source| source.pending.clear }
          end
        end
        @waiting_fibers = 0
        @waiting_sources.clear
        nil
      end

    end
  end
end
