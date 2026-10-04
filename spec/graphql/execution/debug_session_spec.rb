# frozen_string_literal: true
require "spec_helper"

module DebugSessionSpec
  # A lazy value whose resolved value is controlled by the test
  # and whose resolutions are counted.
  class ControlledLazy
    attr_accessor :lazy_value
    attr_reader :resolve_calls

    def initialize(value)
      @lazy_value = value
      @resolve_calls = 0
    end

    def value
      @resolve_calls += 1
      @lazy_value
    end
  end

  class CountingSource < GraphQL::Dataloader::Source
    class << self
      attr_accessor :fetch_calls
    end

    def fetch(keys)
      self.class.fetch_calls += 1
      keys.map { |key| "item-#{key}" }
    end
  end

  class ChildType < GraphQL::Schema::Object
    graphql_name "Child"
    field :name, String, null: false
  end

  class QueryType < GraphQL::Schema::Object
    graphql_name "Query"

    field :plain, String, null: false
    field :lazy_value, String, null: false
    field :item, String, null: false do
      argument :id, Integer, required: true
    end
    field :child, ChildType, null: false

    def plain
      DebugSchema.counters[:plain] += 1
      "plain"
    end

    def lazy_value
      DebugSchema.counters[:lazy_value] += 1
      lazy = ControlledLazy.new(DebugSchema.controlled_values.fetch(:lazy_value, "lazy"))
      DebugSchema.lazies << lazy
      lazy
    end

    def item(id:)
      DebugSchema.counters[:item] += 1
      dataloader.with(CountingSource).load(id)
    end

    def child
      DebugSchema.counters[:child] += 1
      { name: "child-name" }
    end
  end

  class DebugSchema < GraphQL::Schema
    use GraphQL::Dataloader
    lazy_resolve(ControlledLazy, :value)
    query(QueryType)

    class << self
      def counters
        @counters ||= Hash.new(0)
      end

      def lazies
        @lazies ||= []
      end

      def controlled_values
        @controlled_values ||= {}
      end

      def reset_debug_state!
        @counters = Hash.new(0)
        @lazies = []
      end
    end
  end
end

describe GraphQL::Execution::DebugSession do
  let(:schema) { DebugSessionSpec::DebugSchema }

  before do
    schema.reset_debug_state!
    schema.controlled_values.clear
    DebugSessionSpec::CountingSource.fetch_calls = 0
  end

  def stepped_execution(query_str)
    session = GraphQL::Execution::DebugSession.new(schema, query_str)
    pauses = []
    while (pause = session.step)
      pauses << pause
    end
    [session, pauses]
  end

  describe "stepping through a whole execution" do
    it "produces the same result and call counts as Schema.execute" do
      query_str = "{ plain lazyValue a: item(id: 1) b: item(id: 2) child { name } }"

      full_result = schema.execute(query_str).to_h
      full_counters = schema.counters.dup
      full_fetches = DebugSessionSpec::CountingSource.fetch_calls
      full_lazy_resolutions = schema.lazies.map(&:resolve_calls)

      schema.reset_debug_state!
      DebugSessionSpec::CountingSource.fetch_calls = 0

      session, pauses = stepped_execution(query_str)

      assert session.finished?
      assert_equal full_result, session.result.to_h
      assert_equal full_counters, schema.counters
      assert_equal full_fetches, DebugSessionSpec::CountingSource.fetch_calls
      assert_equal full_lazy_resolutions, schema.lazies.map(&:resolve_calls)
      assert pauses.any?(&:field_start?)
      assert pauses.any?(&:field_end?)
      assert pauses.any?(&:batch?)
    end
  end

  describe "pausing" do
    it "pauses at field starts, field ends, and batch boundaries" do
      session = GraphQL::Execution::DebugSession.new(schema, "{ a: item(id: 1) b: item(id: 2) }")
      assert session.ready?

      pause = session.step_to_field_start
      assert session.paused?
      assert pause.field_start?
      assert_equal "Query.item", pause.label
      assert_equal "item", pause.field.graphql_name
      assert pause.frozen?
      assert_equal 0, schema.counters[:item]
      assert_nil session.result

      pause = session.step_to_batch
      assert pause.batch?
      assert_equal "DebugSessionSpec::CountingSource", pause.label
      assert_kind_of DebugSessionSpec::CountingSource, pause.source
      # Both ids were requested before the batch ran:
      assert_equal 2, schema.counters[:item]
      assert_equal 2, pause.source.pending.size
      # The batch itself hasn't run yet:
      assert_equal 0, DebugSessionSpec::CountingSource.fetch_calls

      result = session.run
      assert session.finished?
      assert_equal 1, DebugSessionSpec::CountingSource.fetch_calls
      assert_equal({ "data" => { "a" => "item-1", "b" => "item-2" } }, result.to_h)
    end

    it "pauses at field ends after the resolver ran" do
      session = GraphQL::Execution::DebugSession.new(schema, "{ plain }")
      pause = session.step_to_field_end
      assert pause.field_end?
      assert_equal "Query.plain", pause.label
      assert_equal 1, schema.counters[:plain]
      assert_nil session.step
      assert session.finished?
    end

    it "exposes read-only pending and waiting state while paused" do
      session = GraphQL::Execution::DebugSession.new(schema, "{ plain lazyValue }")
      pause = session.step_to_field_start

      state = pause.pending_state
      assert state.frozen?
      assert state[:waiting_sources].frozen?
      # lazyValue's job is still queued, and session fibers are alive:
      assert state[:pending_jobs] >= 1
      assert state[:alive_fibers] >= 1
      assert_equal state, session.pending_state

      assert_raises(FrozenError) { state[:pending_jobs] = 0 }
      session.terminate
    end
  end

  describe "resuming" do
    it "never re-calls a resolver that already ran" do
      session = GraphQL::Execution::DebugSession.new(schema, "{ plain lazyValue }")

      pause = session.step_to_field_start
      assert_equal "Query.plain", pause.label
      assert_equal 0, schema.counters[:plain]

      pause = session.step_to_field_end
      assert_equal "Query.plain", pause.label
      assert_equal 1, schema.counters[:plain]

      while (pause = session.step)
        assert schema.counters[:plain] <= 1, "plain was called #{schema.counters[:plain]} times"
      end

      assert_equal 1, schema.counters[:plain]
      assert_equal 1, schema.counters[:lazy_value]
      assert_equal [1], schema.lazies.map(&:resolve_calls)
      assert_equal({ "data" => { "plain" => "plain", "lazyValue" => "lazy" } }, session.result.to_h)
    end
  end

  describe "controllable lazy values" do
    it "resolves them with the same values and counts as full execution" do
      schema.controlled_values[:lazy_value] = "controlled-by-test"
      query_str = "{ lazyValue }"

      full_result = schema.execute(query_str).to_h
      full_resolutions = schema.lazies.map(&:resolve_calls)

      schema.reset_debug_state!

      session = GraphQL::Execution::DebugSession.new(schema, query_str)
      session.run

      assert_equal full_result, session.result.to_h
      assert_equal "controlled-by-test", session.result.to_h["data"]["lazyValue"]
      assert_equal full_resolutions, schema.lazies.map(&:resolve_calls)
      assert_equal [1], schema.lazies.map(&:resolve_calls)
    end
  end

  describe "terminate" do
    it "unwinds session fibers and discards queued and waiting work" do
      session = GraphQL::Execution::DebugSession.new(schema, "{ a: item(id: 1) b: item(id: 2) lazyValue }")
      pause = session.step_to_batch
      assert pause.batch?
      assert session.paused?
      assert session.pending_state[:alive_fibers] > 0

      session.terminate
      assert session.terminated?
      refute session.paused?
      refute session.finished?

      state = session.pending_state
      assert_equal 0, state[:alive_fibers]
      assert_equal 0, state[:pending_jobs]
      assert_equal 0, state[:waiting_fibers]
      assert_equal 0, state[:waiting_lazies]
      assert_empty state[:waiting_sources]

      # Waiting work never ran, during or after termination:
      assert_equal 0, DebugSessionSpec::CountingSource.fetch_calls
      assert_equal [0], schema.lazies.map(&:resolve_calls)

      assert_raises(GraphQL::Execution::DebugSession::TerminatedError) { session.step }
      assert_raises(GraphQL::Execution::DebugSession::TerminatedError) { session.run }
    end

    it "can terminate before the first step" do
      session = GraphQL::Execution::DebugSession.new(schema, "{ plain }")
      session.terminate
      assert session.terminated?
      assert_equal 0, schema.counters[:plain]
      assert_raises(GraphQL::Execution::DebugSession::TerminatedError) { session.step }
    end

    it "can terminate after finishing" do
      session = GraphQL::Execution::DebugSession.new(schema, "{ plain }")
      session.run
      assert session.finished?
      session.terminate
      assert session.terminated?
      assert_raises(GraphQL::Execution::DebugSession::TerminatedError) { session.step }
    end
  end

  describe "Schema.execute" do
    it "does not use the debug session path" do
      result = schema.execute("{ plain lazyValue }")
      assert_equal({ "data" => { "plain" => "plain", "lazyValue" => "lazy" } }, result.to_h)
      assert_equal 1, schema.counters[:plain]
      assert_equal 1, schema.counters[:lazy_value]
    end
  end
end
