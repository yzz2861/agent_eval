# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Execution::StepSession do
  class StepSessionSchema < GraphQL::Schema
    module Counters
      @counts = Hash.new(0)

      class << self
        def [](key)
          @counts[key]
        end

        def increment(key)
          @counts[key] += 1
        end

        def to_h
          @counts.dup
        end

        def reset!
          @counts.clear
        end
      end
    end

    class ControlledLazy
      def initialize(tag)
        @tag = tag
      end

      def value
        Counters.increment(:lazy_value)
        "lazy-#{@tag}"
      end
    end

    class NameSource < GraphQL::Dataloader::Source
      def fetch(ids)
        Counters.increment(:name_fetch)
        ids.map { |id| "name-#{id}" }
      end
    end

    class Item < GraphQL::Schema::Object
      field :name, String, null: false

      def name
        Counters.increment(:name)
        dataloader.with(NameSource).load(object[:id])
      end
    end

    class Query < GraphQL::Schema::Object
      field :a, String, null: false
      field :b, String, null: false
      field :echo, String, null: false do
        argument :msg, String
      end
      field :items, [Item], null: false

      def a
        Counters.increment(:a)
        "a"
      end

      def b
        Counters.increment(:b)
        ControlledLazy.new("b")
      end

      def echo(msg:)
        Counters.increment(:echo)
        msg
      end

      def items
        Counters.increment(:items)
        [{ id: 1 }, { id: 2 }, { id: 3 }]
      end
    end

    query(Query)
    use GraphQL::Dataloader
    lazy_resolve(ControlledLazy, :value)
  end

  # Same style of resolvers, but without enabling GraphQL::Dataloader
  class StepSessionLazyOnlySchema < GraphQL::Schema
    class ControlledLazy
      def initialize(tag)
        @tag = tag
      end

      def value
        StepSessionSchema::Counters.increment(:lazy_only_value)
        "lazy-#{@tag}"
      end
    end

    class Query < GraphQL::Schema::Object
      field :a, String, null: false
      field :b, String, null: false

      def a
        StepSessionSchema::Counters.increment(:lazy_only_a)
        "a"
      end

      def b
        StepSessionSchema::Counters.increment(:lazy_only_b)
        ControlledLazy.new("b")
      end
    end

    query(Query)
    lazy_resolve(ControlledLazy, :value)
  end

  QUERY_STRING = "query GetStuff($msg: String!) { a b echo(msg: $msg) items { name } }"
  VARIABLES = { "msg" => "hello" }

  EXPECTED_COUNTS = {
    a: 1,
    b: 1,
    echo: 1,
    items: 1,
    name: 3,
    name_fetch: 1,
    lazy_value: 1,
  }.freeze

  def counters
    StepSessionSchema::Counters
  end

  def make_session(query_string = QUERY_STRING, **kwargs)
    GraphQL::Execution::StepSession.new(StepSessionSchema, query_string, **kwargs)
  end

  def drain(session, mode = nil)
    snapshots = []
    while (snapshot = session.step(mode))
      snapshots << snapshot
    end
    snapshots
  end

  before do
    counters.reset!
  end

  it "produces the same result and resolver call counts as Schema.execute" do
    expected_result = StepSessionSchema.execute(QUERY_STRING, variables: VARIABLES)
    expected_counts = counters.to_h
    assert_equal EXPECTED_COUNTS, expected_counts

    counters.reset!
    session = make_session(variables: VARIABLES)
    result = session.run_to_completion

    assert session.finished?
    assert_equal expected_result.to_h, result.to_h
    assert_equal expected_counts, counters.to_h
  end

  it "pauses before a field resolver runs and after it finishes" do
    session = make_session("{ a b }")

    snapshot = session.step
    assert session.paused?
    assert_equal :field_start, snapshot.event.type
    assert_equal "Query.a", snapshot.event.field_path
    assert_equal 0, counters[:a], "The resolver has not run yet at the field_start boundary"

    snapshot = session.step
    assert_equal "Query.b", snapshot.event.field_path
    assert_equal 1, counters[:a]
    assert_equal 0, counters[:b]

    session.terminate

    counters.reset!
    session = make_session("{ a b }")
    snapshot = session.step(:field_end)
    assert_equal :field_end, snapshot.event.type
    assert_equal "Query.a", snapshot.event.field_path
    assert_equal 1, counters[:a], "The resolver has run at the field_end boundary"
    session.terminate
  end

  it "exposes read-only pending and waiting state while paused" do
    session = make_session(variables: VARIABLES)
    snapshot = session.step

    assert snapshot.frozen?
    assert snapshot.event.frozen?
    assert snapshot.pending_sources.frozen?
    assert snapshot.waiting_sources.frozen?
    assert snapshot.to_h.frozen?
    assert_raises(FrozenError) { snapshot.pending_sources << { source: "Nope", keys: 1 } }
    assert_raises(FrozenError) { snapshot.waiting_sources << "Nope" }

    assert_equal :paused, snapshot.status
    assert_kind_of Integer, snapshot.pending_jobs
    assert_kind_of Integer, snapshot.pending_lazies
    assert_kind_of Integer, snapshot.waiting_fibers
    assert_kind_of Integer, snapshot.fields_started
    assert_kind_of Integer, snapshot.fields_finished

    session.terminate
  end

  it "pauses at batch load boundaries with the pending batch visible" do
    session = make_session(variables: VARIABLES)

    snapshot = session.step(:batch)
    assert_equal :batch, snapshot.event.type
    assert_equal "StepSessionSchema::NameSource", snapshot.event.source_class
    assert_equal [{ source: "StepSessionSchema::NameSource", keys: 3 }], snapshot.pending_sources
    assert_equal 3, snapshot.waiting_fibers
    assert_equal ["StepSessionSchema::NameSource"], snapshot.waiting_sources
    assert_equal 1, snapshot.pending_lazies, "The lazy value of b is still waiting for its round"

    # The next batch boundary is the lazy-resolution round for b
    snapshot = session.step(:batch)
    assert_equal :batch, snapshot.event.type
    assert_nil snapshot.event.source_class

    assert_nil session.step(:batch), "No more batch boundaries remain"
    assert session.finished?
    assert_equal 1, counters[:name_fetch], "All three names were fetched in one batch"
  end

  it "never re-calls an already-executed resolver after resuming" do
    session = make_session(variables: VARIABLES)
    previous_counts = Hash.new(0)

    while (snapshot = session.step)
      EXPECTED_COUNTS.each_key do |key|
        current = counters[key]
        assert current >= previous_counts[key], "Counter #{key} went backwards"
        assert current <= EXPECTED_COUNTS[key], "Resolver #{key} ran too many times"
      end
      previous_counts = counters.to_h
      assert snapshot.fields_started >= snapshot.fields_finished
    end

    assert session.finished?
    assert_equal EXPECTED_COUNTS, counters.to_h
  end

  it "terminates mid-execution, reclaiming fibers and pending work" do
    session = make_session(variables: VARIABLES)
    session.step
    session.step(:batch)
    assert session.paused?

    session.terminate
    assert session.terminated?

    snapshot = session.snapshot
    assert_equal :terminated, snapshot.status
    assert_equal 0, snapshot.pending_jobs
    assert_equal 0, snapshot.pending_lazies
    assert_equal 0, snapshot.waiting_fibers
    assert_equal [], snapshot.pending_sources
    assert_equal [], snapshot.waiting_sources

    assert_raises(GraphQL::Execution::StepSession::SessionError) { session.step }
    assert_raises(GraphQL::Execution::StepSession::SessionError) { session.result }
  end

  it "can be terminated before execution starts" do
    session = make_session(variables: VARIABLES)
    session.terminate
    assert session.terminated?
    assert_equal 0, counters[:a]
    assert_raises(GraphQL::Execution::StepSession::SessionError) { session.step }
  end

  it "treats terminate after completion as a no-op" do
    session = make_session("{ a }")
    session.run_to_completion
    session.terminate
    assert session.finished?
    assert_equal({ "a" => "a" }, session.result.to_h["data"])
  end

  it "raises for a result before execution finishes and returns nil from step when done" do
    session = make_session("{ a }")
    assert_raises(GraphQL::Execution::StepSession::SessionError) { session.result }
    session.step
    assert_raises(GraphQL::Execution::StepSession::SessionError) { session.result }
    assert_nil session.step until session.finished?
    assert_nil session.step
    assert_equal({ "a" => "a" }, session.result.to_h["data"])
  end

  it "rejects unknown step modes" do
    session = make_session("{ a }")
    assert_raises(ArgumentError) { session.step(:nowhere) }
    session.terminate
  end

  it "is not used by a plain Schema.execute" do
    result = StepSessionSchema.execute("{ a }")
    refute_instance_of GraphQL::Execution::StepSession::StepTrace, result.query.current_trace
    assert_equal({ "a" => "a" }, result.to_h["data"])

    session = make_session("{ a }")
    assert_instance_of GraphQL::Execution::StepSession::StepTrace, session.query.current_trace
    session.terminate
  end

  it "also steps, finishes and terminates without Dataloader installed" do
    query_string = "{ a b }"
    expected_result = StepSessionLazyOnlySchema.execute(query_string)
    expected_counts = counters.to_h

    counters.reset!
    session = GraphQL::Execution::StepSession.new(StepSessionLazyOnlySchema, query_string)
    snapshots = drain(session)
    assert snapshots.any? { |s| s.event.type == :field_start }
    assert_equal expected_result.to_h, session.result.to_h
    assert_equal expected_counts, counters.to_h

    session = GraphQL::Execution::StepSession.new(StepSessionLazyOnlySchema, query_string)
    snapshot = session.step(:batch)
    assert_equal :batch, snapshot.event.type
    assert_nil snapshot.event.source_class
    session.terminate
    assert session.terminated?
    assert_equal 0, session.snapshot.pending_lazies
  end
end
