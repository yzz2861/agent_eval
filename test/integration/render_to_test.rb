# frozen_string_literal: true

require 'test_helper'

class RenderToTest < Minitest::Test
  class CollectingSink
    attr_reader :chunks

    def initialize
      @chunks = []
    end

    def call(chunk)
      @chunks << chunk
    end

    def join
      @chunks.join
    end
  end

  def test_streams_plain_text_variables_and_loops_as_separate_chunks
    template = Liquid::Template.parse("Hello {{ name }}! {% for i in (1..3) %}item{{ i }} {% endfor %}done")
    sink = CollectingSink.new

    template.render_to({ "name" => "world" }, sink)

    assert_equal("Hello world! item1 item2 item3 done", sink.join)
    assert_includes(sink.chunks, "Hello ")
    assert_includes(sink.chunks, "world")
    assert_includes(sink.chunks, "done")
    assert_operator(sink.chunks.length, :>, 1)
  end

  def test_accepts_a_block_as_sink
    template = Liquid::Template.parse("a{{ 'b' }}c")
    chunks = []
    template.render_to({}) { |chunk| chunks << chunk }
    assert_equal("abc", chunks.join)
  end

  def test_first_chunk_is_available_before_template_finishes
    template = Liquid::Template.parse("{% for i in (1..100000) %}item{{ i }}\n{% endfor %}")
    mutex = Mutex.new
    first_chunk_arrived = ConditionVariable.new
    release_sink = ConditionVariable.new
    state = { chunks: 0, finished: false, release: false }

    render_thread = Thread.new do
      template.render_to({}) do |_chunk|
        mutex.synchronize do
          if state[:chunks].zero?
            state[:chunks] += 1
            first_chunk_arrived.signal
            release_sink.wait(mutex) until state[:release]
          end
        end
      end
      mutex.synchronize { state[:finished] = true }
    end

    mutex.synchronize do
      first_chunk_arrived.wait(mutex) until state[:chunks].positive?
      refute(state[:finished])
      state[:release] = true
      release_sink.signal
    end
  ensure
    render_thread&.join
  end

  def test_does_not_materialize_the_full_output
    template = Liquid::Template.parse("{% for i in (1..1000) %}{{ i }}{% endfor %}")
    largest = ConcurrentMax.new

    template.render_to({}) do |chunk|
      largest.offer(chunk.bytesize)
    end

    assert_operator(largest.value, :<, template.render({}).bytesize)
  end

  def test_capture_still_buffers_its_body_locally
    template = Liquid::Template.parse("before{% capture cap %}CAP{% endcapture %}after{{ cap }}")
    sink = CollectingSink.new

    template.render_to({}, sink)

    assert_equal("beforeafterCAP", sink.join)
    assert_equal(%w[before after CAP], sink.chunks)
  end

  def test_capture_body_can_be_consumed_like_a_normal_variable
    template = Liquid::Template.parse(
      "{% capture x %}hello {{ name }}{% endcapture %}{{ x | upcase }}"
    )
    sink = CollectingSink.new

    template.render_to({ "name" => "world" }, sink)

    assert_equal("HELLO WORLD", sink.join)
  end

  def test_render_length_limit_still_bounds_total_streamed_output
    environment = Liquid::Environment.build do |env|
      env.default_resource_limits = { render_length_limit: 5 }
    end
    template = Liquid::Template.new(environment: environment)
      .parse("{% for i in (1..100) %}abc{% endfor %}")

    received = CollectingSink.new
    assert_raises(Liquid::MemoryError) do
      template.render_to({}, received)
    end
    assert_operator(received.join.bytesize, :<=, 8)
  end

  def test_capture_length_limit_bounds_locally_materialized_content
    environment = Liquid::Environment.build do |env|
      env.default_resource_limits = { capture_length_limit: 5 }
    end
    template = Liquid::Template.new(environment: environment)
      .parse("{% capture x %}aaaaaaaaaaaa{% endcapture %}{{ x }}")

    assert_raises(Liquid::MemoryError) do
      template.render_to({}) { |_chunk| }
    end
  end

  def test_capture_limit_cannot_be_bypassed_with_nested_captures
    environment = Liquid::Environment.build do |env|
      env.default_resource_limits = { capture_length_limit: 10 }
    end

    # An oversized inner capture is caught on its own budget...
    inner = Liquid::Template.new(environment: environment)
      .parse("{% capture a %}aaaa{% capture b %}bbbbbbbbbbbb{% endcapture %}aaaa{% endcapture %}{{ a }}")
    assert_raises(Liquid::MemoryError) do
      inner.render_to({}) { |_chunk| }
    end

    # ...and so is an oversized outer capture that comes after a small inner one.
    outer = Liquid::Template.new(environment: environment)
      .parse("{% capture b %}bbb{% endcapture %}{% capture a %}aaaaaaaaaaaaaaa{% endcapture %}{{ a }}")
    assert_raises(Liquid::MemoryError) do
      outer.render_to({}) { |_chunk| }
    end
  end

  def test_total_output_limit_cannot_be_bypassed_by_hiding_content_in_capture
    environment = Liquid::Environment.build do |env|
      # Streaming output is not retained, so a capture-heavy template trivially
      # emits little; the captured amount is independently bounded.
      env.default_resource_limits = {
        render_length_limit: 10,
        capture_length_limit: 8,
      }
    end
    template = Liquid::Template.new(environment: environment)
      .parse("{% capture x %}aaaaaaaaaaaa{% endcapture %}ok")

    assert_raises(Liquid::MemoryError) do
      template.render_to({}) { |_chunk| }
    end
  end

  def test_sink_error_stops_subsequent_nodes
    rendered = CountingDrop.new
    template = Liquid::Template.parse("{{ d }}{% for i in (1..5) %}{{ d }}{% endfor %}")
    calls = 0

    assert_raises(RuntimeError, "sink boom") do
      template.render_to({ "d" => rendered }) do |_chunk|
        calls += 1
        raise "sink boom" if calls == 1
      end
    end

    assert_equal(1, rendered.to_liquid_calls)
  end

  def test_sink_error_stops_subsequent_filters
    calls = 0
    filter_module = Module.new do
      define_method(:echo) do |input|
        calls += 1
        input
      end
    end
    template = Liquid::Template.parse("{{ 'a' | echo }}{{ 'b' | echo }}{{ 'c' | echo }}")
    count = 0

    assert_raises(RuntimeError, "sink boom") do
      template.render_to({}, filters: [filter_module]) do |_chunk|
        count += 1
        raise "sink boom" if count == 1
      end
    end

    assert_equal(1, calls)
  end

  def test_sink_error_propagates_the_original_exception
    template = Liquid::Template.parse("hello")
    custom = Class.new(StandardError)

    assert_raises(custom) do
      template.render_to({}) { |_chunk| raise custom, "original" }
    end
  end

  def test_sink_error_restores_context_stacks
    template = Liquid::Template.parse(
      "{% for i in (1..5) %}a{{ i }}{% endfor %}"
    )
    seen = false

    assert_raises(RuntimeError) do
      template.render_to({}) do |_chunk|
        raise "boom" if seen
        seen = true
      end
    end

    # Rendering again works and starts from a clean state (resource limits are
    # reset and no interrupt or loop scope leaked out).
    sink = CollectingSink.new
    template.render_to({}, sink)
    assert_equal("a1a2a3a4a5", sink.join)
  end

  def test_context_scope_from_failed_render_does_not_leak
    template = Liquid::Template.parse("{% for i in (1..3) %}{{ i }}{% endfor %}")
    sink_calls = 0

    context = Liquid::Context.new
    assert_raises(RuntimeError) do
      template.render_to(context) do |_chunk|
        sink_calls += 1
        raise "boom" if sink_calls == 2
      end
    end

    refute(context.key?("i"))
    assert_equal(1, context.scopes.length)
  end

  def test_ordinary_liquid_errors_are_not_sink_errors
    template = Liquid::Template.parse("{{ undefined_missing }}")
    sink = CollectingSink.new
    template.render_to({}, { strict_variables: true }, sink)
    assert_equal("", sink.join)
    refute_empty(template.errors)
  end

  def test_render_to_with_nil_root_returns_without_calling_sink
    template = Liquid::Template.new
    template.render_to({}) { |_chunk| flunk("sink should not be called") }
  end

  def test_render_to_requires_a_sink
    template = Liquid::Template.parse("hi")
    assert_raises(ArgumentError) do
      template.render_to({})
    end
  end

  def test_render_to_output_equals_render
    source = <<~LIQUID
      Header: {{ title | upcase }}
      {% for item in items %}- {{ item.name }}\n{% endfor %}
      {% capture footer %}done{% endcapture %}{{ footer }}
    LIQUID
    assigns = {
      "title" => "list",
      "items" => [{ "name" => "a" }, { "name" => "b" }],
    }
    template = Liquid::Template.parse(source)

    sink = CollectingSink.new
    template.render_to(assigns, sink)

    assert_equal(template.render(assigns), sink.join)
  end

  private

  class ConcurrentMax
    def initialize
      @mutex = Mutex.new
      @value = 0
    end

    def offer(candidate)
      @mutex.synchronize { @value = candidate if candidate > @value }
    end

    attr_reader :value
  end

  class CountingDrop < Liquid::Drop
    attr_reader :to_liquid_calls

    def initialize
      super
      @to_liquid_calls = 0
    end

    def to_liquid
      @to_liquid_calls += 1
      "X"
    end
  end
end
