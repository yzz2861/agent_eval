# frozen_string_literal: true

require 'test_helper'
require 'stringio'

class RenderToTest < Minitest::Test
  module ShoutFilter
    def shout(input)
      "#{input}!"
    end
  end

  class SpyDrop < Liquid::Drop
    attr_reader :calls

    def initialize
      @calls = []
    end

    def greeting
      @calls << :greeting
      'hello'
    end
  end

  def test_render_to_matches_render_output
    source   = "{% capture greeting %}Hello, {{ name }}!{% endcapture %}{{ greeting }}{% for i in (1..3) %}[{{ i }}]{% endfor %}{% if ok %}yes{% endif %}"
    assigns  = { 'name' => 'world', 'ok' => true }
    template = Liquid::Template.parse(source)
    expected = template.render(assigns)

    chunks = []
    template.render_to(->(chunk) { chunks << chunk }, assigns)

    assert_equal(expected, chunks.join)
  end

  def test_sink_interfaces
    template = Liquid::Template.parse("a{{ 'b' }}c")

    chunks = []
    callable = ->(chunk) { chunks << chunk }
    assert_same(callable, template.render_to(callable))
    assert_equal('abc', chunks.join)

    array = []
    assert_same(array, template.render_to(array))
    assert_equal('abc', array.join)

    io = StringIO.new
    assert_same(io, template.render_to(io))
    assert_equal('abc', io.string)

    error = assert_raises(ArgumentError) { template.render_to(Object.new) }
    assert_match(/sink/, error.message)
  end

  def test_render_to_without_assigns
    template = Liquid::Template.parse('hello')
    chunks   = []
    template.render_to(->(chunk) { chunks << chunk })
    assert_equal(['hello'], chunks)
  end

  def test_render_to_accepts_filters
    template = Liquid::Template.parse("{{ 'a' | shout }}")

    chunks = []
    template.render_to(->(chunk) { chunks << chunk }, {}, filters: [ShoutFilter])
    assert_equal(['a!'], chunks)

    chunks = []
    template.render_to(->(chunk) { chunks << chunk }, {}, ShoutFilter)
    assert_equal(['a!'], chunks)
  end

  def test_first_chunk_is_delivered_before_template_finishes
    received = []
    progress = []
    probe = Module.new do
      define_method(:probe) do |_input|
        progress << received.length
        ''
      end
    end

    template = Liquid::Template.parse("{% for i in (1..1000) %}{{ i }}{{ '' | probe }}{% endfor %}")
    template.render_to(->(chunk) { received << chunk }, {}, filters: [probe])

    # the probe filter observed the sink filling up chunk by chunk while the
    # loop was still running, instead of everything arriving at the end
    assert_equal((1..1000).to_a, progress)
    assert_equal((1..1000).map(&:to_s), received)
  end

  def test_capture_buffers_locally_but_streams_result
    template = Liquid::Template.parse("{% capture v %}{% for i in (1..3) %}{{ i }}{% endfor %}{% endcapture %}[{{ v }}]")
    chunks   = []
    template.render_to(->(chunk) { chunks << chunk })

    # nothing is streamed while the capture is in progress; only the final
    # reference to the captured variable is emitted
    assert_equal(['[', '123', ']'], chunks)
  end

  def test_render_length_limit_caps_total_streamed_output
    template = Liquid::Template.parse("{% for i in (1..100) %}0123456789{% endfor %}")
    template.resource_limits.render_length_limit = 50

    received = []
    template.render_to(->(chunk) { received << chunk })

    assert_equal(60, received.join.bytesize)
    assert_operator(received.size, :<, 100)
    assert_instance_of(Liquid::MemoryError, template.errors.first)
  end

  def test_capture_cannot_bypass_output_limit
    template = Liquid::Template.parse("{% capture big %}{% for i in (1..100) %}0123456789{% endfor %}{% endcapture %}")
    template.resource_limits.assign_score_limit = 50

    received = []
    template.render_to(->(chunk) { received << chunk })

    # hiding the whole output inside a capture does not bypass the limits:
    # the local buffer is constrained separately by the assign score
    assert_equal([], received)
    assert_instance_of(Liquid::MemoryError, template.errors.first)
  end

  def test_captured_content_counts_towards_output_limit_when_streamed
    template = Liquid::Template.parse("{% capture big %}{% for i in (1..10) %}0123456789{% endfor %}{% endcapture %}{{ big }}")
    template.resource_limits.render_length_limit = 50
    template.resource_limits.assign_score_limit  = 10_000

    received = []
    template.render_to(->(chunk) { received << chunk })

    assert_equal(100, received.join.bytesize)
    assert_instance_of(Liquid::MemoryError, template.errors.first)
  end

  def test_sink_error_aborts_render_and_skips_drops_and_filters
    filter_calls = []
    spy = Module.new do
      define_method(:record) do |input|
        filter_calls << input
        input
      end
    end
    drop = SpyDrop.new

    received = []
    sink = ->(chunk) do
      received << chunk
      raise 'sink exploded' if received.size == 1
    end

    template = Liquid::Template.parse("{{ 'a' | record }}{{ drop.greeting }}{{ 'b' | record }}")
    context  = Liquid::Context.new('drop' => drop)

    error = assert_raises(Liquid::SinkError) do
      template.render_to(sink, context, filters: [spy])
    end

    assert_equal('sink exploded', error.cause.message)
    assert_equal(['a'], received)
    assert_equal(['a'], filter_calls)
    assert_equal([], drop.calls)
    assert_equal([], template.errors)
  end

  def test_context_is_restored_after_sink_error_inside_for_loop
    received = []
    sink = ->(chunk) do
      received << chunk
      raise 'boom' if received.size == 3
    end

    template = Liquid::Template.parse("{% for i in (1..10) %}{{ i }}{% endfor %}")
    context  = Liquid::Context.new

    assert_raises(Liquid::SinkError) { template.render_to(sink, context) }

    assert_equal(['1', '2', '3'], received)
    assert_equal(1, context.scopes.size)
    assert_equal([], context.registers[:for_stack])
    assert_nil(context.registers.static[:template_error_mode])

    # the same template and context render cleanly afterwards
    chunks = []
    template.render_to(->(chunk) { chunks << chunk }, context)
    assert_equal('12345678910', chunks.join)
  end
end
