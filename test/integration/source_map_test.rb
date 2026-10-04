# frozen_string_literal: true

require 'test_helper'

class SourceMapTest < Minitest::Test
  include Liquid

  class SourceMapFileSystem
    def read_template_file(template_path)
      case template_path
      when 'snippet'
        "<b>{{ value }}</b>\n"
      else
        raise "unknown template #{template_path}"
      end
    end
  end

  def setup
    @environment = Liquid::Environment.build(file_system: SourceMapFileSystem.new)
  end

  def parse(source, **options)
    Liquid::Template.parse(source, **options)
  end

  def test_disabled_by_default
    template = parse("Hello {{ 'world' }}")
    output   = template.render

    assert_equal("Hello world", output)
    assert_nil(template.source_map)
  end

  def test_output_is_identical_to_normal_render
    source  = "Hello {{ name | upcase }}!{% for i in (1..3) %}[{{ i }}]{% endfor %}\n"
    assigns = { 'name' => 'bob' }

    mapped  = parse(source, source_map: true).render(assigns)
    plain   = parse(source).render(assigns)

    assert_equal(plain, mapped)
  end

  def test_records_text_and_variable_nodes
    template = parse("Hello {{ 'world' }}!", source_map: true)
    template.render

    entries = template.source_map.entries
    assert_equal(3, entries.length)

    text, variable, bang = entries

    assert_equal(:text, text.node_type)
    assert_equal(0...6, text.output_range)
    assert_equal(0...6, text.source_range)

    assert_equal(:variable, variable.node_type)
    assert_equal(6...11, variable.output_range)
    assert_equal(6...19, variable.source_range)

    assert_equal(:text, bang.node_type)
    assert_equal(11...12, bang.output_range)
    assert_equal(19...20, bang.source_range)
  end

  def test_filter_output_uses_actual_output_length
    template = parse("{{ 'ab' | upcase }}{{ 'abc' | slice: 0, 1 }}", source_map: true)
    output   = template.render

    assert_equal("ABa", output)

    first, second = template.source_map.entries
    assert_equal(0...2, first.output_range)
    assert_equal(2...3, second.output_range)
  end

  def test_loop_iterations_are_recorded_separately
    template = parse("{% for i in (1..3) %}{{ i }}{% endfor %}", source_map: true)
    template.render

    variables = template.source_map.entries.select { |entry| entry.node_type == :variable }
    assert_equal(3, variables.length)
    assert_equal([0...1, 1...2, 2...3], variables.map(&:output_range))

    # all iterations point at the same template node and source range
    assert(variables.all? { |entry| entry.node.equal?(variables.first.node) })
    assert(variables.all? { |entry| entry.source_range == variables.first.source_range })
  end

  def test_render_stack_is_recorded
    template = parse("{% for i in (1..2) %}{% if i > 1 %}{{ i }}{% endif %}{% endfor %}", source_map: true)
    template.render

    variable = template.source_map.entries.find { |entry| entry.node_type == :variable }
    assert_equal(["for", "if"], variable.stack.map(&:tag_name))

    if_entry = template.source_map.entries.find { |entry| entry.node_type == "if" }
    assert_equal(["for"], if_entry.stack.map(&:tag_name))

    for_entry = template.source_map.entries.find { |entry| entry.node_type == "for" }
    assert_equal([], for_entry.stack)
  end

  def test_block_source_range_spans_whole_block
    source   = "x{% if true %}y{% endif %}z"
    template = parse(source, source_map: true)
    template.render

    if_entry = template.source_map.entries.find { |entry| entry.node_type == "if" }
    assert_equal(1...26, if_entry.source_range)
    assert_equal("{% if true %}y{% endif %}", source[if_entry.source_range])
    assert_equal(1...2, if_entry.output_range)
  end

  def test_liquid_tag_nodes_have_source_ranges
    source   = "a{% liquid\n  echo 1\n  echo 22\n%}z"
    template = parse(source, source_map: true)
    output   = template.render

    assert_equal("a122z", output)

    echoes = template.source_map.entries.select { |entry| entry.node_type == "echo" }
    assert_equal(2, echoes.length)
    assert_equal("echo 1", source[echoes[0].source_range])
    assert_equal("echo 22", source[echoes[1].source_range])
    assert_equal(1...2, echoes[0].output_range)
    assert_equal(2...4, echoes[1].output_range)
  end

  def test_render_tag_records_partial_nodes_with_shared_output_offsets
    template = parse("a{% render 'snippet', value: 1 %}z", source_map: true, environment: @environment)
    output   = template.render

    assert_equal("a<b>1</b>\nz", output)

    render_entry = template.source_map.entries.find { |entry| entry.node_type == "render" }
    assert_equal(1...10, render_entry.output_range)

    variable = template.source_map.entries.find { |entry| entry.node_type == :variable }
    assert_equal(4...5, variable.output_range)
    assert_equal("snippet", variable.template_name)
    assert_equal(["render"], variable.stack.map(&:tag_name))
    assert_equal("{{ value }}", "<b>{{ value }}</b>\n"[variable.source_range])
  end

  def test_include_tag_records_partial_nodes
    template = parse("a{% include 'snippet' %}z", source_map: true, environment: @environment)
    output   = template.render('value' => 2)

    assert_equal("a<b>2</b>\nz", output)

    variable = template.source_map.entries.find { |entry| entry.node_type == :variable }
    assert_equal(4...5, variable.output_range)
    assert_equal("snippet", variable.template_name)
  end

  def test_capture_body_is_not_recorded_against_final_output
    template = parse("a{% capture c %}hidden{% endcapture %}b{{ c }}", source_map: true)
    output   = template.render

    assert_equal("abhidden", output)

    entries = template.source_map.entries
    # the capture body was rendered into a temporary buffer, so only the
    # top-level text nodes are recorded
    assert_equal(["a", "b"], entries.select { |entry| entry.node_type == :text }.map(&:node))

    variable = entries.find { |entry| entry.node_type == :variable }
    assert_equal(2...8, variable.output_range)
  end

  def test_entries_do_not_copy_rendered_values
    template = parse("{{ secret }}", source_map: true)
    template.render('secret' => 'sensitive-value')

    template.source_map.entries.each do |entry|
      entry.instance_variables.each do |ivar|
        refute_includes(entry.instance_variable_get(ivar).inspect, 'sensitive-value')
      end
    end
  end

  def test_entries_at_returns_innermost_first
    template = parse("{% for i in (1..2) %}[{{ i }}]{% endfor %}", source_map: true)
    template.render

    entries = template.source_map.entries_at(1)
    assert_equal(:variable, entries.first.node_type)
    assert_equal("for", entries.last.node_type)
  end

  def test_rerender_replaces_source_map
    template = parse("{{ 1 }}{{ 2 }}", source_map: true)
    template.render
    first_map = template.source_map

    template.render
    refute_same(first_map, template.source_map)
    assert_equal(2, template.source_map.entries.length)
  end

  def test_line_numbers_available_on_entries
    template = parse("a\n{{ 1 }}", source_map: true)
    template.render

    variable = template.source_map.entries.find { |entry| entry.node_type == :variable }
    assert_equal(2, variable.line_number)
  end
end
